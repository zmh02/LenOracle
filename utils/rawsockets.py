#coding=utf-8
import os
from ctypes import *

class Rawsockets(object):
    def __init__(self, src_ip, dst_ip, types=1):
        curr_file = os.path.abspath(__file__)
        curr_path = os.path.abspath(os.path.dirname(curr_file) + os.path.sep + ".")
        paths = os.path.join(curr_path, "rawsocket.so")
        self.lib = cdll.LoadLibrary(paths)

        inits = self.lib.inits
        inits.argtypes = [c_char_p, c_char_p]
        inits.restype = c_int

        inits(src_ip, dst_ip, types)

        self.parallel_tcp_data = self.lib.parallel_tcp_data
        self.parallel_rst = self.lib.parallel_rst
        self.parallel_psh_ack = self.lib.parallel_psh_ack
        self.parallel_ack_data = self.lib.parallel_ack_data
        self.parallel_udp_data = self.lib.parallel_udp_data
        self.parallel_dns_response = self.lib.parallel_dns_response

    def send_parallel_tcp_data(self, s_port, d_ports, seq_num, ack_num, lengths):
        count = len(d_ports)
        if count != len(lengths):
            print("error! padding lengths not match the ports")
            exit(0)
        lst1 = c_uint32 * count
        lst2 = c_uint32 * count
        self.parallel_tcp_data.argtypes = [c_uint32, lst1, c_int32, c_uint32, c_uint32, lst2]
        self.parallel_tcp_data.restype = c_int
        c_d_ports = lst1()
        for i in range(count):
            c_d_ports[i] = c_uint32(d_ports[i])
        c_lengths = lst2()
        for i in range(count):
            c_lengths[i] = c_uint32(lengths[i])
        
        self.parallel_tcp_data(s_port, c_d_ports, count, seq_num, ack_num, c_lengths)
    
    def send_parallel_rst(self, s_port, d_port, seq_nums, ack_num):    
        count = len(seq_nums)
        lst = c_uint32 * count
        self.parallel_rst.argtypes = [c_uint32, c_uint32, lst, c_int32, c_uint32]
        self.parallel_rst.restype = c_int

        c_seq_nums = lst()
        for i in range(count):
            c_seq_nums[i] = c_uint32(seq_nums[i])

        self.parallel_rst(s_port, d_port, c_seq_nums, count, ack_num)

    def send_parallel_psh_ack(self, s_port, d_port, seq_num, ack_nums):
        ack_count = len(ack_nums)
        ack_lst = c_uint32 * ack_count
        self.parallel_psh_ack.argtypes = [c_uint32, c_uint32, c_uint32, ack_lst, c_int32]
        self.parallel_psh_ack.restype = c_int

        c_ack_nums = ack_lst()
        for i in range(ack_count):
            c_ack_nums[i] = c_uint32(ack_nums[i])

        self.parallel_psh_ack(s_port, d_port, seq_num, c_ack_nums, ack_count)
    
    def send_parallel_ack_data(self, s_port, d_port, seq_num, ack_num, data):
        self.parallel_ack_data = self.lib.parallel_ack_data
        self.parallel_ack_data.argtypes = [c_uint32, c_uint32, c_uint32, c_uint32, c_char_p, c_int32]
        self.parallel_ack_data.restype = c_int
        
        count = len(data)
        
        self.parallel_ack_data(s_port, d_port, seq_num, ack_num, data, count)

    def send_parallel_udp_data(self, s_port, d_ports, lengths):
        count = len(d_ports)
        lst1 = c_uint32 * count
        lst2 = c_uint32 * count
        self.parallel_udp_data.argtypes = [c_uint32, lst1, c_uint32, lst2]
        self.parallel_udp_data.restype = c_int
        c_d_ports = lst1()
        for i in range(count):
            c_d_ports[i] = c_uint32(d_ports[i])
        c_lengths = lst2()
        for i in range(count):
            c_lengths[i] = c_uint32(lengths[i])
        self.parallel_udp_data(s_port, c_d_ports, count, c_lengths)
    
    def send_parallel_dns_response(self, s_port, d_port, trids):
        count = len(trids)
        lst = c_uint32 * count
        self.parallel_dns_response.argtypes = [c_uint32, c_uint32, lst, c_int32]
        self.parallel_dns_response.restype = c_int
        c_trids = lst()
        for i in range(count):
            c_trids[i] = c_uint32(trids[i])
        self.parallel_dns_response(s_port, d_port, c_trids, count)