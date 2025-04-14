# LenOracle

## Description

LenOracle is a hijacking attack tool targeting the TCP/IP protocol suite, exploiting a length-based side channel introduced by wireless networks. The repo show some demo for this attack: DNS hijacking attacks, TCP hijacking attacks, and  TCP reset attacks.

## Demo

Demo 1: DNS Hijacking Attack (dns_hijack_attack.py)
- Infers source port by monitoring packet lengths in wireless networks
- Uses multi-bin search algorithm to quickly locate the correct source port
- Injects forged DNS response packets

Demo 2: TCP Hijacking Attack (tcp_hijack_attack.py)
- Supports two source port guessing methods: single-bin and multi-bin search
- Can guess sequence number window and acknowledgment number window
- Capable of injecting custom TCP packets

Demo 3: TCP Reset Attack (tcp_reset_attack.py)
- Infers source port by monitoring packet lengths in wireless networks
- Guesses sequence number window
- Sends RST packets to terminate TCP connections

## Source Code Structure

```
/
├── utils/                     
│   ├── rawsocket.go           # TCP/UDP packet sender
│   └── rawsockets.py          # Python wrapper for the packet sender
├── dns_hijack_attack.py       # DNS hijacking attack demo
├── tcp_hijack_attack.py       # TCP hijacking attack demo
└── tcp_reset_attack.py        # TCP reset attack demo
```

## Prerequisites

- Python 3.x
- Go 1.x (for compiling rawsocket.so)
- tshark (for packet capture)
- Network interface supporting monitor

## Configuration

In each attack script, you need to configure the following parameters:
```python
src_ip = "x.x.x.x"                # Source IP address
dst_ip = "x.x.x.x"                # Destination IP address
NIC = "eth0"                      # Network interface name
victim_mac = "xx:xx:xx:xx:xx:xx"  # Victim's MAC address
dst_port = 22                     # Destination port
WIFI_HEADER_LENGTH = 117          # Need to modify based on packet capture results
CHALLENGE_ACK_LENGTH = 129        # Need to modify based on packet capture results
```

## Compilation

If the `rawsocket.so` file is not suitable for your system, you need to recompile the Go code:

```bash
cd utils
go build -o rawsocket.so -buildmode=c-shared rawsocket.go
```

## Usage

1. Configure attack parameters
2. Run the corresponding attack script:

```bash
# DNS hijacking attack
python3 dns_hijack_attack.py

# TCP hijacking attack
python3 tcp_hijack_attack.py

# TCP reset attack
python3 tcp_reset_attack.py
```

## Notes

1. Running attack scripts requires root privileges
2. Ensure the network interface prepared
3. Make sure all parameters are correctly configured before launching attacks
4. Recommended to conduct experiments in a test environment

## Publication

Stay tuned.