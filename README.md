# pcap2canlog
A small utility to convert pcap files of socketcan traffic to the canlog format used by can-utils

## dependencies
- libpcap

## usage
Converting a pcap file
```
cargo build
cargo run <pcap file> > can.log
```

Injecting can traffic on local virtual can device
```
modprobe vcan
ip link add dev can0 type vcan
pcap2canlog <pcap file> | canplayer -v can0=can0
```
