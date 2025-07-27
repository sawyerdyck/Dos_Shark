#dos_Shark
dos_Shark is a pyshark script which aims to detect anomalies on a selected network interface
script identifies SYN and UDP flood. DNS tunneling, ICMP traffic, unusual packet sizes, and suspicious repetitive pacckets
requires pyshark, a python wrapper for tshark-the command line version of Wireshark
tested by sending an hping flood to a bridged ubuntu VM from host machine
