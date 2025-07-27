import pyshark
from collections import Counter

INTERFACE = 'enp0s3' # network interface to monitor
MIN_DNS = 40 # minimum DNS query length to flag
MAX_SYNS = 10 # max SYN packets before flood warning
MAX_UDP = 100 # max UDP packets before flood warning

tcp_syns = Counter() # counts SYN packets per IP
udp_counter = Counter() # counts UDP packets per IP
tracked_lengths = {} # tracks repeated packet sizes per IP
blocked_ips = set()

print(f"--Live scanning on interface: {INTERFACE}...")
capture = pyshark.LiveCapture(interface=INTERFACE) # starts capture
start_time = None

try:
    for pkt in capture.sniff_continuously():

        if start_time is None:
            start_time = pkt.sniff_time # gets first packet time stamp
        elapsed = (pkt.sniff_time - start_time).total_seconds()
        
        if elapsed > 60: # stops capture after 1 minute
            print(f"\nTime limit reached ({60}s). Stopping...")
            capture.close()
            break

        try:
            # gets packet time, ip and size
            timestamp = pkt.sniff_time 
            ip = pkt.ip.src
            length = int(pkt.length)

            #Checking TCP for SYN flood
            if 'TCP' in pkt:
                tcp = pkt.tcp
                flags = int(tcp.flags, 16) #converts flags (in hex) to int
                if flags & 0x02 and not flags & 0x10: # checks for syn (0x02) flag without ack (0x10) - syn scan
                    tcp_syns[ip] += 1 #counts syns from this ip
                    if tcp_syns[ip] > MAX_SYNS: #flags if syns from this ip go over threshold
                        print(f"[{timestamp}] ! SYN scan from {ip} ({tcp_syns[ip]} SYNs)")
                        print(f" !! Potential SYN flood from {ip}")
                        if tcp_syns[ip] > 100:
                            print(f" !!! SYN flood probable BLOCK {ip} NOW")

            #Checking UDP flood
            if 'UDP' in pkt:
                udp_counter[ip] += 1 #counts udp from this ip
                if udp_counter[ip] > MAX_UDP: #flags if udp from this ip go over threshold
                    print(f"[{timestamp}] ! Possible UDP flood from {ip} ({udp_counter[ip]} UDP packets)")

            #Checking DNS tunneling 
            if 'DNS' in pkt:
                dns = pkt.dns
                query_name = dns.qry_name # gets domain being queried
                if query_name and len(query_name) > MIN_DNS: # checks for susppiciopusly long domain name
                    print(f"[{timestamp}] ! Long DNS query from {ip}: {query_name}")
                if 500 < length < 600: # checks for unusual size dns packets (standard is <500)
                    print(f"[{timestamp}] ! Large DNS packet from {ip}: {length} bytes – check for tunneling")

            #Catches strange ICMP traffic 
            if 'ICMP' in pkt:
                print(f"[{timestamp}] ! ICMP packet from {ip}")
                if length < 28 or length > 1000: #standard ping is 28 bytes (header +8 byte payload)
                    print(f"[{timestamp}] ! Suspicious ICMP size from {ip}: {length} bytes")

            #Catches unusual packet sizes
            if length == 0: # zero length packet
                print(f"[{timestamp}] ! Zero-length packet from {ip}")
            if length > 1500 : # larger than standard eth mtu
                print(f"[{timestamp}] ! Jumbo frame from {ip}: {length} bytes")
            if length < 40 :
                print(f"[{timestamp}] ! Abnormal packet size from {ip}: {length} bytes")

            #Flags repetitive packet sizes
            if ip not in tracked_lengths:
                tracked_lengths[ip] = [] #records packet length
            tracked_lengths[ip].append(length) #counts repeated packet sizes
            if tracked_lengths[ip].count(length) > 10: #flags if goes over 10
                print(f"[{timestamp}] (<>) Repetitive packet size from {ip}: {length} bytes")


        except AttributeError:
            continue  # Skip malformed packets

except Exception as e:
    print(f"\n Unexpected error: {e}")
    capture.close()


#sudo hping3 -S <Ip> -p 80 -c 2000 --interval u10000
#Tested with ^
