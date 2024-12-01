import socket
import struct
import random
import threading
import time
import argparse
import ipaddress  # Import ipaddress module for handling CIDR

# Function to calculate the checksum for IP and TCP headers
def calculate_checksum(data):
    if len(data) % 2 == 1:
        data += b"\x00"
    checksum = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16
    return ~checksum & 0xFFFF

# Function to generate random IPs in bulk
def generate_random_ips(count):
    return [f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}" for _ in range(count)]

# Function to convert CIDR to a list of IPs
def cidr_to_ip_list(cidr):
    # Create an IP network object from the CIDR
    network = ipaddress.IPv4Network(cidr, strict=False)
    
    # Return a list of all the IP addresses in the network
    return [str(ip) for ip in network.hosts()]

# Function to read IPs from a file, handle ranges and CIDR
def read_ips_from_file(file_path):
    try:
        with open(file_path, "r") as file:
            ips = []
            for line in file.readlines():
                line = line.strip()
                # If the line is a CIDR block (e.g., "192.168.1.0/24")
                if '/' in line:
                    ips.extend(cidr_to_ip_list(line))
                # If the line is a range (e.g., "192.168.1.1-192.168.1.100")
                elif '-' in line:
                    start_ip, end_ip = line.split('-')
                    start_ip_parts = list(map(int, start_ip.split('.')))
                    end_ip_parts = list(map(int, end_ip.split('.')))
                    for i in range(start_ip_parts[3], end_ip_parts[3] + 1):
                        ip = f"{start_ip_parts[0]}.{start_ip_parts[1]}.{start_ip_parts[2]}.{i}"
                        ips.append(ip)
                else:
                    # If it's just a single IP address
                    ips.append(line)
            return ips
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return []

# Function to build a TCP header with minimal changes
def build_tcp_header(src_ip, dest_ip, src_port, dest_port, seq_num):
    ack_num = 0  # No acknowledgment in SYN
    offset_res = (5 << 4) + 0  # Data offset and reserved bits
    flags = 0b00000010  # SYN flag
    window = socket.htons(5840)  # Window size
    checksum = 0  # Placeholder for checksum
    urgent_pointer = 0  # No urgent pointer

    # Pack TCP Header (without checksum)
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dest_port,
        seq_num,
        ack_num,
        offset_res,
        flags,
        window,
        checksum,
        urgent_pointer,
    )

    # Pseudo header for checksum calculation
    pseudo_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dest_ip),
        0,
        socket.IPPROTO_TCP,
        len(tcp_header),
    )

    # Calculate checksum
    checksum = calculate_checksum(pseudo_header + tcp_header)

    # Rebuild TCP Header with correct checksum
    tcp_header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dest_port,
        seq_num,
        ack_num,
        offset_res,
        flags,
        window,
        checksum,
        urgent_pointer,
    )

    return tcp_header

# Function to build an IP header
def build_ip_header(src_ip, dest_ip):
    version = 4
    ihl = 5  # Internet Header Length
    tos = 0  # Type of Service
    total_length = 20 + 20  # IP Header + TCP Header
    packet_id = random.randint(0, 65535)  # Random Packet ID
    fragment_offset = 0
    ttl = 64  # Time to Live
    protocol = socket.IPPROTO_TCP  # Protocol type (TCP)
    checksum = 0  # Placeholder for checksum
    src_ip = socket.inet_aton(src_ip)  # Convert source IP to binary
    dest_ip = socket.inet_aton(dest_ip)  # Convert destination IP to binary

    # Pack IP Header
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        (version << 4) + ihl,
        tos,
        total_length,
        packet_id,
        fragment_offset,
        ttl,
        protocol,
        checksum,
        src_ip,
        dest_ip,
    )

    # Calculate checksum
    checksum = calculate_checksum(ip_header)

    # Rebuild IP Header with correct checksum
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        (version << 4) + ihl,
        tos,
        total_length,
        packet_id,
        fragment_offset,
        ttl,
        protocol,
        checksum,
        src_ip,
        dest_ip,
    )

    return ip_header

# Function to parse port input
def parse_ports(port_input):
    ports = set()
    for part in port_input.split(","):
        part = part.strip()
        if "-" in part:  # Handle port range (e.g., 22-60)
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        else:  # Handle individual ports
            ports.add(int(part))
    return sorted(ports)

# Function to send packets and track IPs per second
def send_packets(ports, src_ip, src_port, count, throttle, valid_ips, valid_ips_lock, target_ips, dig, scanned_networks):
    while True:  # Loop to restart the process if a PermissionError occurs
        try:
            # Create raw socket and set options
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            packets_sent = 0
            seq_num = random.randint(0, 4294967295)

            start_time = time.time()
            ips_scanned = 0

            while True:
                # Exit if we have found the required number of valid IPs
                with valid_ips_lock:
                    if count > 0 and len(valid_ips) >= count:
                        break

                # Use target IPs from file or generate random IPs
                ips_to_scan = target_ips if target_ips else generate_random_ips(100)

                for dest_ip in ips_to_scan:
                    for dest_port in ports:
                        ip_header = build_ip_header(src_ip, dest_ip)
                        tcp_header = build_tcp_header(src_ip, dest_ip, src_port, dest_port, seq_num)
                        packet = ip_header + tcp_header

                        # Send packet
                        raw_socket.sendto(packet, (dest_ip, 0))
                        packets_sent += 1
                        ips_scanned += 1

                        # Print IPs per second and valid IP count
                        elapsed_time = time.time() - start_time
                        if elapsed_time >= 1:
                            with valid_ips_lock:
                                found_count = len(valid_ips)
                            print(f"IPs per second: {ips_scanned} (found: {found_count})")
                            ips_scanned = 0
                            start_time = time.time()

                        # Apply throttle if specified
                        if throttle > 0:
                            time.sleep(throttle)

                        # If --dig is enabled, scan /24 network of the found IPs
                        if dig:
                            with valid_ips_lock:
                                # Only dig into the IPs that have been found and validated
                                for found_ip in valid_ips:
                                    # Get the first 3 octets of the IP to form the /24 network
                                    octets = found_ip.split('.')[:3]
                                    network = f"{'.'.join(octets)}.0/24"
                                    
                                    if network not in scanned_networks:
                                        # Mark the network as scanned
                                        scanned_networks.add(network)
                                        subnet_ips = cidr_to_ip_list(network)
                                        for subnet_ip in subnet_ips:
                                            for dest_port in ports:
                                                ip_header = build_ip_header(src_ip, subnet_ip)
                                                tcp_header = build_tcp_header(src_ip, subnet_ip, src_port, dest_port, seq_num)
                                                packet = ip_header + tcp_header
                                                raw_socket.sendto(packet, (subnet_ip, 0))
                                        print(f"Scanning /24 network: {network}")

            raw_socket.close()
        except PermissionError:
            print("[ERROR] Root privileges are required to listen on raw sockets.")
            exit(1)

# Function to listen for responses and track valid IPs
def listen_for_responses(output_file, count, valid_ips, valid_ips_lock, silent):
    try:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        while True:
            packet, addr = recv_socket.recvfrom(65535)

            # Parse IP Header
            ip_header = packet[:20]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            src_ip = socket.inet_ntoa(iph[8])

            # Parse TCP Header
            tcp_header = packet[20:40]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            flags = tcph[5]

            # Check for SYN-ACK (flags = 0b00010010)
            if flags == 0b00010010:
                with valid_ips_lock:
                    if not silent:  # Print IP if not silent mode
                        print(src_ip)
                    if src_ip not in valid_ips:
                        valid_ips.add(src_ip)
                        if output_file:
                            with open(output_file, "a") as f:
                                f.write(f"{src_ip}\n")

                        # Exit if the required number of valid IPs is found
                        if count > 0 and len(valid_ips) >= count:
                            return

    except PermissionError:
        print("[ERROR] Root privileges are required to listen on raw sockets.")
        exit(1)

# Main function
def main():
    parser = argparse.ArgumentParser(description="High-Performance TCP SYN Scanner")
    parser.add_argument("-p", "--port", type=str, required=True, help="Target port(s) (e.g., 22-60 or 1,3,9)")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output file")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of valid IPs to find (0 = endless)")
    parser.add_argument("-t", "--throttle", type=float, default=0, help="Throttle time between packets (in seconds)")
    parser.add_argument("-f", "--file", type=str, default=None, help="File containing list of target IPs, CIDR or ranges")
    parser.add_argument("--srcip", type=str, default="0.0.0.0", help="Source IP address")
    parser.add_argument("--srcport", type=int, default=0, help="Source port (0 = random)")
    parser.add_argument("--dig", action="store_true", help="Scan /24 ranges of the found IPs")
    parser.add_argument("--silent", action="store_true", help="Suppress printing of IPs")

    args = parser.parse_args()

    ports = parse_ports(args.port)
    output_file = args.output
    count = args.count
    throttle = args.throttle
    src_ip = args.srcip
    src_port = args.srcport if args.srcport != 0 else random.randint(1024, 65535)
    dig = args.dig
    silent = args.silent

    # Read target IPs from file if provided
    target_ips = []
    if args.file:
        target_ips = read_ips_from_file(args.file)

    # Shared data between threads
    valid_ips = set()
    valid_ips_lock = threading.Lock()
    scanned_networks = set()  # Track which /24 networks have been scanned

    # Start the listener thread
    listener_thread = threading.Thread(target=listen_for_responses, args=(output_file, count, valid_ips, valid_ips_lock, silent), daemon=True)
    listener_thread.start()

    # Start sending packets
    send_packets(ports, src_ip, src_port, count, throttle, valid_ips, valid_ips_lock, target_ips, dig, scanned_networks)

if __name__ == "__main__":
    main()
