import socket
import struct

def main():
    host = socket.gethostbyname(socket.gethostname())

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print("Packet Sniffer Started...\n")

    try:
        while True:
            raw_packet, addr = sniffer.recvfrom(65535)

            ip_header = raw_packet[0:20]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dest_ip = socket.inet_ntoa(iph[9])

            if protocol == 6:
                proto_name = "TCP"
            elif protocol == 17:
                proto_name = "UDP"
            elif protocol == 1:
                proto_name = "ICMP"
            else:
                proto_name = "OTHER"

            payload = raw_packet[20:60]

            print(f"Source IP      : {src_ip}")
            print(f"Destination IP : {dest_ip}")
            print(f"Protocol       : {proto_name}")
            print(f"Payload Data   : {payload}")
            print("-" * 50)

    except KeyboardInterrupt:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    main()
