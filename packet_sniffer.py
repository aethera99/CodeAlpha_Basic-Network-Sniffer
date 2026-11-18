
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime


def analyze_packet(packet):

    # Check whether the packet contains an IP layer
    if IP in packet:

        ip_layer = packet[IP]

        source_ip = ip_layer.src
        destination_ip = ip_layer.dst

        # Identify the protocol
        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            payload = bytes(packet[TCP].payload)

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport
            payload = bytes(packet[UDP].payload)

        elif ICMP in packet:
            protocol = "ICMP"
            source_port = "-"
            destination_port = "-"
            payload = bytes(packet[ICMP].payload)

        else:
            protocol = "Other IP"
            source_port = "-"
            destination_port = "-"
            payload = bytes(ip_layer.payload)

        # Display packet information
        print("\n" + "=" * 50)
        print("       NETWORK PACKET DETECTED")
        print("=" * 50)

        print("Time:", datetime.now().strftime("%H:%M:%S"))
        print("Source IP:", source_ip)
        print("Destination IP:", destination_ip)
        print("Protocol:", protocol)
        print("Source Port:", source_port)
        print("Destination Port:", destination_port)

        # Display a small hexadecimal payload preview
        if payload:
            print("Payload preview (hex):", payload[:32].hex())
        else:
            print("Payload: No application data detected")

        print("=" * 50)


def start_sniffer():

    print("Starting Network Packet Sniffer...")
    print("Listening for IP packets for 30 seconds.")
    print("Press Ctrl+C to stop early.")

    try:
        sniff(
            filter="ip",
            prn=analyze_packet,
            store=False,
            timeout=30
        )

        print("\nPacket capture completed.")

    except PermissionError:
        print("Permission denied. Run with administrator privileges.")

    except Exception as error:
        print("An error occurred:", error)


if __name__ == "__main__":
    start_sniffer()
