
# Python Network Packet Sniffer

## Project Overview
A basic network packet sniffer built with Python and Scapy.
The program captures live IPv4 network traffic and analyzes
packets to display useful information.

## Features
- Captures live network packets.
- Identifies source and destination IP addresses.
- Detects TCP, UDP and ICMP protocols.
- Displays source and destination ports.
- Displays hexadecimal payload previews.
- Captures traffic for a specified duration.

## Technologies Used
- Python
- Scapy
- Npcap (Windows packet capture support)

## Installation

1. Clone this repository.
2. Create a virtual environment:

   python -m venv venv

3. Activate it on Windows:

   venv\Scripts\activate

4. Install dependencies:

   pip install -r requirements.txt

5. Install Npcap on Windows:
   https://npcap.com/

## Usage

Run your terminal as Administrator on Windows:

   python packet_sniffer.py

Generate network traffic using a browser or ping.

## Learning Outcomes
- Understanding network packet structures.
- Identifying network protocols.
- Understanding IP addresses and port numbers.
- Learning basic packet analysis with Scapy.

## Limitations
- Captures IPv4 traffic only.
- Capture duration is currently 30 seconds.
- Encrypted HTTPS payloads cannot be read as
  plaintext through this basic sniffer.

## Disclaimer
This project is for educational purposes.
Only capture traffic on networks and devices
you own or have explicit permission to monitor.

## Author
Adebayo Abigail
