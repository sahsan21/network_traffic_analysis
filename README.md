# network_traffic_analysis
A Python tool to capture and analyze network traffic. This script uses the `scapy` library to sniff packets on a specified network interface and provides information on TCP, UDP, and other IP packets. The tool helps in monitoring network traffic and identifying unusual patterns or potential security threats.

## Features

- Captures network traffic on a specified interface.
- Analyzes and logs details of TCP, UDP, and other IP packets.
- Provides timestamped logs for each captured packet.

## Requirements

- Python 3.x
- `scapy` library

## Installation

1. **Clone the repository:**

    ```
    git clone https://github.com/sahsan21/network_traffic_analysis.git
    cd network_traffic_analysis
    ```

2. **Install required libraries:**

    ```
    pip install scapy
    ```

## Usage

1. **Run the script with elevated privileges (required to sniff packets):**

    ```
    sudo python3 network_traffic_analysis.py
    ```

2. **Enter the network interface to sniff on (e.g., `eth0`, `wlan0`):**

    ```
    Enter the network interface to sniff on (e.g., eth0, wlan0): wlan0
    ```

3. **The script will start capturing packets and displaying information:**

    ```
    [*] Starting packet capture on wlan0...
    [2024-05-21 10:00:00.000000] TCP Packet: 192.168.1.2:12345 -> 93.184.216.34:80
    [2024-05-21 10:00:01.000000] UDP Packet: 192.168.1.2:12345 -> 8.8.8.8:53
    [2024-05-21 10:00:02.000000] Other IP Packet: 192.168.1.2 -> 192.168.1.1
    ```

## Example Output

```
Enter the network interface to sniff on (e.g., eth0, wlan0): wlan0
[*] Starting packet capture on wlan0...
[2024-05-21 10:00:00.000000] TCP Packet: 192.168.1.2:12345 -> 93.184.216.34:80
[2024-05-21 10:00:01.000000] UDP Packet: 192.168.1.2:12345 -> 8.8.8.8:53
[2024-05-21 10:00:02.000000] Other IP Packet: 192.168.1.2 -> 192.168.1.1


## Source and Destination IP Addresses and Ports:

192.168.1.2:12345 -> 93.184.216.34:80
192.168.1.2 is the source IP address.
12345 is the source port.
93.184.216.34 is the destination IP address.
80 is the destination port.
