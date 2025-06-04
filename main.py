from scapy.all import rdpcap
from analyzers.dns_scanner import analyze_dns_packets
from analyzers.http_scanner import analyze_http_tunnels

file_path = input('Please enter the path of the pcap/pcapng file: ')

if file_path:
    try:
        packets = rdpcap(file_path)
        # results = analyze_dns_packets(packets)
        results = analyze_http_tunnels(packets)
        # print(results)
        for entry in results:
            print(entry)
            print(results[entry])
            print("-------------------------------")
    except Exception as e:
        print(f"Failed to read pcap file:\n{e}")
