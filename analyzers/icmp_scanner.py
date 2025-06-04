from scapy.all import ICMP, IP, Raw
from collections import defaultdict

def analyze_icmp_packets(packets):
    total_icmp = 0
    echo_requests = 0
    echo_replies = 0
    pair_counter = defaultdict(int)
    type_counter = defaultdict(int)
    large_payloads=[]

    for pkt in packets:
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            icmp = pkt[ICMP]
            ip = pkt[IP]
            src, dst = ip.src, ip.dst
            total_icmp += 1

            pair_key = f"{src} → {dst}"
            pair_counter[pair_key] += 1
            type_counter[icmp.type] += 1

            # tracking echo + echo replies -> most common for exfiltration
            if icmp.type == 8:
                echo_requests += 1
            elif icmp.type == 0:
                echo_replies += 1

            # check for reaaly large payloads (if there is any),
            if pkt.haslayer(Raw):  
                payload = pkt[Raw].load
                length = len(payload)

                if length > 1000:
                    large_payloads.append({
                        "src": src, "dst": dst, "length": length
                    })

    # see if we hava high-volume of communication pairs (echo+reply)
    high_volume_pairs = {
        pair: count for pair, count in pair_counter.items() if count > 50
    }

    return {
        "total_icmp_packets": total_icmp,
        "icmp_echo_requests": echo_requests,
        "icmp_echo_replies": echo_replies,
        "high_volume_pairs": high_volume_pairs,
        "type_distribution": dict(type_counter)
    }
