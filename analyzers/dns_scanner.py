from scapy.all import DNS
import math
from collections import Counter, defaultdict

# helper func to compute entropy for names
def shannon_entropy(data):
    p, lns = Counter(data), float(len(data))
    return -sum(count / lns * math.log2(count / lns) for count in p.values())

# we are also looking for any encoded strings, maybe we can decode them
def is_base_encoding(s, base='64'):
    try:
        if base == '64':
            txt = base64.b64decode(s + '==', validate=True)
        elif base == '32':
            txt = base64.b32decode(s + '====', casefold=True)
        elif base == '16':
            txt = base64.b16decode(s.upper(), casefold=True)
        return txt
    except Exception:
        return None

def analyze_dns_packets(packets):
    long_queries = []
    high_volume_domains = {}
    tunneling_candidates = []
    decoded_data=[]
    subdomain_tracker = defaultdict(set)
    query_lengths = defaultdict(int)
    base_domain_counts = defaultdict(int)

    for pkt in packets:
        # get dns and extract what we need
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0: 
            dns_layer = pkt[DNS]
            if dns_layer.qd:
                qname = dns_layer.qd.qname.decode(errors="ignore").rstrip(".")
                qlen = len(qname)
                entropy = shannon_entropy(qname)

                # get the domains
                parts = qname.split(".")
                base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else qname
                subdomain = ".".join(parts[:-2])

                # here we look for labels that might be trivially encoded, and also store the decoded data ;)
                for label in parts:
                    encoding_detected = [
                        is_base_encoding(label, '64'),
                        is_base_encoding(label, '32'),
                        is_base_encoding(label, '16')]
                    
                    for enc in encoding_detected:
                        if enc:
                            decoded_data.append({
                                "query":qname,
                                "data":enc
                            })

                base_domain_counts[base_domain] += 1
                if subdomain:
                    subdomain_tracker[base_domain].add(subdomain)

                # Track query length patterns
                query_lengths[qlen] += 1

                # here, we look for long query + high entropy ones
                if qlen > 45:
                    long_queries.append(qname)

                if entropy > 3.8 and qlen > 35:
                    tunneling_candidates.append({
                        "domain": qname,
                        "entropy": entropy,
                        "length": qlen
                    })

    # here, we look for high frequency calls to same domain
    for domain, count in base_domain_counts.items():
        if count > 20:
            high_volume_domains[domain] = count

    # also check many subdomains per domain
    subdomain_abuse = {
        domain: len(subs)
        for domain, subs in subdomain_tracker.items()
        if len(subs) > 10
    }

    return {
        "long_queries": long_queries,
        "tunneling_candidates": tunneling_candidates,
        "high_volume_domains": high_volume_domains,
        "subdomain_abuse": subdomain_abuse,
    }
