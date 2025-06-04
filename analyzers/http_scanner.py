from scapy.all import TCP, Raw
from collections import defaultdict, Counter
from urllib.parse import urlparse, parse_qs, unquote
import math
import base64
import re

# some entropy global vals
BODY_ENTROPY_TH = 4.2
ENTROPY_TH = 4.0

# same helpers as the ones in dns + extractor
def shannon_entropy(data):
    p, lns = Counter(data), float(len(data))
    return -sum(count / lns * math.log2(count / lns) for count in p.values()) if lns > 0 else 0

def is_base_encoding(s, base='64'):
    try:
        if base == '64':
            return base64.b64decode(s + '==', validate=True)
        elif base == '32':
            return base64.b32decode(s + '====', casefold=True)
        elif base == '16':
            return base64.b16decode(s.upper(), casefold=True)
    except Exception:
        return None

# extractor - helps filter any non valid data = consistency
def extract_http_payload(raw_data):
    try:
        data = raw_data.decode(errors="ignore")
        if data.startswith(("GET", "POST", "PUT", "HEAD", "OPTIONS")):
            return data
        return None
    except Exception:
        return None

def analyze_http_packets(packets):
    global ENTROPY_TH, BODY_ENTROPY_TH

    sus_requests = []
    base_encodings = []
    endpoint_counter = defaultdict(int)
    url_lengths = []
    entropy_scores = []
    body_entropy_list = []
    sus_content_lens = []

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            raw_data = pkt[Raw].load
            http_data = extract_http_payload(raw_data)

            if http_data:
                # separate data from the HTTP packet
                lines = http_data.split("\r\n\r\n", 1)
                headers_section = lines[0]
                body = lines[1] if len(lines) > 1 else ""

                headers_lines = headers_section.split("\r\n")
                request_line = headers_lines[0]
                method, path, *_ = request_line.split(" ")
                headers = {}

                for line in headers_lines[1:]:
                    if ": " in line:
                        key, val = line.split(": ", 1)
                        headers[key.lower()] = val

                host = headers.get("host", "")
                full_url = f"http://{host}{path}"
                url_lengths.append(len(full_url))
                endpoint_counter[host] += 1

                # GET the GET params (haha)
                query = urlparse(path).query
                params = parse_qs(query)

                # decode and get the entropies for analysis
                joined_data = "".join([unquote(x) for val in params.values() for x in val])
                param_entropy = shannon_entropy(joined_data)
                entropy_scores.append(param_entropy)

                for val in params.values():
                    for item in val:
                        item = unquote(item)
                        # here, we check for naive encoding of data
                        # we also decrypt it, maybe we can see the data transfered :)
                        for b in ['64', '32', '16']:
                            decoded = is_base_encoding(item, b)
                            if decoded:
                                base_encodings.append({
                                    "location": "GET param",
                                    "url": full_url,
                                    "encoding": b,
                                    "decoded_data": decoded
                                })

                # we now look at the HTTP body, first note the entropy
                body_entropy = shannon_entropy(body)
                body_entropy_list.append(body_entropy)

                content_length = headers.get("content-length")
                if content_length and content_length.isdigit():
                    content_length = int(content_length)
                    # check for long-ish and high entropy body (not to long cuz entropy will obvs be large)
                    if body_entropy > BODY_ENTROPY_TH and content_length > 150:
                        sus_content_lens.append({
                            "url": full_url,
                            "content_length": content_length,
                            "body_entropy": body_entropy
                        })

                # mark packet as sus + reasons why = basically an if sausage
                sus_markers = []
                if len(full_url) > 100:
                    sus_markers.append("Long URL")
                if param_entropy > 4.0:
                    sus_markers.append("High GET param entropy")
                if body_entropy > 4.2:
                    sus_markers.append("High body entropy")
                if content_length and body_entropy > BODY_ENTROPY_TH and content_length > 150:
                    sus_markers.append("Suspicious Content-Length")
                if any(maybe_enc["location"] == "GET param" and maybe_enc["url"] == full_url 
                        for maybe_enc in base_encodings):
                    sus_markers.append("BaseX-encoded data found in the URL")
                if any(maybe_enc["location"] == "body" and maybe_enc["url"] == full_url 
                        for maybe_enc in base_encodings):
                    sus_markers.append("BaseX-encoded data found in body")

                if sus_markers:
                    sus_requests.append({
                        "url": full_url,
                        "method": method,
                        "host": host,
                        "url_length": len(full_url),
                        "param_entropy": param_entropy,
                        "body_entropy": body_entropy,
                        "content_length": content_length if isinstance(content_length, int) else None,
                        "reasons": sus_markers
                    })


    return {
        "suspicious_requests": sus_requests,
        "base_encodings": base_encodings,
        "high_frequency_endpoints": {
            host: count for host, count in endpoint_counter.items() if count > 20
        },
        "avg_url_length": sum(url_lengths) / len(url_lengths) if url_lengths else 0,
        "avg_param_entropy": sum(entropy_scores) / len(entropy_scores) if entropy_scores else 0,
        "avg_body_entropy": sum(body_entropy_list) / len(body_entropy_list) if body_entropy_list else 0,
        "abnormal_content_lenghts": sus_content_lens
    }
