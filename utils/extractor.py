import os
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP

def extract_flows(pcap_path, max_packets=10000):
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        
    print(f"Extracting flows from PCAP: {pcap_path} (limit: {max_packets} packets)...")
    
    try:
        packets = rdpcap(pcap_path, count=max_packets)
    except Exception as e:
        print(f"Error reading PCAP: {e}")
        return []
        
    flows = {}
    
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
            
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto
        
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        else:
            continue
            
        addr_pair = sorted([(src_ip, sport), (dst_ip, dport)])
        flow_key = (addr_pair[0][0], addr_pair[0][1], addr_pair[1][0], addr_pair[1][1], proto)
        
        pkt_len = len(pkt)
        if ip_layer.len is not None:
            pkt_len = int(ip_layer.len)
            
        pkt_time = float(pkt.time)
        
        if flow_key not in flows:
            flows[flow_key] = {
                'src_ip': src_ip,
                'sport': sport,
                'dst_ip': dst_ip,
                'dport': dport,
                'protocol': proto,
                'first_time': pkt_time,
                'last_time': pkt_time,
                'fwd_src_ip': src_ip,
                'fwd_sport': sport,
                'fwd_pkt_lens': [],
                'bwd_pkt_lens': [],
                'fwd_header_len': 0,
                'bwd_header_len': 0,
                'syn_flag_cnt': 0,
                'rst_flag_cnt': 0,
                'psh_flag_cnt': 0,
                'ack_flag_cnt': 0,
                'urg_flag_cnt': 0,
                'ece_flag_cnt': 0,
                'fin_flag_cnt': 0,
            }
            
        flow = flows[flow_key]
        flow['last_time'] = pkt_time
        
        is_fwd = (src_ip == flow['fwd_src_ip'] and sport == flow['fwd_sport'])
        
        ip_hdr_len = int(ip_layer.ihl) * 4 if hasattr(ip_layer, 'ihl') else 20
        if pkt.haslayer(TCP):
            tcp_hdr_len = int(pkt[TCP].dataofs) * 4 if pkt[TCP].dataofs is not None else 20
            hdr_len = ip_hdr_len + tcp_hdr_len
            
            flags = int(pkt[TCP].flags)
            if flags & 0x01: flow['fin_flag_cnt'] += 1
            if flags & 0x02: flow['syn_flag_cnt'] += 1
            if flags & 0x04: flow['rst_flag_cnt'] += 1
            if flags & 0x08: flow['psh_flag_cnt'] += 1
            if flags & 0x10: flow['ack_flag_cnt'] += 1
            if flags & 0x20: flow['urg_flag_cnt'] += 1
            if flags & 0x40: flow['ece_flag_cnt'] += 1
        else:
            hdr_len = ip_hdr_len + 8
            
        if is_fwd:
            flow['fwd_pkt_lens'].append(pkt_len)
            flow['fwd_header_len'] += hdr_len
        else:
            flow['bwd_pkt_lens'].append(pkt_len)
            flow['bwd_header_len'] += hdr_len

    output_flows = []
    for key, flow in flows.items():
        fwd_lens = flow['fwd_pkt_lens']
        bwd_lens = flow['bwd_pkt_lens']
        
        total_fwd_pkts = len(fwd_lens)
        total_bwd_pkts = len(bwd_lens)
        
        if total_fwd_pkts == 0 and total_bwd_pkts == 0:
            continue
            
        total_fwd_bytes = sum(fwd_lens)
        total_bwd_bytes = sum(bwd_lens)
        
        flow_duration = float((flow['last_time'] - flow['first_time']) * 1000000.0)
        flow_duration = max(flow_duration, 1.0)
        
        dur_sec = flow_duration / 1000000.0
        
        flow_bytes_s = float((total_fwd_bytes + total_bwd_bytes) / dur_sec)
        flow_pkts_s = float((total_fwd_pkts + total_bwd_pkts) / dur_sec)
        
        fwd_pkt_len_max = float(max(fwd_lens)) if fwd_lens else 0.0
        fwd_pkt_len_min = float(min(fwd_lens)) if fwd_lens else 0.0
        fwd_pkt_len_mean = float(np.mean(fwd_lens)) if fwd_lens else 0.0
        
        bwd_pkt_len_max = float(max(bwd_lens)) if bwd_lens else 0.0
        bwd_pkt_len_min = float(min(bwd_lens)) if bwd_lens else 0.0
        bwd_pkt_len_mean = float(np.mean(bwd_lens)) if bwd_lens else 0.0
        
        flow_feature = {
            'src_ip': flow['src_ip'],
            'sport': int(flow['sport']),
            'dst_ip': flow['dst_ip'],
            'dport': int(flow['dport']),
            'protocol_name': 'TCP' if flow['protocol'] == 6 else ('UDP' if flow['protocol'] == 17 else 'Other'),
            
            'flow_duration': flow_duration,
            'total_fwd_pkts': int(total_fwd_pkts),
            'total_bwd_pkts': int(total_bwd_pkts),
            'total_fwd_bytes': int(total_fwd_bytes),
            'total_bwd_bytes': int(total_bwd_bytes),
            'fwd_pkt_len_max': fwd_pkt_len_max,
            'fwd_pkt_len_min': fwd_pkt_len_min,
            'fwd_pkt_len_mean': fwd_pkt_len_mean,
            'bwd_pkt_len_max': bwd_pkt_len_max,
            'bwd_pkt_len_min': bwd_pkt_len_min,
            'bwd_pkt_len_mean': bwd_pkt_len_mean,
            'flow_bytes_s': flow_bytes_s,
            'flow_pkts_s': flow_pkts_s,
            'fwd_header_len': int(flow['fwd_header_len']),
            'bwd_header_len': int(flow['bwd_header_len']),
            'syn_flag_cnt': int(flow['syn_flag_cnt']),
            'rst_flag_cnt': int(flow['rst_flag_cnt']),
            'psh_flag_cnt': int(flow['psh_flag_cnt']),
            'ack_flag_cnt': int(flow['ack_flag_cnt']),
            'urg_flag_cnt': int(flow['urg_flag_cnt']),
            'ece_flag_cnt': int(flow['ece_flag_cnt']),
            'fin_flag_cnt': int(flow['fin_flag_cnt']),
            'protocol': int(flow['protocol'])
        }
        
        output_flows.append(flow_feature)
        
    print(f"Extracted {len(output_flows)} bidirectional flows from PCAP.")
    return output_flows
