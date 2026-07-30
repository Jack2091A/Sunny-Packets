#!/usr/bin/env python3
"""
sankey_multi_compare.py

Compare multiple PCAP+MAC traces on one Sankey diagram.

Each trace contributes:
    root_node -> source-port bucket -> destination-port bucket -> dst_ip -> protocol

New per-device flags:
    --merge-src-ports 0 1 0 ...
    --merge-dst-ports 1 0 0 ...

Where each value corresponds to one --pcap/--mac pair:
    0 = do not merge for that device
    1 = merge for that device
"""

import argparse
import ipaddress
import os
from collections import Counter

from scapy.utils import PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSRR

try:
    from scapy.layers.l2 import Ether, CookedLinux
except Exception:
    Ether = None
    CookedLinux = None

try:
    import plotly.graph_objects as go
except Exception:
    go = None


def normalize_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


def is_external_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        return False


def get_l2_addrs(pkt):
    if Ether is not None and pkt.haslayer(Ether):
        eth = pkt[Ether]
        return (
            str(eth.src).lower() if getattr(eth, "src", None) else None,
            str(eth.dst).lower() if getattr(eth, "dst", None) else None,
        )

    if CookedLinux is not None and pkt.haslayer(CookedLinux):
        sll = pkt[CookedLinux]
        src = str(getattr(sll, "src", "")).lower() if getattr(sll, "src", None) else None
        dst = str(getattr(sll, "dst", "")).lower() if getattr(sll, "dst", None) else None
        if dst == "":
            dst = None
        return src, dst

    src = getattr(pkt, "src", None)
    dst = getattr(pkt, "dst", None)
    if src is not None or dst is not None:
        return (str(src).lower() if src else None, str(dst).lower() if dst else None)

    return None, None


def pkt_ip_tuple(pkt):
    if pkt.haslayer(IP):
        ip = pkt[IP]
        return ip.src, ip.dst
    if pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        return ip6.src, ip6.dst
    return None, None


def pkt_l4_tuple(pkt):
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        return "TCP", int(t.sport), int(t.dport)
    if pkt.haslayer(UDP):
        u = pkt[UDP]
        return "UDP", int(u.sport), int(u.dport)
    return "OTHER", None, None


def l4_payload_bytes(pkt):
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        return bytes(t.payload) if t.payload else b""
    if pkt.haslayer(UDP):
        u = pkt[UDP]
        return bytes(u.payload) if u.payload else b""
    return b""


def looks_like_tls_record_at(payload: bytes, i: int) -> bool:
    if i + 5 > len(payload):
        return False
    ct = payload[i]
    v1 = payload[i + 1]
    v2 = payload[i + 2]
    return ct in (0x14, 0x15, 0x16, 0x17) and v1 == 0x03 and v2 in (0x00, 0x01, 0x02, 0x03, 0x04)


def find_tls_record(payload: bytes, scan_limit: int = 128) -> bool:
    if not payload:
        return False
    end = min(len(payload), scan_limit)
    for i in range(0, end - 4):
        if looks_like_tls_record_at(payload, i):
            return True
    return False


def tls_flow_key(src_ip, dst_ip, proto, sport, dport):
    a = (src_ip, sport)
    b = (dst_ip, dport)
    if a <= b:
        return (proto, a[0], a[1], b[0], b[1])
    return (proto, b[0], b[1], a[0], a[1])


def build_dns_map(pcap_path: str):
    dns_map = {}

    with PcapReader(pcap_path) as pr:
        for pkt in pr:
            if not pkt.haslayer(DNS):
                continue

            dns = pkt[DNS]

            if int(getattr(dns, "qr", 0) or 0) != 1:
                continue

            ancount = int(getattr(dns, "ancount", 0) or 0)
            if ancount <= 0:
                continue

            query_name = None
            qdcount = int(getattr(dns, "qdcount", 0) or 0)
            if qdcount > 0:
                try:
                    qd = dns.qd
                    if qd is not None and hasattr(qd, "qname"):
                        qname = qd.qname
                        if isinstance(qname, bytes):
                            query_name = qname.decode(errors="ignore").rstrip(".")
                        else:
                            query_name = str(qname).rstrip(".")
                except Exception:
                    query_name = None

            if not query_name:
                continue

            for i in range(ancount):
                try:
                    rr = dns.an[i]
                except Exception:
                    break

                if not isinstance(rr, DNSRR):
                    continue

                if rr.type not in (1, 28):
                    continue

                try:
                    ip_val = rr.rdata
                    if isinstance(ip_val, bytes):
                        ip_val = ip_val.decode(errors="ignore")
                    ip_val = str(ip_val)
                except Exception:
                    continue

                if ip_val:
                    dns_map[ip_val] = query_name

    return dns_map


def build_tls_flow_set(pcap_path: str, target_mac: str):
    tls_ports = {443, 8443, 993, 995, 465, 587}
    tls_flows = set()

    with PcapReader(pcap_path) as pr:
        for pkt in pr:
            l2_src, l2_dst = get_l2_addrs(pkt)
            if l2_src != target_mac and l2_dst != target_mac:
                continue

            src_ip, dst_ip = pkt_ip_tuple(pkt)
            if src_ip is None or dst_ip is None:
                continue

            proto, sport, dport = pkt_l4_tuple(pkt)
            if proto not in ("TCP", "UDP") or sport is None or dport is None:
                continue

            payload = l4_payload_bytes(pkt)

            if proto == "TCP":
                if find_tls_record(payload, scan_limit=256):
                    tls_flows.add(tls_flow_key(src_ip, dst_ip, proto, sport, dport))
                    continue
                if sport in tls_ports or dport in tls_ports:
                    tls_flows.add(tls_flow_key(src_ip, dst_ip, proto, sport, dport))
                    continue

            if proto == "UDP":
                if sport == 443 or dport == 443:
                    tls_flows.add(tls_flow_key(src_ip, dst_ip, proto, sport, dport))
                    continue

    return tls_flows


def sankey_src_port_node(root_node: str, dst_ip: str, proto: str, sport: int, ssl: bool, merge_src_ports: bool) -> str:
    if merge_src_ports:
        return f"sport:*|{root_node}|{dst_ip}|{proto}|{int(ssl)}"
    return f"sport:{sport}"


def sankey_dst_port_node(root_node: str, dst_ip: str, proto: str, dport: int, ssl: bool, merge_dst_ports: bool) -> str:
    if merge_dst_ports:
        return f"dport:*|{root_node}|{dst_ip}|{proto}|{int(ssl)}"
    return f"dport:{dport}"


def shorten_domain(domain: str, max_len: int = 38) -> str:
    if len(domain) <= max_len:
        return domain
    return domain[:max_len - 3] + "..."


def write_sankey_png(
    out_png_path: str,
    layer1: Counter,
    layer2: Counter,
    layer3: Counter,
    layer4: Counter,
    top_per_layer: int = 200,
    title: str = "PCAP Sankey Comparison",
    root_nodes=None,
    dns_map: dict | None = None,
):
    if go is None:
        raise RuntimeError("Plotly not installed. Install with: pip install plotly kaleido")

    if dns_map is None:
        dns_map = {}

    if not root_nodes:
        raise ValueError("root_nodes must be provided")

    l1 = Counter(dict(layer1.most_common(top_per_layer)))
    l2 = Counter(dict(layer2.most_common(top_per_layer)))
    l3 = Counter(dict(layer3.most_common(top_per_layer)))
    l4 = Counter(dict(layer4.most_common(top_per_layer)))

    nodes = {}
    shown_labels = []

    def display_label(raw: str) -> str:
        if raw.startswith("ROOT|"):
            return raw.split("|", 1)[1]

        #if raw.startswith("sport_random|"):
        #    return "Device Port:*"
        
        if raw.startswith("sport:*|"):
            return "Device Port:*"

        if raw.startswith("sport:"):
            return raw.replace("sport:", "Device Port:")

        if raw.startswith("dport:*|"):
            return "Endpoint Port:*"

        if raw.startswith("dport:"):
            return raw.replace("dport:", "Endpoint Port:")

        if raw in ("TCP", "UDP", "OTHER"):
            return raw

        if raw in dns_map:
            return shorten_domain(dns_map[raw])

        return raw

    def node_id(raw: str) -> int:
        if raw not in nodes:
            nodes[raw] = len(shown_labels)
            shown_labels.append(display_label(raw))
        return nodes[raw]

    raw_links = []

    for (root, sport_node), c in l1.items():
        raw_links.append((root, sport_node, int(c), f"{root} → {sport_node} ({c})"))

    for (sport_node, dport_node), c in l2.items():
        raw_links.append((sport_node, dport_node, int(c), f"{sport_node} → {dport_node} ({c})"))

    for (dport_node, ip), c in l3.items():
        raw_links.append((dport_node, ip, int(c), f"{dport_node} → {ip} ({c})"))

    for (ip, proto), c in l4.items():
        raw_links.append((ip, proto, int(c), f"{ip} → {proto} ({c})"))

    adj = {}
    for a, b, _c, _lab in raw_links:
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set()).add(a)

    reachable = set()
    stack = list(root_nodes)
    while stack:
        x = stack.pop()
        if x in reachable:
            continue
        reachable.add(x)
        for y in adj.get(x, ()):
            if y not in reachable:
                stack.append(y)

    #raw_links = [L for L in raw_links if (L[0] in reachable and L[1] in reachable)]

    sources, targets, values, link_labels = [], [], [], []
    for a, b, c, lab in raw_links:
        sources.append(node_id(a))
        targets.append(node_id(b))
        MAX_WIDTH = 4500  

        values.append(min(int(c), MAX_WIDTH))
        link_labels.append(lab)

    node_count = len(shown_labels)

    fig = go.Figure(
        data=[
            go.Sankey(
                arrangement="snap",
                node=dict(
                    label=shown_labels,
                    pad=28,
                    thickness=20,
                ),
                link=dict(
                    source=sources,
                    target=targets,
                    value=values,
                    label=link_labels,
                ),
            )
        ]
    )

    fig.update_layout(
        font=dict(size=28),
        height=max(1000, node_count * 28),
        width=2400,
        margin=dict(l=20, r=20, t=20, b=20),
    )

    fig.write_image(out_png_path, scale=2)


def process_trace(
    pcap_path: str,
    target_mac: str,
    root_label: str,
    include_private: bool,
    merge_src_ports: bool,
    merge_dst_ports: bool,
    global_mac_to_ip: Counter,
    global_ip_to_sport: Counter,
    global_sport_to_dport: Counter,
    global_dport_to_proto: Counter,
):
    root_node = f"ROOT|{root_label}"
    tls_flows = build_tls_flow_set(pcap_path, target_mac)

    outgoing_by_dst_ip = Counter()
    dns_map = build_dns_map(pcap_path)

    with PcapReader(pcap_path) as pr:
        for pkt in pr:
            l2_src, l2_dst = get_l2_addrs(pkt)
            if l2_src != target_mac and l2_dst != target_mac:
                continue

            src_ip, dst_ip = pkt_ip_tuple(pkt)
            if src_ip is None or dst_ip is None:
                continue

            proto, sport, dport = pkt_l4_tuple(pkt)
            if proto not in ("TCP", "UDP") or sport is None or dport is None:
                continue

            ssl = tls_flow_key(src_ip, dst_ip, proto, sport, dport) in tls_flows

            if l2_src == target_mac:
                if True:
                    outgoing_by_dst_ip[dst_ip] += 1

                    sport_node = sankey_src_port_node(
                        root_node=root_node,
                        dst_ip=dst_ip,
                        proto=proto,
                        sport=sport,
                        ssl=ssl,
                        merge_src_ports=merge_src_ports,
                    )

                    dport_node = sankey_dst_port_node(
                        root_node=root_node,
                        dst_ip=dst_ip,
                        proto=proto,
                        dport=dport,
                        ssl=ssl,
                        merge_dst_ports=merge_dst_ports,
                    )

                    global_mac_to_ip[(root_node, sport_node)] += 1
                    global_ip_to_sport[(sport_node, dport_node)] += 1
                    global_sport_to_dport[(dport_node, dst_ip)] += 1
                    global_dport_to_proto[(dst_ip, proto)] += 1

    return root_node, dns_map, outgoing_by_dst_ip


def main():
    ap = argparse.ArgumentParser()

    ap.add_argument("--pcap", action="append", required=True, help="Path to PCAP file (repeatable)")
    ap.add_argument("--mac", action="append", required=True, help="Target MAC for that PCAP (repeatable)")
    ap.add_argument("--label", action="append", default=None, help="Optional label for each PCAP/MAC pair")
    ap.add_argument("--include-private", action="store_true", help="Include private/internal IPs")
    ap.add_argument("--top", type=int, default=20, help="How many top rows to print")
    ap.add_argument("--sankey-png", default=None, help="If set, write Sankey PNG to this path")
    ap.add_argument("--sankey-top", type=int, default=300, help="Max links per Sankey layer")

    ap.add_argument(
        "--merge-src-ports",
        nargs="+",
        type=int,
        default=None,
        help="Per-device flags (0/1) to merge source ports. One value per pcap/mac pair.",
    )
    ap.add_argument(
        "--merge-dst-ports",
        nargs="+",
        type=int,
        default=None,
        help="Per-device flags (0/1) to merge destination ports. One value per pcap/mac pair.",
    )

    args = ap.parse_args()

    if len(args.pcap) != len(args.mac):
        raise ValueError("You must provide the same number of --pcap and --mac arguments")

    n = len(args.pcap)

    if args.label is not None and len(args.label) != n:
        raise ValueError("If using --label, provide one label per --pcap/--mac pair")

    if args.merge_src_ports is not None and len(args.merge_src_ports) != n:
        raise ValueError("If using --merge-src-ports, provide one 0/1 value per --pcap/--mac pair")

    if args.merge_dst_ports is not None and len(args.merge_dst_ports) != n:
        raise ValueError("If using --merge-dst-ports, provide one 0/1 value per --pcap/--mac pair")

    labels = args.label if args.label is not None else [os.path.basename(p) for p in args.pcap]
    macs = [normalize_mac(m) for m in args.mac]

    merge_src_flags = [bool(v) for v in args.merge_src_ports] if args.merge_src_ports is not None else [False] * n
    merge_dst_flags = [bool(v) for v in args.merge_dst_ports] if args.merge_dst_ports is not None else [False] * n

    global_mac_to_ip = Counter()
    global_ip_to_sport = Counter()
    global_sport_to_dport = Counter()
    global_dport_to_proto = Counter()
    combined_dns_map = {}
    root_nodes = []

    for i, (pcap_path, mac, label) in enumerate(zip(args.pcap, macs, labels)):
        root_node, dns_map, outgoing_by_dst_ip = process_trace(
            pcap_path=pcap_path,
            target_mac=mac,
            root_label=label,
            include_private=args.include_private,
            merge_src_ports=merge_src_flags[i],
            merge_dst_ports=merge_dst_flags[i],
            global_mac_to_ip=global_mac_to_ip,
            global_ip_to_sport=global_ip_to_sport,
            global_sport_to_dport=global_sport_to_dport,
            global_dport_to_proto=global_dport_to_proto,
        )

        root_nodes.append(root_node)
        combined_dns_map.update(dns_map)

        print(f"\n=== {label} ({mac}) from {pcap_path} ===")
        print(f"merge_src_ports={merge_src_flags[i]}, merge_dst_ports={merge_dst_flags[i]}")
        print("\nTop outgoing destination IPs:")
        for ip, c in outgoing_by_dst_ip.most_common(args.top):
            domain = combined_dns_map.get(ip)
            if domain:
                print(f"{ip:40}  {c:6}  {domain}")
            else:
                print(f"{ip:40}  {c:6}")

    if args.sankey_png:
        write_sankey_png(
            out_png_path=args.sankey_png,
            layer1=global_mac_to_ip,
            layer2=global_ip_to_sport,
            layer3=global_sport_to_dport,
            layer4=global_dport_to_proto,
            top_per_layer=args.sankey_top,
            title="PCAP Sankey Comparison",
            root_nodes=root_nodes,
            dns_map=combined_dns_map,
        )
        print(f"\nWrote Sankey PNG: {args.sankey_png}")


if __name__ == "__main__":
    main()
