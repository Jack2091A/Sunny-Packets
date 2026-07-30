#!/usr/bin/env python3

import argparse
import csv
import sys
from collections import Counter, defaultdict

import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.colors import ListedColormap
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, raw

mpl.rcParams.update({
    "font.size": 21,
    "axes.labelsize": 21,
    "xtick.labelsize": 21,
    "ytick.labelsize": 21,
    "legend.fontsize": 18,
})


def ordinal(n: int) -> str:
    if 10 <= n % 100 <= 20:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def packet_matches_endpoints(pkt, ip_a: str, ip_b: str) -> bool:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
    elif IPv6 in pkt:
        src = pkt[IPv6].src
        dst = pkt[IPv6].dst
    else:
        return False
    return (src == ip_a and dst == ip_b) or (src == ip_b and dst == ip_a)


def packet_matches_ports(pkt, port_a=None, port_b=None) -> bool:
    if port_a is None and port_b is None:
        return True

    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else:
        return False

    if port_a is not None and port_b is not None:
        return ((sport == port_a and dport == port_b) or
                (sport == port_b and dport == port_a))
    elif port_a is not None:
        return sport == port_a or dport == port_a
    else:
        return sport == port_b or dport == port_b


def get_frame_bytes(pkt) -> bytes:
    return bytes(raw(pkt))


def get_ip_packet_bytes(pkt) -> bytes:
    if IP in pkt:
        return bytes(raw(pkt[IP]))
    if IPv6 in pkt:
        return bytes(raw(pkt[IPv6]))
    return b""


def get_transport_payload_bytes(pkt) -> bytes:
    if TCP in pkt:
        return bytes(pkt[TCP].payload)
    if UDP in pkt:
        return bytes(pkt[UDP].payload)
    return b""


def get_comparison_bytes(pkt, length_type: str) -> bytes:
    if length_type == "frame":
        return get_frame_bytes(pkt)
    if length_type == "ip":
        return get_ip_packet_bytes(pkt)
    if length_type == "transport_payload":
        return get_transport_payload_bytes(pkt)
    raise ValueError(f"Unsupported length_type: {length_type}")


def extract_flow(pcap_file: str, ip_a: str, ip_b: str, length_type="frame", port_a=None, port_b=None):
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading PCAP: {e}", file=sys.stderr)
        sys.exit(1)

    flow = []
    for pcap_idx, pkt in enumerate(packets, start=1):
        if not packet_matches_endpoints(pkt, ip_a, ip_b):
            continue
        if not packet_matches_ports(pkt, port_a=port_a, port_b=port_b):
            continue

        compare_bytes = get_comparison_bytes(pkt, length_type)
        pkt_len = len(compare_bytes)

        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
        elif IPv6 in pkt:
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
        else:
            src, dst = "?", "?"

        sport = dport = ""
        proto = "OTHER"
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            proto = "TCP"
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            proto = "UDP"

        flow.append({
            "flow_index": len(flow) + 1,
            "pcap_index": pcap_idx,
            "src": src,
            "dst": dst,
            "sport": sport,
            "dport": dport,
            "proto": proto,
            "compare_bytes": compare_bytes,
            "compare_len": pkt_len,
        })
    return flow


def print_packet_table(flow):
    print("\nFiltered packets:")
    print("FlowIdx | PCAP# | Proto | Source -> Dest | CompareLen")
    print("-" * 85)
    for pkt in flow:
        src_port = f":{pkt['sport']}" if pkt['sport'] != "" else ""
        dst_port = f":{pkt['dport']}" if pkt['dport'] != "" else ""
        print(
            f"{pkt['flow_index']:7d} | "
            f"{pkt['pcap_index']:5d} | "
            f"{pkt['proto']:5s} | "
            f"{pkt['src']}{src_port} -> {pkt['dst']}{dst_port} | "
            f"{pkt['compare_len']:10d}"
        )
    print()


def build_packet_selection(flow, packet_list=None):
    if packet_list:
        selected = []
        for n in packet_list:
            if n < 1 or n > len(flow):
                raise ValueError(f"Packet number {n} is out of range 1..{len(flow)}")
            selected.append(flow[n - 1])
        return selected
    return flow[:]


def safe_len_at(flow, idx):
    if 0 <= idx < len(flow):
        return flow[idx]["compare_len"]
    return None


def make_context_key(flow, idx, window):
    prev_lengths = tuple(safe_len_at(flow, idx - k) for k in range(window, 0, -1))
    next_lengths = tuple(safe_len_at(flow, idx + k) for k in range(1, window + 1))

    prev_same_gap = None
    for j in range(idx - 1, -1, -1):
        if flow[j]["compare_len"] == flow[idx]["compare_len"]:
            prev_same_gap = idx - j
            break

    next_same_gap = None
    for j in range(idx + 1, len(flow)):
        if flow[j]["compare_len"] == flow[idx]["compare_len"]:
            next_same_gap = j - idx
            break

    return (
        prev_lengths,
        next_lengths,
        prev_same_gap,
        next_same_gap,
        flow[idx]["src"],
        flow[idx]["dst"],
        flow[idx]["sport"],
        flow[idx]["dport"],
        flow[idx]["proto"],
    )


def describe_context_key(key):
    prev_lengths, next_lengths, prev_same_gap, next_same_gap, src, dst, sport, dport, proto = key
    return (
        f"prev={list(prev_lengths)} next={list(next_lengths)} "
        f"prev_same_gap={prev_same_gap} next_same_gap={next_same_gap} "
        f"dir={src}:{sport}->{dst}:{dport} proto={proto}"
    )


def split_same_length_by_exact_context(full_flow, target_length, context_window=3):
    candidates = [pkt for pkt in full_flow if pkt["compare_len"] == target_length]
    groups = defaultdict(list)
    for pkt in candidates:
        idx = pkt["flow_index"] - 1
        groups[make_context_key(full_flow, idx, context_window)].append(pkt)

    ordered = []
    for key, packets in groups.items():
        ordered.append({
            "key": key,
            "packets": sorted(packets, key=lambda p: p["flow_index"]),
            "first_flow_index": min(p["flow_index"] for p in packets),
            "count": len(packets),
        })
    ordered.sort(key=lambda g: (g["first_flow_index"], -g["count"]))
    return ordered


def split_same_length_by_local_order(full_flow, target_length, repeats, context_window=3):
    """
    Groups repeated same-length packets by their local occurrence order inside a nearby cluster.

    Example with repeats=2 and target length 153:
      ... 232, 153, 64, 90, 153, 44 ...
    -> first 153 goes to occurrence 1, second 153 goes to occurrence 2,
       as long as they are within context_window packets of each other.

    This is intentionally less strict than exact context matching, so each occurrence bucket
    collects many packets across the capture instead of degenerating into one-packet groups.
    """
    candidates = [pkt for pkt in full_flow if pkt["compare_len"] == target_length]
    if not candidates:
        return []

    candidate_positions = [pkt["flow_index"] - 1 for pkt in candidates]
    clusters = []
    current = [candidate_positions[0]]
    max_gap = context_window + 1  # allow a few packets in between two same-length packets

    for pos in candidate_positions[1:]:
        if pos - current[-1] <= max_gap:
            current.append(pos)
        else:
            clusters.append(current)
            current = [pos]
    clusters.append(current)

    buckets = [[] for _ in range(repeats)]
    bucket_meta = [[] for _ in range(repeats)]

    for cluster in clusters:
        for ordinal_index, pos in enumerate(cluster[:repeats], start=1):
            pkt = full_flow[pos]
            buckets[ordinal_index - 1].append(pkt)
            bucket_meta[ordinal_index - 1].append({
                "cluster_start": full_flow[cluster[0]]["flow_index"],
                "cluster_size": len(cluster),
                "context": make_context_key(full_flow, pos, context_window),
            })

    groups = []
    for i in range(repeats):
        packets = buckets[i]
        if packets:
            groups.append({
                "key": f"local_occurrence_{i+1}",
                "packets": packets,
                "first_flow_index": min(p["flow_index"] for p in packets),
                "count": len(packets),
                "meta": bucket_meta[i],
            })
        else:
            groups.append({
                "key": f"local_occurrence_{i+1}",
                "packets": [],
                "first_flow_index": float('inf'),
                "count": 0,
                "meta": [],
            })
    return groups


def aggregate_similarity(selected_packets, subgroup_label=""):
    byte_match_counts = {}
    byte_total_counts = {}
    detailed_rows = []

    if not selected_packets:
        return byte_match_counts, byte_total_counts, detailed_rows

    compare_lengths = {len(pkt["compare_bytes"]) for pkt in selected_packets}
    if len(compare_lengths) != 1:
        raise ValueError("Selected packets do not all have the same comparison length.")

    compare_length = compare_lengths.pop()
    N = len(selected_packets)

    for pos in range(compare_length):
        values = [pkt["compare_bytes"][pos] for pkt in selected_packets]
        freq = Counter(values)
        max_count = max(freq.values())
        signature = (max_count == N)

        byte_position = pos + 1
        byte_match_counts[byte_position] = N if signature else 0
        byte_total_counts[byte_position] = N
        signature_value = values[0] if signature else None

        for pkt in selected_packets:
            byte_val = pkt["compare_bytes"][pos]
            detailed_rows.append({
                "subgroup_label": subgroup_label,
                "packet_a_flow_index": pkt["flow_index"],
                "packet_a_pcap_index": pkt["pcap_index"],
                "packet_b_flow_index": "",
                "packet_b_pcap_index": "",
                "compare_length": compare_length,
                "byte_position": byte_position,
                "packet_a_byte_hex": f"{byte_val:02x}",
                "packet_b_byte_hex": f"{signature_value:02x}" if signature_value is not None else "",
                "packet_a_byte_dec": byte_val,
                "packet_b_byte_dec": signature_value if signature_value is not None else "",
                "match": 1 if signature else 0,
            })
    return byte_match_counts, byte_total_counts, detailed_rows


def print_similarity_summary(byte_match_counts, byte_total_counts):
    print("\nPer-byte similarity summary:")
    print("BytePos/Matches/TotalComparisons/SimilarityRatio,")
    print("-" * 56)
    for pos in sorted(byte_total_counts):
        matches = byte_match_counts.get(pos, 0)
        total = byte_total_counts[pos]
        ratio = matches / total if total else 0.0
        print(f"{pos:3d}/{matches:2d}/{total:2d}/{ratio:.4f},")


def write_summary_csv(filename, byte_match_counts, byte_total_counts):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["byte_position", "similar_matches", "total_comparisons", "similarity_ratio"])
        for pos in sorted(byte_total_counts):
            matches = byte_match_counts.get(pos, 0)
            total = byte_total_counts[pos]
            ratio = matches / total if total else 0.0
            w.writerow([pos, matches, total, f"{ratio:.6f}"])


def write_detailed_csv(filename, detailed_rows):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "subgroup_label",
            "packet_a_flow_index",
            "packet_a_pcap_index",
            "packet_b_flow_index",
            "packet_b_pcap_index",
            "compare_length",
            "byte_position",
            "packet_a_byte_hex",
            "packet_b_byte_hex",
            "packet_a_byte_dec",
            "packet_b_byte_dec",
            "match",
        ])
        for row in detailed_rows:
            w.writerow([
                row["subgroup_label"],
                row["packet_a_flow_index"],
                row["packet_a_pcap_index"],
                row["packet_b_flow_index"],
                row["packet_b_pcap_index"],
                row["compare_length"],
                row["byte_position"],
                row["packet_a_byte_hex"],
                row["packet_b_byte_hex"],
                row["packet_a_byte_dec"],
                row["packet_b_byte_dec"],
                row["match"],
            ])


def build_binary_row(byte_match_counts, byte_total_counts):
    if not byte_total_counts:
        return None
    max_pos = max(byte_total_counts)
    return [1 if byte_match_counts.get(pos, 0) > 0 else 0 for pos in range(1, max_pos + 1)]


def plot_combined_heatmap(results_by_entry):
    valid = [r for r in results_by_entry if r["row"] is not None]
    if not valid:
        print("No similarity data to plot.")
        return

    max_len = max(len(r["row"]) for r in valid)
    n_rows = len(valid)
    display_rows = 2 * n_rows - 1
    data = np.full((display_rows, max_len), np.nan)

    y_positions = []
    for i, r in enumerate(valid):
        display_i = 2 * i
        row = np.array(r["row"], dtype=float)
        data[display_i, :len(row)] = row
        y_positions.append(display_i)

    inches_per_byte = 0.03
    width = max_len * inches_per_byte
    height_per_row = 0.9
    spacer_height = 0.35
    height = max(3.0, n_rows * height_per_row + (n_rows - 1) * spacer_height + 1.2)

    fig, ax = plt.subplots(figsize=(width, height))
    cmap = ListedColormap(["#6e6a6a", "#ffff00"])
    cmap.set_bad(color="white")

    ax.imshow(data, aspect="auto", interpolation="nearest", cmap=cmap, vmin=0, vmax=1)
    ax.set_xlabel("Byte position", fontsize=21)
    ax.set_yticks(y_positions)
    ax.set_yticklabels([r["row_label"] for r in valid], fontsize=19.5)
    ax.set_ylabel("Periodic packet sent", fontsize=24)

    packet_endpoints = sorted(set(len(r["row"]) for r in valid))
    xtick_positions = [0] + [p - 1 for p in packet_endpoints]
    xtick_labels = ["1"] + [str(p) for p in packet_endpoints]
    ax.set_xticks(xtick_positions)
    ax.set_xticklabels(xtick_labels)
    ax.tick_params(axis="x", length=6, width=1.0)
    ax.tick_params(axis="y", length=0)

    grey_patch = mpatches.Patch(color="#3b3b3b", label="Non-signature Byte")
    yellow_patch = mpatches.Patch(color="#ffff00", label="Signature Byte")
    ax.legend(handles=[grey_patch, yellow_patch], loc="upper center", bbox_to_anchor=(0.5, 1.18), ncol=2, frameon=False, fontsize=18)

    plt.tight_layout()
    plt.show()


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Compare packet bytes for one or more packet lengths and optionally split repeated same-length "
            "entries using local order or exact context. Example: --packet-lengths 808 232 153 153"
        )
    )
    parser.add_argument("pcap", help="Input pcap/pcapng")
    parser.add_argument("ip_a", help="First endpoint IP")
    parser.add_argument("ip_b", help="Second endpoint IP")
    parser.add_argument("--packet-lengths", type=int, nargs="+", required=True,
                        help="One or more target lengths. Repeated lengths are allowed, e.g. 808 232 153 153")
    parser.add_argument("--length-type", choices=["frame", "ip", "transport_payload"], default="frame",
                        help="How packet length is measured.")
    parser.add_argument("--packet-list", type=int, nargs="+",
                        help="Optional packet list within each final filtered subgroup.")
    parser.add_argument("--port-a", type=int, help="Optional port filter")
    parser.add_argument("--port-b", type=int, help="Optional second port filter")
    parser.add_argument("--list", action="store_true", help="List packets used for each requested entry")
    parser.add_argument("--context-window", type=int, default=3,
                        help="How many non-target packets may sit between repeated same-length packets")
    parser.add_argument("--duplicate-split-mode", choices=["local_order", "exact_context"], default="local_order",
                        help="How repeated same-length entries are separated. local_order is better for 153(first)/153(second) patterns.")
    parser.add_argument("--summary-prefix", default="byte_similarity_summary")
    parser.add_argument("--detailed-prefix", default="byte_similarity_detailed")
    parser.add_argument("--show-groups", action="store_true",
                        help="Print detected groups for repeated lengths before selecting the requested occurrence")
    args = parser.parse_args()

    full_flow = extract_flow(args.pcap, args.ip_a, args.ip_b, length_type=args.length_type,
                            port_a=args.port_a, port_b=args.port_b)
    if not full_flow:
        print("No packets found for the requested flow.")
        sys.exit(1)

    requested_occurrence_counter = Counter()
    total_requested_per_length = Counter(args.packet_lengths)
    results_by_entry = []

    for entry_index, target_length in enumerate(args.packet_lengths, start=1):
        requested_occurrence_counter[target_length] += 1
        requested_occurrence = requested_occurrence_counter[target_length]
        duplicate_mode = total_requested_per_length[target_length] > 1

        print("\n" + "=" * 80)
        label = f"{target_length}"
        if duplicate_mode:
            label += f" ({ordinal(requested_occurrence)})"
        print(f"Processing requested entry {entry_index}: {label}")
        print("=" * 80)

        if duplicate_mode:
            if args.duplicate_split_mode == "local_order":
                groups = split_same_length_by_local_order(
                    full_flow,
                    target_length,
                    repeats=total_requested_per_length[target_length],
                    context_window=args.context_window,
                )
            else:
                groups = split_same_length_by_exact_context(
                    full_flow,
                    target_length,
                    context_window=args.context_window,
                )

            if args.show_groups:
                print(f"Detected {len(groups)} group(s) for length {target_length} using mode={args.duplicate_split_mode}:")
                for i, group in enumerate(groups, start=1):
                    print(f"  Group {i}: count={group['count']}, first_flow={group['first_flow_index']}")
                    if args.duplicate_split_mode == "exact_context" and group['count']:
                        print(f"    {describe_context_key(group['key'])}")
                    elif group['count']:
                        first_meta = group.get('meta', [{}])[0]
                        if 'context' in first_meta:
                            print(f"    example_context: {describe_context_key(first_meta['context'])}")

            if requested_occurrence > len(groups):
                print(
                    f"Requested the {ordinal(requested_occurrence)} {target_length}-byte subgroup, "
                    f"but only {len(groups)} group(s) were detected.",
                    file=sys.stderr,
                )
                results_by_entry.append({"row_label": label, "row": None})
                continue

            base_flow = groups[requested_occurrence - 1]["packets"]
            if args.duplicate_split_mode == "exact_context" and groups[requested_occurrence - 1]["count"]:
                print(f"Using exact-context group {requested_occurrence} of {len(groups)} for {target_length}-byte packets.")
                print(f"Group description: {describe_context_key(groups[requested_occurrence - 1]['key'])}")
            else:
                print(f"Using local-occurrence group {requested_occurrence} of {len(groups)} for {target_length}-byte packets.")
        else:
            base_flow = [pkt for pkt in full_flow if pkt["compare_len"] == target_length]

        if not base_flow:
            print(f"No packets found for length {target_length}.")
            results_by_entry.append({"row_label": label, "row": None})
            continue

        if args.list:
            print_packet_table(base_flow)

        try:
            selected_packets = build_packet_selection(base_flow, packet_list=args.packet_list)
        except ValueError as e:
            print(f"Error for {label}: {e}", file=sys.stderr)
            sys.exit(1)

        print(f"Packets available in this entry: {len(base_flow)}")
        print(f"Length type: {args.length_type}")
        print(f"Target length: {target_length}")
        print(f"Number of selected packets: {len(selected_packets)}")
        if len(selected_packets) < 2:
            print("WARNING: fewer than 2 packets in this subgroup, so every byte will appear as a signature byte.")

        print("\nPackets being analysed:")
        for pkt in selected_packets:
            print(f"Flow {pkt['flow_index']} (PCAP #{pkt['pcap_index']})")

        byte_match_counts, byte_total_counts, detailed_rows = aggregate_similarity(selected_packets, subgroup_label=label)
        if not byte_total_counts:
            print(f"No valid comparison data produced for {label}.")
            results_by_entry.append({"row_label": label, "row": None})
            continue

        print_similarity_summary(byte_match_counts, byte_total_counts)

        suffix = f"_{target_length}"
        if duplicate_mode:
            suffix += f"_{requested_occurrence}"

        summary_csv = f"{args.summary_prefix}{suffix}.csv"
        detailed_csv = f"{args.detailed_prefix}{suffix}.csv"
        write_summary_csv(summary_csv, byte_match_counts, byte_total_counts)
        write_detailed_csv(detailed_csv, detailed_rows)
        print(f"\nSummary CSV written to: {summary_csv}")
        print(f"Detailed CSV written to: {detailed_csv}")

        results_by_entry.append({
            "row_label": label,
            "row": build_binary_row(byte_match_counts, byte_total_counts),
        })

    plot_combined_heatmap(results_by_entry)


if __name__ == "__main__":
    main()

