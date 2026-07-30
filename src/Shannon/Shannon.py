#!/usr/bin/env python3

import argparse
import math
import sys
from collections import Counter

import matplotlib as mpl
import matplotlib.pyplot as plt
import numpy as np
from scapy.all import IP, IPv6, TCP, UDP, Raw, rdpcap


# -----------------------------
# Plot styling: LaTeX-like look
# -----------------------------
mpl.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Computer Modern Roman", "CMU Serif", "DejaVu Serif"],
    "mathtext.fontset": "cm",
    "axes.labelsize": 22,
    "axes.titlesize": 24,
    "xtick.labelsize": 18,
    "ytick.labelsize": 18,
    "legend.fontsize": 18,
    "figure.titlesize": 24,
    "axes.linewidth": 1.0,
    "grid.linewidth": 0.6,
    "grid.alpha": 0.25,
})


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte for a byte sequence."""
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def get_payload(pkt) -> bytes:
    """Extract the application/transport payload used for entropy analysis."""
    if Raw in pkt:
        return bytes(pkt[Raw].load)
    if TCP in pkt:
        return bytes(pkt[TCP].payload)
    if UDP in pkt:
        return bytes(pkt[UDP].payload)
    return b""


def get_full_packet_length(pkt) -> int:
    """Return the complete captured packet length in bytes."""
    return len(bytes(pkt))


def get_ip_pair(pkt):
    """Return (source, destination) for IPv4 or IPv6 packets."""
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return None


def matches(pkt, ip_a, ip_b):
    pair = get_ip_pair(pkt)
    if pair is None:
        return False

    src, dst = pair
    return (src == ip_a and dst == ip_b) or (src == ip_b and dst == ip_a)


def is_forward(pkt, ip_a):
    pair = get_ip_pair(pkt)
    return pair is not None and pair[0] == ip_a


def style_axes(ax):
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.tick_params(axis="both", which="major", length=6, width=1.0)
    ax.tick_params(axis="both", which="minor", length=3, width=0.8)
    ax.grid(True, linestyle="--", alpha=0.25)
    ax.set_axisbelow(True)


def summarize_selected_lengths(packet_records, selected_lengths, high_threshold=None):
    if not selected_lengths:
        return

    print("\n=== Selected Length Analysis (full packet length) ===")
    for length in selected_lengths:
        matching_records = [rec for rec in packet_records if rec["full_len"] == length]

        if not matching_records:
            print(f"Length {length}: 0 packets found")
            continue

        entropies = [rec["entropy"] for rec in matching_records]
        print(f"Length {length}:")
        print(f"  Packet count        : {len(matching_records)}")
        print(f"  Average entropy     : {sum(entropies) / len(entropies):.4f} bits/byte")
        print(f"  Minimum entropy     : {min(entropies):.4f} bits/byte")
        print(f"  Maximum entropy     : {max(entropies):.4f} bits/byte")

        if high_threshold is not None:
            high_matches = [value for value in entropies if value >= high_threshold]
            print(f"  Packets >= {high_threshold:.4f}: {len(high_matches)}")
            if high_matches:
                print("  High-entropy values : " + ", ".join(f"{value:.4f}" for value in high_matches))


def print_flow_summary(
    packet_records,
    flow_bytes,
    forward_bytes,
    reverse_bytes,
    ip_a,
    ip_b,
    high_threshold=None,
):
    """Print packet-level and whole-flow entropy statistics."""
    entropies = [record["entropy"] for record in packet_records]

    print("\n=== Flow Entropy Summary ===")
    print(f"Flow                       : {ip_a} <-> {ip_b}")
    print(f"Packets used               : {len(packet_records)}")
    print(f"Payload bytes used         : {len(flow_bytes)}")
    print(f"Whole-flow entropy         : {shannon_entropy(bytes(flow_bytes)):.4f} bits/byte")
    print(f"Average packet entropy     : {sum(entropies) / len(entropies):.4f} bits/byte")
    print(f"Minimum packet entropy     : {min(entropies):.4f} bits/byte")
    print(f"Maximum packet entropy     : {max(entropies):.4f} bits/byte")

    print("\n=== Directional Whole-Flow Entropy ===")
    print(
        f"{ip_a} -> {ip_b:<15}: "
        f"{shannon_entropy(bytes(forward_bytes)):.4f} bits/byte "
        f"({len(forward_bytes)} payload bytes)"
    )
    print(
        f"{ip_b} -> {ip_a:<15}: "
        f"{shannon_entropy(bytes(reverse_bytes)):.4f} bits/byte "
        f"({len(reverse_bytes)} payload bytes)"
    )

    if high_threshold is not None:
        high_count = sum(1 for value in entropies if value >= high_threshold)
        print(f"\nPackets with entropy >= {high_threshold:.4f}: {high_count}")


def find_bin(value, bins):
    """Return the histogram bin index for a value."""
    index = np.searchsorted(bins, value, side="right") - 1
    if value == bins[-1]:
        index = len(bins) - 2
    if 0 <= index < len(bins) - 1:
        return index
    return None


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Calculate packet and whole-flow payload entropy for traffic between "
            "two IP addresses and plot a packet-entropy histogram."
        )
    )
    parser.add_argument("pcap", help="Input PCAP or PCAPNG file")
    parser.add_argument("ip_a", help="First endpoint IP address")
    parser.add_argument("ip_b", help="Second endpoint IP address")
    parser.add_argument("--bins", type=int, default=50, help="Number of histogram bins")
    parser.add_argument(
        "--include-zero",
        action="store_true",
        help="Include packets with no payload as entropy 0",
    )
    parser.add_argument(
        "--split-direction",
        action="store_true",
        help="Plot a separate normalized histogram for each direction",
    )
    parser.add_argument(
        "--lengths",
        nargs="*",
        type=int,
        default=[],
        help="Up to 3 full packet lengths to highlight, e.g. --lengths 66 808 1514",
    )
    parser.add_argument(
        "--high-threshold",
        type=float,
        default=None,
        help="Optional packet-entropy threshold for reporting",
    )
    parser.add_argument("--save-fig", default=None, help="Optional output path for the figure")
    parser.add_argument(
        "--no-show",
        action="store_true",
        help="Do not open an interactive plot window",
    )

    args = parser.parse_args()

    if len(args.lengths) > 3:
        parser.error("you may specify at most 3 lengths with --lengths")
    if args.bins <= 0:
        parser.error("--bins must be greater than zero")
    if args.high_threshold is not None and not 0 <= args.high_threshold <= 8:
        parser.error("--high-threshold must be between 0 and 8 bits/byte")

    try:
        packets = rdpcap(args.pcap)
    except Exception as exc:
        print(f"Error reading PCAP: {exc}", file=sys.stderr)
        sys.exit(1)

    packet_records = []
    flow_bytes = bytearray()
    forward_bytes = bytearray()
    reverse_bytes = bytearray()

    for pkt in packets:
        if not matches(pkt, args.ip_a, args.ip_b):
            continue

        payload = get_payload(pkt)
        if not payload and not args.include_zero:
            continue

        forward = is_forward(pkt, args.ip_a)
        entropy = shannon_entropy(payload)

        packet_records.append({
            "entropy": entropy,
            "full_len": get_full_packet_length(pkt),
            "forward": forward,
        })

        flow_bytes.extend(payload)
        if forward:
            forward_bytes.extend(payload)
        else:
            reverse_bytes.extend(payload)

    if not packet_records:
        print("No matching packets found.")
        return

    print_flow_summary(
        packet_records,
        flow_bytes,
        forward_bytes,
        reverse_bytes,
        args.ip_a,
        args.ip_b,
        args.high_threshold,
    )
    summarize_selected_lengths(packet_records, args.lengths, args.high_threshold)

    entropy_all = [record["entropy"] for record in packet_records]
    entropy_fwd = [record["entropy"] for record in packet_records if record["forward"]]
    entropy_rev = [record["entropy"] for record in packet_records if not record["forward"]]

    fig, ax = plt.subplots(figsize=(12, 7))
    histogram_range = (0, 8)

    if args.split_direction:
        bins = np.linspace(0, 8, args.bins + 1)

        if entropy_fwd:
            ax.hist(
                entropy_fwd,
                bins=bins,
                weights=np.full(len(entropy_fwd), 1 / len(entropy_fwd)),
                alpha=0.45,
                edgecolor="black",
                linewidth=0.8,
                color="#cfe2ff",
                label=f"{args.ip_a} -> {args.ip_b}",
            )
        if entropy_rev:
            ax.hist(
                entropy_rev,
                bins=bins,
                weights=np.full(len(entropy_rev), 1 / len(entropy_rev)),
                alpha=0.45,
                edgecolor="black",
                linewidth=0.8,
                color="#f8d7da",
                label=f"{args.ip_b} -> {args.ip_a}",
            )
        ax.legend(frameon=False)
        counts, _ = np.histogram(entropy_all, bins=bins, weights=np.full(len(entropy_all), 1 / len(entropy_all)))
    else:
        weights = np.full(len(entropy_all), 1 / len(entropy_all))
        counts, bins, _ = ax.hist(
            entropy_all,
            bins=args.bins,
            range=histogram_range,
            weights=weights,
            edgecolor="black",
            linewidth=0.8,
            color="#f2f2f2",
        )

    ax.set_xticks(np.arange(0, 8.5, 0.5))
    ax.set_xlim(0, 8)

    colors = ["#ffb3b3", "#b3d9ff", "#b8f0b8"]

    if args.lengths and not args.split_direction:
        bin_length_counts = {i: {} for i in range(len(bins) - 1)}

        for record in packet_records:
            length = record["full_len"]
            if length not in args.lengths:
                continue

            bin_index = find_bin(record["entropy"], bins)
            if bin_index is not None:
                current = bin_length_counts[bin_index].get(length, 0)
                bin_length_counts[bin_index][length] = current + 1

        for bin_index in range(len(counts)):
            if counts[bin_index] == 0:
                continue

            x_left = bins[bin_index]
            width = bins[bin_index + 1] - x_left
            y_bottom = 0.0

            for color_index, length in enumerate(args.lengths):
                count_for_length = bin_length_counts[bin_index].get(length, 0)
                if count_for_length == 0:
                    continue

                rect_height = count_for_length / len(entropy_all)
                rect = plt.Rectangle(
                    (x_left, y_bottom),
                    width,
                    rect_height,
                    facecolor=colors[color_index % len(colors)],
                    edgecolor="none",
                    alpha=1.0,
                    zorder=3,
                )
                ax.add_patch(rect)
                y_bottom += rect_height

        handles = [
            plt.Rectangle((0, 0), 1, 1, facecolor=colors[i % len(colors)], edgecolor="none")
            for i, _ in enumerate(args.lengths)
        ]
        labels = [f"{length}-byte packets" for length in args.lengths]
        ax.legend(handles, labels, frameon=False)

    ax.set_xlabel("Payload entropy (bits/byte)", labelpad=12)
    ax.set_ylabel("Packet probability", labelpad=12)
    style_axes(ax)

    plt.tight_layout(pad=0.5)

    if args.save_fig:
        plt.savefig(args.save_fig, dpi=300, bbox_inches="tight")
        print(f"\nHistogram saved to: {args.save_fig}")

    if not args.no_show:
        plt.show()
    else:
        plt.close(fig)


if __name__ == "__main__":
    main()
