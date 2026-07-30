#!/usr/bin/env python3

import argparse
import math
import sys
from collections import Counter

import matplotlib as mpl
import matplotlib.pyplot as plt
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
    if not data:
        return 0.0

    counts = Counter(data)
    length = len(data)

    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def get_payload(pkt) -> bytes:
    """
    Exact payload extraction style from your original script.
    This is what entropy is computed on.
    """
    if Raw in pkt:
        return bytes(pkt[Raw].load)
    if TCP in pkt:
        return bytes(pkt[TCP].payload)
    if UDP in pkt:
        return bytes(pkt[UDP].payload)
    return b""


def get_full_packet_length(pkt) -> int:
    """
    Full packet length, matching what you want to specify on the command line.
    """
    return len(bytes(pkt))


def matches(pkt, ip_a, ip_b):
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    else:
        return False

    return (src == ip_a and dst == ip_b) or (src == ip_b and dst == ip_a)


def direction(pkt, ip_a):
    if IP in pkt:
        return pkt[IP].src == ip_a
    if IPv6 in pkt:
        return pkt[IPv6].src == ip_a
    return False


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
    for L in selected_lengths:
        matches_len = [rec for rec in packet_records if rec["full_len"] == L]

        if not matches_len:
            print(f"Length {L}: 0 packets found")
            continue

        entropies = [rec["entropy"] for rec in matches_len]
        avg_e = sum(entropies) / len(entropies)
        min_e = min(entropies)
        max_e = max(entropies)

        print(f"Length {L}:")
        print(f"  Packet count        : {len(matches_len)}")
        print(f"  Average entropy     : {avg_e:.4f} bits/byte")
        print(f"  Minimum entropy     : {min_e:.4f} bits/byte")
        print(f"  Maximum entropy     : {max_e:.4f} bits/byte")

        if high_threshold is not None:
            high_matches = [e for e in entropies if e >= high_threshold]
            print(f"  Packets >= {high_threshold:.4f}: {len(high_matches)}")
            if high_matches:
                print("  High-entropy values : " + ", ".join(f"{e:.4f}" for e in high_matches))


def main():
    parser = argparse.ArgumentParser(
        description="Plot payload-entropy histogram for packets between two IPs, while matching selected full packet lengths."
    )
    parser.add_argument("pcap")
    parser.add_argument("ip_a")
    parser.add_argument("ip_b")
    parser.add_argument("--bins", type=int, default=50, help="Number of histogram bins")
    parser.add_argument("--include-zero", action="store_true",
                        help="Include zero-payload packets (entropy 0)")
    parser.add_argument("--split-direction", action="store_true",
                        help="Separate histograms for each direction")
    parser.add_argument("--lengths", nargs="*", type=int, default=[],
                        help="Up to 3 full packet lengths to highlight, e.g. --lengths 66 808 1514")
    parser.add_argument("--high-threshold", type=float, default=None,
                        help="Optional entropy threshold for reporting")
    parser.add_argument("--save-fig", default=None,
                        help="Optional path to save the figure")

    args = parser.parse_args()

    if len(args.lengths) > 3:
        print("Error: you may specify at most 3 lengths with --lengths")
        sys.exit(1)

    try:
        packets = rdpcap(args.pcap)
    except Exception as e:
        print(f"Error reading PCAP: {e}")
        sys.exit(1)

    packet_records = []
    flow_bytes = bytearray()

    entropy_all = []
    entropy_fwd = []
    entropy_rev = []

    for pkt in packets:
        if not matches(pkt, args.ip_a, args.ip_b):
            continue

        payload = get_payload(pkt)

        # Keep the exact behavior of your original script
        if len(payload) == 0 and not args.include_zero:
            continue

        H = shannon_entropy(payload)
        full_len = get_full_packet_length(pkt)

        packet_records.append({
            "entropy": H,
            "full_len": full_len,
            "forward": direction(pkt, args.ip_a),
        })

        entropy_all.append(H)
        flow_bytes.extend(payload)

        if args.split_direction:
            if direction(pkt, args.ip_a):
                entropy_fwd.append(H)
            else:
                entropy_rev.append(H)

    if not entropy_all:
        print("No matching packets found.")
        return

    print(f"Total packets used         : {len(entropy_all)}")
    print(f"Whole-flow entropy         : {shannon_entropy(bytes(flow_bytes)):.4f} bits/byte")
    print(f"Avg entropy                : {sum(entropy_all)/len(entropy_all):.4f}")
    print(f"Min entropy                : {min(entropy_all):.4f}")
    print(f"Max entropy                : {max(entropy_all):.4f}")

    if args.high_threshold is not None:
        high_count = sum(1 for e in entropy_all if e >= args.high_threshold)
        print(f"Packets with entropy >= {args.high_threshold:.4f}: {high_count}")

    summarize_selected_lengths(packet_records, args.lengths, args.high_threshold)

    fig, ax = plt.subplots(figsize=(12, 7))

    if args.split_direction:
        counts_fwd, bins_fwd, _ = ax.hist(
            entropy_fwd,
            bins=args.bins,
            range=(0, 8),
            alpha=0.45,
            edgecolor="black",
            linewidth=0.8,
            color="#cfe2ff",
            label=f"{args.ip_a} → {args.ip_b}"
        )
        counts_rev, bins_rev, _ = ax.hist(
            entropy_rev,
            bins=args.bins,
            range=(0, 8),
            alpha=0.45,
            edgecolor="black",
            linewidth=0.8,
            color="#f8d7da",
            label=f"{args.ip_b} → {args.ip_a}"
        )
        ax.legend(frameon=False)

        # For highlighting lengths, use the combined bins from 0..8
        bins = bins_fwd
        counts, _ = np.histogram(entropy_all, bins=bins)
    else:
        weights = [1 / len(entropy_all)] * len(entropy_all)

        counts, bins, patches = plt.hist(
            entropy_all,
            bins=args.bins,
            range=(0, 8),
            weights=weights,
            edgecolor="black",
            linewidth=0.8,
            color="#f2f2f2"
        )

        ax.set_xticks(np.arange(0, 8.5, 0.5))
        ax.set_yticks(np.linspace(0, 1, 6))

    ax.set_xlim(0, 8)

    colors = ["#ffb3b3", "#b3d9ff", "#b8f0b8"]

    def find_bin(e, bins_):
        for i in range(len(bins_) - 1):
            if i == len(bins_) - 2:
                if bins_[i] <= e <= bins_[i + 1]:
                    return i
            else:
                if bins_[i] <= e < bins_[i + 1]:
                    return i
        return None

    if args.lengths:
        bin_length_counts = {i: {} for i in range(len(bins) - 1)}

        for rec in packet_records:
            L = rec["full_len"]
            if L not in args.lengths:
                continue

            b = find_bin(rec["entropy"], bins)
            if b is None:
                continue

            bin_length_counts[b][L] = bin_length_counts[b].get(L, 0) + 1

        for b in range(len(counts)):
            total_in_bin = counts[b]
            if total_in_bin == 0:
                continue

            x_left = bins[b]
            x_right = bins[b + 1]
            width = x_right - x_left
            y_bottom = 0.0

            for idx, L in enumerate(args.lengths):
                count_for_length = bin_length_counts[b].get(L, 0)
                if count_for_length == 0:
                    continue
                rect_height = count_for_length / len(entropy_all)
                rect = plt.Rectangle(
                    (x_left, y_bottom),
                    width,
                    rect_height,
                    facecolor=colors[idx % len(colors)],
                    edgecolor="none",
                    alpha=1.0,
                    zorder=3
                )
                ax.add_patch(rect)
                y_bottom += count_for_length

        # crisp outlines
        for b in range(len(counts)):
            if counts[b] == 0:
                continue

            outline = plt.Rectangle(
                (bins[b], 0),
                bins[b + 1] - bins[b],
                counts[b],
                facecolor="none",
                edgecolor="black",
                linewidth=0.8,
                zorder=4
            )
            ax.add_patch(outline)

        handles = [
            plt.Rectangle((0, 0), 1, 1, facecolor=colors[i % len(colors)], edgecolor="none")
            for i, _ in enumerate(args.lengths)
        ]
        labels = [f"{L}-Byte packets" for L in args.lengths]
        ax.legend(handles, labels, frameon=False)

    ax.set_xlabel("X: Entropy", labelpad=12)
    ax.set_ylabel("Probability: P(Entropy = x)", labelpad=12)
    #ax.set_title("Histogram of Packet Payload Entropy", pad=16)

    style_axes(ax)

    plt.tight_layout(pad=0.5)
    plt.margins(x=0, y=0.4)

    if args.save_fig:
        plt.savefig(args.save_fig, dpi=300, bbox_inches="tight")
        print(f"Histogram saved to: {args.save_fig}")

    plt.show()


if __name__ == "__main__":
    import numpy as np
    main()
