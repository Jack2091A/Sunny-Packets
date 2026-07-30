# Packet Similarity Analysis Tool

## Background

A Python utility for identifying deterministic byte positions within repeated network packets. The tool extracts a bidirectional flow from a PCAP, groups packets by length, compares packets byte-by-byte, exports similarity statistics, and visualises protocol signatures using a heatmap.

---

## Usage

Basic syntax:

```bash
python Similarity.py <pcap> <ip_a> <ip_b> --packet-lengths <lengths>
```

Example:

```bash
python Similarity.py Capture01.pcap 192.168.1.235 13.236.198.39 --packet-lengths 808 232 153 153
```

---

### Command Line Options

| Option | Description |
|---------|-------------|
| `--packet-lengths` | One or more packet lengths to analyse (required). |
| `--length-type` | Measure packet length using `frame`, `ip`, or `transport_payload`. |
| `--packet-list` | Analyse only specific packets from the filtered group. |
| `--port-a` | Filter packets containing this port. |
| `--port-b` | Filter packets containing this second port. |
| `--duplicate-split-mode` | `local_order` or `exact_context` for separating repeated packet lengths. |
| `--context-window` | Number of neighbouring packets used for grouping repeated packets. |
| `--show-groups` | Display detected packet groups before analysis. |
| `--list` | Print packets included in each comparison. |
| `--summary-prefix` | Prefix for summary CSV files. |
| `--detailed-prefix` | Prefix for detailed CSV files. |

---

## Features

- Extracts packets exchanged between two IP addresses
- Supports TCP and UDP traffic
- Filters by packet length (Frame, IP, or Transport Payload)
- Optional filtering by source/destination port
- Supports repeated packet lengths (e.g. `153 153`)
- Two duplicate separation modes:
  - Local occurrence
  - Exact packet context
- Produces per-byte similarity statistics
- Exports summary and detailed CSV files
- Generates a binary heatmap highlighting deterministic ("signature") bytes

---

### Duplicate Packet Handling

Protocols often contain repeated packet lengths within the same transaction (for example `153, 153`). The analyser script will be able to distinguish
between the two if the command is prompted as such, i.e. if the pattern expected is 808, 250, 153, 153, then it will distinguish the two 153 lengthed packets.
However, if instead if the prompt was 808, 153, 250, 153, the analyser may fail to distinguish between the two.

## Output Files

For every analysed packet length the tool produces:

### Summary CSV

Contains:

- byte position
- number of matching bytes
- total comparisons
- similarity ratio

Example:

```
byte_position,similar_matches,total_comparisons,similarity_ratio
1,10,10,1.0000
2,10,10,1.0000
3,0,10,0.0000
```

## Heatmap

The generated heatmap visualises deterministic protocol fields.

Legend:

- Yellow — Signature byte (identical across all packets)
- Grey — Variable byte

Each row corresponds to one analysed packet length or subgroup.

---

## Example Output
Generated with command: 

```bash
python Similarity.py Capture01.pcap 192.168.1.235 13.236.198.39 --packet-lengths 808 232 153 153
```

<img width="2423" height="584" alt="image" src="https://github.com/user-attachments/assets/ec684829-e2cb-4540-b07d-6014c045c688" />

