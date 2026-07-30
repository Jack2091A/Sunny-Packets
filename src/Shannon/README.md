# Shannon Payload Entropy Analyzer

`Shannon.py` analyses packet payload entropy within a PCAP or PCAPNG capture for traffic exchanged between two IP addresses. It produces packet-level entropy statistics, calculates Shannon entropy across the complete bidirectional flow, reports directional whole-flow entropy, and plots a normalized entropy histogram.

## What the script calculates

The script reports:

- Shannon entropy for every matching packet payload.
- Average, minimum, and maximum packet entropy.
- **Whole-flow entropy**, calculated after concatenating all matching payload bytes in capture order.
- Separate whole-flow entropy for each communication direction.
- Packet counts and payload-byte totals.
- Entropy statistics for up to three selected full packet lengths.
- The number of packets meeting an optional high-entropy threshold.

Entropy is reported in **bits per byte** and ranges from `0` to `8`:

- Values near `0` indicate highly repetitive or uniform payload data.
- Higher values indicate a more varied byte distribution.
- High entropy can be consistent with encryption or compression, but entropy alone does not prove that either is present.

## Requirements

- Python 3.9 or later
- Scapy
- Matplotlib
- NumPy

Install the dependencies with:

```powershell
python -m pip install scapy matplotlib numpy
```

## Basic usage

```powershell
python Shannon.py <capture.pcap> <IP_A> <IP_B>
```

Example:

```powershell
python Shannon.py Capture01.pcap 192.168.1.235 13.236.198.39
```

The two IP addresses define a bidirectional flow. Packets travelling in either direction are included.

## Common examples

### Save the histogram

```powershell
python Shannon.py Capture01.pcap 192.168.1.235 13.236.198.39 --save-fig entropy.png
```

### Save without opening a plot window

```powershell
python Shannon.py Capture01.pcap 192.168.1.235 13.236.198.39 --save-fig entropy.png --no-show
```

### Split the histogram by direction

```powershell
python Shannon.py Capture01.pcap 192.168.1.235 13.236.198.39 --split-direction
```

### Highlight selected full packet lengths

```powershell
python Shannon.py Capture01.pcap 192.168.1.235 13.236.198.39 --lengths 808 232 153
```

The values supplied to `--lengths` refer to the complete captured packet length, not only the payload length.

### Report packets above an entropy threshold

```powershell
python Shannon.py Capture01.pcap 192.168.1.235 13.236.198.39 --high-threshold 7.5
```

### Include packets with no payload

By default, packets without a payload are excluded. To include them as entropy `0`:

```powershell
python Shannon.py Capture01.pcap 192.168.1.235 13.236.198.39 --include-zero
```

## Command-line options

| Option | Description |
|---|---|
| `pcap` | Input PCAP or PCAPNG file. |
| `ip_a` | First flow endpoint. This is treated as the forward direction source. |
| `ip_b` | Second flow endpoint. |
| `--bins N` | Number of histogram bins. Default: `50`. |
| `--include-zero` | Include packets without payload data as entropy `0`. |
| `--split-direction` | Plot separate normalized histograms for each direction. |
| `--lengths L1 L2 L3` | Highlight up to three full packet lengths. |
| `--high-threshold H` | Count packets with entropy greater than or equal to `H`. |
| `--save-fig PATH` | Save the histogram to a file. |
| `--no-show` | Do not open the interactive plot window. |

Display the built-in help with:

```powershell
python Shannon.py --help
```

## Whole-flow entropy

Packet-average entropy and whole-flow entropy are different measurements.

**Average packet entropy** is the arithmetic mean of the entropy calculated separately for each packet payload.

**Whole-flow entropy** concatenates all matching payload bytes and calculates entropy once across the resulting byte stream:

```text
payload_packet_1 + payload_packet_2 + ... + payload_packet_n
```

The directional results use the same method but concatenate payloads separately for:

```text
IP_A -> IP_B
IP_B -> IP_A
```

This provides a flow-level measure of byte diversity while preserving packet-level statistics for comparison.

## Example output

```text
=== Flow Entropy Summary ===
Flow                       : 192.168.1.235 <-> 13.236.198.39
Packets used               : 184
Payload bytes used         : 48213
Whole-flow entropy         : 7.8421 bits/byte
Average packet entropy     : 6.7314 bits/byte
Minimum packet entropy     : 1.5000 bits/byte
Maximum packet entropy     : 7.9132 bits/byte

=== Directional Whole-Flow Entropy ===
192.168.1.235 -> 13.236.198.39 : 7.7540 bits/byte (16422 payload bytes)
13.236.198.39 -> 192.168.1.235 : 7.8813 bits/byte (31791 payload bytes)
```

## Notes and limitations

- Entropy is calculated from extracted TCP, UDP, or Scapy `Raw` payload bytes.
- TCP retransmissions and duplicated data in the capture are not removed before whole-flow calculation.
- The script does not reconstruct application streams or reorder out-of-order TCP segments.
- Capture truncation, packet loss, and offloading can affect the result.
- A high entropy result should be interpreted alongside protocol identification, TLS inspection, packet-length patterns, timing, and endpoint analysis.

## Suggested repository structure

```text
project/
├── Shannon.py
├── README.md
├── requirements.txt
├── captures/
└── outputs/
```

A minimal `requirements.txt` would contain:

```text
matplotlib
numpy
scapy
```
