# Shannon Payload Entropy Analyzer

## Background

`Shannon.py` analyses packet payload entropy within a PCAP or PCAPNG capture for traffic exchanged between two IP addresses. It produces packet-level entropy statistics, calculates Shannon entropy across the complete bidirectional flow, reports directional whole-flow entropy, and plots a normalized entropy histogram.

## What the script calculates

The script outputs:

- Shannon entropy for every matching packet payload.
- Average, minimum, and maximum packet entropy.
- Whole flow entropy, calculated after concatenating all matching payload bytes in capture order.
- Separate whole-flow entropy for each communication direction.
- Packet counts and payload-byte totals.
- Entropy statistics for up to three selected full packet lengths.
- The number of packets meeting an optional high-entropy threshold.

Entropy is reported in **bits per byte** and ranges from `0` to `8`:

- Values near `0` indicate highly repetitive or uniform payload data.
- Higher values indicate a more varied byte distribution.
- High entropy can be consistent with encryption or compression, but entropy alone does not prove that either is present.

## Usage

```
python Shannon.py <capture.pcap> <IP_A> <IP_B>
```

Example:

```
python Shannon.py Capture01.pcap 192.168.1.235 13.236.198.39
```

The two IP addresses define a bidirectional flow. Packets travelling in either direction are included.

## Common examples

### Save the histogram

```
python Shannon.py Capture01.pcap 192.168.1.235 13.236.198.39 --save-fig entropy.png
```

### Save without opening a plot window

```
python Shannon.py Capture01.pcap 192.168.1.235 13.236.198.39 --save-fig entropy.png --no-show
```

### Split the histogram by direction

```
python Shannon.py Capture01.pcap 192.168.1.235 13.236.198.39 --split-direction
```

### Highlight selected full packet lengths

```
python Shannon.py Capture01.pcap 192.168.1.235 13.236.198.39 --lengths 808 232 153
```

The values supplied to `--lengths` refer to the complete captured packet length, not only the payload length.

### Report packets above an entropy threshold

```
python Shannon.py Capture01.pcap 192.168.1.235 13.236.198.39 --high-threshold 7.5
```

### Include packets with no payload

By default, packets without a payload are excluded. To include them as entropy `0`:

```
python Shannon.py Capture01.pcap 192.168.1.235 13.236.198.39 --include-zero
```

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

