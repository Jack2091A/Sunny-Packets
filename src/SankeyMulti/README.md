# SankeyMulti.py

## Background

SankeyMulti is a python script designed to build Sankey diagrams out of pcap files. It is able to take multiple input pcap files and produce 
combined Sankey diagrams in png and pdf format.
The script takes in mac addresses of the target device. As ports can be assigned at random by devices initiating communications,

### Features

- Analyse one or more PCAP files simultaneously
- Filter traffic by device MAC address
- Automatically resolve destination IP addresses to DNS hostnames
- Compare multiple devices on a single Sankey diagram
- Optional merging of ephemeral source ports
- Optional merging of destination service ports
- Export publication-quality Sankey diagrams as PNG files

---

## Usage

### Generate a Sankey diagram from a single packet capture

```text
python SankeyMulti.py 
  --pcap CaptureA.pcap 
  --sankey-png Output.pdf
```

### Generate a Sankey Diagram using MAC address labelling:
```text
python SankeyMulti.py 
  --pcap CaptureA.pcap 
  --mac ac:19:9f:55:03:b4 
  --label "ac:19:9f:55:03:b4 Local Flow" 
  --sankey-png Finalflow.pdf
```
### Generate a Sankey diagram from multiple packet captures:
```text
python SankeyMulti.py 
  --pcap CaptureA.pcap 
  --pcap CaptureB.pcap
  --mac ac:19:9f:55:03:b4
  --mac 60:c5:a8:71:86:0c
  --sankey-png CombinedOutput.pdf
```
### Generate Sankey Diagram using merge functionality:

When port merging is enabled, ephemeral client ports are grouped into a single node:

```
Device Port: *
```

Likewise, destination service ports may be grouped:

```
Endpoint Port: *
```

This greatly reduces the clutter for highly repetitive traffic with differing port numbers.
```text
python SankeyMulti.py
  --pcap Sungrow5k.pcap
  --mac 60:c5:a8:71:2f:d4
  --label "Remote Flow"
  --merge-src-ports 1
  --merge-dst-ports 0
  --sankey-png MergedFlow.pdf
```

### Command Line Options

| Option | Description |
|---------|-------------|
| `--pcap` | PCAP file to analyse (repeatable). |
| `--mac` | Target MAC address associated with each PCAP. |
| `--label` | Optional label displayed on the Sankey diagram. |
| `--merge-src-ports` | Merge ephemeral source ports for each device (0/1). |
| `--merge-dst-ports` | Merge destination ports for each device (0/1). |
| `--include-private` | Include private destination IP addresses. |
| `--top` | Number of destination IPs printed in the console summary. |
| `--sankey-png` | Output PNG filename. |
| `--sankey-top` | Maximum number of links retained in each Sankey layer. |

---

## Example Output
Generated with command:

```bash
python SankeyMulti.py
  --pcap Capture27A.pcap
  --pcap Capture17.pcap
  --mac ac:19:9f:55:03:b4
  --mac 60:c5:a8:71:86:0c
  --label "ac:19:9f:55:03:b4"
  --label "60:c5:a8:71:86:0c"
  --merge-src-ports 0 1
  --merge-dst-ports 1 0
  --sankey-png combined.pdf
```

<img width="1182" height="504" alt="image" src="https://github.com/user-attachments/assets/d87034c5-e87d-42ca-a746-1c123082bc70" />

