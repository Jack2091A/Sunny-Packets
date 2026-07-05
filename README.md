# SolarSense

## What Is Included

```text
SankeyMulti.py
```

Generates Sankey diagrams from one or more PCAP files to visualise traffic flows between devices, IP addresses, ports, and protocols.

```text
Similarity.py
```

Compares packet captures and identifies similarity between observed traffic patterns. 

```text
Shannon.py
```

Calculates Shannon entropy across packet-level features to measure uncertainty, structure, or randomness in network traffic.
Example packet captures such as Capture01.pcap, if provided.
Output files such as .pdf, .html, .csv, or .png, depending on the selected script options.

## Setup

Create and activate a Python virtual environment:

For Linux Systems:

```text

python3 -m venv .venv
source .venv/bin/activate
```
For Windows Powershell, use:

```text
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Install the required packages:

```text
python -m pip install -r requirements.txt
```

If this does not work, install the items manually using:

```text
python -m pip install scapy pandas numpy matplotlib plotly kaleido
```

## Running SankeyMulti.py

```bash
python SankeyMulti.py \
    --pcap Capture01.pcap \
    --sankey-png output.pdf
```

## Running Similarity.py\

python Similarity.py \
    --pcap Capture01.pcap

## Running Similarity.py\


## Example Workflow

A typical SolarSense workflow is as follows:

```text
python SankeyMulti.py \
  --pcap Capture01.pcap \
  --sankey-png output.pdf

python Similarity.py \
  --pcap Capture01.pcap

python Shannon.py \
  --pcap Capture01.pcap

The Sankey output provides a visual overview of device communication. The similarity script identifies recurring packet patterns. The entropy script provides a quantitative measure of packet variability.
```

## Context

SolarSense's code repository supports the passive analysis component of a study into solar inverter and DER communications. It assists in identifying:

- Local and remote communication flows
- Protocol and port usage
- Repeated packet structures
- Behavioural similarity between captures
- Entropy and variability in network traffic
- Potential indicators of plaintext, structured, or encrypted communication

The tool is intended to help characterise how consumer DER devices communicate and how their network behaviour can be analysed for cybersecurity research.
