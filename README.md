# Sunny Packets

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

Generate a Sankey diagram from a single packet capture:
```text
python SankeyMulti.py \
  --pcap Capture01.pcap \
  --sankey-png output.pdf
```
Generate a Sankey diagram from multiple packet captures:
```text
python SankeyMulti.py \
  --pcap Capture01.pcap \
  --pcap Capture02.pcap \
  --sankey-png combined_output.pdf
```
Example using MAC address labelling:
```text
python SankeyMulti.py \
  --pcap Capture01.pcap \
  --mac ac:19:9f:55:03:b4 \
  --label "ac:19:9f:55:03:b4 Local Flow" \
  --sankey-png local_flow.pdf
```
## Running Similarity.py

```text
python similarity.py capture01.pcap IP_destination IP_source --packet-lengths X Y --context-window Z --show-groups  
 --list
```

Where X and Y are numbers indicative of the specific byte lengths of the packets in question. Z is a numerical flag case to treat packets of identical lengths but separate instances as being separate 
from one another i.e. if there are two packets of length 153 back to back, Z = 2.

## Running Similarity.py
Run packet similarity analysis on one capture:

```text
python Similarity.py 
  --pcap Capture01.pcap
```

This script is used to identify repeated packet structures, recurring communication patterns, and behavioural similarity between solar inverter traffic captures.

## Example Workflow

A typical SolarSense workflow is as follows:

```text
python SankeyMulti.py 
  --pcap Capture01.pcap 
  --sankey-png output.pdf

python Similarity.py 
  --pcap Capture01.pcap

python Shannon.py 
  --pcap Capture01.pcap
```
The Sankey output provides a visual overview of device communication. The similarity script identifies recurring packet patterns. The entropy script provides a quantitative measure of packet variability.

## Context

SolarSense's code repository supports the passive analysis component of a study into solar inverter and DER communications. It assists in identifying:

- Local and remote communication flows
- Protocol and port usage
- Repeated packet structures
- Behavioural similarity between captures
- Entropy and variability in network traffic
- Potential indicators of plaintext, structured, or encrypted communication

The tool is intended to help characterise how consumer DER devices communicate and how their network behaviour can be analysed for cybersecurity research.
