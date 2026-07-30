# Sunny Packets

This repository contains packet capture data (/data) along with various analysis scripts (/src) developed in order to carry out a cyber-risks assessment of commercial solar inverters

The data was collected at UNSW Sydney by means of a custom testbed from which traffic traces of inverters could be captured.

The general structure of this github repository is expressed indicatively as follows:

```text
Sunny-Packets/
├── README.md
├── requirements.txt
├── data/
.       ├── Active/
.       .         ├── Fronius Gen24 5.0/  ------------------------- ├── Fronius_LLM.txt
.       .         ├── Goodwe 55000DST218W0590/                      ├── Fronius_NMAP_TCP.txt
.       .         ├── Sungrow SG5KTL-MT/                            ├── Fronius_NMAP_UDP.txt
.       .         ├── Sungrow SH5K-20/                              ├── Fronius_LANSWEEPER.txt
.       .         └── README.md                                     └── Fronius_ANGRYIP.txt                      
.       .
.       ├── Passive/
.       .          ├── Fronius Gen24 5.0/  ------------------------ ├── Fronius_60min_boot_active.pcap
.       .          ├── Goodwe 55000DST218W0590/                     ├── Fronius_60min_run_active.pcap 
.       .          ├── Sungrow SG5KTL-MT/                           ├── Fronius_90min_run_active.pcap
.       .          ├── Sungrow SH20-5K/                             └── Fronius_90min_active_stop.pcap
.       .          └── README.md                                     
.       .
.       └── README.md
└── src/
       ├── SankeyMulti -------------------------------------------- ├── SankeyMulti.py
       ├── Shannon                                                  └── README.md
       ├── VulnerabilityLookupGrading
       ├── DataSovereignty
       ├── ExposureScore
       └── Similarity

```

| Directory        | Contents                      | Purpose                                                                   |
| ---------------- | ----------------------------- | ------------------------------------------------------------------------- |
| `data/`          | Root data directory           | Stores all datasets used by the project.                                  |
| `data/Active/`   | Active reconnaissance results | Contains outputs from active network enumeration tools for each inverter. |
| `data/Passive/`  | Passive packet captures       | Contains PCAP captures collected during normal inverter operation.        |
| `data/README.md` | Documentation                 | Describes the structure and contents of the data directory.               |
| `src/`          | Root script directory          | Stores all datasets used by the project.                                  |
| `SankeyMulti/`                | Generates Sankey diagrams showing packet flow between endpoints, protocols and ports. |
| `Shannon/`                    | Calculates Shannon entropy for packet payload analysis.                               |
| `VulnerabilityLookupGrading/` | Queries vulnerability databases and calculates vendor vulnerability scores.           |
| `DataSovereignty/`            | Determines communication destinations and assesses data sovereignty.                  |
| `ExposureScore/`              | Computes network exposure scores from discovered services and ports.                  |
| `Similarity/`                 | Compares packet structures and identifies repeated communication patterns.            |


## Context

SunnyPacket's code repository supports the passive analysis component of a study into solar inverter and DER communications. It assists in identifying:

- Local and remote communication flows
- Protocol and port usage
- Repeated packet structures
- Behavioural similarity between captures
- Entropy and variability in network traffic
- Potential indicators of plaintext, structured, or encrypted communication
- Analysing and scoring data , port exposure and manufacturer vulnerability

## What Is Included

Additional information regarding each can be found in their respective README files located in the `/src` directory.

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

```text
DataSovereignty.py
```

Script which inspects packet captures to determine whether a selected device communicates exclusively with infrastructure located within a nominated country.
Traffic involving public IP addresses is geolocated using the MaxMind GeoLite2 Country database before being compared against the target location.


```text
VulnerabilityLookupGrading.py
```

Evaluates a manufacturer's historical cybersecurity exposure by querying the National Vulnerability Database (NVD), retrieving relevant Common Vulnerabilities and Exposures (CVEs), and calculating a percentage exposure score.
Script contains modifiable .yaml file for weighting reassignment.

```text
ExposureScore.py
```
Script for the Network Exposure Score from standard Nmap TCP and UDP scan outputs. The tool parses Nmap text files, identifies exposed network services, calculates protocol-specific exposure scores, and reports the final score as a percentage.

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
python -m pip install scapy pandas numpy matplotlib plotly kaleido geoip2 pycountry
```
