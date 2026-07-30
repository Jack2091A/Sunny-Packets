# Sunny Packets

## Background

This repository contains packet capture data (/data) along with various analysis scripts (/src) developed in order to carry out a cyber-risks assessment of commercial solar inverters
The data was collected at UNSW Sydney by means of a custom testbed from which traffic traces of inverters could be captured. 

## Repository Organisation

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
## What Is Included
Overarhing information and documentation can be found in the respective directories of this repository. The below is a summary:

| Directory        | Purpose                                                                   |
| ---------------- | ------------------------------------------------------------------------- |
| `data/`          | Root Data Directory, Stores all datasets collected by the thesis.         |
| `data/Active/`   | Contains outputs from active network scanning tools for each inverter.    |
| `data/Passive/`  | Contains PCAP captures collected during normal inverter operation.        |
| `data/README.md` | Describes the structure and contents of the data directory.               |
| `src/`           | Stores all datasets used by the project.                                  |
| `SankeyMulti/`                | Script and Documentation. Generates Sankey diagrams showing packet flow between endpoints, protocols and ports.                    |
| `Shannon/`                    | Script and Documentation. Calculates Shannon entropy for packet payload analysis.                                                  |
| `VulnerabilityLookupGrading/` | Script, .yaml config file and Documentation. Queries vulnerability databases and calculates vendor vulnerability scores.           |
| `DataSovereignty/`            | Script, Data File (.mmdb) and Documentation. Determines communication destinations and assesses data sovereignty.                  |
| `ExposureScore/`              | Script and Documentation. Computes network exposure scores from discovered services and ports.                                     |
| `Similarity/`                 | Script and Documentation. Compares packet structures and identifies repeated communication patterns.                               |


## Context

SunnyPacket's code repository supports the passive analysis component of a study into solar inverter and DER communications. It assists in identifying:

- Local and remote communication flows
- Protocol and port usage
- Repeated packet structures
- Behavioural similarity between captures
- Entropy and variability in network traffic
- Potential indicators of plaintext, structured, or encrypted communication
- Analysing and scoring data , port exposure and manufacturer vulnerability


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
