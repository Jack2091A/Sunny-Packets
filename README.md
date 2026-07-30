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
| `src/`           | Stores all datasets used by the project.                          for packet payload analysis.                                                  |
| `VulnerabilityLookupGrading/` | Script, .yaml config file and Documentation. Queries vulnerability databases and calculates vendor vulnerability scores.           |
| `DataSovereignty/`            | Script, Data File (.mmdb) and Documentation. Determ         |
| `SankeyMulti/`                | Script and Documentation. Generates Sankey diagrams showing packet flow between endpoints, protocols and ports.                    |
| `Shannon/`                    | Script and Documentation. Calculates Shannon entropyines communication destinations and assesses data sovereignty.                  |
| `ExposureScore/`              | Script and Documentation. Computes network exposure scores from discovered services and ports.                                     |
| `Similarity/`                 | Script and Documentation. Compares packet structures and identifies repeated communication patterns.                               |


## Context

Sunny Packets supports research into the cybersecurity of commercial solar inverters and Distributed Energy Resources (DERs) by
combining active network reconnaissance, passive traffic analysis and quantitative security assessment methodologies.

The repository provides datasets, analysis tools and supporting documentation that enable researchers to:

- Perform active network reconnaissance using industry-standard scanning tools.
- Analyse passive packet captures collected during inverter operation.
- Visualise communication flows between devices, protocols and services.
- Identify repeated packet structures and behavioural communication patterns.
- Quantify traffic randomness and predictability using Shannon entropy.
- Assess device data sovereignty through IP geolocation.
- Evaluate network exposure from TCP and UDP service discovery.
- Measure historical vendor cybersecurity posture using vulnerability intelligence.
- Produce repeatable and objective cybersecurity metrics for comparison between devices.


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
