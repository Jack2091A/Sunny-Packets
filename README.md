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
Note that script (/src) folders may contain additional configuration files if required.

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
python Similarity.py capture01.pcap IP_destination IP_source --packet-lengths X Y --context-window Z --show-groups  
 --list
```

Where X and Y are numbers indicative of the specific byte lengths of the packets in question. Z is a numerical flag case to treat packets of identical lengths but separate instances as being separate 
from one another i.e. if there are two packets of length 153 back to back, Z = 2.

## Running DataSovereignty.py

Run the script using the following command line structure:

```text
python dataSovereignty.py CaptureGood.pcap
  --mac MAC_ADDR
  --target-country LOCATION
  --geoip-db GeoLite2-Country.mmdb
  --csv sovereignty_report.csv
```
For example, given an identified mac address and if the inverters are located in Australia, the command line should be:

```text
python DataSovereignty.py CaptureGood.pcap
  --mac 34:EA:E7:A6:AB:12
  --target-country Australia
  --geoip-db GeoLite2-Country.mmdb
  --csv sovereignty_report.csv
```
The script will save the findings into a csv file containing the ip addresses found, their location and the ports used in communication.

## Running VulnerabilityLookupGrading.py
Initiate the run as using the following command line:

```text
python ExposureLookupGrading.py
```
Afterwards, the script will prompt the user to enter the name of the manufacturer in question. The script will then fetch NVD records, generate and populate an .xlsx file. It will then prompt the user to fill in the applicability column and save afterwards.
The weightings for this column can be found and modified in the grading_weights.yaml file.

After this has been completed, press enter and the script will complete its run. Note that the .xlsx file is generated once only (unless it is deleted) and future runs will prompt the user to
change the already generated file.

## Running ExposureScore.py

Run the script on two .txt files containing the output of the NMAP scans completed;

```text
python ExposureScore.py tcp_scan.txt udp_scan.txt
```
The script will calculate and print a percentage score directly to the commandline.


