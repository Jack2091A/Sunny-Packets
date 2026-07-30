# SankeyMulti.py

## Background

SankeyMulti is a python script designed to build Sankey diagrams out of pcap files. It is able to take multiple input pcap files and produce 
combined Sankey diagrams in png and pdf format.
The script takes in mac addresses of the target device. As ports can be assigned at random by devices initiating communications,
there is also a merge functionality which improves clarity by merging all such ports into one endpoint on the Sankey diagram.

## Usage

Generate a Sankey diagram from a single packet capture:
```text
python SankeyMulti.py 
  --pcap Capture01.pcap 
  --sankey-png Output.pdf
```
Generate a Sankey diagram from multiple packet captures:
```text
python SankeyMulti.py 
  --pcap Capture01.pcap 
  --pcap Capture02.pcap 
  --sankey-png CombinedOutput.pdf
```
Example using MAC address labelling:
```text
python SankeyMulti.py 
  --pcap Capture01.pcap 
  --mac ac:19:9f:55:03:b4 
  --label "ac:19:9f:55:03:b4 Local Flow" 
  --sankey-png Finalflow.pdf
```
Example using merge functionality:
```text
python SankeyMulti.py
  --pcap Sungrow5k.pcap
  --mac 60:c5:a8:71:2f:d4
  --label "Remote Flow"
  --merge-src-ports 1
  --merge-dst-ports 0
  --sankey-png MergedFlow.pdf
```
