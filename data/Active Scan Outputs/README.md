## Contents
For each inverter, the .txt file contains the output logs of NMAP TCP - full port, NMAP UDP - full port and the outputs of the LLM Scanner (https://github.com/damianStrojek/LLM-Network-Scanner).
Note that XXX.XXX.XXX.XXX is the IP address of the target device.

The NMAP UDP command used is:
sudo nmap -sU -p- 192.168.1.173 
```text
nmap -p- -sV 192.168.1.173
```
The NMAP TCP command used is:
```text
sudo nmap -p- -sV XXX.XXX.XXX.XXX
```

