## Contents
For each inverter, the .txt file contains the output logs of NMAP TCP - full port, NMAP UDP - full port and the outputs of the LLM Scanner (https://github.com/damianStrojek/LLM-Network-Scanner).
Note that XXX.XXX.XXX.XXX is the IP address of the target device.

The NMAP UDP command used is:

```text
sudo nmap -sU -p- XXX.XXX.XXX.XXX
```
The NMAP TCP command used is:
```text
sudo nmap -p- -sV XXX.XXX.XXX.XXX
```

