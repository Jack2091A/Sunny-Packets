# ExposureScore.py

## Background
ExposureScore is a simple python tool which utilises regex filtering to scrape the results of NMAP UDP and TCP scans when provided in .txt format. 
It then calculates a percentage score using the following metric:

$$
TCP Score=max\[0, 7.5 - 0.75\times(numberTCPportsExposed)]
$$
$$
UDP Score=max\[(0, 7.5 - 0.75\times(numberUDPportsExposed)]
$$


## Usage

Run the script on two .txt files containing the output of the NMAP scans completed;

```text
python ExposureScore.py tcp_scan.txt udp_scan.txt
```
The script will calculate and print a percentage score directly to the commandline.
