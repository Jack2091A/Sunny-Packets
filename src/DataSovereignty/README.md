# DataSovereignty.py

## Background
DataSovereignty is a script which takes in packet captures and determines if the destination IP is within the selected country.
It utilises a .mmdb file which is a mapping of all the IPs os IPv4 format. The file is up to date as of the 31st of July 2026, however
it is recommended to continually check for updates. The mmdb file in this directory was sourced from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/.

## Usage
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
