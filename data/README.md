# Data 

## Passive Scans

Each inverter has undergone the same set of four tests with a total of 16 sets for the four studied inverters. 
- 60 minute capture from start to run
- 60 minute capture during runtime
- 90 minute capture during runtime
- 90 minute capture from run to shutdown (Inverter shuts down 5 minutes before capture ends).

The rationale is to capture the behaviour of the devices during normal operation. Each run
is approximately 20 minutes apart from the previous run. Filters have been provided to isolate the behaviour of the device in particular.

The captures are starting with their manufacturer. In the case of Sungrow, they are distinguished by their model names.

#### Sungrow SH5k-20
To isolate the inverter's communications, please use the following filter:
```text
eth.addr==60:c5:a8:71:86:0c
```

#### Sungrow SG5KTL-MT
To isolate the inverter's communications, please use the following filter:
```text
eth.addr==60:c5:a8:71:2f:d4
```

#### Goodwe 55000DST218W0590 (DNS-5 series)
To isolate the inverter's communications, please use the following filter:
```text
eth.addr==34:ea:e7:a6:ab:12
```

#### Fronius Gen 24 5.0
To isolate the inverter's communications, please use the following filter:
```text
eth.addr==00:03:ac:37:65:4c
```
## Active Scans

Each inverter was scanned with 4 different tools and they have been named and organised as such into .txt files which capture the various outputs of the scans.

#### NMAP
Devices were initially all scanned with the open source NMAP tool. A full port scan was completed using the following commands:

The NMAP UDP command used is:

```text
sudo nmap -sU -p- XXX.XXX.XXX.XXX
```
The NMAP TCP command used is:
```text
sudo nmap -p- -sV XXX.XXX.XXX.XXX
```

#### LLM Scanner
An LLM tool was then used to enhance the efficacy of the scans by piping the scan outputs into an OpenAI API. The tool used, along with documentation is found here: https://github.com/damianStrojek/LLM-Network-Scanner.

#### Angry IP Scanner
A separate windows based Network Scanned called Angry IP Scanner was separately used to pry for additional insights. For additional details, see: https://angryip.org/.

#### LANSweeper
A commercial, paid network analysis tool known as LANSweeper was used as well. LANSweeper is not an open-source tool and is used in industry, hence its use provides additional
practical value to the methodology in use. For additional details, see: https://www.lansweeper.com/.



