# ExposureScore.py

## Background
ExposureScore is a simple python tool which utilises regex filtering to scrape the results of NMAP UDP and TCP scans when provided in .txt format. 
It then calculates a percentage score using the following metric with default values:

$$
TCP Score=max\[0, 7.5 - 0.75\times X]
$$
$$
UDP Score=max\[0, 7.5 - 0.75\times Y]
$$

$$where;$$

$$ X\ =\ number\ of\ exposed\ TCP\ ports $$

$$ Y\ =\ number\ of\ exposed\ UDP\ ports $$

7.5 maps to the base-score and 0.75 to the penalty. These values can be configured - see Configurations.

## Features

- Parses standard Nmap normal (`-oN`) output or terminal-copied scan results in .txt file format
- Detects exposed ports with state:
  - `open`
  - `open|filtered` (default)
- Optional strict mode to count only fully open ports
- Calculates independent TCP and UDP exposure scores
- Computes an overall network exposure percentage
- Generates a combined unique-port summary across all scans

## Configurations

| Option | Description |
|---------|-------------|
| `--strict-open` | Count only ports with state `open`. Ignore `open|filtered`. |
| `--base-score` | Starting score before penalties (default: 7.5). |
| `--penalty` | Score reduction per exposed port (default: 0.75). |
| `--summary-only` | Suppress listing of individual exposed ports. |

## Usage

Run the script on two .txt files containing the output of the NMAP scans completed;

```text
python ExposureScore.py tcp_scan.txt udp_scan.txt
```
The script will calculate and print a percentage score directly to the commandline.
