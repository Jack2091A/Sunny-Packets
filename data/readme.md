# Data 

## Whats included

Each inverter has undergone the same set of four tests. The rationale is to capture the behaviour of the devices during normal operation. Each run
is approximately 20 minutes apart from the previous run. Filters have been provided to isolate the behaviour of the device in particular.
- 60 minute capture from start to run
- 60 minute capture during runtime
- 90 minute capture during runtime
- 90 minute capture from run to shutdown
- Active Scan logs - Active.md

### Sungrow SH5k-20
To isolate the inverter's communications, please use the following filter:
```text
eth.addr==
```

### Sungrow SG5KTL-MT
To isolate the inverter's communications, please use the following filter:
```text
eth.addr==
```

### Goodwe 55000DST218W0590
To isolate the inverter's communications, please use the following filter:
```text
eth.addr==34:ea:e7:a6:ab:12
```

### Fronius Gen 24 5.0
To isolate the inverter's communications, please use the following filter:
```text
eth.addr==00:03:ac:37:65:4c
```

