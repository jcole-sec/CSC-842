# Module 02 - PCAP Traffic Analyzer

## What?

pcap_analyzer.py is a script that will recurse through a provided directory to identify pcaps, extract unique public IPs, and provide security intelligence via a user-friendly graph output.

## Why?

This tool is meant to provide intelligence in available network packet data. The primary objectives are:
- To aid in external network traffic characterization IP enrichment
- To identify the presence of malicious connections within network traffic
- To enumerate specific malware attributes associated with malicious connections

## How?

OS walk to retrieve a list of pcaps
Scapy's rdpcap
Create an IP list from the connections
Extract unique public IP addresses
Use RIR data to provide IP enrichment data. The script leverages the RIPE API, which is capable of retrieving other RIR data (ARIN, LACNIC, etc.)
Use ThreatFox data to identify and characterize malicious IPs
Return data to user via a color-formated graph

Data returned includes:
- Public IP Address
- Network Range of associated IP (RIPE data)
- Network name (RIPE data)
- Country of IP registration (RIPE data)
- A malware score based on Threatfox's confidence level (ref: https://threatfox.abuse.ch/api/)
- Threatfox's malware type classification (e.g., `botnet_cc`, `payload_delivery`, ...)
- Threatfox's malware alias or common name (e.g., `Bokbot`, `CobaltStrike`, ...)

## Future Improvements

- [ ] Include support for live data capture via Scapy (real-time monitoring). 
- [ ] Additional IP data enrichments
- [ ] Add counters and directionality (source or destination)

## Install

```
pip3 install -r requirements.txt
```

## Usage


```
usage: i
```

## Demonstration

Sample pcaps from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/2023/) are available within the `samples/` directory of this repository.

- Video: 