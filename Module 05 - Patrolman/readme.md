# Patrolmen

## What?

Patrolman enumerates running processes and identifies associated data attributes, including execution path and arguments, binary hash, and network connection details. 

Patrolman then attempts to identify malicious indicators by analyzing behavioral abnormalities and checking observable indicators for Cyber Threat Intelligence (CTI) pattern matches.

Patrolmen is an upgrade to the netproc (Windows Networked Process Enumerator) tool that adds in the capability to detect malicious process patterns and network traffic

The name Patrolman is derived from "patrolmen", an anagram of malnetproc (mal + netproc).

## Why?

This tool is primarily intended for and security investigation use cases

Some example use cases include:
- Configure as a detective tool to run and log periodically via a scheduler.
- Run interactively during a Windows DFIR investigation to identify malicious process execution.
- Use during an image build process to identify native baseline behaviors.


## How?

Similar to Netproc, Patrolman leverages primary the socket and psutil libraries to enumerate loaded processes and derive data attributes.

These data attributes include:
- process name
- process id
- process sockets (local and remote IP/Ports, Protocol, and host resolution)
- process network communication type (public, private, or local)
- process path
- process execution parameters (command line)
- process SHA-256 hash
- process user
- parent process name and id

Patrolman uses some of this data to then run 'hunt evil' and threat intelligence lookup functions.

The 'Hunt Evil' function leverages detection logic outline in the SANS DFIR poster available [here](https://www.sans.org/posters/hunt-evil/). Primarily this checks for irregulaties in either the process' path, user, or parent process.

The CTI enrichment function checks to determine if the process is communicating with a public remote IP. If it is, it performs the following actions:
- Executes a RIPE API lookup to append the remote network name and country of registry
- Executes a ThreatFox remote IP lookup to appends a threat confidence level, malware common name, and threat type if a match is present

The CTI enrichment function will then perform a similar ThreatFox lookup for the process hash to retrieve the same data (regardless of socket condition).

Tool output is default set to JSON, but can support TSV and condensed console output as well.

...


## Future Improvements

- [ ] Allow service or daemon mode for continual execution and logging
- [ ] Expand detective logic for process patterns (including common lolbas)
- [ ] Including publishing to Windows event log as a dedicated application (e.g., PowerShell's `New-EventLog -LogName Patrolman ...`)
- [ ] Add detective logic for Linux and macOS abnormal process patterns

## Install


### Install Python Libraries

Install for script only:
```
pip3 install -r requirements.txt
```

Install for executable build:
```
pip3 install -r requirements-build.txt
```


### Executable Build

The executable is compiled using PyInstaller, which can be installed via the pip requirements file above. 

Build command:
```
pyinstaller.exe --onefile --icon=assets/Users-Police-icon.png patrolman.py
```
- _Note: the included icon under assets was retrieved from [icon archive](https://www.iconarchive.com/show/windows-8-icons-by-icons8/Users-Police-icon.html) and is marked restricted for personal use only_


## Usage

Run as administrator (required for additional data, such as user enumeration for privileged processes)


```

```

## Demonstration

- Command with display output:
```
python .\netproc.py -d --no-tsv -p
```
![screenshot](assets/demo-netproc-1.png)

Video:

- Video: https://youtu.be/xxxxxx
