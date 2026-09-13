# LOCATIONFINDER

A Python-based command-line tool for finding approximate geographic information associated with IP addresses and domain names.

LOCATIONFINDER supports interactive lookups, single or multiple IP addresses, IP lists from files, domain names, public IP detection, and optional local MaxMind GeoLite2 database comparison.

## Features

* Look up a single IP address
* Look up multiple IP addresses
* Resolve and look up domain names
* Detect and look up your public IP address
* Read multiple IP addresses from a file
* Interactive command-line mode
* Optional MaxMind GeoLite2 City database support
* Simple and lightweight CLI interface
* Useful for networking, cybersecurity labs, and reconnaissance
* Results can provide approximate geographic information such as country, region, city, ISP/organization, and coordinates depending on the data source

## Requirements

* Python 3
* Internet connection for online IP geolocation lookups
* Python dependencies used by `iploc.py`

## Installation

Clone the repository:

```bash
git clone https://github.com/ABHISHEK14677/LOCATIONFINDER.git
```

Enter the project directory:

```bash
cd LOCATIONFINDER
```

Install the required dependencies:

```bash
python3 -m pip install -r requirements.txt
```

If the repository does not contain a `requirements.txt` file, install the dependencies required by `iploc.py` manually.

## Usage

### Interactive Mode

Run the tool without arguments:

```bash
python3 iploc.py
```

The program will start an interactive lookup process.

### Single IP Address

```bash
python3 iploc.py 8.8.8.8
```

### Multiple IP Addresses

```bash
python3 iploc.py 8.8.8.8 1.1.1.1 9.9.9.9
```

### Lookup From a File

Create an IP list:

```bash
nano ips.txt
```

Example:

```text
8.8.8.8
1.1.1.1
9.9.9.9
```

Run:

```bash
python3 iploc.py -f ips.txt
```

### Public IP Lookup

```bash
python3 iploc.py myip
```

### Domain Lookup

You can also provide a domain name:

```bash
python3 iploc.py example.com
```

### MaxMind GeoLite2 Lookup

LOCATIONFINDER can optionally use a local MaxMind GeoLite2 City database for comparison.

Example:

```bash
python3 iploc.py 8.8.8.8 -m /path/to/GeoLite2-City.mmdb
```

The GeoLite2 database must be obtained separately from MaxMind.

## Example

```text
$ python3 iploc.py 8.8.8.8

IP Address : 8.8.8.8
Country    : United States
Region     : California
City       : Mountain View
```

*Output fields may vary depending on the geolocation provider and available data.*

## Input File Format

The input file should contain one IP address per line:

```text
8.8.8.8
1.1.1.1
9.9.9.9
```

Blank lines can be omitted.

## Project Structure

```text
LOCATIONFINDER/
│
├── .idea/
├── iploc.py
├── readme.md
└── requirements.txt
```

## How It Works

The tool accepts an IP address, domain name, or IP list and queries an IP geolocation data source to obtain available geographic information.

For additional verification, an optional local MaxMind GeoLite2 City database can be supplied.

```text
IP / Domain
     │
     ▼
LOCATIONFINDER
     │
     ├── Online IP Geolocation
     │
     └── Optional MaxMind Database
     │
     ▼
Approximate Location Information
```

## Cybersecurity Use Cases

LOCATIONFINDER can be useful for legitimate cybersecurity and networking activities such as:

* Security research
* Network reconnaissance
* IP investigation
* Threat-intelligence learning
* Incident-response analysis
* Network troubleshooting
* Cybersecurity laboratory exercises
* Understanding IP geolocation

## Important Note

IP geolocation is **approximate**.

An IP address generally cannot be used to determine someone's exact physical location. Results can vary depending on the IP address, ISP, VPN/proxy usage, mobile networks, and the geolocation database being used.

Do not use this tool to harass, stalk, target, or invade another person's privacy.

Use LOCATIONFINDER only on IP addresses and systems you are authorized to investigate.

## Limitations

* IP geolocation is not an exact GPS location.
* VPNs and proxies can affect results.
* Mobile and carrier networks may return inaccurate locations.
* Different geolocation databases can produce different results.
* MaxMind GeoLite2 must be obtained separately.
* Internet connectivity may be required for online lookups.

## Author

**ABHISHEK M**

GitHub:
https://github.com/ABHISHEK14677

Repository:
https://github.com/ABHISHEK14677/LOCATIONFINDER

## License

This project is intended for educational, research, networking, and authorized cybersecurity purposes.

Use responsibly and comply with all applicable laws and regulations.
