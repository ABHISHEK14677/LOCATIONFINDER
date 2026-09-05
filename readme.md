# Location Finder

A command-line utility for looking up the geographic information associated with IP addresses. It supports interactive use, one or more IP addresses supplied on the command line, IP lists stored in a file, domain names, and an optional local MaxMind database lookup for comparison.

## Requirements

- Python 3
- The Python dependencies required by `iploc.py`

Install the project dependencies, if provided, before running the script:

```bash
python3 -m pip install -r requirements.txt
```

## Usage

Run the script without arguments to use interactive mode:

```bash
python3 iploc.py
```

Look up a single IP address:

```bash
python3 iploc.py 8.8.8.8
```

Look up multiple IP addresses:

```bash
python3 iploc.py 8.8.8.8 1.1.1.1 9.9.9.9
```

Read IP addresses from a file:

```bash
python3 iploc.py -f ips.txt
```

Look up your public IP address or a domain name:

```bash
python3 iploc.py myip
python3 iploc.py example.com
```

Use a local MaxMind GeoLite2 City database to cross-check a result:

```bash
python3 iploc.py 8.8.8.8 -m /path/GeoLite2-City.mmdb
```

## Input File Format

Provide one IP address per line in `ips.txt`. Blank lines can be omitted.

```text
8.8.8.8
1.1.1.1
9.9.9.9
```

## Notes

- IP geolocation is approximate and should not be treated as a precise physical location.
- A MaxMind database is optional and must be obtained separately. Pass its local path with `-m`.
- Results may vary depending on the data source and the IP address being queried.

## Source

The lookup script is [`iploc.py`](https://github.com/ABHISHEK14677/LOCATIONFINDER/blob/master/iploc.py).
