# Cryptographic Failures

`CryptographicFailures_Automated.py` consolidates the repository's TLS cipher scanning, classification, SWEET32 checking, parsing, and reporting workflow into one tool.

## Features

- Single host + single port
- Single host + ports file
- Hosts file + single port
- Hosts file + ports file
- Explicit `host:port` pairs
- Import an existing standard-format Nmap `.nmap` scan and detect SSL/TLS `host:port` targets
- Nmap `ssl-cert` and `ssl-enum-ciphers` scanning
- Current cipher classification lookup
- Exact `weak` / `insecure` report filtering
- Automatic deduplication
- Separate SWEET32 output
- Raw Nmap evidence retention
- Report-ready TXT, CSV, and Word DOCX
- Word `host:port` instance lines created as actual **Heading 4**

## Requirements

```bash
sudo apt update
sudo apt install -y nmap python3-pip
python3 -m pip install -r requirements.txt
```

## Run

```bash
chmod +x CryptographicFailures_Automated.py
./CryptographicFailures_Automated.py
```

Menu:

```text
1) Single host + single port
2) Single host + ports file
3) Hosts file + single port
4) Hosts file + ports file
5) Host:port pairs file
6) Import existing Nmap scan and detect SSL/TLS targets
0) Exit
```

## Input Files

Hosts:

```text
10.10.10.10
10.10.10.11
server.example.com
```

Ports:

```text
443
8443
9443
```

Pairs:

```text
10.10.10.10:443
10.10.10.11:8443
server.example.com:9443
```

IPv6 pairs use bracket notation:

```text
[2001:db8::10]:443
```

Blank lines and lines beginning with `#` are ignored.

## Import Existing Nmap Results

Mode 6 replaces the old `findSSL.py` workflow.

A typical discovery scan is:

```bash
sudo nmap -v -p- --open --script ssl-enum-ciphers -iL serverips.txt -oA servertestname
```

Select menu option 6 and provide:

```text
servertestname.nmap
```

The parser reads each `Nmap scan report for ...` section, identifies open TCP ports where `ssl-enum-ciphers` produced output, preserves the correct host-to-port relationship in multi-host scans, and feeds those targets into the normal scan/classification/reporting workflow.

Non-interactive:

```bash
./CryptographicFailures_Automated.py   --mode 6   --nmap-file servertestname.nmap
```

## Other Non-interactive Examples

```bash
./CryptographicFailures_Automated.py --mode 1 --host 10.10.10.10 --port 443

./CryptographicFailures_Automated.py   --mode 2 --host 10.10.10.10 --ports-file ports.txt

./CryptographicFailures_Automated.py   --mode 3 --hosts-file hosts.txt --port 443

./CryptographicFailures_Automated.py   --mode 4 --hosts-file hosts.txt --ports-file ports.txt

./CryptographicFailures_Automated.py   --mode 5 --pairs-file targets.txt
```

## Output

Each run creates a timestamped directory:

```text
cryptographic_failures_YYYYMMDD_HHMMSS/
├── findings_tabbed.txt
├── findings.csv
├── findings.docx
├── sweet32_tabbed.txt
├── sweet32.csv
├── sweet32.docx
├── summary.txt
├── raw_nmap/
├── classified_targets/
└── cipher_api_cache/
```

### Report-ready TXT

```text
10.10.10.10:443
    TLS_RSA_WITH_3DES_EDE_CBC_SHA: insecure
    TLS_RSA_WITH_AES_128_CBC_SHA: weak
```

The final output has no `File:` prefix, no trailing `.txt`, and uses `:` rather than `_` between host and port.

### CSV

```csv
IP/Host,Port,Cipher Finding
10.10.10.10,443,TLS_RSA_WITH_3DES_EDE_CBC_SHA: insecure
10.10.10.10,443,TLS_RSA_WITH_AES_128_CBC_SHA: weak
```

IP/host and port are separate columns. Classification remains in the same cell as the cipher.

### Word

`findings.docx` and `sweet32.docx` use an actual Word **Heading 4** for every affected `host:port` instance. Cipher findings are indented beneath that heading.

## Filtering

Only exact reportable classifications are included:

```text
insecure      report
weak          report
secure        exclude
recommended   exclude
```

This avoids the old substring-filtering problem where matching `secure` could also match `insecure`.

## Self-Test

```bash
./CryptographicFailures_Automated.py --self-test
```

The self-test validates Nmap import parsing, multi-host host/port association, filtering, deduplication, TXT formatting, CSV structure, and DOCX generation.

## Replaces the Previous Repository Files

This version incorporates or supersedes the functions of:

- `ScanAndReport.sh`
- `ScanMultiplePortsSingleHost.sh`
- `DisplayGroupOfFindings.sh`
- `Export_Non_Secure_Ciphers_to_CSV.sh`
- `ListKnownWeakandInsecure.sh`
- `ManuallySearchList.sh`
- `Sweet32Check.sh`
- `findSSL.py`

The repository can therefore be reduced to the consolidated Python script and this README for the normal workflow.

## Help

```bash
./CryptographicFailures_Automated.py --help
```
