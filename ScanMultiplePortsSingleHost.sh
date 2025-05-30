#!/bin/bash

# Scan multple ports on single host, for vulnerable ciphers.
# Output Results to individual files for each port.
# Created 20240508
# Created by Tom R.

# Usage: ScanMultiplePortsSingleHost.sh <ip_address> <ports_file>
# Example: ScanMultiplePortsSingleHost.sh 192.168.1.1 ports.txt
# Use https://github.com/mr-tomr/CryptographicFailures/blob/main/findSSL.py to create the port list, if there are a large number of ports.

# Check if both arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <ip_address> <ports_file>"
    exit 1
fi

# Get the IP address and port file from the command line arguments
ip_address=$1
ports_file=$2

# Check if the ports file exists
if [ ! -f "$ports_file" ]; then
    echo "Ports file not found: $ports_file"
    exit 1
fi

# Download cipher information only once per host to avoid redundancy and errors
curl -s --location 'https://ciphersuite.info/api/cs/security/insecure' \
--header 'Accept: application/json' > insecure.json
curl -s --location 'https://ciphersuite.info/api/cs/security/weak' \
--header 'Accept: application/json' > weak.json
curl -s --location 'https://ciphersuite.info/api/cs/security/secure' \
--header 'Accept: application/json' > secure.json
curl -s --location 'https://ciphersuite.info/api/cs/security/recommended' \
--header 'Accept: application/json' > recommended.json

# Loop through each port in the ports file
while IFS= read -r port; do
    # Validate if the port number is an integer
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        echo "Invalid port number: $port"
        continue
    fi

    # Create a filename incorporating the IP address and port number
    file_name="${ip_address}_${port}.txt"

    # Run nmap with the provided IP address and port number
    nmap -Pn --script ssl-cert,ssl-enum-ciphers -p $port $ip_address -oN "${ip_address}_${port}.nmap"

    # Output file where the results will be stored
    output_file="prereport_${port}.txt"
    echo "" > $output_file

    # Extract ciphers from nmap_output.txt between "ciphers:" and "compressors"
    ciphers=$(awk '/ciphers:/,/compressors/' "${ip_address}_${port}.nmap" | sed -n '2,$ p' | sed '$ d')

    # Check each discovered cipher against the lists
    for cipher in $ciphers; do
        if grep -q "\"$cipher\"" insecure.json; then
            echo "$cipher: insecure" >> $output_file
        fi
        if grep -q "\"$cipher\"" weak.json; then
            echo "$cipher: weak" >> $output_file
        fi
        if grep -q "\"$cipher\"" secure.json; then
            echo "$cipher: secure" >> $output_file
        fi
        if grep -q "\"$cipher\"" recommended.json; then
            echo "$cipher: recommended" >> $output_file
        fi
    done

    # Create final report and clean up
    sed -n '/^TLS_/p' $output_file | awk '{print $NF,$0}' | sort | awk '{$1=""; print substr($0, 2)}' > $file_name
    rm $output_file
    rm "${ip_address}_${port}.nmap"
    cat $file_name
done < "$ports_file"

# Cleanup JSON files after all ports are processed
rm *.json
