#!/bin/bash

# Scan site for vulnerable ciphers.
# Created 20230921
# Created by Tom R.

# Usage scanandreport.sh <site_name> [port]
# Example - scanandreport.sh example.com
# Example - scanandreport.sh example.com 8443
# The output can be sorted by severity, by adjusting which SED command is commented.

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Running NMAP Scan and Creating Output File #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Check if at least the site name argument is provided
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <site_name> [port]"
    exit 1
fi

# Get the site name from the command line argument
site_name=$1

# Get the port number from the command line argument, default to 443
port_number=${2:-443}

# Create a filename incorporating the site_name and port_number
file_name="${site_name}_${port_number}"

# Run nmap with the provided site name and port number
nmap -Pn --script ssl-cert,ssl-enum-ciphers -p $port_number $site_name -oN $site_name.nmap


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Download updated certificate status from ciphersuite.com #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Fetch insecure ciphers
curl -s --location 'https://ciphersuite.info/api/cs/security/insecure' \
--header 'Accept: application/json' > insecure.json

# Fetch weak ciphers
curl -s --location 'https://ciphersuite.info/api/cs/security/weak' \
--header 'Accept: application/json' > weak.json

# Fetch secure ciphers
curl -s --location 'https://ciphersuite.info/api/cs/security/secure' \
--header 'Accept: application/json' > secure.json

# Fetch recommended ciphers
curl -s --location 'https://ciphersuite.info/api/cs/security/recommended' \
--header 'Accept: application/json' > recommended.json


# Output file where the results will be stored
output_file="prereport.txt"

# Initialize the output file
echo "" > $output_file

# Extract ciphers from nmap_output.txt between "ciphers:" and "compressors"
ciphers=$(awk '/ciphers:/,/compressors/' $site_name.nmap | sed -n '2,$ p' | sed '$ d')

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Check each discovered cipher against the lists #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

for cipher in $ciphers; do
    # Search the cipher in insecure.json
    if grep -q "\"$cipher\"" insecure.json; then
        echo "$cipher: insecure" >> $output_file
    fi
    
    # Search the cipher in weak.json
    if grep -q "\"$cipher\"" weak.json; then
        echo "$cipher: weak" >> $output_file
    fi

    # Search the cipher in secure.json
    if grep -q "\"$cipher\"" secure.json; then
        echo "$cipher: secure" >> $output_file
    fi

    # Search the cipher in weak.json
    if grep -q "\"$cipher\"" recommended.json; then
        echo "$cipher: recommended" >> $output_file
    fi


done

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Create final report and clean up #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# This SED does not sort the output by severity. Use only one per file name.
#sed -n '/^TLS_/p' prereport.txt > $site_name.txt

# This SED sorts the output by severity. Use only one per file name.
sed -n '/^TLS_/p' prereport.txt | awk '{print $NF,$0}' | sort | awk '{$1=""; print substr($0, 2)}' > $file_name.txt

rm prereport.txt
rm *.json
cat $file_name.txt
