#!/bin/bash

# Scan site for vulnerable ciphers.
# Created 20230921
# Created by Tom R.
# Example Command - scanandreport.sh example.com

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Running NMAP Scan and Creating Output File #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Check if the site name argument is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <site_name>"
    exit 1
fi

# Get the site name from the command line argument
site_name=$1

# Run nmap with the provided site name
nmap --script ssl-cert,ssl-enum-ciphers -p 443 $site_name -oN $site_name.nmap

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
done

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Create final report and clean up #
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

sed '/^-/d' prereport.txt > $site_name.txt
rm prereport.txt
rm *.json
cat $site_name.txt
