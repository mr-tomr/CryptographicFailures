#!/bin/bash

# Report upon ports which have ciphers vulnerable to SWEET32.
# For use on files in a directory that are created via DisplayGroupOfFindings.sh
# Searches for 64 bit block ciphers in each file and creates list of files which have at least one cipher vulnerable.

output_file="sweet32_vulnerable_ports.txt"
> "$output_file"

# Regex pattern for vulnerable ciphers (64-bit block ciphers)
pattern='3DES_EDE_CBC|DES_CBC_SHA'

for file in *.txt; do
    if grep -qE "$pattern" "$file"; then
        # Strip the .txt extension before saving
        echo "${file%.txt}" >> "$output_file"
    fi
done

echo "[+] Scan complete. Vulnerable files saved to: $output_file"
