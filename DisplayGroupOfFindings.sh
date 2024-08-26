#!/bin/bash

# Created by Tom R.
# Created 20240508
# Display contents of each file in directory that has a WC > 0.
# Used when scanning a large number of ports on one host.


# OneLiner - for file in *.txt; do if [[ $(wc -l < "$file") -gt 0 ]]; then echo "File: $file"; cat "$file"; echo; fi; done
# Grep out secure - for file in 11 *.txt; do [ -s "$file" ] && echo "File: $file" && grep -v "secure" "$file" && echo; done > findingslist.txt


# Make Consumable in Word
# Pipe to file named findings or anything you like.
# Add tabs to the lines with ciphers
sed '/^TLS/s/^/\t/' findingsList.txt > findingstabbedtxt

# Put in Word and use Word's regex to highlight the lines with a single IP address.
# 1.1.1.21_([0-9]{1,5})
# Ensure "Use wildcards" is selected.
# Use Replace to chnage the selection to the appropriate Style.
# Note, select "Replace with:" box then select the new Style under "Replace Format"

# Named catresults.txt in this example

#!/bin/bash
 
# Loop through all files in the current directory
for file in *.txt; do
    # Check if wc output for the file is greater than 0
    if [[ $(wc -l < "$file") -gt 0 ]]; then
        # Echo the filename
        echo "File: $file"
        # Display the content of the file
        cat "$file"
        echo  # Add an empty line for separation
    fi
done


# This will need to be filtered to create Instances in a report
# output results then grab the host names with IPs
./catresults.sh | grep Host | awk '{print $4}' | sort -t '_' -k 2n | sed 's/\.txt$//'

# Filter results for a list of ports that have ssl

./catresults.sh | grep Host | awk '{print $4}' | sort -t '_' -k 2n | sed 's/\.txt$//' | awk -F_ '{print $2}'

