# In some cases Vulnerabiltiy Management teams would like the weak ciphers exported to CSV.

# Run the following one liner to remove any lines where cipher is listed as secure or recommended and create a copy in the csv directory.

mkdir -p csv && for f in 11*.txt; do grep -v 'secure|recommended' "$f" > "csv/$f"; done

# Create a Bash script named csvparse.sh and use it to create a CSV file 
# Where each filename is the IP and port number and in the first column.
# Non secure ciphers are in the second column in the corresponding cell.

#!/bin/bash
#csvparse.sh
output="output.csv"
echo "filename,contents" > "$output"

# Loop through files starting with 11 and ending with .txt
for file in 11*.txt; do
    if [[ -f "$file" ]]; then
        # Read entire file content and escape double quotes
        contents=$(<"$file")
        contents="${contents//\"/\"\"}"  # escape quotes for CSV
        filename="${file%.txt}"         # remove .txt extension

        # Write to CSV with contents quoted
        echo "\"$filename\",\"$contents\"" >> "$output"
    fi
done
