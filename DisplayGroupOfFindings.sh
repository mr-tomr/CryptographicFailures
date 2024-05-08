#!/bin/bash

# Created by Tom R.
# Created 20240508
# Display contents of each file in directory that has a WC > 0.
# Used when scanning a large number of ports on one host.


# OneLiner - for file in *; do if [[ $(wc -l < "$file") -gt 0 ]]; then echo "File: $file"; cat "$file"; echo; fi; done

#!/bin/bash
 
# Loop through all files in the current directory
for file in *; do
    # Check if wc output for the file is greater than 0
    if [[ $(wc -l < "$file") -gt 0 ]]; then
        # Echo the filename
        echo "File: $file"
        # Display the content of the file
        cat "$file"
        echo  # Add an empty line for separation
    fi
done
