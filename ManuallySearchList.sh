#!/bin/bash

# Created 20230921
# Manually search files for ciphers in all results files

# Usage - ./script_name.sh your_search_term
# Usage example "./ManuallySearchList.sh TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"

# Check if the argument is supplied
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 search_term"
  exit 1
fi

# Assign the search term from the first argument
search_term="$1"

# Loop through each .json file in the directory
for file in *.json; do
  # Perform a quiet grep, only interested in the return value
  if grep -q "$search_term" "$file"; then
    echo "Yes, found in $file"
  else
    echo "No, not found in $file"
  fi
done
