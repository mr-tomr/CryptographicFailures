#!/bin/bash

# ListKnownWeakandInsecure.sh
# Created 20230921
# Aggregates Weak and Insecure ciphers from the https://ciphersuite.info API
# To do - consider cleaning up extra files when complete, if not needed.

# Fetch insecure ciphers
curl -s --location 'https://ciphersuite.info/api/cs/security/insecure' \
--header 'Accept: application/json' > insecure.json

# Fetch weak ciphers
curl -s --location 'https://ciphersuite.info/api/cs/security/weak' \
--header 'Accept: application/json' > weak.json

# Combine both JSONs into one
echo "{" > all_responses.json
cat insecure.json | sed 's/}$//' >> all_responses.json
echo "," >> all_responses.json
cat weak.json | sed 's/^{//' >> all_responses.json
echo "}" >> all_responses.json

# Extract 'gnutls_name' from the combined JSON using grep and awk
grep -o '"gnutls_name": "[^"]*' all_responses.json | awk -F'"' '{ if ($4) print $4 }' > gnutls_name>

#!/bin/bash

# Fetch insecure ciphers
curl -s --location 'https://ciphersuite.info/api/cs/security/insecure' \
--header 'Accept: application/json' > insecure.json

# Fetch weak ciphers
curl -s --location 'https://ciphersuite.info/api/cs/security/weak' \
--header 'Accept: application/json' > weak.json

# Combine both JSONs into one
echo "{" > all_responses.json
cat insecure.json | sed 's/}$//' >> all_responses.json
echo "," >> all_responses.json
cat weak.json | sed 's/^{//' >> all_responses.json
echo "}" >> all_responses.json

# Extract 'gnutls_name' from the combined JSON using grep and awk
grep -o '"gnutls_name": "[^"]*' all_responses.json | awk -F'"' '{ if ($4) print $4 }' > finallist.txt
