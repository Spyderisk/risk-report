#!/bin/sh

# Loop through all files ending with .nq.gz in the current directory
for FILE in *.nq.gz; do
    # Extract the base name of the file (without the extension)
    BASENAME=$(basename "$FILE" .nq.gz)
    
    # Get the current datetime string
    DATETIME=$(date +"%Y%m%d%H%M%S")
    mkdir -p "/tmp/${DATETIME}"
    
    # Execute the command with the appropriate arguments
    ../risk-report.py -i "$FILE" -o "/tmp/${DATETIME}/${BASENAME}.csv" -d ~/domain-network/csv
done

echo "All files processed successfully. Output is in /tmp/${DATETIME}/"