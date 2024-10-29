#!/bin/sh

# Runs the risk-report.py script on all .nq.gz files in the current directory
# Assumes the correct domain model is at ~/domain-network/csv

DATETIME=$(date +"%Y%m%d%H%M%S")
LOGDIR="/tmp/risk-report-${DATETIME}"
mkdir -p ${LOGDIR}

# Loop through all files ending with .nq.gz in the current directory
for FILE in *.nq.gz; do
    # Extract the base name of the file (without the extension)
    BASENAME=$(basename "$FILE" .nq.gz)
   
    # Execute the command with the appropriate arguments and capture stdout and stderr
    echo "Processing '$FILE'..."
    LOGFILE="${LOGDIR}/${BASENAME}.log"
    ../risk-report.py -i "${FILE}" -o "${LOGDIR}/${BASENAME}.csv" -d ~/domain-network/csv > "${LOGFILE}" 2>&1
    # Check for "Traceback" in the log file and output the relevant lines if found
    if grep -q "Traceback" "${LOGFILE}"; then
        echo "\nError found when processing '${FILE}':"
        grep -A 1000 "Traceback" "${LOGFILE}"
        echo
    fi
done

echo "Output is in ${LOGDIR}/"