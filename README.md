# Spyderisk Risk Reporting Tool

This is a Python prototype by @scp93ch to figure out the right algorithm for a
risk report, as discussed in [system-modeller Issue
133](https://github.com/Spyderisk/system-modeller/issues/133). Eventually
someone will take this algorithm and implement it in system-modeller Java code.

The tool is implemented in Python and can be directly executed directly from
the command line, provided the required libraries (described in
requirements.txt) are installed.

Alternatively, you can run the code using the Makefile utility, which
automatically manages the python virtual environment and installs the necessary
dependencies.


## Input Requirements

The reporting tool requires the following inputs:

- system model 
   - local file, an exported system model in `.nq`, or `.nq.gz` format
   - remote URL, a system model web key URL (no need to export or download)
- Domain model CSV folder, it can be downlowed from [...] and unzipped locally before running the tool


### Help page

```
usage: risk-report.py [-h] -i NQ_filename|Model_URL -o output_csv_filename -d
                      CSV_directory [-m URI_fragment [URI_fragment ...]] [-s]
                      [--hide-initial-causes] [--version]

Generate risk reports for Spyderisk system models

options:
  -h, --help            show this help message and exit
  -i NQ_filename|Model_URL, --input NQ_filename|Model_URL
                        Filename of the validated system model NQ file
                        (compressed or not) or the Spyderisk webkey model URL
  -o output_csv_filename, --output output_csv_filename
                        Output CSV filename
  -d CSV_directory, --domain CSV_directory
                        Directory containing the domain model CSV files
  -m URI_fragment [URI_fragment ...], --misbehaviour URI_fragment [URI_fragment ...]
                        Target misbehaviour IDs, e.g. 'MS-
                        LossOfControl-f8b49f60'. If not specified then the
                        high impact and high risk ones will be analysed.
  -s, --simple-root-causes
                        Keep the root causes simple (no top-level OR). Using
                        this means more repetition.
  --hide-initial-causes
                        Don't output the initial causes
  --version             show program's version number and exit
```

e.g. risk-report.py -i SteelMill.nq.gz -o steel.pdf -d ../domain-network/csv/ -m MS-LossOfControl-f8b49f60


## Examples running reporting through Makefile

Show help info:


```
make report ARGS="-h"
```

Use a local system model NQ file:
```
make report ARGS="-i 'example b132-e5cfa54.nq.gz' -o test2.csv -d domain-network-132-e5cfa54/csv"
```

Use the URL of system model directly:
```
make report ARGS="-i 'https://nemecys2.it-innovation.soton.ac.uk/system-modeller/models/2ag...' -o test2.csv -d domain-network-132-e5cfa54/csv"
```



