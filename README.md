# Spyderisk Risk Reporting Tool

This is a standalone tool, authored initially by @scp93ch, to figure out the correct algorithm for a
risk report, as discussed in [system-modeller Issue
133](https://github.com/Spyderisk/system-modeller/issues/133). In the longer term, this will either be 
integrated into Spyderisk as-is, or will be re-implemented in Java to run in the Spyderisk service.

The tool is implemented in Python and can be executed directly from
the command line, provided that the required libraries (listed in
requirements.txt) are installed.

For convenience, we provice a Makefile which automatically manages a python virtual environment, 
installs the necessary dependencies, then generates the risk report.

Note that the instructions to use 'make' below assume a Linux environment. The tool will also work in Windows, 
using exactly the same commands, which can be achieved by using WSL. 
For further info on using WSL, see [README_WIN.md](https://github.com/Spyderisk/risk-report/blob/main/README_WIN.md).

## Input Requirements

The reporting tool requires the following inputs:

- system model, either:
   - local file, an exported system model in `.nq`, or `.nq.gz` format
   - remote URI, a system model web key URI (exporting from System Modeller is done automatically)
- domain model CSV folder, which can be either:
   - obtained directly from the [Git repository](https://github.com/Spyderisk/domain-network.git)
   - extracted from a domain model zip file, if available

N.B: The model webkey can be found in the Spyderisk Dashboard by clicking the
model's *Share Model* icon and copying the *Edit Access* or *View-only Access* URI. 
Technically, the trailing `/edit` or `/read` should be removed, however the report 
tool will remove these automatically, if present.

### Help page

```
usage: risk-report.py [-h] -i NQ_filename|Model_URI -o output_csv_filename -iso ISO_standard -d CSV_directory [-m URI_fragment [URI_fragment ...]] [-s]
                      [--hide-initial-causes] [--version]

Generate risk reports for Spyderisk system models

options:
  -h, --help            show this help message and exit
  -i NQ_filename|Model_URI, --input NQ_filename|Model_URI
                        Filename of the validated system model NQ file (compressed or not) or the Spyderisk model webkey URI
  -o output_csv_filename, --output output_csv_filename
                        Output CSV filename
  -iso ISO_standard, --iso ISO_standard
                        Select ISO standard (27001 or 14971)
  -d CSV_directory, --domain CSV_directory
                        Directory containing the domain model CSV files
  -m URI_fragment [URI_fragment ...], --misbehaviour URI_fragment [URI_fragment ...]
                        Target misbehaviour IDs, e.g. 'MS-LossOfControl-f8b49f60'. If not specified then the high impact and high risk ones will be analysed.
  -s, --simple-root-causes
                        Keep the root causes simple (no top-level OR). Using this means more repetition.
  --hide-initial-causes
                        Don't output the initial causes
  --version             show program's version number and exit

e.g. risk-report.py -i SteelMill.nq.gz -o steel.pdf -iso 27001 -d ../domain-network/csv/ -m MS-LossOfControl-f8b49f60


## Examples running reporting through Makefile

Show help info:

```
make report ARGS="-h"
```

Show Makefile targets:

```
make help
```

Use a local system model NQ as the input file:

```
make report ARGS="-i 'example b132-e5cfa54.nq.gz' -o test2.csv -iso 14971 -d domain-network-132-e5cfa54/csv"
```

Use the URI of system model directly as the input:

```
make report ARGS="-i 'https://nemecys2.it-innovation.soton.ac.uk/system-modeller/models/2ag...' -o test2.csv -iso 14971 -d domain-network-132-e5cfa54/csv"
```



