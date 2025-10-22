# virtual env vars
VENV_DIR = env
PYTHON = $(VENV_DIR)/bin/python
PIP = $(VENV_DIR)/bin/pip
PACKAGE_NAME = risk-report
VERSION = 0.1.0

.PHONY: init clean install help

.SILENT: clean

# create virtual env and install dependencies
init: $(VENV_DIR)/bin/activate
	@echo "Virtual environment and dependencies set up."

$(VENV_DIR)/bin/activate: requirements.txt
	@echo "Creating virtual environment in $(VENV_DIR)..."
	@python3 -m venv $(VENV_DIR)
	@echo "Installing dependencies from requirements.txt..."
	$(PIP) install -r requirements.txt

# clean up
clean:
	find . -name "*.pyc" -exec rm -f {} +
	find . -name "__pycache__" -exec rm -rf {} +
	find . -type d \( -name "*.egg-info" -o -name "build" -o -name "dist" -o -name "__pycache__" \) -exec rm -rf {} +
	rm -rf $(VENV_DIR)
	rm -rf $(DIST_DIR) build *.egg-info

# run report
report: $(VENV_DIR)/bin/activate
	@echo "Running Risk Reporting..."
	env/bin/python risk-report.py $(ARGS)

# show help
help:
	@echo "Available targets:"
	@echo "  init       - Create virtual environment and install dependencies"
	@echo "  clean      - Clean up unnecessary files"
	@echo "  report     - Execute risk-report e.g. make report ARGS=\"-i system_model.nq.gz -o risk-report.csv -d domain-network/csv\""



