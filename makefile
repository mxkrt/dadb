SHELL := /bin/bash

.PHONY: help
help:
	@echo
	@echo "makefile targets"
	@echo "----------------"
	@echo "  make venv      - create new virtualenv in ~/.virtualenvs/dadb"
	@echo "  make install   - install dadb in currently activated virtualenv"
	@echo "  make clean     - cleanup temporary files"
	@echo "  make uninstall - uninstall dadb from currently activated virtualenv"
	@echo "  make purge     - remove ~/.virtualenvs/dadb"
	@echo ""

.PHONY: clean
clean:
	rm -rf dadb/__pycache__
	rm -rf dadb/test/__pycache__
	rm -rf dadb/models/__pycache__

.PHONY: venv
venv:
	@echo "Creating new virtualenv ~/.virtualenvs/dadb"
	@python3 -m venv ~/.virtualenvs/dadb
	@echo
	@echo "Activate dadb virtualenv as follows:"
	@echo
	@echo ". ~/.virtualenvs/dadb/bin/activate"
	@echo

.PHONY: install
install:
	@echo "Installing dadb in currently activated virtualenv"
	pip3 install .

.PHONY: uninstall
uninstall:
	@echo "Removing dadb from currently activated virtualenv"
	pip3 uninstall dadb

.PHONY: purge
purge:
	@echo "removing virtualenv ~/.virtualenvs/dadb"
	rm -rf ~/.virtualenvs/dadb

.PHONY: test
test:
	pytest-3 --cov=dadb
