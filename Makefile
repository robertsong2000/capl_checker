# Makefile for CAPL Static Syntax Checker

.PHONY: help test check clean install

# Default target
help:
	@echo "CAPL Static Syntax Checker"
	@echo "=========================="
	@echo "Available targets:"
	@echo "  help     - Show this help message"
	@echo "  test     - Run test suite"
	@echo "  check    - Check sample.can file"
	@echo "  clean    - Clean temporary files"
	@echo "  install  - Make capl_checker.py executable"
	@echo ""
	@echo "Usage examples:"
	@echo "  make check                    # Check sample file"
	@echo "  python3 capl_checker.py file.can  # Check specific file"
	@echo "  python3 capl_checker.py --format xml file.can  # XML output"

# Run test suite
test:
	@echo "Running CAPL checker test suite..."
	python3 test_checker.py

# Check sample file
check:
	@echo "Checking sample.can..."
	python3 capl_checker.py sample.can || true

# Check sample file with XML output
check-xml:
	@echo "Checking sample.can (XML format)..."
	python3 capl_checker.py --format xml sample.can

# Check sample file with JSON output
check-json:
	@echo "Checking sample.can (JSON format)..."
	python3 capl_checker.py --format json sample.can

# Clean temporary files
clean:
	@echo "Cleaning temporary files..."
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.tmp" -delete
	find . -name "*.temp" -delete

# Make script executable
install:
	@echo "Making capl_checker.py executable..."
	chmod +x capl_checker.py
	@echo "You can now run: ./capl_checker.py file.can"

# Show version info
version:
	@echo "CAPL Static Syntax Checker v1.0"
	@python3 --version