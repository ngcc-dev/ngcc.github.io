# Independent builder for https://ngcc.dev/nist/.
# Inputs are the public, reproducible registry maintained by ngcc-harness/nist.
SOURCE ?= ../../ngcc-harness/nist
OUTPUT ?= ../docs/nist
PORT ?= 8000
HARNESS_REV ?=

.PHONY: build check check-built serve clean
build:
	python3 build.py --source "$(SOURCE)" --output "$(OUTPUT)" --harness-rev "$(HARNESS_REV)"

check: build
	python3 check.py --source "$(SOURCE)" --output "$(OUTPUT)" --harness-rev "$(HARNESS_REV)"

check-built:
	python3 check.py --source "$(SOURCE)" --output "$(OUTPUT)" --harness-rev "$(HARNESS_REV)"

serve: build
	@echo "NIST signature reports: http://localhost:$(PORT)/nist/"
	python3 -m http.server --directory ../docs $(PORT)

clean:
	python3 build.py --output "$(OUTPUT)" --clean
