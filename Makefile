.PHONY: install lint format test simulate demo-azure checkov tf-validate package-lambda package-azure-function publish-azure-function clean

PY ?= python3
FUNC_APP ?=

install:
	$(PY) -m pip install -e ".[dev]" checkov

lint:
	ruff check src functions tests
	ruff format --check src functions tests

format:
	ruff format src functions tests
	ruff check --fix src functions tests
	terraform fmt -recursive terraform tests/fixtures

test:
	$(PY) -m pytest

simulate:
	palisade simulate --report docs/attack-simulation-report.md

demo-azure:
	palisade scan azure --snapshot examples/azure-snapshot.json
	palisade remediate azure --snapshot examples/azure-snapshot.json

checkov:
	checkov -d terraform --external-checks-dir policies/checkov --framework terraform --compact

tf-validate:
	cd terraform/aws && terraform init -backend=false -input=false >/dev/null && terraform validate
	cd terraform/azure && terraform init -backend=false -input=false >/dev/null && terraform validate

# Lambda bundle: handler + palisade + PyYAML (boto3 ships with the runtime).
package-lambda:
	rm -rf build/lambda && mkdir -p build/lambda
	cp functions/aws_lambda/handler.py build/lambda/
	cp -r src/palisade build/lambda/
	$(PY) -m pip install --quiet --target build/lambda --platform manylinux2014_x86_64 \
		--python-version 3.12 --only-binary=:all: "PyYAML>=6.0"

package-azure-function:
	rm -rf build/azure_function && mkdir -p build/azure_function
	cp functions/azure_function/*.py functions/azure_function/host.json functions/azure_function/requirements.txt build/azure_function/
	cp -r src/palisade build/azure_function/

publish-azure-function: package-azure-function
	@test -n "$(FUNC_APP)" || (echo "Usage: make publish-azure-function FUNC_APP=<name from terraform output>" && exit 1)
	cd build/azure_function && func azure functionapp publish $(FUNC_APP) --python

clean:
	rm -rf build .pytest_cache .ruff_cache **/__pycache__ *.egg-info src/*.egg-info
