.PHONY: install test lint typecheck check coverage docs-rules demo sbom clean

install:            ## editable install with dev tools
	pip install -e ".[dev]"

test:               ## run the test suite
	python -m pytest tests/

lint:               ## ruff lint
	ruff check .

typecheck:          ## mypy strict
	mypy

check: lint typecheck test  ## everything CI runs

coverage:           ## test suite with coverage report
	python -m pytest tests/ --cov=cairn --cov-report=term-missing

docs-rules:         ## regenerate docs/rules.md from the rule registry
	python scripts/generate_rules_doc.py

demo:               ## scan the deliberately vulnerable example
	cairn scan examples/vulnerable --fail-on NEVER

sbom:               ## generate a CycloneDX SBOM (needs: pip install cyclonedx-bom)
	cyclonedx-py environment > sbom.cyclonedx.json
	@echo "wrote sbom.cyclonedx.json"

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache
	find . -name __pycache__ -type d -exec rm -rf {} +
