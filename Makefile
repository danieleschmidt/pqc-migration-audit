.PHONY: help install install-dev test lint format clean docs

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install package
	pip install -e .

install-dev:  ## Install package with development dependencies
	pip install -e ".[dev]"
	pre-commit install

test:  ## Run tests
	pytest

test-cov:  ## Run tests with coverage report
	pytest --cov=src/pqc_migration_audit --cov-report=html --cov-report=term

lint:  ## Run linting
	flake8 src/ tests/
	mypy src/

format:  ## Format code
	black src/ tests/ scripts/
	isort src/ tests/ scripts/

check:  ## Run all checks (lint + test)
	make lint
	make test

clean:  ## Clean build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

docs:  ## Build documentation
	cd docs && make html

docs-serve:  ## Serve documentation locally
	cd docs/_build/html && python -m http.server 8000

build:  ## Build package
	python -m build

release:  ## Create a release (requires VERSION env var)
	@if [ -z "$(VERSION)" ]; then echo "VERSION is required. Use: make release VERSION=1.0.0"; exit 1; fi
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	git push origin v$(VERSION)
	python -m build
	twine upload dist/*