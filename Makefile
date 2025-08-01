.PHONY: help install install-dev test lint format clean docs docker security

# Default variables
VERSION ?= $(shell grep -Po '(?<=version = ")[^"]*' pyproject.toml)
IMAGE_NAME ?= pqc-migration-audit
REGISTRY ?= docker.io/terragonlabs
PLATFORM ?= linux/amd64,linux/arm64

help:  ## Show this help message
	@echo "PQC Migration Audit - Build System"
	@echo "=================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-25s\033[0m %s\n", $$1, $$2}'

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

# ============================================================================
# Container Build Targets
# ============================================================================

docker-build:  ## Build Docker image
	docker build -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest .

docker-build-multi:  ## Build multi-platform Docker image
	docker buildx create --use --name multiarch || true
	docker buildx build --platform $(PLATFORM) -t $(REGISTRY)/$(IMAGE_NAME):$(VERSION) -t $(REGISTRY)/$(IMAGE_NAME):latest --push .

docker-run:  ## Run Docker container locally
	docker run --rm -it -v $(PWD):/workspace $(IMAGE_NAME):latest

docker-scan:  ## Scan Docker image for vulnerabilities
	docker scout cves $(IMAGE_NAME):$(VERSION) || echo "Docker Scout not available, using trivy..."
	trivy image $(IMAGE_NAME):$(VERSION) || echo "Trivy not available"

docker-test:  ## Test Docker image functionality
	docker run --rm $(IMAGE_NAME):$(VERSION) --version
	docker run --rm $(IMAGE_NAME):$(VERSION) --help

docker-push:  ## Push Docker image to registry
	docker tag $(IMAGE_NAME):$(VERSION) $(REGISTRY)/$(IMAGE_NAME):$(VERSION)
	docker tag $(IMAGE_NAME):latest $(REGISTRY)/$(IMAGE_NAME):latest  
	docker push $(REGISTRY)/$(IMAGE_NAME):$(VERSION)
	docker push $(REGISTRY)/$(IMAGE_NAME):latest

docker-clean:  ## Clean Docker images and build cache
	docker rmi $(IMAGE_NAME):$(VERSION) $(IMAGE_NAME):latest 2>/dev/null || true
	docker system prune -f
	docker buildx prune -f

# ============================================================================
# Security and Quality Targets  
# ============================================================================

security:  ## Run security scans
	@echo "Running security scans..."
	bandit -r src/ -f json -o bandit-report.json || true
	safety check --json --output safety-report.json || true
	@echo "Security scan complete. Check bandit-report.json and safety-report.json"

security-container:  ## Security scan for container
	@echo "Scanning container for vulnerabilities..."
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		-v $(PWD):/workspace \
		aquasec/trivy image $(IMAGE_NAME):$(VERSION)

sbom:  ## Generate Software Bill of Materials
	./scripts/generate-sbom.sh

vulnerability-scan:  ## Run vulnerability scans
	@echo "Running vulnerability scans..."
	./scripts/dependency-scan.sh
	./scripts/container-security-scan.sh

# ============================================================================
# CI/CD Targets
# ============================================================================

ci-install:  ## Install dependencies for CI
	pip install --upgrade pip
	pip install -e ".[dev,test]"

ci-test:  ## Run tests in CI environment
	pytest --cov=src/pqc_migration_audit \
		--cov-report=xml \
		--cov-report=term-missing \
		--cov-fail-under=85 \
		--junit-xml=test-results.xml

ci-lint:  ## Run comprehensive linting for CI
	black --check src/ tests/
	isort --check-only src/ tests/
	flake8 src/ tests/
	mypy src/
	ruff check src/ tests/

ci-security:  ## Run security checks in CI
	bandit -r src/ -f json -o bandit-report.json
	safety check --json --output safety-report.json

ci-build:  ## Complete CI build pipeline
	make ci-install
	make ci-lint
	make ci-test
	make ci-security
	make docker-build
	make docker-test

# ============================================================================
# Development Targets
# ============================================================================

dev-setup:  ## Complete development environment setup
	./scripts/setup-dev.sh
	make install-dev
	pre-commit install
	@echo "Development environment ready!"

dev-test:  ## Run tests in development mode with file watching
	pytest-watch -- --cov=src/pqc_migration_audit --cov-report=html

benchmark:  ## Run performance benchmarks
	pytest tests/performance/ --benchmark-only --benchmark-json=benchmark-results.json

profile:  ## Profile application performance  
	python -m cProfile -o profile-results.prof -m pqc_migration_audit.cli scan --help
	@echo "Profile results saved to profile-results.prof"

# ============================================================================
# Release Targets
# ============================================================================

pre-release:  ## Prepare for release (run all checks)
	make clean
	make ci-build
	make security
	make docs
	@echo "Pre-release checks completed successfully!"

release:  ## Create a release (requires VERSION env var)
	@if [ -z "$(VERSION)" ]; then echo "VERSION is required. Use: make release VERSION=1.0.0"; exit 1; fi
	make pre-release
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	git push origin v$(VERSION)
	python -m build
	make docker-build-multi
	@echo "Release v$(VERSION) created successfully!"

release-dry-run:  ## Test release process without publishing
	@echo "Testing release process..."
	python -m build
	twine check dist/*
	@echo "Release dry-run completed successfully!"

# ============================================================================
# Utility Targets
# ============================================================================

env-info:  ## Display environment information
	@echo "Environment Information:"
	@echo "======================="
	@echo "Python: $(shell python --version)"
	@echo "Pip: $(shell pip --version)"
	@echo "Docker: $(shell docker --version 2>/dev/null || echo 'Not available')"
	@echo "Version: $(VERSION)"
	@echo "Image: $(REGISTRY)/$(IMAGE_NAME):$(VERSION)"
	@echo "Platform: $(PLATFORM)"

clean-all:  ## Clean everything (build artifacts, caches, containers)
	make clean
	make docker-clean
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/  
	rm -rf .pytest_cache/
	rm -rf node_modules/
	rm -f *.prof
	rm -f *-report.json
	rm -f test-results.xml
	rm -f benchmark-results.json

deps-update:  ## Update dependencies
	pip-compile --upgrade requirements.in
	pip-compile --upgrade requirements-dev.in