# Development Guide

This guide helps you set up a development environment and understand the project structure.

## Quick Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/terragonlabs/pqc-migration-audit.git
   cd pqc-migration-audit
   ```

2. **Run the setup script**:
   ```bash
   ./scripts/setup-dev.sh
   ```

3. **Activate the virtual environment**:
   ```bash
   source venv/bin/activate
   ```

## Manual Setup

If the automated setup doesn't work:

1. **Create virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Linux/macOS
   # or
   venv\Scripts\activate  # Windows
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements-dev.txt
   pip install -e .
   ```

3. **Set up pre-commit hooks**:
   ```bash
   pre-commit install
   ```

## Project Structure

```
pqc-migration-audit/
├── src/pqc_migration_audit/    # Main package source
│   ├── __init__.py
│   ├── cli.py                  # Command-line interface
│   ├── core.py                 # Core auditing logic
│   ├── scanners/               # Language-specific scanners
│   ├── analyzers/              # Vulnerability analyzers
│   └── reporters/              # Report generators
├── tests/                      # Test suite
│   ├── unit/                   # Unit tests
│   ├── integration/            # Integration tests
│   └── fixtures/               # Test data
├── docs/                       # Documentation
├── scripts/                    # Development scripts
└── examples/                   # Usage examples
```

## Development Workflow

### Making Changes

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the coding standards

3. **Run tests frequently**:
   ```bash
   make test
   # or
   pytest
   ```

4. **Format code before committing**:
   ```bash
   make format
   # or
   black src/ tests/
   isort src/ tests/
   ```

5. **Run all checks**:
   ```bash
   make check  # Runs lint + test
   ```

### Testing

- **Run all tests**: `pytest`
- **Run with coverage**: `pytest --cov`
- **Run specific test**: `pytest tests/test_specific.py::test_function`
- **Run integration tests**: `pytest tests/integration/`

### Code Quality

- **Formatting**: Black (line length: 88)
- **Import sorting**: isort (Black profile)
- **Linting**: flake8 with docstring checks
- **Type checking**: mypy with strict mode
- **Pre-commit hooks**: Automatically run on commit

### Documentation

- **Build docs locally**:
  ```bash
  cd docs
  make html
  ```

- **Serve docs locally**:
  ```bash
  make docs-serve
  ```

## Architecture Overview

### Core Components

1. **CryptoAuditor**: Main scanning engine
2. **Scanners**: Language-specific code analyzers
3. **Analyzers**: Vulnerability pattern matchers
4. **RiskAssessment**: Risk scoring and prioritization
5. **Reporters**: Output formatters (JSON, HTML, SARIF)

### Plugin System

The tool supports plugins for:
- Additional programming languages
- Custom vulnerability patterns
- Output formats
- Cloud service integrations

### Performance Considerations

- **Parallel scanning**: Multiple files processed concurrently
- **Incremental analysis**: Only scan changed files
- **Memory management**: Large repositories handled efficiently
- **Caching**: Results cached between runs

## Debugging

### Common Issues

1. **Import errors**: Ensure package is installed with `pip install -e .`
2. **Test failures**: Check Python version compatibility (≥3.8)
3. **Linting errors**: Run `make format` before committing
4. **Memory issues**: Use `--max-workers` flag to limit parallelism

### Debugging Tools

- **pytest-pdb**: Drop into debugger on test failures
- **rich.print**: Enhanced console output for debugging
- **logging**: Comprehensive logging throughout the codebase

## Contributing Guidelines

1. **Code coverage**: Maintain ≥80% test coverage
2. **Documentation**: Update docs for new features
3. **Backwards compatibility**: Avoid breaking changes
4. **Security**: Never commit secrets or credentials

## Performance Testing

```bash
# Benchmark scanning performance
python -m pytest tests/performance/ --benchmark-only

# Profile memory usage
python -m memory_profiler scripts/profile_scan.py

# Load testing with large repositories
python scripts/load_test.py --repo-size large
```

## Release Process

1. **Update version** in `pyproject.toml` and `__init__.py`
2. **Update CHANGELOG.md** with new features and fixes
3. **Create and push tag**: `git tag v1.0.0 && git push origin v1.0.0`
4. **GitHub Actions** automatically builds and publishes to PyPI

## Getting Help

- **Documentation**: Check `docs/` directory
- **Issues**: Search existing GitHub issues
- **Discussions**: Use GitHub Discussions for questions
- **Chat**: Join our Slack channel (see CONTRIBUTING.md)