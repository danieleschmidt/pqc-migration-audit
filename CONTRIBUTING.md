# Contributing to PQC Migration Audit

We welcome contributions to the PQC Migration Audit project! This guide outlines how to contribute effectively.

## Quick Start

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/your-username/pqc-migration-audit.git
   cd pqc-migration-audit
   ```
3. **Set up development environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements-dev.txt
   pre-commit install
   ```

## Development Workflow

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following our coding standards

3. **Run tests**:
   ```bash
   pytest
   ```

4. **Format code**:
   ```bash
   black src/ tests/
   isort src/ tests/
   ```

5. **Submit a Pull Request**

## Priority Contribution Areas

- 🔍 **Language Support**: Add scanning for additional programming languages
- ☁️ **Cloud Integrations**: AWS KMS, Azure Key Vault, GCP Secret Manager
- 🚀 **Performance**: Optimize large repository scanning
- 🔧 **Migration Tools**: Automated refactoring capabilities
- 📚 **Documentation**: Examples, tutorials, best practices

## Coding Standards

- **Python 3.8+** compatibility required
- **Type hints** for all public functions
- **Docstrings** following Google style
- **Test coverage** ≥80% for new code
- **Pre-commit hooks** must pass

## Reporting Issues

Use our [issue templates](https://github.com/terragonlabs/pqc-migration-audit/issues/new/choose):
- 🐛 Bug reports
- 💡 Feature requests
- 📚 Documentation improvements
- 🔒 Security vulnerabilities (see SECURITY.md)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under the MIT License.