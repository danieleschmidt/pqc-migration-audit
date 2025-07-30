#!/bin/bash
# Development environment setup script

set -e  # Exit on any error

echo "🔧 Setting up PQC Migration Audit development environment..."

# Check Python version
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Error: Python $required_version or higher is required. Found: $python_version"
    exit 1
fi

echo "✅ Python version: $python_version (OK)"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️ Upgrading pip..."
pip install --upgrade pip

# Install development dependencies
echo "📚 Installing development dependencies..."
pip install -r requirements-dev.txt

# Install package in development mode
echo "🔧 Installing package in development mode..."
pip install -e .

# Set up pre-commit hooks
echo "🪝 Setting up pre-commit hooks..."
pre-commit install

# Run initial tests to verify setup
echo "🧪 Running initial tests..."
if pytest tests/test_example.py -v; then
    echo "✅ Tests passed! Development environment is ready."
else
    echo "❌ Tests failed. Please check the setup."
    exit 1
fi

echo ""
echo "🎉 Development environment setup complete!"
echo ""
echo "Next steps:"
echo "  1. Activate the environment: source venv/bin/activate"
echo "  2. Run tests: make test"
echo "  3. Format code: make format"
echo "  4. Run linting: make lint"
echo ""
echo "Happy coding! 🚀"