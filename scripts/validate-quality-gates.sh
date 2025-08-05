#!/bin/bash
set -euo pipefail

# PQC Migration Audit - Quality Gates Validation Script
# This script runs all quality gates required for production deployment

echo "🚀 PQC Migration Audit - Quality Gates Validation"
echo "================================================="

# Initialize counters
TOTAL_GATES=4
PASSED_GATES=0
FAILED_GATES=0

# Quality Gate 1: Test Coverage
echo ""
echo "📋 Quality Gate 1: Test Coverage (≥85%)"
echo "----------------------------------------"

if command -v pytest &> /dev/null; then
    # Run tests with coverage
    if python3 -m pytest --cov=src/pqc_migration_audit --cov-report=term --cov-report=html --cov-fail-under=85; then
        echo "✅ Test Coverage: PASSED"
        ((PASSED_GATES++))
    else
        echo "❌ Test Coverage: FAILED"
        ((FAILED_GATES++))
    fi
else
    echo "⚠️  pytest not found, running basic tests"
    if python3 -m unittest discover -s tests -p "test_*.py"; then
        echo "✅ Basic Tests: PASSED"
        ((PASSED_GATES++))
    else
        echo "❌ Basic Tests: FAILED"
        ((FAILED_GATES++))
    fi
fi

# Quality Gate 2: Security Scanning
echo ""
echo "🔒 Quality Gate 2: Security Scanning (≥85/100)"
echo "-----------------------------------------------"

if python3 security_scan.py; then
    echo "✅ Security Scanning: PASSED"
    ((PASSED_GATES++))
else
    echo "❌ Security Scanning: FAILED"
    ((FAILED_GATES++))
fi

# Quality Gate 3: Performance Benchmarking
echo ""
echo "⚡ Quality Gate 3: Performance Benchmarking (≥75/100)"
echo "-----------------------------------------------------"

if python3 performance_benchmark.py; then
    echo "✅ Performance Benchmarking: PASSED"
    ((PASSED_GATES++))
else
    echo "❌ Performance Benchmarking: FAILED"
    ((FAILED_GATES++))
fi

# Quality Gate 4: Static Code Analysis
echo ""
echo "🔍 Quality Gate 4: Static Code Analysis"
echo "---------------------------------------"

# Check if code analysis tools are available
HAS_FLAKE8=false
HAS_PYLINT=false
HAS_MYPY=false

if command -v flake8 &> /dev/null; then
    HAS_FLAKE8=true
fi

if command -v pylint &> /dev/null; then
    HAS_PYLINT=true
fi

if command -v mypy &> /dev/null; then
    HAS_MYPY=true
fi

STATIC_ANALYSIS_PASSED=true

# Run flake8 if available
if $HAS_FLAKE8; then
    echo "Running flake8..."
    if flake8 src/ --max-line-length=100 --ignore=E203,W503; then
        echo "  ✅ flake8: No issues found"
    else
        echo "  ❌ flake8: Issues found"
        STATIC_ANALYSIS_PASSED=false
    fi
fi

# Run basic Python syntax check as fallback
if ! $HAS_FLAKE8 && ! $HAS_PYLINT; then
    echo "Running Python syntax validation..."
    if python3 -m py_compile src/pqc_migration_audit/*.py; then
        echo "  ✅ Python syntax: Valid"
    else
        echo "  ❌ Python syntax: Invalid"
        STATIC_ANALYSIS_PASSED=false
    fi
fi

if $STATIC_ANALYSIS_PASSED; then
    echo "✅ Static Code Analysis: PASSED"
    ((PASSED_GATES++))
else
    echo "❌ Static Code Analysis: FAILED"
    ((FAILED_GATES++))
fi

# Summary
echo ""
echo "📊 Quality Gates Summary"
echo "========================"
echo "Total Gates: $TOTAL_GATES"
echo "Passed: $PASSED_GATES"
echo "Failed: $FAILED_GATES"

# Calculate percentage
PERCENTAGE=$((PASSED_GATES * 100 / TOTAL_GATES))
echo "Success Rate: $PERCENTAGE%"

echo ""
if [ $PASSED_GATES -eq $TOTAL_GATES ]; then
    echo "🎉 ALL QUALITY GATES PASSED - READY FOR PRODUCTION"
    exit 0
elif [ $PERCENTAGE -ge 75 ]; then
    echo "⚠️  QUALITY GATES MOSTLY PASSED - REVIEW FAILURES"
    exit 1
else
    echo "❌ QUALITY GATES FAILED - NOT READY FOR PRODUCTION"
    exit 1
fi