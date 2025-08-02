#!/usr/bin/env python3
"""
Code quality monitoring script for PQC Migration Audit project.
Monitors various code quality metrics and generates reports.
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

def run_command(cmd: str) -> tuple[int, str, str]:
    """Run a shell command and return exit code, stdout, stderr."""
    try:
        result = subprocess.run(
            cmd.split(),
            capture_output=True,
            text=True,
            timeout=120
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)

def check_code_formatting() -> Dict[str, Any]:
    """Check code formatting with black and isort."""
    results = {
        "black_formatted": False,
        "isort_formatted": False,
        "formatting_issues": []
    }
    
    # Check black formatting
    code, stdout, stderr = run_command("python -m black --check --diff src/ tests/")
    if code == 0:
        results["black_formatted"] = True
    else:
        results["formatting_issues"].extend(stdout.split('\n') if stdout else [])
    
    # Check isort formatting
    code, stdout, stderr = run_command("python -m isort --check-only --diff src/ tests/")
    if code == 0:
        results["isort_formatted"] = True
    else:
        results["formatting_issues"].extend(stdout.split('\n') if stdout else [])
    
    return results

def check_linting() -> Dict[str, Any]:
    """Check code linting with flake8 and pylint."""
    results = {
        "flake8_score": 0,
        "pylint_score": 0.0,
        "total_issues": 0,
        "issues_by_type": {},
        "critical_issues": []
    }
    
    # Run flake8
    code, stdout, stderr = run_command("python -m flake8 src/ tests/ --statistics")
    if code == 0:
        results["flake8_score"] = 100
    else:
        lines = stdout.split('\n')
        total_issues = 0
        for line in lines:
            if line.strip() and not line.startswith('src/') and not line.startswith('tests/'):
                try:
                    parts = line.split()
                    if len(parts) >= 2:
                        count = int(parts[0])
                        error_type = parts[1]
                        results["issues_by_type"][error_type] = count
                        total_issues += count
                        
                        # Critical issues (errors, not warnings)
                        if error_type.startswith('E'):
                            results["critical_issues"].append({
                                "type": error_type,
                                "count": count,
                                "tool": "flake8"
                            })
                except (ValueError, IndexError):
                    continue
        
        results["total_issues"] = total_issues
        # Calculate score based on issues (max 100, decreases with issues)
        results["flake8_score"] = max(0, 100 - total_issues)
    
    # Run pylint if available
    code, stdout, stderr = run_command("python -m pylint src/ --output-format=json")
    if code != 127:  # Command exists
        try:
            if stdout:
                pylint_results = json.loads(stdout)
                error_count = sum(1 for msg in pylint_results if msg.get("type") == "error")
                warning_count = sum(1 for msg in pylint_results if msg.get("type") == "warning")
                
                # Simple scoring: start at 10, subtract for errors and warnings
                results["pylint_score"] = max(0.0, 10.0 - (error_count * 2) - (warning_count * 0.5))
                
                # Add critical pylint issues
                for msg in pylint_results:
                    if msg.get("type") == "error":
                        results["critical_issues"].append({
                            "type": msg.get("symbol", "unknown"),
                            "message": msg.get("message", ""),
                            "line": msg.get("line", 0),
                            "tool": "pylint"
                        })
        except json.JSONDecodeError:
            pass
    
    return results

def check_type_coverage() -> Dict[str, Any]:
    """Check type annotation coverage with mypy."""
    results = {
        "mypy_score": 0,
        "type_issues": 0,
        "type_coverage_percent": 0,
        "critical_type_errors": []
    }
    
    # Run mypy
    code, stdout, stderr = run_command("python -m mypy src/ --ignore-missing-imports")
    
    lines = stdout.split('\n') if stdout else []
    error_count = 0
    
    for line in lines:
        if ": error:" in line:
            error_count += 1
            # Extract critical errors
            if any(keyword in line.lower() for keyword in ["incompatible", "argument", "return"]):
                results["critical_type_errors"].append(line.strip())
    
    results["type_issues"] = error_count
    results["mypy_score"] = max(0, 100 - (error_count * 5))
    
    # Estimate type coverage by counting typed vs untyped functions
    typed_functions = 0
    total_functions = 0
    
    for py_file in Path("src").rglob("*.py"):
        try:
            with open(py_file, 'r') as f:
                content = f.read()
                lines = content.split('\n')
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('def ') and '(' in line:
                        total_functions += 1
                        # Check if function has type annotations
                        if '->' in line or ':' in line.split('(')[1].split(')')[0]:
                            typed_functions += 1
        except Exception:
            continue
    
    if total_functions > 0:
        results["type_coverage_percent"] = int((typed_functions / total_functions) * 100)
    
    return results

def check_complexity() -> Dict[str, Any]:
    """Check code complexity."""
    results = {
        "average_complexity": 0,
        "max_complexity": 0,
        "complex_functions": [],
        "complexity_score": 100
    }
    
    # Use radon to check complexity if available
    code, stdout, stderr = run_command("python -m radon cc src/ -j")
    if code == 0:
        try:
            complexity_data = json.loads(stdout)
            complexities = []
            
            for file_path, functions in complexity_data.items():
                for func in functions:
                    complexity = func.get("complexity", 0)
                    complexities.append(complexity)
                    
                    if complexity > 10:  # High complexity threshold
                        results["complex_functions"].append({
                            "file": file_path,
                            "function": func.get("name", "unknown"),
                            "complexity": complexity,
                            "line": func.get("lineno", 0)
                        })
            
            if complexities:
                results["average_complexity"] = sum(complexities) / len(complexities)
                results["max_complexity"] = max(complexities)
                
                # Score based on average complexity (ideal < 5, acceptable < 10)
                avg_complexity = results["average_complexity"]
                if avg_complexity <= 5:
                    results["complexity_score"] = 100
                elif avg_complexity <= 10:
                    results["complexity_score"] = 80
                else:
                    results["complexity_score"] = max(0, 100 - (avg_complexity - 10) * 5)
        except json.JSONDecodeError:
            pass
    
    return results

def check_test_quality() -> Dict[str, Any]:
    """Check test quality and coverage."""
    results = {
        "test_coverage_percent": 0,
        "test_count": 0,
        "test_quality_score": 0,
        "missing_coverage_files": []
    }
    
    # Run coverage
    code, stdout, stderr = run_command("python -m pytest --cov=src --cov-report=json --cov-report=term")
    
    # Parse coverage from JSON report if available
    coverage_file = Path("coverage.json")
    if coverage_file.exists():
        try:
            with open(coverage_file, 'r') as f:
                coverage_data = json.load(f)
                
                total_coverage = coverage_data.get("totals", {}).get("percent_covered", 0)
                results["test_coverage_percent"] = round(total_coverage, 1)
                
                # Find files with low coverage
                for filename, file_data in coverage_data.get("files", {}).items():
                    file_coverage = file_data.get("summary", {}).get("percent_covered", 0)
                    if file_coverage < 80:  # Low coverage threshold
                        results["missing_coverage_files"].append({
                            "file": filename,
                            "coverage": round(file_coverage, 1)
                        })
        except (json.JSONDecodeError, FileNotFoundError):
            pass
    
    # Count test files and functions
    test_count = 0
    for test_file in Path("tests").rglob("test_*.py"):
        try:
            with open(test_file, 'r') as f:
                content = f.read()
                test_count += content.count("def test_")
        except Exception:
            continue
    
    results["test_count"] = test_count
    
    # Calculate overall test quality score
    coverage_score = results["test_coverage_percent"]
    test_density_score = min(100, test_count * 2)  # 2 points per test, max 100
    results["test_quality_score"] = int((coverage_score + test_density_score) / 2)
    
    return results

def generate_quality_report(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a comprehensive quality report."""
    report = {
        "timestamp": datetime.now().isoformat(),
        "overall_score": 0,
        "metrics": metrics,
        "summary": {},
        "recommendations": []
    }
    
    # Calculate overall score
    scores = []
    if "formatting" in metrics:
        formatting_score = 100 if metrics["formatting"]["black_formatted"] and metrics["formatting"]["isort_formatted"] else 50
        scores.append(formatting_score)
    
    if "linting" in metrics:
        scores.append(metrics["linting"]["flake8_score"])
    
    if "typing" in metrics:
        scores.append(metrics["typing"]["mypy_score"])
    
    if "complexity" in metrics:
        scores.append(metrics["complexity"]["complexity_score"])
    
    if "testing" in metrics:
        scores.append(metrics["testing"]["test_quality_score"])
    
    if scores:
        report["overall_score"] = int(sum(scores) / len(scores))
    
    # Generate summary
    report["summary"] = {
        "grade": get_quality_grade(report["overall_score"]),
        "critical_issues": get_critical_issues_count(metrics),
        "improvement_areas": get_improvement_areas(metrics)
    }
    
    # Generate recommendations
    report["recommendations"] = generate_quality_recommendations(metrics)
    
    return report

def get_quality_grade(score: int) -> str:
    """Get letter grade based on score."""
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"

def get_critical_issues_count(metrics: Dict[str, Any]) -> int:
    """Count critical issues across all metrics."""
    count = 0
    
    if "linting" in metrics:
        count += len(metrics["linting"].get("critical_issues", []))
    
    if "typing" in metrics:
        count += len(metrics["typing"].get("critical_type_errors", []))
    
    if "complexity" in metrics:
        count += len(metrics["complexity"].get("complex_functions", []))
    
    return count

def get_improvement_areas(metrics: Dict[str, Any]) -> List[str]:
    """Identify main areas for improvement."""
    areas = []
    
    if "formatting" in metrics and not metrics["formatting"]["black_formatted"]:
        areas.append("Code Formatting")
    
    if "linting" in metrics and metrics["linting"]["flake8_score"] < 80:
        areas.append("Code Linting")
    
    if "typing" in metrics and metrics["typing"]["type_coverage_percent"] < 80:
        areas.append("Type Annotations")
    
    if "complexity" in metrics and metrics["complexity"]["average_complexity"] > 10:
        areas.append("Code Complexity")
    
    if "testing" in metrics and metrics["testing"]["test_coverage_percent"] < 80:
        areas.append("Test Coverage")
    
    return areas

def generate_quality_recommendations(metrics: Dict[str, Any]) -> List[str]:
    """Generate specific recommendations based on metrics."""
    recommendations = []
    
    if "formatting" in metrics:
        if not metrics["formatting"]["black_formatted"]:
            recommendations.append("🔧 Run 'black src/ tests/' to fix code formatting")
        if not metrics["formatting"]["isort_formatted"]:
            recommendations.append("🔧 Run 'isort src/ tests/' to fix import ordering")
    
    if "linting" in metrics:
        if metrics["linting"]["total_issues"] > 0:
            recommendations.append(f"🔍 Fix {metrics['linting']['total_issues']} linting issues found by flake8")
    
    if "typing" in metrics:
        if metrics["typing"]["type_coverage_percent"] < 80:
            recommendations.append("📝 Add type annotations to improve type coverage")
        if metrics["typing"]["type_issues"] > 0:
            recommendations.append(f"🐛 Fix {metrics['typing']['type_issues']} type errors found by mypy")
    
    if "complexity" in metrics:
        complex_funcs = len(metrics["complexity"].get("complex_functions", []))
        if complex_funcs > 0:
            recommendations.append(f"🔨 Refactor {complex_funcs} complex function(s) to reduce complexity")
    
    if "testing" in metrics:
        if metrics["testing"]["test_coverage_percent"] < 80:
            recommendations.append("🧪 Write more tests to improve coverage above 80%")
        if metrics["testing"]["test_count"] < 10:
            recommendations.append("🧪 Add more unit tests to improve test suite quality")
    
    if not recommendations:
        recommendations.append("✅ Code quality looks good! Keep up the excellent work!")
    
    return recommendations

def save_quality_report(report: Dict[str, Any]) -> None:
    """Save the quality report to a JSON file."""
    output_file = Path("quality-report.json")
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"📄 Quality report saved to {output_file}")

def main():
    """Main quality monitoring function."""
    print("🔍 Running code quality analysis...")
    
    metrics = {}
    
    print("✨ Checking code formatting...")
    metrics["formatting"] = check_code_formatting()
    
    print("🔍 Running linting checks...")
    metrics["linting"] = check_linting()
    
    print("📝 Checking type annotations...")
    metrics["typing"] = check_type_coverage()
    
    print("🔧 Analyzing code complexity...")
    metrics["complexity"] = check_complexity()
    
    print("🧪 Evaluating test quality...")
    metrics["testing"] = check_test_quality()
    
    print("📊 Generating quality report...")
    report = generate_quality_report(metrics)
    
    # Display summary
    print("\n" + "="*60)
    print("📈 CODE QUALITY REPORT")
    print("="*60)
    print(f"Overall Score: {report['overall_score']}/100 (Grade: {report['summary']['grade']})")
    print(f"Critical Issues: {report['summary']['critical_issues']}")
    
    if report['summary']['improvement_areas']:
        print(f"Improvement Areas: {', '.join(report['summary']['improvement_areas'])}")
    
    print("\n💡 RECOMMENDATIONS:")
    for rec in report["recommendations"][:5]:  # Show first 5 recommendations
        print(f"  {rec}")
    
    # Save report
    save_quality_report(report)
    
    print("\n✅ Quality analysis completed!")
    
    # Exit with error code if quality is poor
    if report["overall_score"] < 70:
        print("⚠️  Quality score below threshold (70). Please address issues before proceeding.")
        sys.exit(1)

if __name__ == "__main__":
    main()