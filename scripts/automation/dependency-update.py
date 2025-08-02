#!/usr/bin/env python3
"""
Automated dependency update script for PQC Migration Audit project.
Checks for outdated dependencies and creates update recommendations.
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
            timeout=60
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)

def check_pip_outdated() -> List[Dict[str, str]]:
    """Check for outdated pip packages."""
    outdated = []
    
    code, stdout, stderr = run_command("python -m pip list --outdated --format=json")
    if code == 0:
        try:
            packages = json.loads(stdout)
            for pkg in packages:
                outdated.append({
                    "name": pkg["name"],
                    "current_version": pkg["version"],
                    "latest_version": pkg["latest_version"],
                    "type": "pip"
                })
        except json.JSONDecodeError:
            print(f"Failed to parse pip outdated output: {stdout}")
    
    return outdated

def check_security_vulnerabilities() -> List[Dict[str, Any]]:
    """Check for security vulnerabilities in dependencies."""
    vulnerabilities = []
    
    # Run safety check
    code, stdout, stderr = run_command("python -m safety check --json")
    if code != 0:  # safety returns non-zero when vulnerabilities found
        try:
            # Try to parse as JSON even on non-zero exit
            vuln_data = json.loads(stdout)
            for vuln in vuln_data:
                vulnerabilities.append({
                    "package": vuln.get("package_name", "unknown"),
                    "version": vuln.get("analyzed_version", "unknown"),
                    "vulnerability_id": vuln.get("vulnerability_id", "unknown"),
                    "advisory": vuln.get("advisory", "No advisory available"),
                    "severity": "MEDIUM",  # Default severity
                    "type": "security"
                })
        except json.JSONDecodeError:
            # If JSON parsing fails, try to parse text output
            lines = stdout.split('\n')
            for line in lines:
                if "vulnerability" in line.lower():
                    vulnerabilities.append({
                        "package": "unknown",
                        "version": "unknown",
                        "vulnerability_id": "unknown",
                        "advisory": line.strip(),
                        "severity": "MEDIUM",
                        "type": "security"
                    })
    
    return vulnerabilities

def create_update_plan(outdated: List[Dict[str, str]], vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Create an update plan based on outdated packages and vulnerabilities."""
    plan = {
        "created_at": datetime.now().isoformat(),
        "total_outdated": len(outdated),
        "total_vulnerabilities": len(vulnerabilities),
        "updates": {
            "high_priority": [],    # Security vulnerabilities
            "medium_priority": [],  # Major version updates
            "low_priority": []      # Minor/patch updates
        },
        "recommendations": []
    }
    
    # Prioritize security vulnerabilities
    vuln_packages = {vuln["package"] for vuln in vulnerabilities}
    
    for pkg in outdated:
        update_item = {
            "package": pkg["name"],
            "current_version": pkg["current_version"],
            "latest_version": pkg["latest_version"],
            "update_type": determine_update_type(pkg["current_version"], pkg["latest_version"]),
            "has_vulnerability": pkg["name"] in vuln_packages
        }
        
        if pkg["name"] in vuln_packages:
            plan["updates"]["high_priority"].append(update_item)
        elif is_major_version_update(pkg["current_version"], pkg["latest_version"]):
            plan["updates"]["medium_priority"].append(update_item)
        else:
            plan["updates"]["low_priority"].append(update_item)
    
    # Add vulnerabilities without updates available
    for vuln in vulnerabilities:
        if vuln["package"] not in [pkg["name"] for pkg in outdated]:
            plan["updates"]["high_priority"].append({
                "package": vuln["package"],
                "current_version": vuln["version"],
                "latest_version": "No update available",
                "update_type": "security_fix_needed",
                "has_vulnerability": True,
                "vulnerability_details": vuln
            })
    
    # Generate recommendations
    plan["recommendations"] = generate_recommendations(plan)
    
    return plan

def determine_update_type(current: str, latest: str) -> str:
    """Determine the type of version update (major, minor, patch)."""
    try:
        current_parts = [int(x) for x in current.split('.')]
        latest_parts = [int(x) for x in latest.split('.')]
        
        if len(current_parts) >= 1 and len(latest_parts) >= 1:
            if current_parts[0] != latest_parts[0]:
                return "major"
            elif len(current_parts) >= 2 and len(latest_parts) >= 2:
                if current_parts[1] != latest_parts[1]:
                    return "minor"
                else:
                    return "patch"
    except (ValueError, IndexError):
        pass
    
    return "unknown"

def is_major_version_update(current: str, latest: str) -> bool:
    """Check if the update is a major version change."""
    return determine_update_type(current, latest) == "major"

def generate_recommendations(plan: Dict[str, Any]) -> List[str]:
    """Generate human-readable recommendations based on the update plan."""
    recommendations = []
    
    high_priority_count = len(plan["updates"]["high_priority"])
    medium_priority_count = len(plan["updates"]["medium_priority"])
    low_priority_count = len(plan["updates"]["low_priority"])
    
    if high_priority_count > 0:
        recommendations.append(
            f"🚨 URGENT: {high_priority_count} package(s) have security vulnerabilities. "
            "Update immediately!"
        )
    
    if medium_priority_count > 0:
        recommendations.append(
            f"⚠️  REVIEW: {medium_priority_count} package(s) have major version updates available. "
            "Review breaking changes before updating."
        )
    
    if low_priority_count > 0:
        recommendations.append(
            f"📦 UPDATE: {low_priority_count} package(s) have minor/patch updates available. "
            "Safe to update in next maintenance window."
        )
    
    if high_priority_count == 0 and medium_priority_count == 0 and low_priority_count == 0:
        recommendations.append("✅ All dependencies are up to date!")
    
    recommendations.extend([
        "💡 Run tests after each update to ensure compatibility",
        "📝 Document any breaking changes in CHANGELOG.md",
        "🔒 Always prioritize security updates over feature updates"
    ])
    
    return recommendations

def save_update_plan(plan: Dict[str, Any]) -> None:
    """Save the update plan to a JSON file."""
    output_file = Path("dependency-update-plan.json")
    
    with open(output_file, 'w') as f:
        json.dump(plan, f, indent=2)
    
    print(f"📄 Update plan saved to {output_file}")

def generate_update_commands(plan: Dict[str, Any]) -> List[str]:
    """Generate shell commands to perform the updates."""
    commands = []
    
    # High priority updates (security)
    for update in plan["updates"]["high_priority"]:
        if update["latest_version"] != "No update available":
            commands.append(f"pip install --upgrade {update['package']}")
    
    # Low priority updates (safe updates)
    for update in plan["updates"]["low_priority"]:
        commands.append(f"pip install --upgrade {update['package']}")
    
    return commands

def main():
    """Main dependency update checking function."""
    print("🔍 Checking for dependency updates...")
    
    print("📦 Checking for outdated pip packages...")
    outdated = check_pip_outdated()
    
    print("🔒 Checking for security vulnerabilities...")
    vulnerabilities = check_security_vulnerabilities()
    
    print("📋 Creating update plan...")
    plan = create_update_plan(outdated, vulnerabilities)
    
    # Display summary
    print("\n" + "="*60)
    print("📊 DEPENDENCY UPDATE SUMMARY")
    print("="*60)
    print(f"Total outdated packages: {plan['total_outdated']}")
    print(f"Security vulnerabilities: {plan['total_vulnerabilities']}")
    print(f"High priority updates: {len(plan['updates']['high_priority'])}")
    print(f"Medium priority updates: {len(plan['updates']['medium_priority'])}")
    print(f"Low priority updates: {len(plan['updates']['low_priority'])}")
    
    print("\n💡 RECOMMENDATIONS:")
    for rec in plan["recommendations"]:
        print(f"  {rec}")
    
    # Save plan
    save_update_plan(plan)
    
    # Generate update commands
    commands = generate_update_commands(plan)
    if commands:
        print(f"\n🚀 SUGGESTED UPDATE COMMANDS:")
        for cmd in commands[:5]:  # Show first 5 commands
            print(f"  {cmd}")
        if len(commands) > 5:
            print(f"  ... and {len(commands) - 5} more (see dependency-update-plan.json)")
    
    print("\n✅ Dependency check completed!")
    
    # Exit with error code if high priority updates needed
    if len(plan["updates"]["high_priority"]) > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()