#!/usr/bin/env python3
"""
Terragon Autonomous SDLC Value Discovery Engine
Continuously discovers, scores, and prioritizes value opportunities
"""

import json
import yaml
import subprocess
import re
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class ValueItem:
    """Represents a value opportunity discovered in the codebase."""
    id: str
    title: str
    description: str
    category: str
    source: str
    file_path: Optional[str]
    line_number: Optional[int]
    priority: str
    estimated_effort_hours: float
    wsjf_score: float
    ice_score: float
    technical_debt_score: float
    composite_score: float
    created_at: str
    dependencies: List[str]
    risk_level: str
    impact_areas: List[str]


class ValueDiscoveryEngine:
    """Main engine for discovering and scoring value opportunities."""
    
    def __init__(self, config_path: str = ".terragon/value-config.yaml"):
        """Initialize the discovery engine with configuration."""
        self.config_path = config_path
        self.config = self._load_config()
        self.repo_root = Path.cwd()
        self.history_file = self.repo_root / ".terragon" / "value-history.json"
        self.backlog_file = self.repo_root / ".terragon" / "backlog.json"
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return self._default_config()
    
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration if file not found."""
        return {
            "scoring": {
                "weights": {"maturing": {"wsjf": 0.6, "ice": 0.1, "technicalDebt": 0.2, "security": 0.1}},
                "thresholds": {"minScore": 10, "maxRisk": 0.8, "securityBoost": 2.0}
            },
            "discovery": {"sources": ["gitHistory", "staticAnalysis", "codeComments"]},
            "repository": {"maturityLevel": 65, "name": "unknown"}
        }
    
    def discover_value_opportunities(self) -> List[ValueItem]:
        """Main discovery method - finds all value opportunities."""
        opportunities = []
        
        # Discover from multiple sources
        opportunities.extend(self._discover_from_git_history())
        opportunities.extend(self._discover_from_code_comments())
        opportunities.extend(self._discover_from_static_analysis())
        opportunities.extend(self._discover_from_tests())
        opportunities.extend(self._discover_from_dependencies())
        opportunities.extend(self._discover_security_opportunities())
        
        # Score all opportunities
        scored_opportunities = []
        for opp in opportunities:
            scored_opp = self._calculate_scores(opp)
            if scored_opp.composite_score >= self.config["scoring"]["thresholds"]["minScore"]:
                scored_opportunities.append(scored_opp)
        
        # Sort by composite score descending
        scored_opportunities.sort(key=lambda x: x.composite_score, reverse=True)
        
        return scored_opportunities
    
    def _discover_from_git_history(self) -> List[ValueItem]:
        """Discover opportunities from Git commit history."""
        opportunities = []
        
        try:
            # Get recent commits with specific patterns
            result = subprocess.run([
                "git", "log", "--oneline", "--grep=TODO", "--grep=FIXME", 
                "--grep=hack", "--grep=temporary", "-n", "50"
            ], capture_output=True, text=True, cwd=self.repo_root)
            
            for line in result.stdout.strip().split('\n'):
                if line:
                    commit_hash = line.split()[0]
                    message = ' '.join(line.split()[1:])
                    
                    opportunities.append(ValueItem(
                        id=f"git-{commit_hash}",
                        title=f"Address technical debt from commit: {message[:50]}...",
                        description=f"Commit {commit_hash} indicates technical debt: {message}",
                        category="technical-debt",
                        source="git-history",
                        file_path=None,
                        line_number=None,
                        priority="medium",
                        estimated_effort_hours=2.0,
                        wsjf_score=0.0,
                        ice_score=0.0,
                        technical_debt_score=0.0,
                        composite_score=0.0,
                        created_at=datetime.now().isoformat(),
                        dependencies=[],
                        risk_level="low",
                        impact_areas=["maintainability"]
                    ))
                    
        except subprocess.CalledProcessError:
            pass  # Git not available or other error
            
        return opportunities
    
    def _discover_from_code_comments(self) -> List[ValueItem]:
        """Discover opportunities from code comments (TODO, FIXME, etc.)."""
        opportunities = []
        patterns = self.config["discovery"].get("patterns", {})
        debt_patterns = patterns.get("technicalDebt", ["TODO", "FIXME", "HACK", "XXX"])
        
        # Search for debt patterns in Python files
        for py_file in self.repo_root.rglob("*.py"):
            if ".venv" in str(py_file) or "__pycache__" in str(py_file):
                continue
                
            try:
                with open(py_file, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        for pattern in debt_patterns:
                            if pattern.lower() in line.lower():
                                opportunities.append(ValueItem(
                                    id=f"comment-{py_file.name}-{line_num}",
                                    title=f"Address {pattern} in {py_file.name}",
                                    description=f"Line {line_num}: {line.strip()}",
                                    category="technical-debt",
                                    source="code-comments",
                                    file_path=str(py_file.relative_to(self.repo_root)),
                                    line_number=line_num,
                                    priority="medium",
                                    estimated_effort_hours=1.5,
                                    wsjf_score=0.0,
                                    ice_score=0.0,
                                    technical_debt_score=0.0,
                                    composite_score=0.0,
                                    created_at=datetime.now().isoformat(),
                                    dependencies=[],
                                    risk_level="low",
                                    impact_areas=["code-quality", "maintainability"]
                                ))
                                break  # Only one pattern per line
            except (UnicodeDecodeError, FileNotFoundError):
                continue
                
        return opportunities
    
    def _discover_from_static_analysis(self) -> List[ValueItem]:
        """Discover opportunities from static analysis tools."""
        opportunities = []
        
        # Run mypy and parse output
        try:
            result = subprocess.run([
                "python", "-m", "mypy", "src/", "--ignore-missing-imports"
            ], capture_output=True, text=True, cwd=self.repo_root)
            
            for line in result.stdout.split('\n'):
                if ".py:" in line and "error:" in line:
                    parts = line.split(':')
                    if len(parts) >= 3:
                        file_path = parts[0]
                        line_num = parts[1]
                        error_msg = ':'.join(parts[3:]).strip()
                        
                        opportunities.append(ValueItem(
                            id=f"mypy-{file_path}-{line_num}",
                            title=f"Fix type error in {Path(file_path).name}",
                            description=f"MyPy error: {error_msg}",
                            category="code-quality",
                            source="static-analysis",
                            file_path=file_path,
                            line_number=int(line_num) if line_num.isdigit() else None,
                            priority="medium",
                            estimated_effort_hours=0.5,
                            wsjf_score=0.0,
                            ice_score=0.0,
                            technical_debt_score=0.0,
                            composite_score=0.0,
                            created_at=datetime.now().isoformat(),
                            dependencies=[],
                            risk_level="low",
                            impact_areas=["code-quality", "type-safety"]
                        ))
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
            
        return opportunities
    
    def _discover_from_tests(self) -> List[ValueItem]:
        """Discover test-related opportunities."""
        opportunities = []
        
        # Check test coverage
        try:
            result = subprocess.run([
                "python", "-m", "pytest", "--cov=src", "--cov-report=json", "--quiet"
            ], capture_output=True, text=True, cwd=self.repo_root)
            
            # Look for coverage report
            coverage_file = self.repo_root / "coverage.json"
            if coverage_file.exists():
                with open(coverage_file, 'r') as f:
                    coverage_data = json.load(f)
                    
                for file_path, file_data in coverage_data.get("files", {}).items():
                    coverage = file_data.get("summary", {}).get("percent_covered", 100)
                    if coverage < 80:  # Below target coverage
                        opportunities.append(ValueItem(
                            id=f"coverage-{Path(file_path).name}",
                            title=f"Improve test coverage for {Path(file_path).name}",
                            description=f"Current coverage: {coverage:.1f}%, target: 80%+",
                            category="testing",
                            source="test-analysis",
                            file_path=file_path,
                            line_number=None,
                            priority="high" if coverage < 60 else "medium",
                            estimated_effort_hours=3.0,
                            wsjf_score=0.0,
                            ice_score=0.0,
                            technical_debt_score=0.0,
                            composite_score=0.0,
                            created_at=datetime.now().isoformat(),
                            dependencies=[],
                            risk_level="medium",
                            impact_areas=["test-coverage", "reliability"]
                        ))
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
            
        return opportunities
    
    def _discover_from_dependencies(self) -> List[ValueItem]:
        """Discover dependency-related opportunities."""
        opportunities = []
        
        # Check for outdated dependencies
        try:
            result = subprocess.run([
                "pip", "list", "--outdated", "--format=json"
            ], capture_output=True, text=True, cwd=self.repo_root)
            
            if result.stdout:
                outdated = json.loads(result.stdout)
                for pkg in outdated[:5]:  # Limit to top 5
                    opportunities.append(ValueItem(
                        id=f"dep-{pkg['name']}",
                        title=f"Update {pkg['name']} dependency",
                        description=f"Current: {pkg['version']}, Latest: {pkg['latest_version']}",
                        category="dependencies",
                        source="dependency-analysis",
                        file_path="requirements.txt",
                        line_number=None,
                        priority="low",
                        estimated_effort_hours=0.5,
                        wsjf_score=0.0,
                        ice_score=0.0,
                        technical_debt_score=0.0,
                        composite_score=0.0,
                        created_at=datetime.now().isoformat(),
                        dependencies=[],
                        risk_level="low",
                        impact_areas=["security", "performance"]
                    ))
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass
            
        return opportunities
    
    def _discover_security_opportunities(self) -> List[ValueItem]:
        """Discover security-related opportunities - high priority for this project."""
        opportunities = []
        
        # For a PQC security tool, look for placeholder implementations
        core_files = ["src/pqc_migration_audit/core.py", "src/pqc_migration_audit/cli.py"]
        
        for file_path in core_files:
            full_path = self.repo_root / file_path
            if full_path.exists():
                try:
                    with open(full_path, 'r') as f:
                        content = f.read()
                        if "placeholder" in content.lower() or "pass" in content:
                            opportunities.append(ValueItem(
                                id=f"security-impl-{Path(file_path).stem}",
                                title=f"Implement core functionality in {Path(file_path).name}",
                                description=f"Critical security functionality needs implementation",
                                category="security-implementation",
                                source="security-analysis",
                                file_path=file_path,
                                line_number=None,
                                priority="high",
                                estimated_effort_hours=8.0,
                                wsjf_score=0.0,
                                ice_score=0.0,
                                technical_debt_score=0.0,
                                composite_score=0.0,
                                created_at=datetime.now().isoformat(),
                                dependencies=[],
                                risk_level="high",
                                impact_areas=["security", "functionality", "product-readiness"]
                            ))
                except FileNotFoundError:
                    continue
                    
        return opportunities
    
    def _calculate_scores(self, item: ValueItem) -> ValueItem:
        """Calculate WSJF, ICE, and composite scores for a value item."""
        
        # WSJF Components
        user_business_value = self._calculate_user_business_value(item)
        time_criticality = self._calculate_time_criticality(item) 
        risk_reduction = self._calculate_risk_reduction(item)
        opportunity_enablement = self._calculate_opportunity_enablement(item)
        
        cost_of_delay = user_business_value + time_criticality + risk_reduction + opportunity_enablement
        job_size = item.estimated_effort_hours / 4  # Convert to story points (4 hours = 1 point)
        
        item.wsjf_score = cost_of_delay / max(job_size, 0.5)  # Avoid division by zero
        
        # ICE Components
        impact = self._calculate_impact(item)
        confidence = self._calculate_confidence(item)
        ease = self._calculate_ease(item)
        
        item.ice_score = impact * confidence * ease
        
        # Technical Debt Score
        item.technical_debt_score = self._calculate_technical_debt_score(item)
        
        # Composite Score with adaptive weights
        maturity_level = self.config["repository"]["maturityLevel"]
        if maturity_level >= 75:
            weights = self.config["scoring"]["weights"]["advanced"]
        elif maturity_level >= 50:
            weights = self.config["scoring"]["weights"]["maturing"]
        elif maturity_level >= 25:  
            weights = self.config["scoring"]["weights"]["developing"]
        else:
            weights = self.config["scoring"]["weights"]["nascent"]
        
        normalized_wsjf = min(item.wsjf_score / 50, 1.0)  # Normalize to 0-1
        normalized_ice = min(item.ice_score / 1000, 1.0)
        normalized_debt = min(item.technical_debt_score / 100, 1.0)
        
        item.composite_score = (
            weights["wsjf"] * normalized_wsjf * 100 +
            weights["ice"] * normalized_ice * 100 +
            weights["technicalDebt"] * normalized_debt * 100
        )
        
        # Apply category boosts
        if item.category in ["security", "security-implementation"]:
            item.composite_score *= self.config["scoring"]["thresholds"]["securityBoost"]
        elif item.category == "compliance":
            item.composite_score *= self.config["scoring"]["thresholds"]["complianceBoost"]
        elif item.category == "performance":
            item.composite_score *= self.config["scoring"]["thresholds"].get("performanceBoost", 1.5)
            
        return item
    
    def _calculate_user_business_value(self, item: ValueItem) -> float:
        """Calculate user/business value component of WSJF."""
        category_values = {
            "security": 10,
            "security-implementation": 15,
            "testing": 8,
            "performance": 7,
            "code-quality": 5,
            "technical-debt": 4,
            "dependencies": 3,
            "documentation": 3
        }
        return category_values.get(item.category, 5)
    
    def _calculate_time_criticality(self, item: ValueItem) -> float:
        """Calculate time criticality component of WSJF."""
        if item.priority == "high":
            return 8
        elif item.priority == "medium":
            return 5
        else:
            return 2
    
    def _calculate_risk_reduction(self, item: ValueItem) -> float:
        """Calculate risk reduction component of WSJF."""
        risk_values = {
            "high": 10,
            "medium": 6,
            "low": 3
        }
        return risk_values.get(item.risk_level, 3)
    
    def _calculate_opportunity_enablement(self, item: ValueItem) -> float:
        """Calculate opportunity enablement component of WSJF."""
        if "security" in item.impact_areas or "functionality" in item.impact_areas:
            return 8
        elif "performance" in item.impact_areas:
            return 6
        else:
            return 4
    
    def _calculate_impact(self, item: ValueItem) -> float:
        """Calculate impact component of ICE (1-10 scale)."""
        if item.category in ["security", "security-implementation"]:
            return 9
        elif item.category == "testing":
            return 7
        elif item.category in ["performance", "code-quality"]:
            return 6
        else:
            return 4
    
    def _calculate_confidence(self, item: ValueItem) -> float:
        """Calculate confidence component of ICE (1-10 scale)."""
        if item.file_path and item.line_number:
            return 8  # High confidence - specific location
        elif item.file_path:
            return 6  # Medium confidence - specific file
        else:
            return 4  # Lower confidence - general item
    
    def _calculate_ease(self, item: ValueItem) -> float:
        """Calculate ease component of ICE (1-10 scale)."""
        if item.estimated_effort_hours <= 1:
            return 9
        elif item.estimated_effort_hours <= 4:
            return 7
        elif item.estimated_effort_hours <= 8:
            return 5
        else:
            return 3
    
    def _calculate_technical_debt_score(self, item: ValueItem) -> float:
        """Calculate technical debt score."""
        if item.category == "technical-debt":
            return 60
        elif item.category in ["code-quality", "testing"]:
            return 40
        elif item.category == "dependencies":
            return 20
        else:
            return 10
    
    def save_backlog(self, opportunities: List[ValueItem]) -> None:
        """Save discovered opportunities to backlog file."""
        backlog_data = {
            "last_updated": datetime.now().isoformat(),
            "total_items": len(opportunities),
            "repository": self.config["repository"]["name"],
            "maturity_level": self.config["repository"]["maturityLevel"],
            "items": [asdict(item) for item in opportunities]
        }
        
        os.makedirs(self.backlog_file.parent, exist_ok=True)
        with open(self.backlog_file, 'w') as f:
            json.dump(backlog_data, f, indent=2)
    
    def load_backlog(self) -> List[ValueItem]:
        """Load existing backlog from file."""
        if not self.backlog_file.exists():
            return []
            
        try:
            with open(self.backlog_file, 'r') as f:
                data = json.load(f)
                return [ValueItem(**item) for item in data.get("items", [])]
        except (json.JSONDecodeError, TypeError):
            return []
    
    def get_next_best_value(self) -> Optional[ValueItem]:
        """Get the next highest-value item to work on."""
        opportunities = self.load_backlog()
        if not opportunities:
            opportunities = self.discover_value_opportunities()
            self.save_backlog(opportunities)
        
        # Filter out items that are too risky or have unmet dependencies
        viable_items = []
        for item in opportunities:
            if self._assess_item_viability(item):
                viable_items.append(item)
        
        return viable_items[0] if viable_items else None
    
    def _assess_item_viability(self, item: ValueItem) -> bool:
        """Assess if an item is viable for execution."""
        # Check risk threshold
        max_risk = self.config["scoring"]["thresholds"]["maxRisk"]
        risk_scores = {"low": 0.2, "medium": 0.5, "high": 0.8}
        if risk_scores.get(item.risk_level, 0.5) > max_risk:
            return False
        
        # Check dependencies (simplified - assume no dependencies for now)
        if item.dependencies:
            return False
            
        return True


def main():
    """Main entry point for the discovery engine."""
    engine = ValueDiscoveryEngine()
    
    print("🔍 Terragon Value Discovery Engine")
    print("=" * 50)
    
    # Discover opportunities
    opportunities = engine.discover_value_opportunities()
    engine.save_backlog(opportunities)
    
    print(f"📊 Discovered {len(opportunities)} value opportunities")
    
    # Show top 5
    print("\n🎯 Top 5 Value Opportunities:")
    for i, item in enumerate(opportunities[:5], 1):
        print(f"{i}. [{item.composite_score:.1f}] {item.title}")
        print(f"   Category: {item.category} | Effort: {item.estimated_effort_hours}h | Risk: {item.risk_level}")
        print(f"   WSJF: {item.wsjf_score:.1f} | ICE: {item.ice_score:.0f} | Debt: {item.technical_debt_score:.0f}")
        print()
    
    # Get next best value
    next_item = engine.get_next_best_value()
    if next_item:
        print(f"🚀 Next Best Value: {next_item.title}")
        print(f"   Score: {next_item.composite_score:.1f} | Effort: {next_item.estimated_effort_hours}h")


if __name__ == "__main__":
    main()