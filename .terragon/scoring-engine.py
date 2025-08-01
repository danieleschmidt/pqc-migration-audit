#!/usr/bin/env python3
"""
Terragon Advanced Scoring Engine
Implements WSJF + ICE + Technical Debt + Machine Learning scoring
"""

import json
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import pickle
import os
from pathlib import Path


@dataclass 
class ScoringMetrics:
    """Comprehensive scoring metrics for a value item."""
    wsjf_score: float
    ice_score: float
    technical_debt_score: float
    security_score: float
    performance_score: float
    composite_score: float
    confidence_interval: Tuple[float, float]
    risk_adjusted_score: float
    
    
@dataclass
class ExecutionOutcome:
    """Records the outcome of executing a value item."""
    item_id: str
    predicted_effort: float
    actual_effort: float
    predicted_impact: float
    actual_impact: float
    success: bool
    completion_time: str
    lessons_learned: str
    

class AdaptiveScoringEngine:
    """Advanced scoring engine with machine learning capabilities."""
    
    def __init__(self, config_path: str = ".terragon/value-config.yaml"):
        """Initialize the adaptive scoring engine."""
        self.config_path = config_path
        self.model_path = Path(".terragon/scoring-model.pkl")
        self.history_path = Path(".terragon/execution-history.json")
        self.learning_enabled = True
        
        # Load or initialize scoring model
        self.model = self._load_or_create_model()
        self.execution_history = self._load_execution_history()
        
    def _load_or_create_model(self) -> Dict[str, Any]:
        """Load existing model or create new one."""
        if self.model_path.exists():
            try:
                with open(self.model_path, 'rb') as f:
                    return pickle.load(f)
            except (pickle.UnpicklingError, FileNotFoundError):
                pass
                
        return {
            "effort_weights": {"complexity": 0.4, "scope": 0.3, "dependencies": 0.3},
            "impact_weights": {"users": 0.3, "technical": 0.3, "business": 0.4},
            "accuracy_metrics": {"effort": 0.85, "impact": 0.78},
            "calibration_data": [],
            "last_updated": datetime.now().isoformat()
        }
    
    def _save_model(self) -> None:
        """Save the current model state."""
        os.makedirs(self.model_path.parent, exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump(self.model, f)
    
    def _load_execution_history(self) -> List[ExecutionOutcome]:
        """Load historical execution outcomes."""
        if not self.history_path.exists():
            return []
            
        try:
            with open(self.history_path, 'r') as f:
                data = json.load(f)
                return [ExecutionOutcome(**item) for item in data.get("outcomes", [])]
        except (json.JSONDecodeError, TypeError):
            return []
    
    def _save_execution_history(self) -> None:
        """Save execution history to file."""
        history_data = {
            "last_updated": datetime.now().isoformat(),
            "total_outcomes": len(self.execution_history),
            "outcomes": [asdict(outcome) for outcome in self.execution_history]
        }
        
        os.makedirs(self.history_path.parent, exist_ok=True)
        with open(self.history_path, 'w') as f:
            json.dump(history_data, f, indent=2)
    
    def calculate_comprehensive_score(self, item: Dict[str, Any]) -> ScoringMetrics:
        """Calculate comprehensive scoring metrics for a value item."""
        
        # Calculate individual scores
        wsjf = self._calculate_wsjf_score(item)
        ice = self._calculate_ice_score(item)
        tech_debt = self._calculate_technical_debt_score(item)
        security = self._calculate_security_score(item)
        performance = self._calculate_performance_score(item)
        
        # Calculate composite score with adaptive weights
        composite = self._calculate_composite_score(wsjf, ice, tech_debt, security, performance, item)
        
        # Calculate confidence interval based on historical accuracy
        confidence_interval = self._calculate_confidence_interval(composite, item)
        
        # Risk-adjusted score
        risk_adjusted = self._calculate_risk_adjusted_score(composite, item)
        
        return ScoringMetrics(
            wsjf_score=wsjf,
            ice_score=ice,
            technical_debt_score=tech_debt,
            security_score=security,
            performance_score=performance,
            composite_score=composite,
            confidence_interval=confidence_interval,
            risk_adjusted_score=risk_adjusted
        )
    
    def _calculate_wsjf_score(self, item: Dict[str, Any]) -> float:
        """Calculate Weighted Shortest Job First score."""
        
        # Cost of Delay components
        user_business_value = self._get_user_business_value(item)
        time_criticality = self._get_time_criticality(item)
        risk_reduction = self._get_risk_reduction_value(item)
        opportunity_enablement = self._get_opportunity_enablement(item)
        
        cost_of_delay = user_business_value + time_criticality + risk_reduction + opportunity_enablement
        
        # Job Size (adjusted by historical data)
        base_effort = item.get("estimated_effort_hours", 4.0)
        adjusted_effort = self._adjust_effort_estimate(base_effort, item)
        job_size = adjusted_effort / 4.0  # Convert to story points
        
        return cost_of_delay / max(job_size, 0.25)  # Avoid division by zero
    
    def _calculate_ice_score(self, item: Dict[str, Any]) -> float:
        """Calculate Impact, Confidence, Ease score."""
        
        impact = self._get_impact_score(item)
        confidence = self._get_confidence_score(item)  
        ease = self._get_ease_score(item)
        
        return impact * confidence * ease
    
    def _calculate_technical_debt_score(self, item: Dict[str, Any]) -> float:
        """Calculate technical debt impact score."""
        
        category = item.get("category", "")
        file_path = item.get("file_path", "")
        
        base_score = {
            "technical-debt": 70,
            "code-quality": 50,
            "testing": 40,
            "dependencies": 25,
            "documentation": 15
        }.get(category, 30)
        
        # Adjust based on file criticality
        critical_paths = [
            "src/pqc_migration_audit/core.py",
            "src/pqc_migration_audit/cli.py", 
            "tests/"
        ]
        
        if any(critical in file_path for critical in critical_paths):
            base_score *= 1.5
        
        # Adjust based on historical churn (if available)
        churn_multiplier = self._get_file_churn_multiplier(file_path)
        
        return base_score * churn_multiplier
    
    def _calculate_security_score(self, item: Dict[str, Any]) -> float:
        """Calculate security impact score - critical for this project."""
        
        category = item.get("category", "")
        impact_areas = item.get("impact_areas", [])
        
        base_score = 0
        if category in ["security", "security-implementation"]:
            base_score = 90
        elif "security" in impact_areas:
            base_score = 60
        elif category in ["dependencies", "code-quality"]:
            base_score = 30
        
        # Boost for cryptography-related items
        description = item.get("description", "").lower()
        if any(crypto_term in description for crypto_term in ["crypto", "rsa", "ecc", "key", "encrypt"]):
            base_score *= 1.8
        
        return base_score
    
    def _calculate_performance_score(self, item: Dict[str, Any]) -> float:
        """Calculate performance impact score."""
        
        impact_areas = item.get("impact_areas", [])
        category = item.get("category", "")
        
        if "performance" in impact_areas:
            return 70
        elif category in ["testing", "code-quality"]:
            return 40
        elif category == "dependencies":
            return 25
        else:
            return 10
    
    def _calculate_composite_score(self, wsjf: float, ice: float, tech_debt: float, 
                                 security: float, performance: float, item: Dict[str, Any]) -> float:
        """Calculate weighted composite score."""
        
        # Normalize scores to 0-100 range
        normalized_wsjf = min(wsjf * 2, 100)  # WSJF typically 0-50
        normalized_ice = min(ice / 10, 100)   # ICE typically 0-1000
        normalized_debt = min(tech_debt, 100)
        normalized_security = min(security, 100)
        normalized_performance = min(performance, 100)
        
        # Adaptive weights based on project type and maturity
        weights = self._get_adaptive_weights(item)
        
        composite = (
            weights["wsjf"] * normalized_wsjf +
            weights["ice"] * normalized_ice +
            weights["technical_debt"] * normalized_debt +
            weights["security"] * normalized_security +
            weights["performance"] * normalized_performance
        )
        
        return composite
    
    def _get_adaptive_weights(self, item: Dict[str, Any]) -> Dict[str, float]:
        """Get adaptive weights based on context."""
        
        # Base weights for security-focused project
        base_weights = {
            "wsjf": 0.35,
            "ice": 0.15, 
            "technical_debt": 0.20,
            "security": 0.25,
            "performance": 0.05
        }
        
        # Adjust based on item category
        category = item.get("category", "")
        if category in ["security", "security-implementation"]:
            base_weights["security"] *= 1.5
            base_weights["wsjf"] *= 1.2
        elif category == "performance":
            base_weights["performance"] *= 2.0
            base_weights["wsjf"] *= 1.1
        elif category == "technical-debt":
            base_weights["technical_debt"] *= 1.3
            
        # Normalize weights to sum to 1.0
        total = sum(base_weights.values())
        return {k: v/total for k, v in base_weights.items()}
    
    def _calculate_confidence_interval(self, score: float, item: Dict[str, Any]) -> Tuple[float, float]:
        """Calculate confidence interval based on historical accuracy."""
        
        accuracy = self.model["accuracy_metrics"]["impact"]
        std_dev = (1.0 - accuracy) * score * 0.5  # Higher uncertainty for lower accuracy
        
        return (max(0, score - std_dev), min(100, score + std_dev))
    
    def _calculate_risk_adjusted_score(self, score: float, item: Dict[str, Any]) -> float:
        """Calculate risk-adjusted score."""
        
        risk_level = item.get("risk_level", "medium")
        risk_multipliers = {"low": 1.0, "medium": 0.9, "high": 0.7}
        
        return score * risk_multipliers.get(risk_level, 0.9)
    
    def _get_user_business_value(self, item: Dict[str, Any]) -> float:
        """Get user/business value component."""
        category_values = {
            "security": 15,
            "security-implementation": 20,
            "testing": 10,
            "performance": 8,
            "code-quality": 6,
            "technical-debt": 5,
            "dependencies": 4,
            "documentation": 3
        }
        
        base_value = category_values.get(item.get("category", ""), 5)
        
        # Boost for critical functionality
        if "core functionality" in item.get("description", "").lower():
            base_value *= 1.5
            
        return base_value
    
    def _get_time_criticality(self, item: Dict[str, Any]) -> float:
        """Get time criticality component."""
        priority = item.get("priority", "medium")
        priority_values = {"high": 12, "medium": 7, "low": 3}
        
        base_value = priority_values.get(priority, 7)
        
        # Boost for security items (regulatory compliance)
        if item.get("category") in ["security", "security-implementation"]:
            base_value *= 1.3
            
        return base_value
    
    def _get_risk_reduction_value(self, item: Dict[str, Any]) -> float:
        """Get risk reduction component."""
        risk_level = item.get("risk_level", "medium") 
        impact_areas = item.get("impact_areas", [])
        
        base_values = {"high": 15, "medium": 8, "low": 4}
        base_value = base_values.get(risk_level, 8)
        
        # Boost for security and reliability risks
        if any(area in impact_areas for area in ["security", "reliability", "functionality"]):
            base_value *= 1.4
            
        return base_value
    
    def _get_opportunity_enablement(self, item: Dict[str, Any]) -> float:
        """Get opportunity enablement component."""
        impact_areas = item.get("impact_areas", [])
        category = item.get("category", "")
        
        if "functionality" in impact_areas or category == "security-implementation":
            return 12
        elif "performance" in impact_areas:
            return 8
        elif "maintainability" in impact_areas:
            return 6
        else:
            return 4
    
    def _get_impact_score(self, item: Dict[str, Any]) -> float:
        """Get ICE impact score (1-10)."""
        category = item.get("category", "")
        
        impact_scores = {
            "security": 10,
            "security-implementation": 10,
            "performance": 8,
            "testing": 7,
            "code-quality": 6,
            "technical-debt": 5,
            "dependencies": 4,
            "documentation": 3
        }
        
        return impact_scores.get(category, 5)
    
    def _get_confidence_score(self, item: Dict[str, Any]) -> float:
        """Get ICE confidence score (1-10)."""
        confidence = 5  # Base confidence
        
        # Higher confidence for specific locations
        if item.get("file_path") and item.get("line_number"):
            confidence = 9
        elif item.get("file_path"):
            confidence = 7
        
        # Adjust based on historical accuracy for this category
        category = item.get("category", "")
        category_accuracy = self._get_category_accuracy(category)
        confidence *= category_accuracy
        
        return min(confidence, 10)
    
    def _get_ease_score(self, item: Dict[str, Any]) -> float:
        """Get ICE ease score (1-10)."""
        effort = item.get("estimated_effort_hours", 4.0)
        
        if effort <= 1:
            return 10
        elif effort <= 2:
            return 9
        elif effort <= 4:
            return 7
        elif effort <= 8:
            return 5
        elif effort <= 16:
            return 3
        else:
            return 2
    
    def _adjust_effort_estimate(self, base_effort: float, item: Dict[str, Any]) -> float:
        """Adjust effort estimate based on historical data."""
        category = item.get("category", "")
        
        # Get historical accuracy for this category
        category_outcomes = [o for o in self.execution_history if category in o.item_id]
        
        if len(category_outcomes) >= 3:
            avg_ratio = np.mean([o.actual_effort / max(o.predicted_effort, 0.1) for o in category_outcomes])
            return base_effort * avg_ratio
        
        # Default adjustments based on category complexity
        complexity_multipliers = {
            "security-implementation": 1.4,
            "security": 1.2,
            "performance": 1.3,
            "testing": 1.1,
            "technical-debt": 0.9,
            "dependencies": 0.8
        }
        
        return base_effort * complexity_multipliers.get(category, 1.0)
    
    def _get_file_churn_multiplier(self, file_path: str) -> float:
        """Get churn multiplier for file (simplified version)."""
        # In a real implementation, this would analyze git history
        critical_files = [
            "src/pqc_migration_audit/core.py",
            "src/pqc_migration_audit/cli.py"
        ]
        
        if any(critical in file_path for critical in critical_files):
            return 1.5  # High impact files get higher multiplier
        else:
            return 1.0
    
    def _get_category_accuracy(self, category: str) -> float:
        """Get historical accuracy for a category."""
        if not self.execution_history:
            return 1.0
            
        category_outcomes = [o for o in self.execution_history if category in o.item_id]
        
        if not category_outcomes:
            return 1.0
            
        # Calculate average success rate
        success_rate = sum(1 for o in category_outcomes if o.success) / len(category_outcomes)
        return success_rate
    
    def record_execution_outcome(self, outcome: ExecutionOutcome) -> None:
        """Record the outcome of an executed item."""
        self.execution_history.append(outcome)
        self._save_execution_history()
        
        # Update model if learning is enabled
        if self.learning_enabled:
            self._update_model_from_outcome(outcome)
    
    def _update_model_from_outcome(self, outcome: ExecutionOutcome) -> None:
        """Update scoring model based on execution outcome."""
        
        # Update effort estimation accuracy
        effort_ratio = outcome.actual_effort / max(outcome.predicted_effort, 0.1)
        impact_ratio = outcome.actual_impact / max(outcome.predicted_impact, 0.1)
        
        # Store calibration data
        self.model["calibration_data"].append({
            "effort_ratio": effort_ratio,
            "impact_ratio": impact_ratio,
            "success": outcome.success,
            "timestamp": outcome.completion_time
        })
        
        # Keep only recent calibration data (last 50 outcomes)
        if len(self.model["calibration_data"]) > 50:
            self.model["calibration_data"] = self.model["calibration_data"][-50:]
        
        # Recalculate accuracy metrics
        if len(self.model["calibration_data"]) >= 5:
            effort_ratios = [d["effort_ratio"] for d in self.model["calibration_data"]]
            impact_ratios = [d["impact_ratio"] for d in self.model["calibration_data"]]
            
            # Update accuracy metrics (simplified)
            effort_accuracy = 1.0 - min(0.5, np.std(effort_ratios))
            impact_accuracy = 1.0 - min(0.5, np.std(impact_ratios))
            
            self.model["accuracy_metrics"]["effort"] = effort_accuracy
            self.model["accuracy_metrics"]["impact"] = impact_accuracy
        
        self.model["last_updated"] = datetime.now().isoformat()
        self._save_model()
    
    def get_scoring_insights(self) -> Dict[str, Any]:
        """Get insights about scoring performance and model state."""
        
        insights = {
            "model_accuracy": self.model["accuracy_metrics"],
            "total_outcomes": len(self.execution_history),
            "recent_success_rate": 0.0,
            "top_performing_categories": [],
            "calibration_status": "good"
        }
        
        if self.execution_history:
            # Calculate recent success rate (last 10 outcomes)
            recent_outcomes = self.execution_history[-10:]
            insights["recent_success_rate"] = sum(1 for o in recent_outcomes if o.success) / len(recent_outcomes)
            
            # Find top performing categories
            category_performance = {}
            for outcome in self.execution_history:
                category = outcome.item_id.split('-')[0] if '-' in outcome.item_id else 'unknown'
                if category not in category_performance:
                    category_performance[category] = {"success": 0, "total": 0}
                category_performance[category]["total"] += 1
                if outcome.success:
                    category_performance[category]["success"] += 1
            
            # Sort by success rate
            sorted_categories = sorted(
                category_performance.items(),
                key=lambda x: x[1]["success"] / max(x[1]["total"], 1),
                reverse=True
            )
            
            insights["top_performing_categories"] = [
                {"category": cat, "success_rate": data["success"] / data["total"]}
                for cat, data in sorted_categories[:5]
            ]
        
        return insights


def main():
    """Main entry point for scoring engine testing."""
    engine = AdaptiveScoringEngine()
    
    # Test with a sample item
    sample_item = {
        "id": "security-impl-core",
        "title": "Implement core cryptographic scanning functionality",
        "category": "security-implementation",
        "priority": "high",
        "estimated_effort_hours": 8.0,
        "risk_level": "medium",
        "impact_areas": ["security", "functionality", "product-readiness"],
        "file_path": "src/pqc_migration_audit/core.py",
        "description": "Critical security functionality needs implementation"
    }
    
    print("🎯 Terragon Advanced Scoring Engine")
    print("=" * 50)
    
    metrics = engine.calculate_comprehensive_score(sample_item)
    
    print(f"📊 Comprehensive Scoring Results:")
    print(f"   WSJF Score: {metrics.wsjf_score:.2f}")
    print(f"   ICE Score: {metrics.ice_score:.0f}")
    print(f"   Technical Debt: {metrics.technical_debt_score:.1f}")
    print(f"   Security Score: {metrics.security_score:.1f}")
    print(f"   Performance Score: {metrics.performance_score:.1f}")
    print(f"   Composite Score: {metrics.composite_score:.1f}")
    print(f"   Confidence Interval: ({metrics.confidence_interval[0]:.1f}, {metrics.confidence_interval[1]:.1f})")
    print(f"   Risk-Adjusted Score: {metrics.risk_adjusted_score:.1f}")
    
    print(f"\n🧠 Model Insights:")
    insights = engine.get_scoring_insights()
    print(f"   Model Accuracy - Effort: {insights['model_accuracy']['effort']:.2%}")
    print(f"   Model Accuracy - Impact: {insights['model_accuracy']['impact']:.2%}")
    print(f"   Total Outcomes: {insights['total_outcomes']}")
    print(f"   Recent Success Rate: {insights['recent_success_rate']:.2%}")


if __name__ == "__main__":
    main()