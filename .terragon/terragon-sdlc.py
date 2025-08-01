#!/usr/bin/env python3
"""
Terragon Autonomous SDLC Orchestrator
Main entry point for the autonomous SDLC enhancement system
"""

import json
import yaml
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import sys
import os

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    from discovery_engine import ValueDiscoveryEngine
    from scoring_engine import AdaptiveScoringEngine  
    from autonomous_executor import AutonomousExecutor
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're running from the repository root directory")
    sys.exit(1)


class TerrragonSDLC:
    """Main orchestrator for Terragon Autonomous SDLC."""
    
    def __init__(self, config_path: str = ".terragon/value-config.yaml"):
        """Initialize the Terragon SDLC system."""
        self.config_path = config_path
        self.repo_root = Path.cwd()
        
        # Initialize components
        self.discovery_engine = ValueDiscoveryEngine(config_path)
        self.scoring_engine = AdaptiveScoringEngine(config_path)
        self.executor = AutonomousExecutor(config_path)
        
    def discover_value(self) -> int:
        """Run value discovery and update backlog."""
        print("🔍 Terragon Value Discovery")
        print("=" * 50)
        
        # Discover opportunities
        opportunities = self.discovery_engine.discover_value_opportunities()
        self.discovery_engine.save_backlog(opportunities)
        
        print(f"📊 Discovered {len(opportunities)} value opportunities")
        
        if opportunities:
            print("\n🎯 Top 5 Value Opportunities:")
            for i, item in enumerate(opportunities[:5], 1):
                print(f"{i}. [{item.composite_score:.1f}] {item.title}")
                print(f"   Category: {item.category} | Effort: {item.estimated_effort_hours}h")
                print(f"   Risk: {item.risk_level} | Priority: {item.priority}")
                print()
        
        return len(opportunities)
    
    def execute_next(self) -> bool:
        """Execute the next highest-value item."""
        print("🚀 Terragon Autonomous Execution")
        print("=" * 50)
        
        result = self.executor.execute_next_best_value()
        
        if result:
            success = "✅ SUCCESS" if result.success else "❌ FAILED"
            print(f"\n{success}")
            print(f"Duration: {result.duration:.1f}s")
            print(f"Steps Completed: {result.steps_completed}")
            
            if result.errors:
                print(f"Errors: {len(result.errors)}")
                for error in result.errors[:3]:  # Show first 3 errors
                    print(f"  - {error}")
            
            return result.success
        else:
            print("📭 No value items available for execution")
            return False
    
    def run_continuous(self, max_iterations: int = 10) -> None:
        """Run continuous autonomous loop."""
        print("🔄 Terragon Continuous Autonomous SDLC")
        print("=" * 50)
        print(f"Running up to {max_iterations} iterations...")
        print()
        
        self.executor.run_continuous_loop(max_iterations)
    
    def generate_backlog_report(self) -> None:
        """Generate comprehensive backlog report."""
        print("📋 Terragon Backlog Report")
        print("=" * 50)
        
        # Load current backlog
        opportunities = self.discovery_engine.load_backlog()
        
        if not opportunities:
            print("📭 No items in backlog. Run discovery first.")
            return
        
        # Generate BACKLOG.md
        self._generate_backlog_markdown(opportunities)
        
        # Print summary
        total_items = len(opportunities)
        total_effort = sum(item.estimated_effort_hours for item in opportunities)
        avg_score = sum(item.composite_score for item in opportunities) / total_items
        
        categories = {}
        for item in opportunities:
            categories[item.category] = categories.get(item.category, 0) + 1
        
        print(f"📊 Backlog Summary:")
        print(f"   Total Items: {total_items}")
        print(f"   Total Effort: {total_effort:.1f} hours")
        print(f"   Average Score: {avg_score:.1f}")
        print(f"   Categories: {len(categories)}")
        
        print(f"\n📈 Category Breakdown:")
        for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            print(f"   {category}: {count} items")
        
        print(f"\n🎯 Next Best Value:")
        if opportunities:
            next_item = opportunities[0]
            print(f"   {next_item.title}")
            print(f"   Score: {next_item.composite_score:.1f} | Effort: {next_item.estimated_effort_hours}h")
            print(f"   Category: {next_item.category} | Priority: {next_item.priority}")
    
    def _generate_backlog_markdown(self, opportunities: List) -> None:
        """Generate BACKLOG.md file with discovered opportunities."""
        
        backlog_content = f"""# 📊 Terragon Autonomous Value Backlog

**Repository**: {self.discovery_engine.config.get('repository', {}).get('name', 'Unknown')}
**Last Updated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
**Total Items**: {len(opportunities)}

## 🎯 Next Best Value Item

"""
        
        if opportunities:
            next_item = opportunities[0]
            backlog_content += f"""**[{next_item.id.upper()}] {next_item.title}**
- **Composite Score**: {next_item.composite_score:.1f}
- **WSJF**: {next_item.wsjf_score:.1f} | **ICE**: {next_item.ice_score:.0f} | **Tech Debt**: {next_item.technical_debt_score:.0f}
- **Estimated Effort**: {next_item.estimated_effort_hours} hours
- **Category**: {next_item.category}
- **Priority**: {next_item.priority} | **Risk**: {next_item.risk_level}
- **Impact Areas**: {', '.join(next_item.impact_areas)}

"""
        
        backlog_content += """## 📋 Top 10 Backlog Items

| Rank | ID | Title | Score | Category | Hours | Priority | Risk |
|------|-----|--------|---------|----------|-------|----------|------|
"""
        
        for i, item in enumerate(opportunities[:10], 1):
            title_short = item.title[:50] + "..." if len(item.title) > 50 else item.title
            backlog_content += f"| {i} | {item.id} | {title_short} | {item.composite_score:.1f} | {item.category} | {item.estimated_effort_hours} | {item.priority} | {item.risk_level} |\n"
        
        # Category breakdown
        categories = {}
        for item in opportunities:
            if item.category not in categories:
                categories[item.category] = {"count": 0, "effort": 0, "avg_score": 0}
            categories[item.category]["count"] += 1
            categories[item.category]["effort"] += item.estimated_effort_hours
            categories[item.category]["avg_score"] += item.composite_score
        
        # Calculate averages
        for category, data in categories.items():
            data["avg_score"] = data["avg_score"] / data["count"]
        
        backlog_content += f"""

## 📈 Category Analysis

| Category | Count | Total Hours | Avg Score | Priority |
|----------|-------|-------------|-----------|----------|
"""
        
        for category, data in sorted(categories.items(), key=lambda x: x[1]["avg_score"], reverse=True):
            backlog_content += f"| {category} | {data['count']} | {data['effort']:.1f} | {data['avg_score']:.1f} | {'🔴' if data['avg_score'] > 70 else '🟡' if data['avg_score'] > 50 else '🟢'} |\n"
        
        # Value metrics
        total_effort = sum(item.estimated_effort_hours for item in opportunities)
        security_items = [item for item in opportunities if "security" in item.category]
        high_priority = [item for item in opportunities if item.priority == "high"]
        
        backlog_content += f"""

## 📊 Value Metrics

- **Total Backlog Effort**: {total_effort:.1f} hours
- **Average Item Score**: {sum(item.composite_score for item in opportunities) / len(opportunities):.1f}
- **Security Items**: {len(security_items)} ({len(security_items)/len(opportunities)*100:.1f}%)
- **High Priority Items**: {len(high_priority)} ({len(high_priority)/len(opportunities)*100:.1f}%)
- **Technical Debt Items**: {len([i for i in opportunities if i.category == 'technical-debt'])}

## 🔄 Discovery Sources

Items discovered from:
- **Git History**: {len([i for i in opportunities if i.source == 'git-history'])} items
- **Code Comments**: {len([i for i in opportunities if i.source == 'code-comments'])} items  
- **Static Analysis**: {len([i for i in opportunities if i.source == 'static-analysis'])} items
- **Security Analysis**: {len([i for i in opportunities if i.source == 'security-analysis'])} items
- **Test Analysis**: {len([i for i in opportunities if i.source == 'test-analysis'])} items
- **Dependency Analysis**: {len([i for i in opportunities if i.source == 'dependency-analysis'])} items

## 🎯 Execution Strategy

### Phase 1: Critical Security Implementation
Focus on security-implementation items with scores >80

### Phase 2: Technical Debt Reduction  
Address high-impact technical debt items

### Phase 3: Quality & Performance
Improve code quality and performance optimizations

### Phase 4: Documentation & Dependencies
Complete documentation and dependency updates

---

*Last generated by Terragon Autonomous SDLC on {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}*
*Next discovery cycle: {(datetime.now()).strftime('%Y-%m-%d %H:%M:%S UTC')} (scheduled)*
"""
        
        # Write to file
        backlog_file = self.repo_root / "BACKLOG.md"
        with open(backlog_file, 'w') as f:
            f.write(backlog_content)
        
        print(f"📝 Generated backlog report: {backlog_file}")
    
    def show_insights(self) -> None:
        """Show scoring insights and system health."""
        print("🧠 Terragon System Insights")
        print("=" * 50)
        
        insights = self.scoring_engine.get_scoring_insights()
        
        print(f"📊 Model Performance:")
        print(f"   Effort Accuracy: {insights['model_accuracy']['effort']:.1%}")
        print(f"   Impact Accuracy: {insights['model_accuracy']['impact']:.1%}")
        print(f"   Total Outcomes: {insights['total_outcomes']}")
        print(f"   Recent Success Rate: {insights['recent_success_rate']:.1%}")
        
        if insights['top_performing_categories']:
            print(f"\n🏆 Top Performing Categories:")
            for cat_data in insights['top_performing_categories']:
                print(f"   {cat_data['category']}: {cat_data['success_rate']:.1%} success")
        
        # Repository health
        config = self.discovery_engine.config
        repo_info = config.get("repository", {})
        
        print(f"\n🏥 Repository Health:")
        print(f"   Maturity Level: {repo_info.get('maturityLevel', 'Unknown')}%")
        print(f"   Primary Language: {repo_info.get('primaryLanguage', 'Unknown')}")
        print(f"   Type: {repo_info.get('type', 'Unknown')}")
        
        # Load recent backlog to check system status
        opportunities = self.discovery_engine.load_backlog()
        if opportunities:
            avg_score = sum(item.composite_score for item in opportunities) / len(opportunities)
            high_value_items = len([item for item in opportunities if item.composite_score > 70])
            
            print(f"\n📈 Value Pipeline:")
            print(f"   Backlog Items: {len(opportunities)}")
            print(f"   Average Score: {avg_score:.1f}")
            print(f"   High-Value Items (>70): {high_value_items}")
            
            system_health = "🟢 Healthy" if avg_score > 50 and high_value_items > 0 else "🟡 Needs Attention"
            print(f"   System Health: {system_health}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="Terragon Autonomous SDLC Enhancement System")
    
    parser.add_argument(
        "command",
        choices=["discover", "execute", "continuous", "backlog", "insights", "full-cycle"],
        help="Command to execute"
    )
    
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=10,
        help="Maximum iterations for continuous mode (default: 10)"
    )
    
    parser.add_argument(
        "--config",
        default=".terragon/value-config.yaml",
        help="Path to configuration file"
    )
    
    args = parser.parse_args()
    
    # Initialize Terragon SDLC
    terragon = TerrragonSDLC(args.config)
    
    print("🤖 Terragon Autonomous SDLC Enhancement System")
    print(f"⚡ Repository: {terragon.discovery_engine.config.get('repository', {}).get('name', 'Unknown')}")
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print()
    
    try:
        if args.command == "discover":
            count = terragon.discover_value()
            print(f"\n✅ Discovered {count} value opportunities")
            
        elif args.command == "execute":
            success = terragon.execute_next()
            sys.exit(0 if success else 1)
            
        elif args.command == "continuous":
            terragon.run_continuous(args.max_iterations)
            
        elif args.command == "backlog":
            terragon.generate_backlog_report()
            
        elif args.command == "insights":
            terragon.show_insights()
            
        elif args.command == "full-cycle":
            print("🔄 Running Full Autonomous SDLC Cycle")
            print("=" * 50)
            
            # 1. Discover value
            print("\n1️⃣  VALUE DISCOVERY")
            count = terragon.discover_value()
            
            if count > 0:
                # 2. Generate backlog  
                print("\n2️⃣  BACKLOG GENERATION")
                terragon.generate_backlog_report()
                
                # 3. Execute next best value
                print("\n3️⃣  AUTONOMOUS EXECUTION")
                success = terragon.execute_next()
                
                # 4. Show insights
                print("\n4️⃣  SYSTEM INSIGHTS")
                terragon.show_insights()
                
                print(f"\n✅ Full cycle completed {'successfully' if success else 'with issues'}")
            else:
                print("\n📭 No value opportunities found")
    
    except KeyboardInterrupt:
        print("\n⏹️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()