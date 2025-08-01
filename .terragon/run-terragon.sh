#!/bin/bash
#
# Terragon Autonomous SDLC Runner
# Main entry point for the autonomous SDLC enhancement system
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}🤖 Terragon Autonomous SDLC Enhancement System${NC}"
echo -e "${CYAN}===============================================${NC}"
echo -e "${BLUE}Repository: $(basename "$REPO_ROOT")${NC}"
echo -e "${BLUE}Timestamp: $(date -u '+%Y-%m-%d %H:%M:%S UTC')${NC}"
echo

# Check dependencies
echo -e "${YELLOW}🔍 Checking dependencies...${NC}"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 is required but not installed${NC}"
    exit 1
fi

# Check Git
if ! command -v git &> /dev/null; then
    echo -e "${RED}❌ Git is required but not installed${NC}"
    exit 1
fi

# Check if we're in a Git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${RED}❌ Not in a Git repository${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Dependencies satisfied${NC}"

# Install Python dependencies if needed
if [ ! -f "$REPO_ROOT/requirements.txt" ]; then
    echo -e "${YELLOW}⚠️  No requirements.txt found${NC}"
else
    echo -e "${YELLOW}📦 Installing Python dependencies...${NC}"
    cd "$REPO_ROOT"
    pip install -q -r requirements.txt
    echo -e "${GREEN}✅ Dependencies installed${NC}"
fi

# Change to repo root
cd "$REPO_ROOT"

# Parse command line arguments
COMMAND=${1:-"full-cycle"}
MAX_ITERATIONS=${2:-10}

case "$COMMAND" in
    "discover")
        echo -e "${PURPLE}🔍 Running Value Discovery...${NC}"
        python3 .terragon/terragon-sdlc.py discover
        ;;
    
    "execute")
        echo -e "${PURPLE}🚀 Executing Next Best Value...${NC}"
        python3 .terragon/terragon-sdlc.py execute
        ;;
    
    "continuous")
        echo -e "${PURPLE}🔄 Running Continuous Execution...${NC}"
        python3 .terragon/terragon-sdlc.py continuous --max-iterations "$MAX_ITERATIONS"
        ;;
    
    "backlog")
        echo -e "${PURPLE}📋 Generating Backlog Report...${NC}"
        python3 .terragon/terragon-sdlc.py backlog
        ;;
    
    "insights")
        echo -e "${PURPLE}🧠 Showing System Insights...${NC}"
        python3 .terragon/terragon-sdlc.py insights
        ;;
    
    "full-cycle")
        echo -e "${PURPLE}🔄 Running Full Autonomous SDLC Cycle...${NC}"
        python3 .terragon/terragon-sdlc.py full-cycle
        ;;
    
    "schedule")
        echo -e "${PURPLE}⏰ Setting up Autonomous Scheduling...${NC}"
        
        # Create cron-compatible scripts
        cat > "$SCRIPT_DIR/hourly-scan.sh" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")/.."
python3 .terragon/terragon-sdlc.py discover > .terragon/logs/hourly-$(date +%Y%m%d-%H).log 2>&1
EOF
        
        cat > "$SCRIPT_DIR/daily-execution.sh" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")/.."
python3 .terragon/terragon-sdlc.py execute > .terragon/logs/daily-$(date +%Y%m%d).log 2>&1
EOF
        
        chmod +x "$SCRIPT_DIR"/{hourly-scan.sh,daily-execution.sh}
        
        echo -e "${GREEN}✅ Scheduling scripts created${NC}"
        echo -e "${YELLOW}💡 To enable automated scheduling, add these cron entries:${NC}"
        echo -e "${CYAN}# Hourly security scan${NC}"
        echo -e "${CYAN}0 * * * * $SCRIPT_DIR/hourly-scan.sh${NC}"
        echo -e "${CYAN}# Daily autonomous execution${NC}"
        echo -e "${CYAN}0 2 * * * $SCRIPT_DIR/daily-execution.sh${NC}"
        ;;
    
    "test")
        echo -e "${PURPLE}🧪 Testing Terragon System...${NC}"
        
        # Test discovery engine
        echo -e "${YELLOW}Testing Discovery Engine...${NC}"
        python3 .terragon/discovery-engine.py
        
        echo
        
        # Test scoring engine  
        echo -e "${YELLOW}Testing Scoring Engine...${NC}"
        python3 .terragon/scoring-engine.py
        
        echo -e "${GREEN}✅ System tests completed${NC}"
        ;;
    
    "init")
        echo -e "${PURPLE}🏗️  Initializing Terragon System...${NC}"
        
        # Create necessary directories
        mkdir -p .terragon/{logs,artifacts}
        
        # Initialize empty files
        touch .terragon/{value-history.json,backlog.json,execution-history.json}
        
        # Add to gitignore if not present
        if [ -f .gitignore ]; then
            if ! grep -q ".terragon/logs" .gitignore; then
                echo "" >> .gitignore
                echo "# Terragon SDLC artifacts" >> .gitignore
                echo ".terragon/logs/" >> .gitignore
                echo ".terragon/artifacts/" >> .gitignore
                echo ".terragon/*.pkl" >> .gitignore
                echo ".terragon/*-history.json" >> .gitignore
            fi
        fi
        
        echo -e "${GREEN}✅ Terragon system initialized${NC}"
        echo -e "${YELLOW}💡 Run './terragon/run-terragon.sh test' to verify installation${NC}"
        ;;
    
    "help"|"-h"|"--help")
        echo -e "${CYAN}Terragon Autonomous SDLC Commands:${NC}"
        echo
        echo -e "${YELLOW}Basic Commands:${NC}"
        echo -e "  ${GREEN}discover${NC}     - Discover value opportunities"
        echo -e "  ${GREEN}execute${NC}      - Execute next best value item"
        echo -e "  ${GREEN}backlog${NC}      - Generate backlog report"
        echo -e "  ${GREEN}insights${NC}     - Show system insights"
        echo
        echo -e "${YELLOW}Advanced Commands:${NC}"
        echo -e "  ${GREEN}continuous${NC}   - Run continuous execution loop"
        echo -e "  ${GREEN}full-cycle${NC}   - Run complete SDLC cycle (default)"
        echo -e "  ${GREEN}schedule${NC}     - Setup autonomous scheduling"
        echo
        echo -e "${YELLOW}System Commands:${NC}"
        echo -e "  ${GREEN}init${NC}         - Initialize Terragon system"
        echo -e "  ${GREEN}test${NC}         - Test system components"
        echo -e "  ${GREEN}help${NC}         - Show this help message"
        echo
        echo -e "${YELLOW}Examples:${NC}"
        echo -e "  ${CYAN}./terragon/run-terragon.sh discover${NC}"
        echo -e "  ${CYAN}./terragon/run-terragon.sh continuous 5${NC}"
        echo -e "  ${CYAN}./terragon/run-terragon.sh full-cycle${NC}"
        ;;
    
    *)
        echo -e "${RED}❌ Unknown command: $COMMAND${NC}"
        echo -e "${YELLOW}💡 Run './terragon/run-terragon.sh help' for available commands${NC}"
        exit 1
        ;;
esac

echo
echo -e "${CYAN}🏁 Terragon execution completed at $(date -u '+%Y-%m-%d %H:%M:%S UTC')${NC}"