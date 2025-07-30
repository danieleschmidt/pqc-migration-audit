# Architecture Documentation

## Overview

PQC Migration Audit is designed as a modular, extensible tool for identifying quantum-vulnerable cryptographic implementations and suggesting post-quantum secure alternatives.

## System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Interface │    │   Web Interface │    │  GitHub Action  │
│                 │    │                 │    │                 │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────▼──────────────┐
                    │      Core Engine           │
                    │  ┌─────────────────────┐   │
                    │  │   CryptoAuditor     │   │
                    │  └─────────────────────┘   │
                    └─────────────┬──────────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
   ┌──────▼──────┐        ┌───────▼───────┐       ┌──────▼──────┐
   │  Scanners   │        │   Analyzers   │       │  Reporters  │
   │             │        │               │       │             │
   │ • Python    │        │ • RSA         │       │ • JSON      │
   │ • Java      │        │ • ECC         │       │ • HTML      │
   │ • Go        │        │ • DSA         │       │ • SARIF     │
   │ • JavaScript│        │ • Diffie-Hell │       │ • CSV       │
   │ • C/C++     │        │ • Custom      │       │ • Dashboard │
   └─────────────┘        └───────────────┘       └─────────────┘
```

## Core Components

### 1. CryptoAuditor (Core Engine)

**Responsibilities**:
- Orchestrates the scanning process
- Manages scanner and analyzer plugins
- Coordinates risk assessment
- Handles configuration and settings

**Key Methods**:
```python
class CryptoAuditor:
    def scan_directory(path: str, options: ScanOptions) -> ScanResults
    def scan_file(file: Path, language: str) -> FileResults
    def analyze_vulnerabilities(results: ScanResults) -> RiskAssessment
    def generate_patches(vulnerabilities: List[Vulnerability]) -> PatchSet
```

### 2. Scanner System

**Purpose**: Language-specific code parsing and analysis.

**Architecture**:
```python
class Scanner(ABC):
    @abstractmethod
    def scan_file(self, file_path: Path) -> List[Finding]
    
    @abstractmethod
    def supported_extensions(self) -> List[str]
    
    @abstractmethod
    def extract_crypto_usage(self, ast: AST) -> List[CryptoUsage]

# Language-specific implementations
class PythonScanner(Scanner): ...
class JavaScanner(Scanner): ...
class GoScanner(Scanner): ...
```

**Scanner Registry**:
- Auto-discovery of scanner plugins
- Language detection based on file extensions
- Custom scanner registration for enterprise use

### 3. Analyzer System

**Purpose**: Pattern matching for cryptographic vulnerabilities.

**Vulnerability Types**:
- **Asymmetric Crypto**: RSA, ECC, DSA, Diffie-Hellman
- **Key Sizes**: Insufficient key lengths
- **Algorithms**: Deprecated/weak algorithms
- **Libraries**: Known vulnerable implementations
- **Configurations**: Insecure parameter usage

**Analyzer Chain**:
```python
class AnalyzerChain:
    def __init__(self):
        self.analyzers = [
            RSAAnalyzer(),
            ECCAnalyzer(),
            DSAAnalyzer(),
            DHAnalyzer(),
            WeakRandomAnalyzer(),
            CustomPatternAnalyzer()
        ]
    
    def analyze(self, findings: List[Finding]) -> List[Vulnerability]:
        vulnerabilities = []
        for analyzer in self.analyzers:
            vulnerabilities.extend(analyzer.analyze(findings))
        return self.deduplicate(vulnerabilities)
```

### 4. Risk Assessment Engine

**Components**:
- **HNDL Calculator**: Harvest Now, Decrypt Later risk scoring
- **Timeline Assessor**: Migration urgency based on quantum timeline
- **Impact Analyzer**: Business impact assessment
- **Effort Estimator**: Migration complexity scoring

**Risk Scoring Formula**:
```
Risk Score = (Algorithm_Weakness × 0.4) + 
             (Key_Size_Factor × 0.3) + 
             (Usage_Frequency × 0.2) + 
             (Timeline_Urgency × 0.1)

Where each factor ranges from 0-100
```

### 5. Reporter System

**Output Formats**:
- **JSON**: Machine-readable results
- **HTML**: Interactive dashboard with charts
- **SARIF**: Security analysis format for CI/CD
- **CSV**: Spreadsheet-compatible export
- **PDF**: Executive summary reports

**Report Components**:
- Executive summary with key metrics
- Detailed vulnerability listings
- Risk heat maps and visualizations
- Migration roadmap and timelines
- Cost-benefit analysis

## Data Flow

### 1. Scanning Phase
```
Repository → File Discovery → Language Detection → Scanner Selection → 
AST Parsing → Crypto Pattern Extraction → Finding Generation
```

### 2. Analysis Phase
```
Findings → Vulnerability Matching → Risk Scoring → 
Impact Assessment → Prioritization → Patch Generation
```

### 3. Reporting Phase
```
Vulnerabilities → Report Generation → Format Selection → 
Output Generation → Dashboard Updates → Notifications
```

## Plugin Architecture

### Scanner Plugins
```python
# Plugin structure
pqc_migration_audit/
├── scanners/
│   ├── python_scanner.py
│   ├── java_scanner.py
│   └── plugins/
│       ├── rust_scanner.py        # Third-party plugin
│       └── kotlin_scanner.py      # Custom scanner
```

### Analyzer Plugins
```python
# Custom vulnerability patterns
class CustomAnalyzer(Analyzer):
    def __init__(self, patterns_file: Path):
        self.patterns = self.load_patterns(patterns_file)
    
    def analyze(self, findings: List[Finding]) -> List[Vulnerability]:
        # Custom pattern matching logic
        pass
```

### Reporter Plugins
```python
# Custom output formats
class SlackReporter(Reporter):
    def generate_report(self, results: ScanResults) -> None:
        # Send formatted results to Slack
        pass
```

## Configuration System

### Configuration Hierarchy
1. **Default settings**: Built-in secure defaults
2. **Global config**: System-wide settings
3. **Project config**: Repository-specific settings
4. **CLI arguments**: Runtime overrides

### Configuration Files
```yaml
# .pqc-audit.yml
scan:
  languages: ["python", "java", "go"]
  exclude_patterns: ["*/tests/*", "*/venv/*"]
  max_file_size: "10MB"

analyzers:
  rsa:
    min_key_size: 2048
    warn_key_size: 4096
  ecc:
    allowed_curves: ["secp256r1", "secp384r1"]

reporting:
  formats: ["json", "html"]
  output_dir: "./pqc-reports"
  include_patches: true

risk_assessment:
  timeline: "2027-01-01"  # Migration deadline
  criticality_threshold: 75
```

## Security Considerations

### Input Validation
- File path sanitization
- Maximum file size limits
- Repository size constraints
- Malicious pattern detection

### Output Sanitization
- No sensitive data in reports
- Configurable data masking
- Secure temporary file handling
- Audit trail logging

### Runtime Security
- Sandboxed execution environment
- Resource usage limits
- Permission restrictions
- Network access controls

## Performance Optimizations

### Parallel Processing
- Multi-threaded file scanning
- Concurrent analyzer execution
- Parallel report generation
- Worker pool management

### Caching Strategy
- AST parsing results cached
- Vulnerability pattern cache
- Incremental scanning support
- Result memoization

### Memory Management
- Streaming file processing
- Lazy loading of resources
- Garbage collection optimization
- Memory usage monitoring

## Extensibility Points

### Adding New Languages
1. Implement `Scanner` interface
2. Register file extension mappings
3. Provide AST parsing logic
4. Define crypto pattern extractors

### Custom Vulnerability Patterns
1. Define pattern in YAML/JSON
2. Specify matching rules
3. Configure risk scoring
4. Add mitigation suggestions

### Integration Points
- **CI/CD Systems**: GitHub Actions, Jenkins, GitLab CI
- **Cloud Platforms**: AWS, Azure, GCP
- **Security Tools**: SonarQube, Veracode, Checkmarx
- **Monitoring**: Prometheus, Grafana, DataDog

## Future Architecture Enhancements

### Planned Features
- **Machine Learning**: Pattern recognition improvements
- **Cloud Backend**: Centralized vulnerability database
- **Real-time Monitoring**: Continuous crypto scanning
- **API Gateway**: RESTful API for integrations
- **Microservices**: Distributed scanning architecture