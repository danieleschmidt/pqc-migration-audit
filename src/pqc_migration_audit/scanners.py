"""Language-specific scanners for cryptographic vulnerability detection."""

import re
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass

from .types import CryptoAlgorithm, Severity


@dataclass
class Finding:
    """Represents a single cryptographic finding from scanning."""
    pattern: str
    file_path: str
    line_number: int
    context: str
    algorithm: str
    confidence: float = 1.0


class BaseScanner:
    """Base class for language-specific scanners."""
    
    def __init__(self):
        self.patterns = {}
    
    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan a file for cryptographic patterns."""
        raise NotImplementedError


class PythonScanner(BaseScanner):
    """Scanner for Python files."""
    
    def __init__(self):
        super().__init__()
        self.patterns = {
            'rsa_generation': [
                r'rsa\.generate_private_key\s*\(',
                r'RSA\.generate\s*\(',
                r'from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+rsa',
            ],
            'ecc_generation': [
                r'ec\.generate_private_key\s*\(',
                r'ECC\.generate\s*\(',
                r'SECP256R1\s*\(',
                r'SECP384R1\s*\(',
                r'SECP521R1\s*\(',
            ],
        }
    
    def scan_file(self, file_path: Path) -> List[Finding]:
        """Scan Python file for crypto patterns."""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Scan for RSA patterns
            for pattern in self.patterns['rsa_generation']:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    
                    # Get multi-line context for key size detection
                    context_lines = []
                    start_line = max(0, line_num - 1)
                    end_line = min(len(lines), line_num + 5)  # Look ahead for key_size
                    for i in range(start_line, end_line):
                        if i < len(lines):
                            context_lines.append(lines[i].strip())
                    
                    context = " ".join(context_lines)
                    
                    findings.append(Finding(
                        pattern=pattern,
                        file_path=str(file_path),
                        line_number=line_num,
                        context=context,
                        algorithm="RSA"
                    ))
            
            # Scan for ECC patterns
            for pattern in self.patterns['ecc_generation']:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append(Finding(
                        pattern=pattern,
                        file_path=str(file_path),
                        line_number=line_num,
                        context=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        algorithm="ECC"
                    ))
                    
        except Exception as e:
            # Handle file reading errors gracefully
            pass
            
        return findings