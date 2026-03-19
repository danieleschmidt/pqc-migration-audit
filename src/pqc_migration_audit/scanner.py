"""
CryptoScanner: Detects quantum-vulnerable cryptographic usage in source code.

Supports Python, Go, Java, C/C++ files.
Detects: RSA, ECC, DH, DSA in imports, function calls, and key size declarations.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


# ──────────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class CryptoFinding:
    file_path: str
    line_number: int
    line_text: str
    algorithm: str          # RSA | ECC | DH | DSA
    usage_context: str      # import | keygen | sign | encrypt | handshake | keysize
    key_size: int | None = None
    matched_pattern: str = ""


# ──────────────────────────────────────────────────────────────────────────────
# Per-language pattern tables
# ──────────────────────────────────────────────────────────────────────────────

# Each entry: (regex, algorithm, usage_context)
_PYTHON_PATTERNS: list[tuple[str, str, str]] = [
    # RSA
    (r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+rsa", "RSA", "import"),
    (r"import\s+Crypto\.PublicKey\.RSA", "RSA", "import"),
    (r"from\s+Crypto\.PublicKey\s+import\s+RSA", "RSA", "import"),
    (r"rsa\.generate_private_key\s*\(", "RSA", "keygen"),
    (r"RSA\.generate\s*\(", "RSA", "keygen"),
    (r"RSA\.import_key\s*\(", "RSA", "import"),
    (r"PKCS1v15\s*\(", "RSA", "sign"),
    (r"PKCS1OAEP\s*\(", "RSA", "encrypt"),
    (r"rsa\.encrypt\s*\(", "RSA", "encrypt"),
    (r"rsa\.decrypt\s*\(", "RSA", "encrypt"),
    (r"rsa\.sign\s*\(", "RSA", "sign"),
    (r"rsa\.verify\s*\(", "RSA", "sign"),
    # ECC
    (r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+ec", "ECC", "import"),
    (r"from\s+Crypto\.PublicKey\s+import\s+ECC", "ECC", "import"),
    (r"ec\.generate_private_key\s*\(", "ECC", "keygen"),
    (r"ECC\.generate\s*\(", "ECC", "keygen"),
    (r"SECP(?:256|384|521)R1\s*\(", "ECC", "keygen"),
    (r"SECP256K1\s*\(", "ECC", "keygen"),
    (r"ECDSA\s*\(", "ECC", "sign"),
    (r"ECDH\s*\(", "ECC", "handshake"),
    # DH
    (r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+dh", "DH", "import"),
    (r"dh\.generate_parameters\s*\(", "DH", "keygen"),
    (r"DHparams_make\s*\(", "DH", "keygen"),
    # DSA
    (r"from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+dsa", "DSA", "import"),
    (r"from\s+Crypto\.PublicKey\s+import\s+DSA", "DSA", "import"),
    (r"dsa\.generate_private_key\s*\(", "DSA", "keygen"),
    (r"DSA\.generate\s*\(", "DSA", "keygen"),
    # Key size declarations (RSA/DH)
    (r"key_size\s*=\s*(\d+)", "RSA", "keysize"),
    (r"key_bits\s*=\s*(\d+)", "RSA", "keysize"),
]

_GO_PATTERNS: list[tuple[str, str, str]] = [
    # RSA
    (r'"crypto/rsa"', "RSA", "import"),
    (r"rsa\.GenerateKey\s*\(", "RSA", "keygen"),
    (r"rsa\.EncryptOAEP\s*\(", "RSA", "encrypt"),
    (r"rsa\.DecryptOAEP\s*\(", "RSA", "encrypt"),
    (r"rsa\.SignPKCS1v15\s*\(", "RSA", "sign"),
    (r"rsa\.VerifyPKCS1v15\s*\(", "RSA", "sign"),
    (r"rsa\.SignPSS\s*\(", "RSA", "sign"),
    (r"rsa\.VerifyPSS\s*\(", "RSA", "sign"),
    # ECC / ECDSA / ECDH
    (r'"crypto/elliptic"', "ECC", "import"),
    (r'"crypto/ecdsa"', "ECC", "import"),
    (r"ecdsa\.GenerateKey\s*\(", "ECC", "keygen"),
    (r"elliptic\.P(?:224|256|384|521)\b", "ECC", "keygen"),
    (r"ecdsa\.Sign\s*\(", "ECC", "sign"),
    (r"ecdsa\.Verify\s*\(", "ECC", "sign"),
    (r'"golang\.org/x/crypto/curve25519"', "ECC", "import"),
    (r"curve25519\.X25519\s*\(", "ECC", "handshake"),
    # DH
    (r'"crypto/dh"', "DH", "import"),
    # DSA
    (r'"crypto/dsa"', "DSA", "import"),
    (r"dsa\.GenerateKey\s*\(", "DSA", "keygen"),
    (r"dsa\.Sign\s*\(", "DSA", "sign"),
    (r"dsa\.Verify\s*\(", "DSA", "sign"),
    # Key sizes
    (r"bits\s*:?=\s*(\d+)", "RSA", "keysize"),
]

_JAVA_PATTERNS: list[tuple[str, str, str]] = [
    # RSA
    (r"import\s+java\.security\.interfaces\.RSA(?:Public|Private)Key", "RSA", "import"),
    (r'KeyPairGenerator\.getInstance\s*\(\s*"RSA"', "RSA", "keygen"),
    (r'Cipher\.getInstance\s*\(\s*"RSA', "RSA", "encrypt"),
    (r"RSAKeyGenParameterSpec\s*\(", "RSA", "keysize"),
    (r'Signature\.getInstance\s*\(\s*"SHA\d+withRSA', "RSA", "sign"),
    # ECC
    (r"import\s+java\.security\.interfaces\.ECKey", "ECC", "import"),
    (r'KeyPairGenerator\.getInstance\s*\(\s*"EC"', "ECC", "keygen"),
    (r'Signature\.getInstance\s*\(\s*"SHA\d+withECDSA', "ECC", "sign"),
    (r"ECNamedCurveTable\.getParameterSpec\s*\(", "ECC", "keygen"),
    (r"ECGenParameterSpec\s*\(", "ECC", "keygen"),
    # DH
    (r"import\s+javax\.crypto\.interfaces\.DHKey", "DH", "import"),
    (r'KeyPairGenerator\.getInstance\s*\(\s*"DH"', "DH", "keygen"),
    (r"DHParameterSpec\s*\(", "DH", "keysize"),
    # DSA
    (r"import\s+java\.security\.interfaces\.DSAKey", "DSA", "import"),
    (r'KeyPairGenerator\.getInstance\s*\(\s*"DSA"', "DSA", "keygen"),
    (r'Signature\.getInstance\s*\(\s*"SHA\d+withDSA', "DSA", "sign"),
    # Key sizes
    (r"initialize\s*\(\s*(\d+)\s*\)", "RSA", "keysize"),
]

_C_CPP_PATTERNS: list[tuple[str, str, str]] = [
    # RSA
    (r"#include\s+[<\"]openssl/rsa\.h[>\"]", "RSA", "import"),
    (r"RSA_generate_key(?:_ex)?\s*\(", "RSA", "keygen"),
    (r"RSA_public_encrypt\s*\(", "RSA", "encrypt"),
    (r"RSA_private_decrypt\s*\(", "RSA", "encrypt"),
    (r"RSA_sign\s*\(", "RSA", "sign"),
    (r"RSA_verify\s*\(", "RSA", "sign"),
    (r"EVP_RSA_gen\s*\(", "RSA", "keygen"),
    # ECC
    (r"#include\s+[<\"]openssl/ec\.h[>\"]", "ECC", "import"),
    (r"EC_KEY_generate_key\s*\(", "ECC", "keygen"),
    (r"EC_GROUP_new_by_curve_name\s*\(", "ECC", "keygen"),
    (r"ECDSA_sign\s*\(", "ECC", "sign"),
    (r"ECDSA_verify\s*\(", "ECC", "sign"),
    (r"ECDH_compute_key\s*\(", "ECC", "handshake"),
    # DH
    (r"#include\s+[<\"]openssl/dh\.h[>\"]", "DH", "import"),
    (r"DH_generate_parameters(?:_ex)?\s*\(", "DH", "keygen"),
    (r"DH_generate_key\s*\(", "DH", "keygen"),
    # DSA
    (r"#include\s+[<\"]openssl/dsa\.h[>\"]", "DSA", "import"),
    (r"DSA_generate_key\s*\(", "DSA", "keygen"),
    (r"DSA_sign\s*\(", "DSA", "sign"),
    (r"DSA_verify\s*\(", "DSA", "sign"),
    # Key sizes (bits=, RSA_bits, etc.)
    (r"RSA_bits\s*\(\s*\w+\s*\)", "RSA", "keysize"),
    (r"(?:key_bits|key_size|nBits)\s*=\s*(\d+)", "RSA", "keysize"),
]

_EXTENSION_MAP: dict[str, list[tuple[str, str, str]]] = {
    ".py":   _PYTHON_PATTERNS,
    ".go":   _GO_PATTERNS,
    ".java": _JAVA_PATTERNS,
    ".c":    _C_CPP_PATTERNS,
    ".cpp":  _C_CPP_PATTERNS,
    ".cc":   _C_CPP_PATTERNS,
    ".cxx":  _C_CPP_PATTERNS,
    ".h":    _C_CPP_PATTERNS,
    ".hpp":  _C_CPP_PATTERNS,
}

# ──────────────────────────────────────────────────────────────────────────────
# Key-size extraction helper
# ──────────────────────────────────────────────────────────────────────────────

_SIZE_INLINE = re.compile(r"\b(\d{3,5})\b")  # 3–5 digit numbers on the same line


def _extract_key_size(line: str, match: re.Match) -> int | None:
    """Try to extract a key-size integer from the regex match or surrounding text."""
    # First try a captured group from the pattern itself
    try:
        val = int(match.group(1))
        if 512 <= val <= 16384:
            return val
    except (IndexError, ValueError):
        pass
    # Fall back to any plausible size on the line
    for m in _SIZE_INLINE.finditer(line):
        v = int(m.group(1))
        if 512 <= v <= 16384:
            return v
    return None


# ──────────────────────────────────────────────────────────────────────────────
# CryptoScanner
# ──────────────────────────────────────────────────────────────────────────────

class CryptoScanner:
    """Scan a codebase directory for quantum-vulnerable cryptographic usage."""

    SUPPORTED_EXTENSIONS = set(_EXTENSION_MAP.keys())

    def scan_file(self, path: Path) -> list[CryptoFinding]:
        """Return findings for a single file."""
        suffix = path.suffix.lower()
        patterns = _EXTENSION_MAP.get(suffix)
        if patterns is None:
            return []

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

        findings: list[CryptoFinding] = []
        lines = text.splitlines()

        compiled = [(re.compile(pat, re.IGNORECASE), algo, ctx)
                    for pat, algo, ctx in patterns]

        for lineno, line in enumerate(lines, start=1):
            for regex, algo, ctx in compiled:
                m = regex.search(line)
                if m:
                    key_size = None
                    if ctx == "keysize":
                        key_size = _extract_key_size(line, m)
                    findings.append(CryptoFinding(
                        file_path=str(path),
                        line_number=lineno,
                        line_text=line.strip(),
                        algorithm=algo,
                        usage_context=ctx,
                        key_size=key_size,
                        matched_pattern=regex.pattern,
                    ))
                    # one match per line per pattern is enough
        return findings

    def scan_directory(self, root: Path,
                       exclude_dirs: set[str] | None = None) -> Iterator[CryptoFinding]:
        """Recursively scan *root* and yield findings."""
        exclude_dirs = exclude_dirs or {
            ".git", ".tox", ".venv", "venv", "env", "node_modules",
            "__pycache__", "dist", "build", ".terragon",
        }
        for path in root.rglob("*"):
            if path.is_file():
                if any(p in path.parts for p in exclude_dirs):
                    continue
                yield from self.scan_file(path)
