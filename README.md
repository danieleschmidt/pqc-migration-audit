# pqc-migration-audit

**Post-Quantum Cryptography Migration Auditor** — scans your codebase for quantum-vulnerable cryptography and generates a prioritised migration roadmap aligned with NIST FIPS 203/204/205.

---

## Why This Matters

Classical public-key cryptography (RSA, ECC, DH, DSA) will be broken by sufficiently powerful quantum computers via Shor's algorithm. The **harvest-now-decrypt-later (HNDL)** threat means adversaries are already archiving encrypted traffic to decrypt once quantum computers arrive.

NIST finalised its first post-quantum standards in 2024:

| NIST Standard | Algorithm  | Purpose              |
|--------------|-----------|----------------------|
| FIPS 203     | **ML-KEM** (Kyber)      | Key encapsulation    |
| FIPS 204     | **ML-DSA** (Dilithium)  | Digital signatures   |
| FIPS 205     | **SLH-DSA** (SPHINCS+)  | Hash-based signatures |

This tool identifies every quantum-vulnerable algorithm in your codebase and maps each finding to the appropriate PQC replacement with step-by-step migration guidance.

---

## Features

- **Multi-language scanning**: Python, Go, Java, C, C++
- **Comprehensive pattern detection**: imports, key generation, signing, encryption, key exchange, key size declarations
- **Risk scoring**: CRITICAL / HIGH / MEDIUM / LOW based on algorithm, usage context, key size, and HNDL exposure
- **Migration roadmaps**: per-finding migration paths to ML-KEM, ML-DSA, or SLH-DSA
- **Enterprise reports**: JSON (CI/CD integration) or human-readable text
- **Zero dependencies**: pure Python stdlib only

---

## Installation

```bash
# From source
pip install -e .

# Or run directly
python -m pqc_migration_audit /path/to/codebase
```

---

## Usage

```bash
# Scan a codebase and print text report
pqc-audit /path/to/project

# Output JSON report to file
pqc-audit /path/to/project --output report.json --format json

# Filter to CRITICAL and HIGH findings only
pqc-audit /path/to/project --min-risk HIGH

# Exclude certain directories
pqc-audit /path/to/project --exclude vendor --exclude third_party
```

**Exit codes:**
- `0` — scan complete, no CRITICAL findings
- `1` — CRITICAL findings detected (useful for CI/CD gates)

---

## Example Output

```
══════════════════════════════════════════════════════════════════════
  PQC Migration Audit Report
  Scan root: /path/to/project
══════════════════════════════════════════════════════════════════════

SUMMARY
-------
  Total findings  : 7
  Unique files    : 4
  Est. total effort: 43 developer-days

  Risk breakdown:
    CRITICAL   2
    HIGH       3
    MEDIUM     1
    LOW        1

MIGRATION ROADMAP (sorted by risk)
──────────────────────────────────
  [1] CRITICAL — ECC (handshake)
       File  : src/tls/client.py:14
       Code  : ECDH()
       → Replace with: ML-KEM
       Replace ECDH key exchange with ML-KEM — highest HNDL risk.
       ...
```

---

## Architecture

```
src/pqc_migration_audit/
├── scanner.py    # CryptoScanner — pattern matching per language
├── risk.py       # RiskScorer — CRITICAL/HIGH/MEDIUM/LOW assignment
├── planner.py    # MigrationPlanner — PQC migration paths
├── report.py     # AuditReport — JSON + text report generation
└── cli.py        # CLI entry point (pqc-audit)
```

### Components

**`CryptoScanner`**
Walks a directory tree scanning Python/Go/Java/C/C++ files for ~80 patterns covering RSA, ECC, DH, and DSA across imports, key generation, signing, encryption, handshakes, and key size declarations.

**`RiskScorer`**
Scores each finding based on:
- Algorithm family (DH/DSA > ECC > RSA by quantum urgency)
- Usage context (handshake > sign > encrypt > import)
- Key size (sub-2048-bit RSA/DH earns additional risk)

**`MigrationPlanner`**
Maps each (algorithm, context) pair to a concrete migration path using a knowledge base aligned with NIST IR 8547 and FIPS 203/204/205. Recommends hybrid KEM patterns for transition periods.

**`AuditReport`**
Aggregates findings into a report with summary statistics, per-finding migration steps, effort estimates, and timeline recommendations by risk tier.

---

## Running Tests

```bash
~/anaconda3/bin/python3 -m pytest tests/ -v
```

---

## References

- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 — SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST IR 8547 — Migration to Post-Quantum Cryptography](https://csrc.nist.gov/pubs/ir/8547/ipd)
- [CISA Post-Quantum Cryptography Guidance](https://www.cisa.gov/quantum)

---

## License

MIT
