"""Tests for CryptoScanner using synthetic code snippets."""

import textwrap
from pathlib import Path

import pytest

from pqc_migration_audit.scanner import CryptoScanner


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_file(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ── Python ────────────────────────────────────────────────────────────────────

PYTHON_RSA_KEYGEN = """\
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
"""

PYTHON_ECC_SIGN = """\
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

    key = ec.generate_private_key(ec.SECP256R1())
    signature = key.sign(data, ECDSA(hashes.SHA256()))
"""

PYTHON_DH = """\
    from cryptography.hazmat.primitives.asymmetric import dh
    parameters = dh.generate_parameters(generator=2, key_size=2048)
"""

PYTHON_DSA = """\
    from Crypto.PublicKey import DSA
    key = DSA.generate(2048)
"""

PYTHON_RSA_OAEP = """\
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    key = RSA.generate(2048)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(b"secret")
"""

def test_python_rsa_keygen(tmp_path):
    f = make_file(tmp_path, "crypto.py", PYTHON_RSA_KEYGEN)
    scanner = CryptoScanner()
    findings = scanner.scan_file(f)
    algos = {x.algorithm for x in findings}
    assert "RSA" in algos
    contexts = {x.usage_context for x in findings}
    assert "import" in contexts or "keygen" in contexts


def test_python_ecc_sign(tmp_path):
    f = make_file(tmp_path, "sign.py", PYTHON_ECC_SIGN)
    findings = CryptoScanner().scan_file(f)
    assert any(x.algorithm == "ECC" for x in findings)
    assert any(x.usage_context in ("sign", "keygen", "import") for x in findings)


def test_python_dh(tmp_path):
    f = make_file(tmp_path, "dh.py", PYTHON_DH)
    findings = CryptoScanner().scan_file(f)
    assert any(x.algorithm == "DH" for x in findings)


def test_python_dsa(tmp_path):
    f = make_file(tmp_path, "dsa.py", PYTHON_DSA)
    findings = CryptoScanner().scan_file(f)
    assert any(x.algorithm == "DSA" for x in findings)


def test_python_rsa_encrypt(tmp_path):
    f = make_file(tmp_path, "oaep.py", PYTHON_RSA_OAEP)
    findings = CryptoScanner().scan_file(f)
    assert any(x.algorithm == "RSA" for x in findings)


def test_no_findings_in_clean_file(tmp_path):
    f = make_file(tmp_path, "clean.py", "x = 42\nprint('hello')\n")
    findings = CryptoScanner().scan_file(f)
    assert findings == []


# ── Go ────────────────────────────────────────────────────────────────────────

GO_RSA = """\
    package main

    import (
        "crypto/rsa"
        "crypto/rand"
    )

    func main() {
        key, _ := rsa.GenerateKey(rand.Reader, 2048)
        _ = rsa.SignPKCS1v15(rand.Reader, key, 0, nil)
    }
"""

GO_ECDSA = """\
    package main

    import (
        "crypto/ecdsa"
        "crypto/elliptic"
        "crypto/rand"
    )

    func main() {
        key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
        sig, _ := ecdsa.Sign(rand.Reader, key, nil)
        _ = sig
    }
"""

def test_go_rsa(tmp_path):
    f = make_file(tmp_path, "rsa.go", GO_RSA)
    findings = CryptoScanner().scan_file(f)
    assert any(x.algorithm == "RSA" for x in findings)


def test_go_ecdsa(tmp_path):
    f = make_file(tmp_path, "ecdsa.go", GO_ECDSA)
    findings = CryptoScanner().scan_file(f)
    assert any(x.algorithm == "ECC" for x in findings)


# ── Java ─────────────────────────────────────────────────────────────────────

JAVA_RSA = """\
    import java.security.KeyPairGenerator;
    import java.security.interfaces.RSAPublicKey;

    public class RsaExample {
        public static void main(String[] args) throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
        }
    }
"""

JAVA_ECDSA = """\
    import java.security.KeyPairGenerator;
    import java.security.Signature;
    import java.security.spec.ECGenParameterSpec;

    public class EcdsaExample {
        public void sign() throws Exception {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            Signature sig = Signature.getInstance("SHA256withECDSA");
        }
    }
"""

def test_java_rsa(tmp_path):
    f = make_file(tmp_path, "Rsa.java", JAVA_RSA)
    findings = CryptoScanner().scan_file(f)
    assert any(x.algorithm == "RSA" for x in findings)


def test_java_ecdsa(tmp_path):
    f = make_file(tmp_path, "Ecdsa.java", JAVA_ECDSA)
    findings = CryptoScanner().scan_file(f)
    assert any(x.algorithm == "ECC" for x in findings)


# ── C / C++ ──────────────────────────────────────────────────────────────────

C_RSA = """\
    #include <openssl/rsa.h>
    #include <openssl/pem.h>

    int main() {
        RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
        return 0;
    }
"""

CPP_ECDSA = """\
    #include <openssl/ec.h>
    #include <openssl/ecdsa.h>

    void do_sign() {
        EC_KEY *key = EC_KEY_generate_key(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
        ECDSA_sign(0, NULL, 0, NULL, NULL, key);
    }
"""

def test_c_rsa(tmp_path):
    f = make_file(tmp_path, "rsa.c", C_RSA)
    findings = CryptoScanner().scan_file(f)
    assert any(x.algorithm == "RSA" for x in findings)


def test_cpp_ecdsa(tmp_path):
    f = make_file(tmp_path, "ecdsa.cpp", CPP_ECDSA)
    findings = CryptoScanner().scan_file(f)
    assert any(x.algorithm == "ECC" for x in findings)


# ── Directory scan ────────────────────────────────────────────────────────────

def test_scan_directory(tmp_path):
    make_file(tmp_path, "a.py", PYTHON_RSA_KEYGEN)
    make_file(tmp_path, "b.go", GO_RSA)
    make_file(tmp_path, "c.java", JAVA_ECDSA)
    make_file(tmp_path, "clean.py", "x = 1\n")

    scanner = CryptoScanner()
    findings = list(scanner.scan_directory(tmp_path))
    assert len(findings) >= 3
    algos = {f.algorithm for f in findings}
    assert "RSA" in algos
    assert "ECC" in algos


def test_excludes_hidden_dirs(tmp_path):
    venv = tmp_path / ".venv"
    venv.mkdir()
    make_file(venv, "hidden.py", PYTHON_RSA_KEYGEN)
    make_file(tmp_path, "real.py", "x = 1\n")

    findings = list(CryptoScanner().scan_directory(tmp_path))
    for f in findings:
        assert ".venv" not in f.file_path
