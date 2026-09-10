# 🛡️ Aegis Vault & Security Suite — Military-Grade File Encryption & Modern Web App

An ultra-fast, memory-efficient, authenticated file encryption suite and enterprise-grade **Java 25 Security & Authentication System**, featuring a state-of-the-art **Cyberpunk Glassmorphism Web App**, zero-knowledge streaming **AES-256-GCM** cipher with **PBKDF2-HMAC-SHA256** key derivation (600,000 iterations), passphrase fortress, and security telemetry.

---

## 🌟 Complete Application Features

### 1. 🛡️ Vault Studio (In-Browser Encrypt & Decrypt)
- **Zero-Knowledge Streaming AES-256-GCM**: Encrypts and decrypts files in 64 KB chunks right in the browser using the Web Crypto API.
- **100% Bit-for-Bit Interoperability**: Compatible across Python (`crypto_engine.py`), Java SE 25 (`JavaCryptoEngine.java`), and Web Crypto.
- **Real-Time Stream Processing**: Live chunk progress bar, throughput benchmark meter (MB/s), and instant `.vault` file download.
- **Plaintext Previewer**: In-browser preview for decrypted images, text files, markdown, and hex dumps.

### 2. 📂 Encrypted Browser Safe (Local Locker)
- Persistent in-browser IndexedDB storage to organize encrypted files.
- Search, filter by tags, instant unlock & decrypt, and manifest export/import.

### 3. 🔍 SECV Binary Header & Structure Inspector
- Inspect any `.vault` file's internal 37-byte header:
  - Magic Identifier: `SECV` (0x53454356)
  - Version: `0x01`
  - Chunk Size: 64 KB
  - CSPRNG Salt (128-bit) & Base Nonce (96-bit)
  - Chunk sequence analysis and AAD anti-tamper verification.

### 4. 🔑 Passphrase Fortress & Generator
- High-entropy cryptographic generator (8–64 characters) with character set controls.
- Memorable Diceware Passphrase mode (3–8 words).
- Real-time bit entropy calculation, brute-force crack time estimator (GPU vs Supercomputer), and NIST SP 800-63B compliance rating.

### 5. 👤 Zero-Knowledge Identity & Auth Portal
- PBKDF2-HMAC-SHA256 password hashing (600,000 iterations) with 128-bit per-user cryptographic salts.
- Automatic brute-force account lockout defense (5 failed attempts = 5 min cooldown).
- Remote Java REST server integration with graceful offline standalone mode fallback.

### 6. 📊 Security Audit & Telemetry
- Real-time event logging of authentication, encryptions, decryptions, and lockout defenses.
- Export audit trail to CSV.

### 7. ⚡ Performance Benchmark Lab
- In-browser cryptographic performance benchmark testing PBKDF2 600K key derivation speed (ms) and AES-GCM encryption throughput (MB/s).

### 8. 🎨 Cyberpunk Glassmorphic Aesthetics & Sound Engine
- Ambient animated constellation canvas.
- Synthesizer sound effects (Web Audio API) for lock, unlock, click, and alerts.
- Keyboard shortcuts: `Ctrl+E` (Encrypt), `Ctrl+D` (Decrypt), `Ctrl+G` (Generator), `Ctrl+L` (Safe), `Esc` (Close).

---

## 🚀 Quick Start — Launching the Desktop Application

### Option A: 1-Click Desktop App Launcher (Recommended)
Double-click or run:
```cmd
launch_app.bat
```
Or via Python:
```powershell
py launch_app.py
# or: py main.py
```
*Starts the Aegis Security Node and opens the dedicated Native Desktop App window with the modern Cyberpunk Glassmorphic GUI.*

### Option B: Run Security Test Suite & Cross-Interop Tests
```cmd
run_tests.bat
```
Or test Python <-> Java interoperability:
```powershell
py test_interop.py
```

---


## 🔐 REST API Reference

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `POST` | `/api/auth/register` | Register new user account | No |
| `POST` | `/api/auth/login` | Authenticate user and issue 256-bit session token | No |
| `GET` | `/api/auth/verify` | Validate active session token | Yes (`Bearer <token>`) |
| `POST` | `/api/auth/logout` | Revoke session token | Yes (`Bearer <token>`) |
| `POST` | `/api/auth/change-password` | Update user master passphrase | Yes (`Bearer <token>`) |
| `GET` | `/api/auth/audit` | Fetch account security audit trail | Yes (`Bearer <token>`) |
| `GET` | `/api/auth/status` | Server status, active users & uptime | No |

---

## 🔐 Cryptographic Specifications

- **Symmetric Cipher**: AES-256-GCM (Galois/Counter Mode, 128-bit authentication tags)
- **Key Derivation Function (KDF)**: PBKDF2-HMAC-SHA256 (600,000 iterations, OWASP recommended)
- **Password Salt**: 16 bytes (128-bit CSPRNG per file & user)
- **Base Nonce**: 12 bytes (96-bit CSPRNG)
- **Associated Data (AAD)**: 17-byte anti-reordering & anti-truncation payload per chunk
- **File Format Header**: `SECV` Magic Identifier (Version 1, 37-byte binary header)
