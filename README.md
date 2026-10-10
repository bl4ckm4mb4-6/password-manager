# CLI Password Manager

A lightweight, secure, command-line password manager written in Python. This tool uses strong cryptographic primitives to encrypt your sensitive credentials and stores them locally in an SQLite database.

---

## Features

- **Robust Cryptography**: Uses **PBKDF2HMAC** with SHA-256 for key derivation (480,000 iterations) and **Fernet** (symmetric encryption based on AES-128 in CBC mode) to protect credentials.
- **Local & Private**: All data is stored locally in an SQLite database—no cloud dependencies or external servers.
- **SQL Injection Defense**: Prepared statements (`?` parameters) are used for all database queries.
- **Secure Master Password Input**: Hides password typing using Python's `getpass` module.
- **Full Credential Lifecycle**: Add, view, list, and delete individual or all stored credentials.

---

## Technical Stack

- **Language**: Python 3.x
- **Encryption**: [`cryptography`](https://pypi.org/project/cryptography/) (`PBKDF2HMAC`, `Fernet`)
- **Database**: `sqlite3`

---

## Prerequisites & Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/bl4ckm4mb4-6/password-manager.git
   cd password-manager
   ```

2. **Install dependencies**:
   This project requires the `cryptography` library. Install it via `pip`:
   ```bash
   pip install cryptography
   ```

---

## Usage

Run the script from your terminal:

```bash
python gestore_password.py
```

### Menu Options

```
-----MENU-----
1) Inserisci nuove credenziali (Add new credentials)
2) Visualizza credenziali di un servizio (View credentials for a specific service)
3) Visualizza credenziali di tutti i servizi (View credentials for all services)
4) Elimina un servizio (Delete a specific service)
5) Elimina tutto (Delete all entries)
6) Exit
```

> **Important**: The **Master Password** is used as the seed to derive your encryption key. You **must** use the same Master Password consistently to encrypt and decrypt your stored credentials. The Master Password **is not stored** in any files or database; therefore, **remember it or keep it safe**.

---

## File Structure

When run, the application automatically creates a `files/` directory containing:

```
files/
├── manager_pw.db  # SQLite database storing encrypted credentials
└── salt.bin       # Cryptographic salt generated for PBKDF2 key derivation
```

You can obviously change the folder name.

> ⚠️ **Security Warning**: Do not upload or share your `files/` directory or its contents (`salt.bin`, `manager_pw.db`). Make sure to add `files/` to your `.gitignore` file.

---

## License

This project is open-source and available under the [MIT License](LICENSE).
