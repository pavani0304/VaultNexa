# TrustVault — Secure Document Sharing Prototype

Features included:
- User registration and login with hashed passwords
- Separate administrator role and admin dashboard
- Document ownership
- Per-user `view`, `download`, or `view_download` permissions
- Share, update permission, and revoke access
- Encryption of uploaded document bytes at rest using Fernet
- Admin-only audit logs for login attempts, uploads, views, downloads, sharing, revocation, deletion, and access denials
- Admin statistics for registered/active users, document owners, documents, shared documents, grants, and recently active users
- Search, 20 MB upload limit, extension allowlist, and user enable/disable controls

## Run in Windows / VS Code
1. Open this folder in VS Code.
2. Open Terminal → New Terminal.
3. Run `python -m pip install -r requirements.txt`
4. Run `python trustvault.py`
5. Open `http://127.0.0.1:5000` in Chrome.
6. First-run administrator: username `admin`, temporary password `ChangeMe123!`. Change it immediately when prompted.
7. Register a second user to test sharing and permissions.

## Important
The app creates `trustvault_data/` containing the SQLite database, encrypted files, `.vault_key`, and `.flask_secret`. Never delete or lose `.vault_key`, or encrypted documents cannot be recovered. Never commit `trustvault_data/` to GitHub.

This is a student prototype, not production-certified. Before public deployment, add CSRF protection, login rate-limiting, malware scanning, secure key management, backups, HTTPS, a production WSGI server, and a security review. Set `TRUSTVAULT_HTTPS=1` only when correctly serving the app behind HTTPS. The admin's recent-active count is approximate (last request within five minutes). Preview is browser-dependent for different file types. Admins see metadata and audit events, not all document contents.
