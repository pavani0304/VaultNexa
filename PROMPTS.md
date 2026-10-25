# VaultNexa — AI Prompts and Development Notes

## Project Overview
VaultNexa is a Flask-based document vault project developed using Python and VS Code Insiders.

## 1. Account Creation and Login
**Goal:** Implement account creation and login functionality.

**Testing:** Created a test account and logged in successfully.

**Result:** The dashboard opened after login.

**Issues and corrections:** Record any actual AI-generated errors and the corrections made during development here.

## 2. Document Upload and Download
**Goal:** Allow users to upload, view, and download documents.

**Testing:** Uploaded a test screenshot. The document count increased, and the downloaded file opened successfully.

**Result:** Basic upload and download functionality worked in local testing.

**Issues and corrections:** Record any actual errors and fixes here.

## 3. Login Protection and Logout
**Goal:** Prevent unauthenticated access to the dashboard and other protected pages.

**Testing:** After logout, refreshing the dashboard URL returned the login page.

**Observation:** The browser Back button briefly displayed cached dashboard content until the page was refreshed.

**Follow-up:** Verify that protected pages cannot expose private information through browser caching after logout.

## 4. Document Sharing and Access Control
**Goal:** Allow document owners to manage access for other users.

**Testing:** The document page displayed the sharing section and indicated that another user account was needed to test sharing.

**Status:** Sharing between two separate accounts and unauthorized-access prevention still need verification.

## 5. Encryption Verification
**Goal:** Protect stored documents using encryption.

**Testing:** The document page displayed “Encrypted at rest: Yes.”

**Limitation:** This message alone does not prove that encryption is correctly implemented.

**Follow-up:** Inspect the implementation, verify encryption and key handling, and test the behavior before claiming that encryption is secure.

## 6. Deployment and Final Testing
**Status:** Public GitHub upload, deployment, and live-site testing must be completed and verified.

**Follow-up checklist:**
- [ ] Publish the project in a public GitHub repository.
- [ ] Commit meaningful changes as development progresses.
- [ ] Verify that secrets, private databases, and uploaded documents are excluded from Git.
- [ ] Deploy the Flask application and document the live URL.
- [ ] Test the live URL in a private/incognito window and on another device.
- [ ] Record remaining limitations honestly.

## AI Prompt and Correction Log
For each significant AI-assisted change, record:
- **Date:**
- **Prompt or task:**
- **AI suggestion:**
- **Problem or limitation found:**
- **Correction made:**
- **Test performed and result:**
- **Related GitHub commit:** 