# 📝 Future Roadmap & Implementation Plan

## 1. 📂 File Upload & Scanning Features
**Goal**: Allow users to verify the safety of documents and files (PDF, EXE, DOCX), extending protection beyond just URLs.

- [ ] **Backend**:
    - Implement `FileScannerService` integrating with VirusTotal `/files` API.
    - Setup asynchronous job processing for large file uploads.
- [ ] **Frontend**:
    - Build a modern "Drag & Drop" file upload zone (using `react-dropzone`).
    - Show real-time upload progress and scanning status.
- [ ] **Privacy & Storage**:
    - Configure temporary storage (Local/S3) with strict **Auto-Deletion Policy** (e.g., files deleted immediately after analysis).
    - Encrypt files at rest.
- [ ] **Constraints**:
    - enforce strict file size limits (e.g., max 16MB) and MIME type validation.

## 2. 🛡️ Security Hardening & Attack Prevention
**Goal**: Fortify the application against abuse, bots, and common web vulnerabilities.

- [X] **Rate Limiting**:
    - Implement granular throttling per IP (e.g., 5 scans per minute) using middleware.
    - Add special limits for "Expensive" APIs like VirusTotal.
- [x] **HTTP Security Headers**:
    - Configure Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), and X-Content-Type-Options.
- [x] **Input Sanitization**:
    - Audit all user inputs for XSS vectors.
    - Normalize input data to prevent bypass techniques.

## 3. 💬 Community Pool & Discussions
**Goal**: Transform the platform into a community-driven trust ecosystem.

- [ ] **Authentication**:
    - Add Login/Register system (email + Social Login like Google/GitHub).
- [ ] **Discussion System**:
    - Add a "Comments & Insights" section to the Result Page.
    - Allow users to discuss why a site is flagged or safe.
- [ ] **Voting & Reputation**:
    - Implement an internal "Upvote/Downvote" system (persisted in local DB).
    - Display "Community Trust Score" alongside algorithmic scores.
    - (Future) User reputation/badges for accurate reporting.
