# Secure Mail Platform (Anti-Phishing)

A lightweight Thunderbird-like web email client with:
- Account linking via SMTPS (port 465, TLS) and IMAPS (port 993, TLS)
- Inline compose editor (`contenteditable`)
- Send and receive email support
- Anti-phishing risk analysis for incoming emails and composed messages

## Security note
No software can guarantee **zero phishing risk**. This project reduces risk with strict transport settings, URL analysis, and risky-content warnings/blocking.

## Run

1. Install dependencies:
   ```bash
   npm install
   ```
2. Copy env file:
   ```bash
   cp .env.example .env
   ```
3. Start server:
   ```bash
   npm start
   ```
4. Open:
   - http://localhost:4300

## What is implemented

- Enforced SMTPS for sending:
  - `secure: true`
  - default port `465`
- Enforced IMAPS for receiving:
  - `secure: true`
  - default port `993`
- Account link test before use (SMTP + IMAP authentication)
- Message list + message details retrieval from inbox
- Send message from inline editor
- URL/domain mismatch and suspicious-pattern phishing scoring
- Display and send-time warnings for high-risk content

## API

- `POST /api/account/link`
- `POST /api/messages`
- `GET /api/messages`
- `GET /api/messages/:uid`
- `POST /api/analyze`
- `GET /api/health`
