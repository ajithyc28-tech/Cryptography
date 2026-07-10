# MemCrypt Lab — VS Code Setup

## Option 1 — Live Server Extension (Easiest, recommended)

1. Open VS Code
2. Install the **Live Server** extension by Ritwick Dey
   - Go to Extensions (Ctrl+Shift+X)
   - Search: `Live Server`
   - Click Install
3. Open this project folder in VS Code:
   - File → Open Folder → select `memcrypt-lab`
4. Right-click `index.html` in the Explorer panel
5. Click **"Open with Live Server"**
6. Browser opens at `http://127.0.0.1:5500`

---

## Option 2 — Node.js (No extension needed)

Requires Node.js installed — download from https://nodejs.org

```bash
# Open terminal in VS Code (Ctrl + `)
# Navigate to project folder, then run:

npx live-server --port=3000 --open=index.html
```

Browser opens at `http://localhost:3000`

---

## Option 3 — Python (if you have Python installed)

```bash
# Python 3
python -m http.server 3000

# Python 2
python -m SimpleHTTPServer 3000
```

Then open `http://localhost:3000` in your browser.

---

## Why a server is needed

The Crypto Engine uses the browser's **Web Crypto API** (real AES-GCM,
RSA-OAEP, SHA hashes). This API requires either:
- `localhost` / `127.0.0.1`, or
- An HTTPS connection

Simply double-clicking `index.html` (file://) will cause the
encryption and decryption to fail. Use any option above to avoid this.

---

## Project structure

```
memcrypt-lab/
├── index.html      ← entire app (single file)
├── package.json    ← npm scripts
└── README.md       ← this file
```
