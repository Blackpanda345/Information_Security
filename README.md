# SecureGate: login system with 2FA, RBAC, salt and pepper

Pure HTML, CSS and JavaScript. No build step, no dependencies. Works on GitHub and Vercel as a static site.

## Files

| File | Purpose |
|---|---|
| `index.html` | All screens (sign in, 2FA, register, authenticator setup, dashboard) |
| `style.css` | Responsive styling (light and dark) |
| `crypto.js` | Salt + pepper hashing, constant-time compare, TOTP (RFC 6238) |
| `app.js` | Registration, login, 2FA, RBAC, lockout, session timeout, audit log |
| `vercel.json` | Security headers (CSP, HSTS, no framing) |

## Run locally

Open `index.html` through any static server (the Web Crypto API needs `localhost` or HTTPS, so double-clicking the file may not work):

```bash
npx serve .
# or
python3 -m http.server 8000
```

## Deploy

1. Create a GitHub repository and upload all five files to the repository root.
2. In Vercel, choose **Add New > Project**, import the repository, and press **Deploy**. Framework preset: **Other**. No build command, no output directory.

## Before you deploy: change the pepper

Open `crypto.js` and replace the value of `PEPPER` with your own long random string.

## Using it

1. **Create account.** The first account registered becomes the **Administrator**; every later account is a **Standard user**.
2. Add the displayed setup key to an authenticator app (Google Authenticator, Microsoft Authenticator, Authy, 2FAS): *Add account > Enter a setup key > Time-based*.
3. Type the 6-digit code to finish registration.
4. **Sign in** with username and password, then enter the current 6-digit code. A code that was already used is refused, so wait for the next one.
5. The administrator can change roles, unlock or delete users and read the audit log.

## Roles

| Role | Permissions |
|---|---|
| Administrator | content:read, content:write, users:manage, audit:view |
| Editor | content:read, content:write |
| Standard user | content:read |

## Security controls

- Per-user random salt (16 bytes) plus an application-wide pepper, hashed with PBKDF2-SHA256 (210,000 iterations)
- TOTP two-factor authentication with replay protection
- Password policy: 10+ characters, upper, lower, number, symbol, common-password and username checks
- Lockout for 15 minutes after 5 failed attempts
- Generic error messages (no username enumeration) and constant-time comparisons
- Session ends after 10 minutes of inactivity
- Authorization checked inside every protected action, not only in the interface
- Audit log of sign-ins, failures, role changes and denied access
- Content Security Policy, and all user text rendered with `textContent` (no XSS)

## Honest limitations (educational demo)

This is a front-end-only project. Accounts live in the browser's `localStorage`, so:

- The pepper is in the JavaScript, so it is not truly secret. In production it must live in a server-side secret store.
- Someone with access to the browser's developer tools can edit local data, so authorization is not tamper-proof. In production the server must enforce roles.
- Accounts are not shared between devices.

See the Word document for how each of these would be solved with a real back end.
