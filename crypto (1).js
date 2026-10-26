/* =====================================================================
   crypto.js  -  Pure security helpers (no DOM access)
   - Salted + peppered password hashing (HMAC-SHA256 pepper -> PBKDF2-SHA256)
   - Constant-time comparison
   - RFC 6238 TOTP (Google Authenticator compatible) for two-factor auth
   Uses only the built-in Web Crypto API: no third-party libraries.
   ===================================================================== */
const SGCrypto = (() => {
  'use strict';

  const CONFIG = {
    APP_NAME: 'SecureGate',

    // PEPPER: one secret shared by the whole application and NEVER stored with
    // the user records. In this static (front-end only) demo it has to live in
    // the code. In a real deployment it belongs in a server-side environment
    // variable / secrets manager (see the Word document, section 6).
    // >>> Change this value to your own long random string before deploying. <<<
    PEPPER: 'k9$Tz!2vQe#Lm7@Xp4^Rw8&Bn1*Hc5(Yd3)Ua6_Fg0+Js',

    PBKDF2_ITERATIONS: 210000, // OWASP guidance for PBKDF2-HMAC-SHA256
    SALT_BYTES: 16,

    MAX_ATTEMPTS: 5,              // failed attempts before lockout
    LOCK_MS: 15 * 60 * 1000,      // lockout length
    IDLE_MS: 10 * 60 * 1000,      // session idle timeout
    PENDING_MS: 3 * 60 * 1000,    // time allowed between password step and 2FA step

    TOTP_STEP: 30,                // seconds per code
    TOTP_DIGITS: 6,
    TOTP_WINDOW: 1                // accept +/- 1 step to tolerate clock drift
  };

  const subtle = (globalThis.crypto || require('node:crypto').webcrypto).subtle;
  const rng = (globalThis.crypto || require('node:crypto').webcrypto);
  const enc = new TextEncoder();

  /* ---------- encoding helpers ---------- */
  const b64 = {
    enc: (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))),
    dec: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
  };

  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function b32encode(bytes) {
    let bits = 0, val = 0, out = '';
    for (const b of bytes) {
      val = (val << 8) | b;
      bits += 8;
      while (bits >= 5) {
        out += B32[(val >>> (bits - 5)) & 31];
        bits -= 5;
      }
      val &= (1 << bits) - 1;
    }
    if (bits > 0) out += B32[(val << (5 - bits)) & 31];
    return out;
  }

  function b32decode(str) {
    const clean = str.replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
    let bits = 0, val = 0;
    const out = [];
    for (const ch of clean) {
      const idx = B32.indexOf(ch);
      if (idx < 0) throw new Error('Invalid base32 character');
      val = (val << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        out.push((val >>> (bits - 8)) & 255);
        bits -= 8;
      }
      val &= (1 << bits) - 1;
    }
    return Uint8Array.from(out);
  }

  const randomBytes = (n) => rng.getRandomValues(new Uint8Array(n));

  /* ---------- primitives ---------- */
  async function hmac(keyBytes, data, hash = 'SHA-256') {
    const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash }, false, ['sign']);
    return new Uint8Array(await subtle.sign('HMAC', key, data));
  }

  // Constant-time comparison: always inspects every byte so timing does not
  // reveal where two values first differ.
  function timingSafeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  /* ---------- salt + pepper password hashing ----------
     1. PEPPER  : HMAC-SHA256(key = app pepper, message = password)
     2. SALT    : PBKDF2-SHA256(peppered value, per-user random salt, 210k iterations)
     Only { salt, hash } are stored. The pepper is not stored with them, so a
     stolen user database alone cannot be attacked offline without it.      */
  async function hashPassword(password, saltBytes) {
    const peppered = await hmac(enc.encode(CONFIG.PEPPER), enc.encode(password));
    const baseKey = await subtle.importKey('raw', peppered, 'PBKDF2', false, ['deriveBits']);
    const bits = await subtle.deriveBits(
      { name: 'PBKDF2', salt: saltBytes, iterations: CONFIG.PBKDF2_ITERATIONS, hash: 'SHA-256' },
      baseKey,
      256
    );
    return new Uint8Array(bits);
  }

  /* ---------- TOTP (RFC 6238 / HOTP RFC 4226) ---------- */
  async function hotp(secretBytes, counter, digits = CONFIG.TOTP_DIGITS) {
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    view.setUint32(0, Math.floor(counter / 2 ** 32));
    view.setUint32(4, counter >>> 0);
    const h = await hmac(secretBytes, buf, 'SHA-1');
    const o = h[h.length - 1] & 0x0f;
    const bin =
      ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
    return String(bin % 10 ** digits).padStart(digits, '0');
  }

  async function totp(secretB32, nowMs = Date.now()) {
    const step = Math.floor(nowMs / 1000 / CONFIG.TOTP_STEP);
    return hotp(b32decode(secretB32), step);
  }

  // Returns the matched time-step (a number) or null.
  // lastStep gives replay protection: a code from a step already used is refused.
  async function verifyTotp(secretB32, code, lastStep = 0, nowMs = Date.now()) {
    if (!/^\d{6}$/.test(code)) return null;
    const secret = b32decode(secretB32);
    const current = Math.floor(nowMs / 1000 / CONFIG.TOTP_STEP);
    let matched = null;
    for (let w = -CONFIG.TOTP_WINDOW; w <= CONFIG.TOTP_WINDOW; w++) {
      const step = current + w;
      const expected = await hotp(secret, step);
      if (timingSafeEqual(enc.encode(expected), enc.encode(code)) && step > lastStep) {
        matched = step;
      }
    }
    return matched;
  }

  function otpauthURI(username, secretB32) {
    const issuer = encodeURIComponent(CONFIG.APP_NAME);
    const label = `${issuer}:${encodeURIComponent(username)}`;
    return `otpauth://totp/${label}?secret=${secretB32}&issuer=${issuer}&algorithm=SHA1&digits=${CONFIG.TOTP_DIGITS}&period=${CONFIG.TOTP_STEP}`;
  }

  return {
    CONFIG, b64, b32encode, b32decode, randomBytes, hmac,
    timingSafeEqual, hashPassword, hotp, totp, verifyTotp, otpauthURI
  };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = SGCrypto;
