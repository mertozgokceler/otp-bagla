// OTP API — Express + Firebase Admin + Nodemailer
require("dotenv").config(); // lokal .env için
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

// --- ENV --- (Render/Railway’de bunları panelden girersin)
const {
  GOOGLE_APPLICATION_CREDENTIALS_JSON,
  SMTP_HOST, SMTP_PORT, SMTP_SECURE, SMTP_USER, SMTP_PASS,
  APP_NAME = "TechConnect",
  OTP_PEPPER = "change-this-long-random-secret"
} = process.env;

if (!GOOGLE_APPLICATION_CREDENTIALS_JSON) {
  throw new Error("Missing GOOGLE_APPLICATION_CREDENTIALS_JSON");
}

// Firebase Admin init
admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(GOOGLE_APPLICATION_CREDENTIALS_JSON))
});
const db = admin.firestore();

// SMTP
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: Number(SMTP_PORT || 465),
  secure: String(SMTP_SECURE || "true") === "true", // 465:true, 587:false
  auth: { user: SMTP_USER, pass: SMTP_PASS }
});

// Helpers
function sixDigit() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
function hash(code, uid) {
  return crypto.createHash("sha256").update(`${code}|${uid}|${OTP_PEPPER}`).digest("hex");
}
function toMillis(ts) {
  return ts && typeof ts.toMillis === "function" ? ts.toMillis() : 0;
}

// App
const app = express();
app.use(cors());            // istersen origin kısıtlayabilirsin
app.use(express.json());

// Auth middleware: Firebase ID token doğrula
async function auth(req, res, next) {
  try {
    const hdr = req.headers.authorization || "";
    const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing token" });
    const decoded = await admin.auth().verifyIdToken(token);
    req.uid = decoded.uid;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// OTP iste (mail gönder)
app.post("/otp/request", auth, async (req, res) => {
  try {
    const uid = req.uid;
    const user = await admin.auth().getUser(uid);
    const email = user.email;
    if (!email) return res.status(400).json({ error: "No email on account" });

    // rate limit: 45 sn
    const ref = db.collection("emailOtps").doc(uid);
    const snap = await ref.get();
    if (snap.exists) {
      const last = toMillis(snap.data().lastSentAt);
      if (Date.now() - last < 45000) {
        return res.status(429).json({ error: "Please wait before requesting again" });
      }
    }

    const code = sixDigit();
    const codeHash = hash(code, uid);
    const now = admin.firestore.Timestamp.now();
    const expiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + 10 * 60 * 1000); // 10 dk

    await ref.set({
      codeHash,
      expiresAt,
      attempts: 0,
      lastSentAt: now,
      createdAt: now,
      emailSnapshot: email
    }, { merge: true });

    await transporter.sendMail({
      from: SMTP_USER,
      to: email,
      subject: `${APP_NAME} - Doğrulama Kodun`,
      text: `Doğrulama kodun: ${code}\nBu kod 10 dakika geçerlidir.`,
      html: `<p>Doğrulama kodun: <b style="font-size:18px">${code}</b></p><p>Kod 10 dakika geçerlidir.</p>`
    });

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "send_failed" });
  }
});

// OTP doğrula
app.post("/otp/verify", auth, async (req, res) => {
  try {
    const uid = req.uid;
    const code = String(req.body?.code || "").trim();
    if (code.length !== 6) return res.status(400).json({ ok: false, reason: "bad_code" });

    const ref = db.collection("emailOtps").doc(uid);
    const snap = await ref.get();
    if (!snap.exists) return res.json({ ok: false });

    const d = snap.data() || {};
    if ((d.attempts || 0) >= 5) return res.json({ ok: false });
    if (Date.now() > toMillis(d.expiresAt)) return res.json({ ok: false });

    const codeHash = hash(code, uid);
    if (codeHash !== d.codeHash) {
      await ref.set({ attempts: (d.attempts || 0) + 1 }, { merge: true });
      return res.json({ ok: false });
    }

    await db.collection("users").doc(uid).set({ emailVerified: true }, { merge: true });
    await ref.delete();
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, reason: "verify_failed" });
  }
});

// Health
app.get("/", (_req, res) => res.send("OK"));

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`OTP API listening on :${PORT}`));
