// OTP API — Express + Firebase Admin + SendGrid (HTTP API)
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const sgMail = require("@sendgrid/mail");
const crypto = require("crypto");

const {
  GOOGLE_APPLICATION_CREDENTIALS_JSON,
  SENDGRID_API_KEY,
  FROM_EMAIL,
  APP_NAME = "TechConnect",
  OTP_PEPPER = "change-this-long-random-secret",
  CORS_ORIGIN,
  PORT = 8080,
} = process.env;

if (!GOOGLE_APPLICATION_CREDENTIALS_JSON) throw new Error("Missing GOOGLE_APPLICATION_CREDENTIALS_JSON");
if (!SENDGRID_API_KEY) throw new Error("Missing SENDGRID_API_KEY");
if (!FROM_EMAIL) throw new Error("Missing FROM_EMAIL");

// Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(GOOGLE_APPLICATION_CREDENTIALS_JSON)),
});
const db = admin.firestore();

// SendGrid init
sgMail.setApiKey(SENDGRID_API_KEY);
async function sendEmail({ to, subject, text, html }) {
  await sgMail.send({ to, from: FROM_EMAIL, subject, text, html });
}

// Helpers
const sixDigit = () => Math.floor(100000 + Math.random() * 900000).toString();
const hash = (code, uid) => crypto.createHash("sha256").update(`${code}|${uid}|${OTP_PEPPER}`).digest("hex");
const toMillis = (ts) => (ts && typeof ts.toMillis === "function" ? ts.toMillis() : 0);

// App
const app = express();
app.use(CORS_ORIGIN ? cors({ origin: CORS_ORIGIN }) : cors());
app.use(express.json());

// Firebase ID token doğrulayan middleware
async function auth(req, res, next) {
  try {
    const hdr = req.headers.authorization || "";
    const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing token" });
    const decoded = await admin.auth().verifyIdToken(token);
    req.uid = decoded.uid;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// OTP iste — e-posta gönder
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
      if (Date.now() - last < 45_000) return res.status(429).json({ error: "Please wait before requesting again" });
    }

    const code = sixDigit();
    const codeHash = hash(code, uid);
    const now = admin.firestore.Timestamp.now();
    const expiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + 10 * 60 * 1000);

    await ref.set(
      { codeHash, expiresAt, attempts: 0, lastSentAt: now, createdAt: now, emailSnapshot: email },
      { merge: true }
    );

    await sendEmail({
      to: email,
      subject: `${APP_NAME} — E-posta Doğrulama Kodun`,
      text:
        `Merhaba, TechConnect'e hoş geldin!\n` +
        `Aşağıda doğrulama kodunu bulabilirsin.\n\n` +
        `Doğrulama kodun:\n${code}\n\n` +
        `Bu kod 10 dakika geçerlidir.`,
      html: `
    <div style="font-family:Arial,sans-serif;line-height:1.6">
      <h2 style="margin:0 0 12px">Merhaba, TechConnect'e hoş geldin! 🎉</h2>
      <p>Aşağıda doğrulama kodunu bulabilirsin.</p>

      <p style="margin:16px 0 8px;font-weight:600">Doğrulama kodun:</p>
      <p style="font-size:24px;letter-spacing:3px;font-weight:bold">${code}</p>

      <hr style="border:none;border-top:1px solid #eee;margin:20px 0">
      <p style="color:#555">Bu kod <strong>10 dakika</strong> geçerlidir.</p>
    </div>`
    });

    res.json({ ok: true });
  } catch (e) {
    console.error("OTP request error:", e);
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
    console.error("OTP verify error:", e);
    res.status(500).json({ ok: false, reason: "verify_failed" });
  }
});

// Health
app.get("/", (_req, res) => res.send("OK"));

app.listen(Number(PORT), () => console.log(`OTP API listening on :${PORT}`));
