const express = require('express');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json({ limit: '25mb' }));

// ----- Configuration (all via environment variables) -----
const GMAIL_USER = process.env.GMAIL_USER || '';
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || '';
const APP_PASSWORD = process.env.APP_PASSWORD || '';
const FROM_NAME = process.env.FROM_NAME || 'CoQuest';
const DEFAULT_DELAY_MS = Number(process.env.SEND_DELAY_MS || 400);

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// In-memory job store. Fine for a single Railway instance.
const jobs = new Map();

function makeTransport() {
  return nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    pool: true,
    maxConnections: 3,
    maxMessages: 100,
    auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD },
  });
}

// Replace {{token}} with the matching field from a recipient row (case-insensitive key).
function fillTemplate(str, row) {
  if (!str) return '';
  return str.replace(/\{\{\s*([\w.-]+)\s*\}\}/g, (match, key) => {
    const lower = key.toLowerCase();
    for (const k of Object.keys(row)) {
      if (k.toLowerCase() === lower && row[k] != null) return String(row[k]);
    }
    return '';
  });
}

function maskEmail(addr) {
  if (!addr) return null;
  const at = addr.indexOf('@');
  if (at <= 1) return addr;
  return addr.slice(0, 2) + '***' + addr.slice(at);
}

// ----- Static assets (template, etc.) then the app UI -----
app.use(express.static(path.join(__dirname)));

// Report configuration state to the UI (never returns secrets).
app.get('/api/config', (req, res) => {
  res.json({
    gmailConfigured: !!(GMAIL_USER && GMAIL_APP_PASSWORD),
    passwordRequired: !!APP_PASSWORD,
    fromName: FROM_NAME,
    fromEmail: maskEmail(GMAIL_USER),
    defaultDelayMs: DEFAULT_DELAY_MS,
  });
});

// Simple health check for Railway.
app.get('/healthz', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

function authorize(req, res) {
  if (APP_PASSWORD && (req.body || {}).password !== APP_PASSWORD) {
    res.status(401).json({ error: 'Invalid app password.' });
    return false;
  }
  return true;
}

function ensureConfigured(res) {
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD) {
    res.status(500).json({
      error: 'Server is not configured. Set GMAIL_USER and GMAIL_APP_PASSWORD in Railway.',
    });
    return false;
  }
  return true;
}

// Send a single test email to the configured account.
app.post('/api/test', async (req, res) => {
  if (!authorize(req, res)) return;
  if (!ensureConfigured(res)) return;
  const { subject, html } = req.body || {};
  if (!subject || !html) return res.status(400).json({ error: 'Subject and body are required.' });

  const sample = { name: 'there', email: GMAIL_USER };
  const transporter = makeTransport();
  try {
    await transporter.sendMail({
      from: `"${FROM_NAME}" <${GMAIL_USER}>`,
      to: GMAIL_USER,
      subject: '[TEST] ' + fillTemplate(subject, sample),
      html: fillTemplate(html, sample),
    });
    res.json({ ok: true, sentTo: GMAIL_USER });
  } catch (e) {
    res.status(500).json({ error: 'Send failed: ' + e.message });
  } finally {
    transporter.close();
  }
});

// Kick off a bulk send. Returns a jobId the UI polls for progress.
app.post('/api/send', async (req, res) => {
  if (!authorize(req, res)) return;
  if (!ensureConfigured(res)) return;

  const { subject, html, recipients } = req.body || {};
  let delayMs = Number((req.body || {}).delayMs);
  if (!Number.isFinite(delayMs)) delayMs = DEFAULT_DELAY_MS;
  delayMs = Math.max(0, Math.min(10000, delayMs));

  if (!subject || !html) return res.status(400).json({ error: 'Subject and body are required.' });
  if (!Array.isArray(recipients) || recipients.length === 0) {
    return res.status(400).json({ error: 'No recipients provided.' });
  }

  // Validate and de-duplicate recipients.
  const seen = new Set();
  const valid = [];
  const invalid = [];
  for (const r of recipients) {
    const email = (r && r.email ? String(r.email) : '').trim();
    if (!EMAIL_RE.test(email)) { invalid.push(email); continue; }
    const key = email.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    valid.push({ ...r, email });
  }
  if (valid.length === 0) {
    return res.status(400).json({ error: 'No valid email addresses found.', invalid });
  }

  const jobId = crypto.randomBytes(8).toString('hex');
  const job = {
    id: jobId,
    total: valid.length,
    sent: 0,
    failed: 0,
    done: false,
    startedAt: Date.now(),
    finishedAt: null,
    skippedInvalid: invalid.length,
    failures: [],
  };
  jobs.set(jobId, job);

  // Respond immediately; process in the background.
  res.json({ jobId, total: valid.length, skippedInvalid: invalid.length });

  const transporter = makeTransport();
  (async () => {
    for (const r of valid) {
      try {
        await transporter.sendMail({
          from: `"${FROM_NAME}" <${GMAIL_USER}>`,
          to: r.email,
          subject: fillTemplate(subject, r),
          html: fillTemplate(html, r),
        });
        job.sent++;
      } catch (e) {
        job.failed++;
        if (job.failures.length < 100) job.failures.push({ email: r.email, error: e.message });
      }
      if (delayMs) await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
    job.done = true;
    job.finishedAt = Date.now();
    transporter.close();
    // Drop the job from memory after 10 minutes.
    setTimeout(() => jobs.delete(jobId), 10 * 60 * 1000);
  })();
});

// Poll job progress. jobId is unguessable, so no auth needed here.
app.get('/api/job/:id', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found (it may have expired).' });
  res.json(job);
});

// Serve the compose app.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
