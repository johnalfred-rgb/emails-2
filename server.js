const express = require('express');
const path = require('path');
const crypto = require('crypto');
const MailComposer = require('nodemailer/lib/mail-composer');

const app = express();
app.use(express.json({ limit: '25mb' }));

// ----- Configuration (all via environment variables) -----
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const ALLOWED_DOMAIN = (process.env.ALLOWED_DOMAIN || 'coquest.com').toLowerCase();
const APP_BASE_URL = (process.env.APP_BASE_URL || '').replace(/\/+$/, '');
const DEFAULT_DELAY_MS = Number(process.env.SEND_DELAY_MS || 400);

// openid/email/profile identify the user; gmail.send lets them send AS themselves.
const SCOPES = ['openid', 'email', 'profile', 'https://www.googleapis.com/auth/gmail.send'];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// In-memory stores. Fine for a single Railway instance (reset on redeploy).
const jobs = new Map();      // jobId -> job
const sessions = new Map();  // sid   -> { email, name, accessToken, refreshToken, expiresAt }

// ----- Helpers -----
function baseUrl(req) {
  if (APP_BASE_URL) return APP_BASE_URL;
  const proto = String(req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0];
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return proto + '://' + host;
}
function redirectUri(req) { return baseUrl(req) + '/oauth2/callback'; }
function isSecure(req) { return baseUrl(req).startsWith('https'); }

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || '';
  raw.split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

// Decode a Google ID token payload. Safe to trust without signature checks because
// it was returned to us directly from Google's token endpoint over TLS.
function decodeJwt(token) {
  try {
    const part = String(token).split('.')[1];
    return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch (e) {
    return {};
  }
}

function getSession(req) { return sessions.get(parseCookies(req).sid || ''); }

function requireAuth(req, res) {
  const s = getSession(req);
  if (!s) { res.status(401).json({ error: 'Not signed in.' }); return null; }
  return s;
}

// Ensure the session has a valid access token, refreshing via the refresh token if needed.
async function ensureFreshToken(s) {
  if (s.accessToken && Date.now() < s.expiresAt) return;
  if (!s.refreshToken) throw new Error('Session expired — please sign in again.');
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      refresh_token: s.refreshToken,
      grant_type: 'refresh_token',
    }),
  });
  const d = await r.json();
  if (!r.ok || !d.access_token) throw new Error('Could not refresh Google session — please sign in again.');
  s.accessToken = d.access_token;
  s.expiresAt = Date.now() + (Number(d.expires_in || 3600) * 1000) - 60000;
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

// Build a raw RFC-822 message (base64url) for the Gmail API.
function buildRaw(mail) {
  return new Promise((resolve, reject) => {
    new MailComposer(mail).compile().build((err, msg) => {
      if (err) return reject(err);
      resolve(msg.toString('base64url'));
    });
  });
}

// Send one message as the signed-in user via the Gmail API (gmail.send scope).
async function gmailSend(accessToken, mail) {
  const raw = await buildRaw(mail);
  const resp = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + accessToken, 'Content-Type': 'application/json' },
    body: JSON.stringify({ raw }),
  });
  if (!resp.ok) {
    let detail = '';
    try { const j = await resp.json(); detail = (j.error && j.error.message) || ''; } catch (e) { /* ignore */ }
    throw new Error('Gmail API ' + resp.status + (detail ? ': ' + detail : ''));
  }
  return resp.json();
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ----- Auth routes -----
app.get('/auth/google', (req, res) => {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    return res.status(500).send('Google sign-in is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.');
  }
  const state = crypto.randomBytes(16).toString('hex');
  res.cookie('oauth_state', state, { httpOnly: true, secure: isSecure(req), sameSite: 'lax', maxAge: 10 * 60 * 1000, path: '/' });
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: redirectUri(req),
    response_type: 'code',
    scope: SCOPES.join(' '),
    access_type: 'offline',
    prompt: 'consent',
    include_granted_scopes: 'true',
    state,
    hd: ALLOWED_DOMAIN, // hint the account chooser to the org domain
  });
  res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + params.toString());
});

app.get('/oauth2/callback', async (req, res) => {
  const fail = (msg) => res.redirect('/?error=' + encodeURIComponent(msg));
  try {
    const { code, state, error } = req.query;
    if (error) return fail(String(error));
    const cookies = parseCookies(req);
    if (!code || !state || state !== cookies.oauth_state) return fail('Invalid sign-in state. Please try again.');
    res.clearCookie('oauth_state', { path: '/' });

    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code: String(code),
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: redirectUri(req),
        grant_type: 'authorization_code',
      }),
    });
    const tok = await tokenResp.json();
    if (!tokenResp.ok || !tok.access_token) return fail('Google sign-in failed.');

    const claims = decodeJwt(tok.id_token);
    const email = String(claims.email || '').toLowerCase();
    const domain = String(claims.hd || email.split('@')[1] || '').toLowerCase();
    const okDomain = domain === ALLOWED_DOMAIN && email.endsWith('@' + ALLOWED_DOMAIN);
    if (claims.aud !== CLIENT_ID || claims.email_verified === false || !okDomain) {
      return fail('Only @' + ALLOWED_DOMAIN + ' accounts can sign in.');
    }

    const sid = crypto.randomBytes(24).toString('hex');
    sessions.set(sid, {
      email,
      name: claims.name || email,
      accessToken: tok.access_token,
      refreshToken: tok.refresh_token || null,
      expiresAt: Date.now() + (Number(tok.expires_in || 3600) * 1000) - 60000,
    });
    res.cookie('sid', sid, { httpOnly: true, secure: isSecure(req), sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000, path: '/' });
    res.redirect('/');
  } catch (e) {
    fail('Sign-in error. Please try again.');
  }
});

app.get('/auth/logout', (req, res) => {
  const sid = parseCookies(req).sid;
  if (sid) sessions.delete(sid);
  res.clearCookie('sid', { path: '/' });
  res.redirect('/');
});

// ----- API -----
// Who am I? Drives the UI (login gate vs. compose).
app.get('/api/me', (req, res) => {
  const s = getSession(req);
  res.json({
    authenticated: !!s,
    email: s ? s.email : null,
    name: s ? s.name : null,
    domain: ALLOWED_DOMAIN,
    oauthConfigured: !!(CLIENT_ID && CLIENT_SECRET),
    defaultDelayMs: DEFAULT_DELAY_MS,
  });
});

// Simple health check for Railway.
app.get('/healthz', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Send a single test email to yourself.
app.post('/api/test', async (req, res) => {
  const s = requireAuth(req, res);
  if (!s) return;
  const { subject, html } = req.body || {};
  if (!subject || !html) return res.status(400).json({ error: 'Subject and body are required.' });

  const sample = { name: 'there', email: s.email };
  try {
    await ensureFreshToken(s);
    await gmailSend(s.accessToken, {
      from: `"${s.name}" <${s.email}>`,
      to: s.email,
      subject: '[TEST] ' + fillTemplate(subject, sample),
      html: fillTemplate(html, sample),
    });
    res.json({ ok: true, sentTo: s.email });
  } catch (e) {
    res.status(500).json({ error: 'Send failed: ' + e.message });
  }
});

// Kick off a bulk send from the signed-in user's Gmail. Returns a jobId the UI polls.
app.post('/api/send', async (req, res) => {
  const s = requireAuth(req, res);
  if (!s) return;

  const sid = parseCookies(req).sid;
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
    owner: sid,
    from: s.email,
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

  (async () => {
    try {
      await ensureFreshToken(s);
      for (const r of valid) {
        try {
          await ensureFreshToken(s); // access tokens last ~1h; refresh mid-job if needed
          await gmailSend(s.accessToken, {
            from: `"${s.name}" <${s.email}>`,
            to: r.email,
            subject: fillTemplate(subject, r),
            html: fillTemplate(html, r),
          });
          job.sent++;
        } catch (e) {
          job.failed++;
          if (job.failures.length < 100) job.failures.push({ email: r.email, error: e.message });
        }
        if (delayMs) await sleep(delayMs);
      }
    } catch (e) {
      if (job.failures.length < 100) job.failures.push({ email: '(all remaining)', error: e.message });
    } finally {
      job.done = true;
      job.finishedAt = Date.now();
      // Drop the job from memory after 10 minutes.
      setTimeout(() => jobs.delete(jobId), 10 * 60 * 1000);
    }
  })();
});

// Poll job progress. Only the owner (same session) may read it.
app.get('/api/job/:id', (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found (it may have expired).' });
  if (job.owner && job.owner !== parseCookies(req).sid) return res.status(403).json({ error: 'Not your job.' });
  res.json(job);
});

// Serve the app.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
