import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import nodemailer from 'nodemailer';
import sanitizeHtml from 'sanitize-html';
import { ImapFlow } from 'imapflow';
import { simpleParser } from 'mailparser';
import { z } from 'zod';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzePhishing } from './phishing.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const PORT = Number(process.env.PORT || 4300);
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || `http://localhost:${PORT}`;
const SESSION_TTL_MINUTES = Number(process.env.SESSION_TTL_MINUTES || 30);
const MAX_BODY_CHARS = Number(process.env.MAX_BODY_CHARS || 200000);

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: ALLOWED_ORIGIN, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(rootDir, 'public')));

const sessionStore = new Map();

const accountSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
  smtpHost: z.string().min(1),
  smtpPort: z.number().int().positive().default(465),
  imapHost: z.string().min(1),
  imapPort: z.number().int().positive().default(993)
});

function createSessionId() {
  return `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

function getSession(sessionId) {
  const session = sessionStore.get(sessionId);
  if (!session) return null;
  const ageMs = Date.now() - session.createdAt;
  if (ageMs > SESSION_TTL_MINUTES * 60 * 1000) {
    sessionStore.delete(sessionId);
    return null;
  }
  return session;
}

function transportFor(account) {
  return nodemailer.createTransport({
    host: account.smtpHost,
    port: account.smtpPort || 465,
    secure: true,
    auth: {
      user: account.email,
      pass: account.password
    },
    tls: {
      minVersion: 'TLSv1.2',
      rejectUnauthorized: true
    }
  });
}

function imapFor(account) {
  return new ImapFlow({
    host: account.imapHost,
    port: account.imapPort || 993,
    secure: true,
    auth: {
      user: account.email,
      pass: account.password
    },
    tls: {
      minVersion: 'TLSv1.2',
      rejectUnauthorized: true
    }
  });
}

function requireSession(req, res, next) {
  const sessionId = req.header('x-session-id');
  if (!sessionId) return res.status(401).json({ error: 'Missing session.' });
  const session = getSession(sessionId);
  if (!session) return res.status(401).json({ error: 'Session expired or invalid.' });
  req.session = session;
  next();
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, uptimeSec: process.uptime() });
});

app.post('/api/account/link', async (req, res) => {
  try {
    const parsed = accountSchema.parse({
      ...req.body,
      smtpPort: Number(req.body.smtpPort || 465),
      imapPort: Number(req.body.imapPort || 993)
    });

    if (parsed.smtpPort !== 465 || parsed.imapPort !== 993) {
      return res.status(400).json({ error: 'Only SMTPS 465 and IMAPS 993 are allowed.' });
    }

    const transporter = transportFor(parsed);
    await transporter.verify();

    const imap = imapFor(parsed);
    await imap.connect();
    await imap.logout();

    const sessionId = createSessionId();
    sessionStore.set(sessionId, { account: parsed, createdAt: Date.now() });

    return res.json({ ok: true, sessionId, email: parsed.email });
  } catch (error) {
    return res.status(400).json({
      error: 'Failed to link account. Check credentials and server settings.',
      details: error?.message || 'Unknown error'
    });
  }
});

app.post('/api/analyze', (req, res) => {
  const subject = String(req.body.subject || '');
  const text = String(req.body.text || '');
  const html = String(req.body.html || '');
  const from = String(req.body.from || '');
  const analysis = analyzePhishing({ from, subject, text, html });
  res.json({ ok: true, analysis });
});

app.post('/api/messages', requireSession, async (req, res) => {
  try {
    const { to, cc, bcc, subject, html, text } = req.body;

    const cleanSubject = String(subject || '').slice(0, 300);
    const cleanText = String(text || '').slice(0, MAX_BODY_CHARS);
    const cleanHtml = sanitizeHtml(String(html || '').slice(0, MAX_BODY_CHARS), {
      allowedTags: ['p', 'b', 'strong', 'i', 'em', 'u', 'br', 'ul', 'ol', 'li', 'a', 'blockquote'],
      allowedAttributes: {
        a: ['href', 'target', 'rel']
      },
      allowedSchemes: ['https', 'mailto']
    });

    const analysis = analyzePhishing({
      from: req.session.account.email,
      subject: cleanSubject,
      text: cleanText,
      html: cleanHtml
    });

    if (analysis.riskLevel === 'high') {
      return res.status(400).json({
        error: 'Message blocked due to high phishing risk.',
        analysis
      });
    }

    const transporter = transportFor(req.session.account);

    const info = await transporter.sendMail({
      from: req.session.account.email,
      to,
      cc,
      bcc,
      subject: cleanSubject,
      text: cleanText || undefined,
      html: cleanHtml || undefined
    });

    return res.json({ ok: true, messageId: info.messageId, analysis });
  } catch (error) {
    return res.status(400).json({ error: 'Failed to send email.', details: error?.message || 'Unknown error' });
  }
});

app.get('/api/messages', requireSession, async (req, res) => {
  const limit = Math.min(Number(req.query.limit || 20), 50);
  let imap;
  try {
    imap = imapFor(req.session.account);
    await imap.connect();

    const lock = await imap.getMailboxLock('INBOX');
    try {
      const list = [];
      for await (const msg of imap.fetch('1:*', {
        uid: true,
        envelope: true,
        flags: true,
        internalDate: true,
        bodyStructure: true
      })) {
        list.push({
          uid: msg.uid,
          subject: msg.envelope?.subject || '(No subject)',
          from: msg.envelope?.from?.[0]?.address || '',
          date: msg.internalDate,
          seen: msg.flags?.has('\\Seen') || false
        });
      }

      const latest = list.slice(-limit).reverse();
      return res.json({ ok: true, messages: latest });
    } finally {
      lock.release();
    }
  } catch (error) {
    return res.status(400).json({ error: 'Failed to fetch inbox.', details: error?.message || 'Unknown error' });
  } finally {
    if (imap) await imap.logout().catch(() => {});
  }
});

app.get('/api/messages/:uid', requireSession, async (req, res) => {
  const uid = Number(req.params.uid);
  let imap;
  try {
    imap = imapFor(req.session.account);
    await imap.connect();

    const lock = await imap.getMailboxLock('INBOX');
    try {
      const message = await imap.fetchOne(uid, { source: true, envelope: true, uid: true }, { uid: true });
      if (!message?.source) {
        return res.status(404).json({ error: 'Message not found.' });
      }

      const parsed = await simpleParser(message.source);
      const html = sanitizeHtml(parsed.html || '', {
        allowedTags: ['p', 'b', 'strong', 'i', 'em', 'u', 'br', 'ul', 'ol', 'li', 'a', 'blockquote'],
        allowedAttributes: { a: ['href', 'target', 'rel'] },
        allowedSchemes: ['https', 'mailto']
      });

      const text = parsed.text || '';
      const subject = parsed.subject || '';
      const from = parsed.from?.text || '';
      const analysis = analyzePhishing({ from, subject, text, html });

      return res.json({
        ok: true,
        message: {
          uid,
          subject,
          from,
          to: parsed.to?.text || '',
          date: parsed.date,
          text,
          html,
          analysis
        }
      });
    } finally {
      lock.release();
    }
  } catch (error) {
    return res.status(400).json({ error: 'Failed to fetch message.', details: error?.message || 'Unknown error' });
  } finally {
    if (imap) await imap.logout().catch(() => {});
  }
});

app.listen(PORT, () => {
  console.log(`Secure mail app running on http://localhost:${PORT}`);
});
