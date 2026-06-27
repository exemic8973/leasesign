/**
 * LeaseSign Production Server
 * Texas Residential Lease E-Signature Platform
 *
 * Features:
 * - User authentication (JWT)
 * - Document management (CRUD)
 * - E-signature workflow
 * - Email notifications
 * - PDF generation with TAR form
 * - Audit logging
 * - PostgreSQL database
 */

// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');
const { Pool } = require('pg');

const multer = require('multer');
const pdfParse = require('pdf-parse');
const zlib = require('zlib');
const { PNG } = require('pngjs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'leasesign-secret-key-change-in-production-' + crypto.randomBytes(16).toString('hex');
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

// Warn if JWT_SECRET is not explicitly set
if (!process.env.JWT_SECRET) {
  console.warn('\n⚠️  WARNING: JWT_SECRET environment variable is not set.');
  console.warn('   All sessions will be invalidated on every server restart.');
  console.warn('   Set JWT_SECRET in your .env file for production use.\n');
}

// Simple in-memory rate limiter for login endpoint
const loginAttempts = new Map();
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX = 10;

const checkLoginRateLimit = (ip) => {
  const now = Date.now();
  const record = loginAttempts.get(ip) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
  if (now > record.resetAt) { record.count = 0; record.resetAt = now + RATE_LIMIT_WINDOW_MS; }
  record.count++;
  loginAttempts.set(ip, record);
  return record.count > RATE_LIMIT_MAX;
};
setInterval(() => {
  const now = Date.now();
  for (const [ip, r] of loginAttempts.entries()) { if (now > r.resetAt) loginAttempts.delete(ip); }
}, 60 * 60 * 1000);

// Vercel serverless: use /tmp for writable storage
const isVercel = process.env.VERCEL === '1';

// Data storage paths (for uploads and generated files)
const UPLOADS_DIR = isVercel ? '/tmp/uploads' : path.join(__dirname, '../uploads');
const GENERATED_DIR = isVercel ? '/tmp/generated' : path.join(__dirname, '../generated');

// Ensure directories exist (on Vercel /tmp is the only writable path)
const PDF_UPLOADS_DIR = path.join(UPLOADS_DIR, 'pdfs');
[UPLOADS_DIR, GENERATED_DIR, PDF_UPLOADS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Multer config for PDF uploads (max 25MB)
const pdfUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, PDF_UPLOADS_DIR),
    filename: (req, file, cb) => cb(null, `${uuidv4()}.pdf`)
  }),
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') return cb(null, true);
    cb(new Error('Only PDF files are allowed'));
  }
});

// PostgreSQL connection
// SSL mode is controlled via DATABASE_URL (add ?sslmode=require or ?sslmode=no-verify)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// Initialize database tables
async function initDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        company VARCHAR(255) DEFAULT '',
        phone VARCHAR(50) DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS documents (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        status VARCHAR(50) DEFAULT 'draft',
        title VARCHAR(255),
        data JSONB DEFAULT '{}',
        landlord_sign_token UUID,
        tenant_sign_token UUID,
        landlord_signature TEXT,
        landlord_signed_at TIMESTAMP,
        landlord_signed_ip VARCHAR(50),
        tenant_signature TEXT,
        tenant_signed_at TIMESTAMP,
        tenant_signed_ip VARCHAR(50),
        link_expires_at TIMESTAMP,
        voided_at TIMESTAMP,
        void_reason TEXT,
        is_template BOOLEAN DEFAULT FALSE,
        template_name VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        document_id UUID REFERENCES documents(id) ON DELETE CASCADE,
        action VARCHAR(100) NOT NULL,
        actor VARCHAR(255),
        ip VARCHAR(50),
        user_agent TEXT,
        details JSONB,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(50),
        title VARCHAR(255),
        message TEXT,
        document_id UUID,
        read BOOLEAN DEFAULT FALSE,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        document_id UUID REFERENCES documents(id) ON DELETE CASCADE,
        author_id UUID,
        author_name VARCHAR(255),
        author_email VARCHAR(255),
        signer_type VARCHAR(50),
        text TEXT NOT NULL,
        section VARCHAR(255),
        resolved BOOLEAN DEFAULT FALSE,
        resolved_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS password_resets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        token UUID NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('Database tables initialized successfully');
  } catch (err) {
    console.error('Database initialization error:', err);
  } finally {
    client.release();
  }
}

// Lazy DB initialization — first request awaits table creation (critical for serverless cold starts)
let dbReady = null;
const ensureDb = async () => {
  if (!dbReady) {
    dbReady = initDatabase().catch(err => {
      console.error('Database initialization error:', err);
      dbReady = null; // allow retry on next request
      throw err;
    });
  }
  return dbReady;
};

// Link expiration time (7 days in milliseconds)
const LINK_EXPIRATION_MS = 7 * 24 * 60 * 60 * 1000;

// Helper to create notification
const createNotification = async (userId, type, title, message, documentId = null) => {
  try {
    await pool.query(
      `INSERT INTO notifications (user_id, type, title, message, document_id) VALUES ($1, $2, $3, $4, $5)`,
      [userId, type, title, message, documentId]
    );
  } catch (err) {
    console.error('Create notification error:', err);
  }
};

// Middleware
app.use(async (req, res, next) => {
  try {
    await ensureDb();
    next();
  } catch (e) {
    res.status(500).json({ error: 'Database unavailable', details: e.message });
  }
});
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, '../public')));

// Email transporter — starts as a safe no-op wrapper to prevent crashes before async init completes
let mailer = {
  sendMail: async (opts) => {
    console.warn(`Mailer not yet initialized; email not sent to: ${opts.to}`);
    return null;
  }
};

const createMailer = async () => {
  // Check if custom SMTP is configured
  if (process.env.SMTP_HOST) {
    const smtpConfig = {
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT) || 587,
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    };

    console.log('='.repeat(60));
    console.log('CUSTOM SMTP CONFIGURED');
    console.log('='.repeat(60));
    console.log(`Host: ${smtpConfig.host}`);
    console.log(`Port: ${smtpConfig.port}`);
    console.log(`Secure: ${smtpConfig.secure}`);
    console.log(`User: ${smtpConfig.auth.user}`);
    console.log('='.repeat(60));

    const transporter = nodemailer.createTransport(smtpConfig);

    // Verify SMTP connection
    try {
      await transporter.verify();
      console.log('SMTP connection verified successfully!\n');
    } catch (err) {
      console.error('SMTP connection failed:', err.message);
      console.log('Emails may not be delivered. Check your SMTP settings.\n');
    }

    // Wrap sendMail to log sent emails
    const originalSendMail = transporter.sendMail.bind(transporter);
    transporter.sendMail = async (opts) => {
      try {
        const info = await originalSendMail(opts);
        console.log('\n' + '='.repeat(60));
        console.log('EMAIL SENT SUCCESSFULLY');
        console.log('='.repeat(60));
        console.log(`To: ${opts.to}`);
        console.log(`Subject: ${opts.subject}`);
        console.log(`Message ID: ${info.messageId}`);
        console.log('='.repeat(60) + '\n');
        return info;
      } catch (err) {
        console.error('\n' + '='.repeat(60));
        console.error('EMAIL FAILED TO SEND');
        console.error('='.repeat(60));
        console.error(`To: ${opts.to}`);
        console.error(`Error: ${err.message}`);
        console.error('='.repeat(60) + '\n');
        throw err;
      }
    };

    return transporter;
  }

  // Development: use Ethereal for email testing
  console.log('No SMTP configured. Creating Ethereal test email account...');
  const testAccount = await nodemailer.createTestAccount();
  console.log('='.repeat(60));
  console.log('ETHEREAL TEST EMAIL CONFIGURED');
  console.log('='.repeat(60));
  console.log(`View sent emails at: https://ethereal.email`);
  console.log(`Login: ${testAccount.user}`);
  console.log(`Password: ${testAccount.pass}`);
  console.log('='.repeat(60));
  console.log('To use your own SMTP, create a .env file with:');
  console.log('   SMTP_HOST=smtp.gmail.com');
  console.log('   SMTP_PORT=587');
  console.log('   SMTP_SECURE=false');
  console.log('   SMTP_USER=your-email@gmail.com');
  console.log('   SMTP_PASS=your-app-password');
  console.log('='.repeat(60) + '\n');

  const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    secure: false,
    auth: {
      user: testAccount.user,
      pass: testAccount.pass
    }
  });

  // Wrap sendMail to log preview URLs
  const originalSendMail = transporter.sendMail.bind(transporter);
  transporter.sendMail = async (opts) => {
    const info = await originalSendMail(opts);
    console.log('\n' + '='.repeat(60));
    console.log('EMAIL SENT (Ethereal)');
    console.log('='.repeat(60));
    console.log(`To: ${opts.to}`);
    console.log(`Subject: ${opts.subject}`);
    console.log(`Preview URL: ${nodemailer.getTestMessageUrl(info)}`);
    console.log('='.repeat(60) + '\n');
    return info;
  };

  return transporter;
};

// Initialize mailer asynchronously
(async () => {
  try {
    mailer = await createMailer();
  } catch (err) {
    console.error('Mailer initialization failed:', err.message);
  }
})();

// SMS Support (Twilio)
const sendSMS = async (to, message) => {
  if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN || !process.env.TWILIO_PHONE_NUMBER) {
    console.log('SMS not configured (Twilio credentials missing)');
    return null;
  }

  try {
    const accountSid = process.env.TWILIO_ACCOUNT_SID;
    const authToken = process.env.TWILIO_AUTH_TOKEN;
    const fromNumber = process.env.TWILIO_PHONE_NUMBER;

    // Make Twilio API call
    const response = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`, {
      method: 'POST',
      headers: {
        'Authorization': 'Basic ' + Buffer.from(`${accountSid}:${authToken}`).toString('base64'),
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({ To: to, From: fromNumber, Body: message })
    });

    const data = await response.json();
    if (data.sid) {
      console.log(`SMS sent to ${to}: ${data.sid}`);
      return data;
    } else {
      console.error('SMS failed:', data.message || data);
      return null;
    }
  } catch (err) {
    console.error('SMS error:', err.message);
    return null;
  }
};

// Helper to convert document row to object with camelCase and data merged
const docRowToObject = (row) => {
  if (!row) return null;
  const data = row.data || {};
  return {
    id: row.id,
    userId: row.user_id,
    status: row.status,
    title: row.title,
    landlordSignToken: row.landlord_sign_token,
    tenantSignToken: row.tenant_sign_token,
    landlordSignature: row.landlord_signature,
    landlordSignedAt: row.landlord_signed_at,
    landlordSignedIp: row.landlord_signed_ip,
    tenantSignature: row.tenant_signature,
    tenantSignedAt: row.tenant_signed_at,
    tenantSignedIp: row.tenant_signed_ip,
    linkExpiresAt: row.link_expires_at,
    voidedAt: row.voided_at,
    voidReason: row.void_reason,
    isTemplate: row.is_template,
    templateName: row.template_name,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    ...data
  };
};

// Auth middleware
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [decoded.id]);
    req.user = result.rows[0];
    if (!req.user) return res.status(401).json({ error: 'User not found' });
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Audit logging
const logAudit = async (documentId, action, actor, req, details = null) => {
  try {
    await pool.query(
      `INSERT INTO audit_logs (document_id, action, actor, ip, user_agent, details) VALUES ($1, $2, $3, $4, $5, $6)`,
      [documentId, action, actor, req.ip || req.connection?.remoteAddress || 'unknown', req.headers['user-agent'], details ? JSON.stringify(details) : null]
    );
  } catch (err) {
    console.error('Audit log error:', err);
  }
};

// ==================== AUTH ROUTES ====================

app.post('/api/auth/register', async (req, res) => {
  try {
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    if (checkLoginRateLimit(ip)) {
      return res.status(429).json({ error: 'Too many attempts. Please try again in 15 minutes.' });
    }

    const { email, password, name, company, phone } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (email, password, name, company, phone) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [email, hashedPassword, name, company || '', phone || '']
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    const { password: _, ...safeUser } = user;

    res.json({ token, user: safeUser });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    if (checkLoginRateLimit(ip)) {
      return res.status(429).json({ error: 'Too many login attempts. Please try again in 15 minutes.' });
    }

    const { email, password } = req.body;

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    const { password: _, ...safeUser } = user;

    res.json({ token, user: safeUser });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/me', auth, (req, res) => {
  const { password: _, ...safeUser } = req.user;
  res.json(safeUser);
});

// ==================== PASSWORD RESET ====================

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    // Always return success to prevent email enumeration
    if (!user) {
      return res.json({ success: true, message: 'If an account exists, a reset link has been sent.' });
    }

    // Generate reset token (expires in 1 hour)
    const resetToken = uuidv4();
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

    // Delete any existing reset tokens for this user
    await pool.query('DELETE FROM password_resets WHERE user_id = $1', [user.id]);

    // Create new reset token
    await pool.query(
      'INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [user.id, resetToken, expiresAt]
    );

    // Send reset email
    const resetUrl = `${APP_URL}/reset-password/${resetToken}`;
    await mailer.sendMail({
      from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
      to: email,
      subject: 'Reset Your LeaseSign Password',
      html: `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f3f4f6;">
  <table width="100%" style="max-width:600px;margin:0 auto;padding:20px;">
    <tr>
      <td style="background:linear-gradient(135deg,#4f46e5 0%,#818cf8 100%);padding:40px 30px;text-align:center;border-radius:12px 12px 0 0;">
        <h1 style="color:white;margin:0;font-size:28px;">Password Reset</h1>
      </td>
    </tr>
    <tr>
      <td style="background:white;padding:40px 30px;border:1px solid #e5e7eb;border-top:none;">
        <h2 style="color:#111827;margin:0 0 20px;">Hello ${user.name},</h2>
        <p style="color:#4b5563;line-height:1.6;">We received a request to reset your password. Click the button below to create a new password:</p>
        <table width="100%"><tr><td style="text-align:center;padding:20px 0;">
          <a href="${resetUrl}" style="display:inline-block;background:#4f46e5;color:white;padding:16px 40px;text-decoration:none;border-radius:8px;font-weight:600;">Reset Password</a>
        </td></tr></table>
        <p style="color:#9ca3af;font-size:13px;border-top:1px solid #e5e7eb;padding-top:20px;margin-top:20px;">
          This link expires in 1 hour. If you didn't request this reset, you can safely ignore this email.
        </p>
      </td>
    </tr>
  </table>
</body>
</html>`
    });

    console.log(`Password reset email sent to ${email}`);
    res.json({ success: true, message: 'If an account exists, a reset link has been sent.' });
  } catch (e) {
    console.error('Forgot password error:', e);
    res.status(500).json({ error: 'Failed to send reset email' });
  }
});

app.get('/api/auth/reset-password/:token', async (req, res) => {
  const result = await pool.query('SELECT * FROM password_resets WHERE token = $1', [req.params.token]);
  const reset = result.rows[0];
  if (!reset) return res.status(404).json({ error: 'Invalid or expired reset link' });
  if (new Date(reset.expires_at) < new Date()) {
    await pool.query('DELETE FROM password_resets WHERE id = $1', [reset.id]);
    return res.status(410).json({ error: 'Reset link has expired' });
  }
  res.json({ valid: true });
});

app.post('/api/auth/reset-password/:token', async (req, res) => {
  try {
    const { password } = req.body;
    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const result = await pool.query('SELECT * FROM password_resets WHERE token = $1', [req.params.token]);
    const reset = result.rows[0];
    if (!reset) return res.status(404).json({ error: 'Invalid or expired reset link' });
    if (new Date(reset.expires_at) < new Date()) {
      await pool.query('DELETE FROM password_resets WHERE id = $1', [reset.id]);
      return res.status(410).json({ error: 'Reset link has expired' });
    }

    // Update password
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', [hashedPassword, reset.user_id]);

    // Delete reset token
    await pool.query('DELETE FROM password_resets WHERE id = $1', [reset.id]);

    res.json({ success: true, message: 'Password reset successfully' });
  } catch (e) {
    console.error('Reset password error:', e);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ==================== DOCUMENT COMMENTS ====================

app.get('/api/documents/:id/comments', auth, async (req, res) => {
  const docResult = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
  if (docResult.rows.length === 0) {
    return res.status(404).json({ error: 'Document not found' });
  }

  const result = await pool.query(
    'SELECT * FROM comments WHERE document_id = $1 ORDER BY created_at ASC',
    [req.params.id]
  );
  res.json(result.rows);
});

app.post('/api/documents/:id/comments', auth, async (req, res) => {
  const docResult = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
  if (docResult.rows.length === 0) {
    return res.status(404).json({ error: 'Document not found' });
  }

  const { text, section } = req.body;
  if (!text) return res.status(400).json({ error: 'Comment text required' });

  const result = await pool.query(
    `INSERT INTO comments (document_id, author_id, author_name, author_email, text, section)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
    [req.params.id, req.user.id, req.user.name, req.user.email, text, section || null]
  );

  res.json(result.rows[0]);
});

app.post('/api/sign/:token/comments', async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM documents WHERE landlord_sign_token = $1 OR tenant_sign_token = $1',
    [req.params.token]
  );
  const doc = docRowToObject(result.rows[0]);

  if (!doc) return res.status(404).json({ error: 'Document not found' });

  const signerType = doc.landlordSignToken === req.params.token ? 'landlord' : 'tenant';
  const signerName = signerType === 'landlord' ? doc.landlordName : doc.tenantName;
  const signerEmail = signerType === 'landlord' ? doc.landlordEmail : doc.tenantEmail;

  const { text, section } = req.body;
  if (!text) return res.status(400).json({ error: 'Comment text required' });

  const commentResult = await pool.query(
    `INSERT INTO comments (document_id, author_name, author_email, signer_type, text, section)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
    [doc.id, signerName, signerEmail, signerType, text, section || null]
  );

  // Notify document owner
  await createNotification(doc.userId, 'comment', 'New Comment', `${signerName} commented on the lease for ${doc.propertyAddress}`, doc.id);

  res.json(commentResult.rows[0]);
});

app.get('/api/sign/:token/comments', async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM documents WHERE landlord_sign_token = $1 OR tenant_sign_token = $1',
    [req.params.token]
  );

  if (result.rows.length === 0) return res.status(404).json({ error: 'Document not found' });

  const comments = await pool.query(
    'SELECT * FROM comments WHERE document_id = $1 ORDER BY created_at ASC',
    [result.rows[0].id]
  );
  res.json(comments.rows);
});

app.patch('/api/documents/:docId/comments/:commentId/resolve', auth, async (req, res) => {
  const docResult = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [req.params.docId, req.user.id]);
  if (docResult.rows.length === 0) {
    return res.status(404).json({ error: 'Document not found' });
  }

  const commentResult = await pool.query('SELECT * FROM comments WHERE id = $1 AND document_id = $2', [req.params.commentId, req.params.docId]);
  if (commentResult.rows.length === 0) {
    return res.status(404).json({ error: 'Comment not found' });
  }

  const result = await pool.query(
    'UPDATE comments SET resolved = TRUE, resolved_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *',
    [req.params.commentId]
  );
  res.json(result.rows[0]);
});

// ==================== DOCUMENT ROUTES ====================

app.get('/api/documents', auth, async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM documents WHERE user_id = $1 AND (is_template = FALSE OR is_template IS NULL) ORDER BY updated_at DESC',
    [req.user.id]
  );
  res.json(result.rows.map(docRowToObject));
});

app.get('/api/documents/:id', auth, async (req, res) => {
  const result = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'Document not found' });
  }
  res.json(docRowToObject(result.rows[0]));
});

app.post('/api/documents', auth, async (req, res) => {
  try {
    const { title, ...docData } = req.body;
    if (Array.isArray(docData.additionalTenants)) {
      docData.additionalTenants = docData.additionalTenants.map(t => ({
        name: t.name || '',
        email: t.email || '',
        phone: t.phone || '',
        signToken: uuidv4(),
        signature: null,
        signedAt: null,
        signedIp: null
      }));
    } else {
      docData.additionalTenants = [];
    }
    const result = await pool.query(
      `INSERT INTO documents (user_id, status, title, data, landlord_sign_token, tenant_sign_token)
       VALUES ($1, 'draft', $2, $3, $4, $5) RETURNING *`,
      [req.user.id, title || null, JSON.stringify(docData), uuidv4(), uuidv4()]
    );

    const doc = docRowToObject(result.rows[0]);
    await logAudit(doc.id, 'DOCUMENT_CREATED', req.user.email, req);
    res.json(doc);
  } catch (e) {
    console.error('Create error:', e);
    res.status(500).json({ error: 'Failed to create document' });
  }
});

app.put('/api/documents/:id', auth, async (req, res) => {
  const docResult = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
  if (docResult.rows.length === 0) {
    return res.status(404).json({ error: 'Document not found' });
  }

  const doc = docRowToObject(docResult.rows[0]);
  if (doc.status === 'completed') {
    return res.status(400).json({ error: 'Cannot modify completed document' });
  }

  const { title, status, ...docData } = req.body;
  const existingData = docResult.rows[0].data || {};
  if (Array.isArray(docData.additionalTenants)) {
    docData.additionalTenants = docData.additionalTenants.map((t, i) => {
      const existing = existingData.additionalTenants?.[i];
      return {
        name: t.name || '',
        email: t.email || '',
        phone: t.phone || '',
        signToken: existing?.signToken || uuidv4(),
        signature: existing?.signature || null,
        signedAt: existing?.signedAt || null,
        signedIp: existing?.signedIp || null
      };
    });
  }
  const mergedData = { ...existingData, ...docData };

  const result = await pool.query(
    `UPDATE documents SET title = COALESCE($1, title), data = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3 RETURNING *`,
    [title, JSON.stringify(mergedData), req.params.id]
  );

  await logAudit(doc.id, 'DOCUMENT_UPDATED', req.user.email, req);
  res.json(docRowToObject(result.rows[0]));
});

app.delete('/api/documents/:id', auth, async (req, res) => {
  const result = await pool.query('DELETE FROM documents WHERE id = $1 AND user_id = $2 RETURNING id', [req.params.id, req.user.id]);
  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'Document not found' });
  }
  res.json({ success: true });
});

// ==================== PDF IMPORT ====================

// Convert raw RGB/Gray pixel data to PNG buffer with transparent background (pure JS, works on Vercel)
function rawToPng(rawData, width, height, channels) {
  const png = new PNG({ width, height, colorType: 6 }); // RGBA
  const pxCount = width * height;

  for (let i = 0; i < pxCount; i++) {
    const si = i * channels;
    const di = i * 4;

    let brightness;
    if (channels === 1) {
      brightness = rawData[si];
    } else {
      brightness = rawData[si] * 0.299 + rawData[si + 1] * 0.587 + rawData[si + 2] * 0.114;
    }

    // PDFKit signature canvas: background=0, strokes vary from 10-255
    // Boost faint strokes: multiply by 5 for visibility, cap at 255
    const alpha = brightness > 8 ? Math.min(255, brightness * 5) : 0;
    png.data[di]     = 0;      // R
    png.data[di + 1] = 0;      // G
    png.data[di + 2] = 0;      // B
    png.data[di + 3] = alpha;  // A
  }

  return PNG.sync.write(png);
}

// Generate a visible signature image from a text name (pure JS fallback, works on Vercel)
function textSignatureToPng(name, width = 400, height = 150) {
  const png = new PNG({ width, height, colorType: 6 });
  const pxCount = width * height;

  // Simple text rendering: draw name centered with basic pixel art
  const chars = name.split('');
  const charWidth = 14;
  const charHeight = 24;
  const startX = Math.max(10, (width - chars.length * charWidth) / 2);
  const startY = (height - charHeight) / 2;

  // Simple 5x7 font bitmap (very basic — covers A-Z, a-z, 0-9, space)
  const bitmap = buildBitmap(chars, charWidth, charHeight);

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const di = (y * width + x) * 4;
      const bx = x - startX;
      const by = y - startY;
      if (bx >= 0 && bx < chars.length * charWidth && by >= 0 && by < charHeight) {
        const charIdx = Math.floor(bx / charWidth);
        const px = bx % charWidth;
        if (bitmap[charIdx] && bitmap[charIdx][by] && bitmap[charIdx][by][px]) {
          png.data[di] = 26;     // dark blue
          png.data[di + 1] = 26;
          png.data[di + 2] = 138;
          png.data[di + 3] = 220;
        } else {
          png.data[di + 3] = 0;  // transparent
        }
      } else {
        png.data[di + 3] = 0;    // transparent
      }
    }
  }

  return PNG.sync.write(png);
}

// Minimal bitmap font for signature fallback (only covers needed chars)
function buildBitmap(chars, cw, ch) {
  const glyphs = {};
  // Simplified 7x10 glyph patterns for common letters
  const patterns = {
    'A': ['  ##  ',' #  # ',' #  # ','##### ','#    #','#    #','#    #'],
    'B': ['####  ','#   # ','####  ','#   # ','#   # ','#   # ','####  '],
    'C': [' #### ','#    #','#     ','#     ','#     ','#    #',' #### '],
    'D': ['####  ','#   # ','#    #','#    #','#    #','#   # ','####  '],
    'E': ['######','#     ','####  ','#     ','#     ','#     ','######'],
    'F': ['######','#     ','####  ','#     ','#     ','#     ','#     '],
    'G': [' #### ','#    #','#     ','#  ###','#    #','#   # ',' ###  '],
    'H': ['#    #','#    #','######','#    #','#    #','#    #','#    #'],
    'I': ['##### ','  #   ','  #   ','  #   ','  #   ','  #   ','##### '],
    'J': [' #####','    # ','    # ','    # ','#   # ','#   # ',' ###  '],
    'K': ['#   # ','#  #  ','###   ','#  #  ','#   # ','#    #','#    #'],
    'L': ['#     ','#     ','#     ','#     ','#     ','#     ','######'],
    'M': ['#    #','##  ##','# ## #','# #  #','#    #','#    #','#    #'],
    'N': ['#    #','##   #','# #  #','#  # #','#   ##','#    #','#    #'],
    'O': [' ###  ','#   # ','#    #','#    #','#    #','#   # ',' ###  '],
    'P': ['####  ','#   # ','#   # ','####  ','#     ','#     ','#     '],
    'Q': [' ###  ','#   # ','#    #','#    #','#  # #','#   # ',' #### '],
    'R': ['####  ','#   # ','#   # ','####  ','#  #  ','#   # ','#    #'],
    'S': [' #### ','#    #','#     ',' ###  ','     #','#    #',' #### '],
    'T': ['##### ','  #   ','  #   ','  #   ','  #   ','  #   ','  #   '],
    'U': ['#    #','#    #','#    #','#    #','#    #','#   # ',' ###  '],
    'V': ['#    #','#    #',' #  # ',' #  # ','  ##  ','  ##  ','   #   '],
    'W': ['#    #','#    #','#    #','# #  #','# #  #','##  ##','#    #'],
    'X': ['#    #',' #  # ','  ##  ','  ##  ','  ##  ',' #  # ','#    #'],
    'Y': ['#    #',' #  # ','  ##  ','   #   ','   #   ','   #   ','   #   '],
    'Z': ['######','    # ','   #  ','  #   ',' #    ','#     ','######'],
    ' ': ['       ','       ','       ','       ','       ','       ','       '],
    'a': ['       ','  ##  ','     #',' #####','#    #','#   # ',' #### '],
    'e': ['       ','      ',' #### ','#    #','######','#     ',' #### '],
    'h': ['#     ','#     ','# ### ','##   #','#    #','#    #','#    #'],
    'i': ['  #   ','      ',' ##   ','  #   ','  #   ','  #   ','##### '],
    'k': ['#     ','#     ','#   # ','#  #  ','###   ','#  #  ','#   #'],
    'l': [' ##   ','  #   ','  #   ','  #   ','  #   ','  #   ','##### '],
    'm': ['       ','       ','# # # ','# # # ','# # # ','# # # ','# # # '],
    'n': ['       ','       ','# ### ','##   #','#    #','#    #','#    #'],
    'o': ['       ','       ',' ###  ','#   # ','#    #','#   # ',' ###  '],
    'q': ['       ','       ',' #### ','#    #','#   ##',' #### ','     #'],
    'r': ['       ','       ','# ### ','##    ','#     ','#     ','#     '],
    's': ['       ','       ',' #### ','#     ',' ###  ','     #','####  '],
    't': ['  #   ','  #   ','##### ','  #   ','  #   ','  #   ','   ## '],
    'u': ['       ','       ','#    #','#    #','#    #','#   # ',' #### '],
    'w': ['       ','       ','#    #','# #  #','# #  #','# #  #',' ###  '],
    'y': ['       ','       ','#    #',' #  # ','  ##  ','  #   ','##    '],
    'z': ['       ','       ','######','   #  ','  #   ',' #    ','######'],
  };

  return chars.map(c => {
    const p = patterns[c] || patterns[' '];
    const rows = [];
    for (const row of p) {
      const pixels = [];
      for (const ch of row) {
        pixels.push(ch === '#');
      }
      // Pad to charWidth
      while (pixels.length < cw) pixels.push(false);
      rows.push(pixels.slice(0, cw));
    }
    // Pad to charHeight
    while (rows.length < ch) rows.push(new Array(cw).fill(false));
    return rows.slice(0, ch);
  });
}

// Extract embedded signature images from PDF binary
function extractSignatureImages(pdfPath) {
  try {
    const buf = fs.readFileSync(pdfPath);
    const str = buf.toString('latin1');
    const images = [];

    // Find image XObjects by iterating obj...endobj blocks
    const objRegex = /(\d+ \d+ obj)\s*(<<[\s\S]*?>>)\s*(?:stream\r?\n([\s\S]*?)endstream)?\s*endobj/g;
    let match;

    while ((match = objRegex.exec(str)) !== null) {
      const dict = match[2];
      const streamData = match[3];

      // Must be an image XObject with a stream
      if (!streamData) continue;
      if (!dict.includes('/Subtype /Image')) continue;
      if (!dict.includes('/Type /XObject')) continue;

      const wMatch = dict.match(/\/Width\s+(\d+)/);
      const hMatch = dict.match(/\/Height\s+(\d+)/);
      const fMatch = dict.match(/\/Filter\s*\/(\w+)/);
      const cMatch = dict.match(/\/ColorSpace\s*\/Device(\w+)/);

      const width = wMatch ? parseInt(wMatch[1]) : 0;
      const height = hMatch ? parseInt(hMatch[1]) : 0;
      const filter = fMatch ? fMatch[1] : '';
      const color = cMatch ? cMatch[1] : 'RGB';

      // Signature images are typically 400x150 (PDFKit signature canvas)
      if (width < 100 || height < 30) continue;

      try {
        let rawData;
        if (filter === 'FlateDecode') {
          rawData = zlib.inflateSync(Buffer.from(streamData, 'latin1'));
        } else if (filter === 'DCTDecode') {
          rawData = Buffer.from(streamData, 'latin1');
        } else {
          continue;
        }

        const channels = color === 'Gray' ? 1 : 3;

        const pngBuf = rawToPng(rawData, width, height, channels);
        const dataUri = `data:image/png;base64,${pngBuf.toString('base64')}`;

        images.push({ width, height, color, dataUri });
      } catch (e) {
        // Ignore individual image failures
      }
    }

    return images;
  } catch (e) {
    console.warn('Signature image extraction failed:', e.message);
    return [];
  }
}

// Extract lease fields from PDF text using regex patterns
function extractLeaseData(text) {
  const data = {};

  // 1. PARTIES — Landlord & Tenant
  const partiesMatch = text.match(/Landlord\):\s*(.+?);/);
  if (partiesMatch) data.landlordName = partiesMatch[1].trim();

  const tenantMatch = text.match(/Tenant"?\):\s*(.+?)\./);
  if (tenantMatch) {
    const tenants = tenantMatch[1].trim();
    const names = tenants.split(/,\s*/);
    data.tenantName = names[0] || '';
    // Store additional tenants if more than one
    if (names.length > 1) {
      data.additionalTenants = names.slice(1).map(name => ({
        name: name.trim(), email: '', phone: '',
        signToken: null, signature: null, signedAt: null, signedIp: null
      }));
    }
  }

  // 2. PROPERTY
  const addrMatch = text.match(/A\.\s*Address:\s*(.+?)(?:\n|$)/);
  if (addrMatch) {
    const fullAddr = addrMatch[1].trim();
    data.propertyAddress = fullAddr;
    // Try to parse city, state, zip
    const cityMatch = fullAddr.match(/(.+),\s*(.+),\s*TX\s*(\d{5})/);
    if (cityMatch) {
      data.propertyAddress = cityMatch[1].trim();
      data.propertyCity = cityMatch[2].trim();
      data.propertyZip = cityMatch[3];
    }
  }

  const countyMatch = text.match(/C\.\s*County:\s*(.+?)(?:\n|$)/);
  if (countyMatch) data.propertyCounty = countyMatch[1].trim();

  // 3. TERM — Dates
  const commenceMatch = text.match(/Commencement Date:\s*(\d{4}-\d{2}-\d{2})/);
  if (commenceMatch) data.commencementDate = commenceMatch[1];

  const expireMatch = text.match(/Expiration Date:\s*(\d{4}-\d{2}-\d{2})/);
  if (expireMatch) data.expirationDate = expireMatch[1];

  // 4. RENEWAL — notice days
  const noticeMatch = text.match(/at least\s*(\d+)\s*days before the Expiration Date/);
  if (noticeMatch) data.terminationNoticeDays = noticeMatch[1];

  // 5. RENT
  const rentMatch = text.match(/Monthly Rent:\s*\$?([\d,]+\.?\d*)/);
  if (rentMatch) data.monthlyRent = parseFloat(rentMatch[1].replace(/,/g, ''));

  const proratedMatch = text.match(/Prorated Rent:\s*\$?([\d,]+\.?\d*)/);
  if (proratedMatch) data.proratedRent = parseFloat(proratedMatch[1].replace(/,/g, ''));

  // 6. LATE CHARGES
  const lateMatch = text.match(/Initial late charge:\s*\$?([\d,]+\.?\d*)/);
  if (lateMatch) data.initialLateFee = parseFloat(lateMatch[1].replace(/,/g, ''));

  const dailyMatch = text.match(/Additional daily charge:\s*\$?([\d,]+\.?\d*)/);
  if (dailyMatch) data.dailyLateFee = parseFloat(dailyMatch[1].replace(/,/g, ''));

  // 7. RETURNED PAYMENTS
  const returnedMatch = text.match(/Tenant will pay\s*\$?([\d,]+\.?\d*)\s*for each returned/);
  if (returnedMatch) data.returnedPaymentFee = parseFloat(returnedMatch[1].replace(/,/g, ''));

  // 9. ANIMALS
  if (text.includes('[X] No animals permitted') || text.includes('[X] No animals')) {
    data.petsAllowed = false;
  } else {
    const petsMatch = text.match(/Animals permitted:\s*(.+?)(?:\n|$)/);
    if (petsMatch && petsMatch[1].trim()) {
      data.petsAllowed = true;
      data.allowedPets = petsMatch[1].trim();
    }
  }

  const petFeeMatch = text.match(/Unauthorized animal fee:\s*\$?([\d,]+\.?\d*)/);
  if (petFeeMatch) data.unauthorizedPetFee = parseFloat(petFeeMatch[1].replace(/,/g, ''));

  // 10. SECURITY DEPOSIT
  const depositMatch = text.match(/A\.\s*Amount:\s*\$?([\d,]+\.?\d*)/);
  if (depositMatch) data.securityDeposit = parseFloat(depositMatch[1].replace(/,/g, ''));

  // 11. UTILITIES
  const utilMatch = text.match(/Tenant pays all utilities except:\s*(.+?)(?:\n|$)/);
  if (utilMatch && utilMatch[1].trim() !== 'None') data.landlordPaysUtilities = utilMatch[1].trim();

  // 12. HOA
  const hoaMatch = text.match(/HOA:\s*(.+?)(?:\n|$)/);
  if (hoaMatch && !hoaMatch[1].includes('Not subject')) data.hoaName = hoaMatch[1].trim();

  // 14. ACCESS
  const accessMatch = text.match(/Landlord may enter at reasonable times with\s*(\d+)\s*hours notice/);
  if (accessMatch) data.accessNoticeHours = accessMatch[1];

  // 17. SMOKING
  if (text.includes('[X] NOT Permitted') && text.includes('Smoking:')) {
    data.smokingAllowed = false;
  } else if (text.includes('[X] Permitted') && text.includes('Smoking:')) {
    data.smokingAllowed = true;
  }

  // 18. REPAIRS
  const repairMatch = text.match(/Contact for repairs:\s*(.+?)\s+at\s+(\d+)/);
  if (repairMatch) {
    data.emergencyContact = repairMatch[1].trim();
    data.landlordPhone = repairMatch[2].trim();
  }

  // 22. HOLDOVER
  const holdoverMatch = text.match(/If Tenant remains after expiration:\s*\$?([\d,]+\.?\d*)/);
  if (holdoverMatch) data.holdoverRent = parseFloat(holdoverMatch[1].replace(/,/g, ''));

  // 26. SPECIAL PROVISIONS
  const spMatch = text.match(/26\.\s*SPECIAL PROVISIONS\n([\s\S]*?)(?:27\.|$)/);
  if (spMatch) {
    const provisions = spMatch[1]
      .split(/\n/)
      .map(l => l.replace(/^[a-z]\.\s*/, '').trim())
      .filter(l => l.length > 10);
    if (provisions.length > 0) data.specialProvisions = provisions.join('\n');
  }

  // 32. NOTICES — extract landlord & tenant emails
  const noticeSection = text.match(/32\.\s*NOTICES?\n([\s\S]*?)(?:33\.|$)/);
  if (noticeSection) {
    const landlordNotice = noticeSection[1].match(/Landlord:\s*(.+)/);
    if (landlordNotice) {
      const parts = landlordNotice[1].split(/,\s*/);
      const emailPart = parts.find(p => p.includes('@'));
      if (emailPart) data.landlordEmail = emailPart.trim();
      // Extract landlord address from notices
      if (parts.length >= 3) {
        const addrParts = parts.filter(p => !p.includes('@')).join(', ').trim();
        if (addrParts && !data.landlordAddress) data.landlordAddress = addrParts;
      }
    }
    const tenantNotice = noticeSection[1].match(/Tenant:\s*(.+)/);
    if (tenantNotice) {
      const tParts = tenantNotice[1].split(/,\s*/);
      const tEmail = tParts.find(p => p.includes('@'));
      if (tEmail) data.tenantEmail = tEmail.trim();
    }
  }

  // EXECUTION — extract signatures, dates, and status
  const execSection = text.match(/EXECUTION\n([\s\S]*)/);
  if (execSection) {
    const execText = execSection[1];

    // Landlord signature
    const llSig = execText.match(/LANDLORD:\s*\n?\s*Signed:\s*(.+?)\s+on\s+([\d/]+,\s*[\d:APM\s]+?)\s*\|\s*IP:\s*(\S+)/);
    if (llSig) {
      data.landlordSignature = llSig[1].trim();
      data.landlordSignedAt = new Date(llSig[2]).toISOString();
      data.landlordSignedIp = llSig[3].trim();
    }

    // Tenant signature
    const tSig = execText.match(/TENANT:\s*\n?\s*Signed:\s*(.+?)\s+on\s+([\d/]+,\s*[\d:APM\s]+?)\s*\|\s*IP:\s*(\S+)/);
    if (tSig) {
      data.tenantSignature = tSig[1].trim();
      data.tenantSignedAt = new Date(tSig[2]).toISOString();
      data.tenantSignedIp = tSig[3].trim();
    }

    // Co-tenant signatures — look for CO-TENANT N blocks
    const coSigRegex = /CO-TENANT\s*\d+\s*:\s*\n?\s*Signed:\s*(.+?)\s+on\s+([\d/]+,\s*[\d:APM\s]+?)\s*\|\s*IP:\s*(\S+)/g;
    let coMatch;
    const coSignatures = [];
    while ((coMatch = coSigRegex.exec(execText)) !== null) {
      coSignatures.push({
        name: coMatch[1].trim(),
        signedAt: new Date(coMatch[2]).toISOString(),
        signedIp: coMatch[3].trim()
      });
    }
    // Merge co-tenant signatures into additionalTenants
    if (coSignatures.length > 0 && data.additionalTenants) {
      data.additionalTenants = data.additionalTenants.map((t, i) => ({
        ...t,
        ...(coSignatures[i] || {}),
        signature: coSignatures[i]?.name || t.signature
      }));
    }

    // Document ID from certificate
    const docIdMatch = execText.match(/Document ID:\s*([a-f0-9-]+)/);
    if (docIdMatch) data._originalDocumentId = docIdMatch[1];

    // Status
    if (execText.includes('FULLY EXECUTED')) {
      data.status = 'completed';
    } else if (data.landlordSignature && data.tenantSignature) {
      data.status = 'completed';
    } else if (data.landlordSignature || data.tenantSignature) {
      data.status = 'partial';
    }
  }

  // Fallback: derive title from address if no title provided
  if (data.propertyAddress) {
    data._suggestedTitle = data.propertyAddress;
  }

  return data;
}

// Import an existing lease PDF — extracts text and auto-fills lease fields
app.post('/api/documents/import-pdf', auth, pdfUpload.single('pdf'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'PDF file is required' });
    }

    const storedPath = req.file.path;
    const filename = req.file.originalname || 'imported-lease.pdf';

    // Derive a title from the filename
    const title = req.body.title || filename.replace(/\.pdf$/i, '').replace(/[-_]/g, ' ');

    // Extract text from the uploaded PDF and parse lease fields
    let extractedData = {};
    try {
      const pdfBuffer = fs.readFileSync(storedPath);
      const pdfData = await pdfParse(pdfBuffer);
      console.log(`PDF parsed: ${pdfData.numpages} pages, ${pdfData.text.length} chars`);
      extractedData = extractLeaseData(pdfData.text);
      console.log('Extracted fields:', Object.keys(extractedData).filter(k => !k.startsWith('_')).join(', '));
    } catch (parseErr) {
      console.warn('PDF text extraction failed (non-critical):', parseErr.message);
    }

    // Extract embedded signature images from PDF (overrides text-extracted names)
    try {
      const sigImages = extractSignatureImages(storedPath);
      console.log(`Found ${sigImages.length} embedded signature image(s)`);
      // Helper: check if an extracted signature image has actual content (>500 bytes base64 = visible strokes)
      const hasContent = (dataUri) => {
        if (!dataUri) return false;
        const b64 = dataUri.replace(/^data:image\/png;base64,/, '');
        return b64.length > 500;
      };

      // Signature images come in pairs (Gray + RGB). Use the RGB versions (even indices).
      if (sigImages.length >= 2 && hasContent(sigImages[1].dataUri)) {
        extractedData.landlordSignature = sigImages[1].dataUri;
      } else if (sigImages.length >= 1 && hasContent(sigImages[0].dataUri)) {
        extractedData.landlordSignature = sigImages[0].dataUri;
      }
      if (sigImages.length >= 4 && hasContent(sigImages[3].dataUri)) {
        extractedData.tenantSignature = sigImages[3].dataUri;
      } else if (sigImages.length >= 3 && hasContent(sigImages[2].dataUri)) {
        extractedData.tenantSignature = sigImages[2].dataUri;
      }
      // Co-tenant signatures
      if (sigImages.length >= 6 && extractedData.additionalTenants) {
        let imgIdx = 5;
        for (const t of extractedData.additionalTenants) {
          if (imgIdx < sigImages.length && hasContent(sigImages[imgIdx].dataUri)) {
            t.signature = sigImages[imgIdx].dataUri;
            imgIdx += 2;
          }
        }
      }

      // Fallback: generate text-based signature images when binary extraction yields nothing visible
      const llName = extractedData.landlordName || 'Landlord';
      const tName = extractedData.tenantName || 'Tenant';
      if (!extractedData.landlordSignature || !hasContent(extractedData.landlordSignature)) {
        const buf = textSignatureToPng(llName);
        extractedData.landlordSignature = `data:image/png;base64,${buf.toString('base64')}`;
      }
      if (!extractedData.tenantSignature || !hasContent(extractedData.tenantSignature)) {
        const buf = textSignatureToPng(tName);
        extractedData.tenantSignature = `data:image/png;base64,${buf.toString('base64')}`;
      }
      if (extractedData.additionalTenants) {
        for (const t of extractedData.additionalTenants) {
          if (!t.signature || !hasContent(t.signature)) {
            const buf = textSignatureToPng(t.name || 'Co-Tenant');
            t.signature = `data:image/png;base64,${buf.toString('base64')}`;
          }
        }
      }
    } catch (sigErr) {
      console.warn('Signature image extraction failed (non-critical):', sigErr.message);
    }

    const docData = {
      uploadedPdf: storedPath,
      uploadedPdfName: filename,
      importedAt: new Date().toISOString(),
      ...extractedData
    };

    // Determine status from extraction (defaults to 'draft' if not found)
    const docStatus = extractedData.status || 'draft';
    delete docData.status; // handled via column, not data JSON

    // Use address-based title if no explicit title and address was extracted
    const finalTitle = title || extractedData._suggestedTitle || 'Imported Lease';
    delete docData._suggestedTitle;
    delete docData._originalDocumentId; // internal reference only

    // For completed docs, set signature columns directly
    const llSig = extractedData.landlordSignature || null;
    const llDate = extractedData.landlordSignedAt || null;
    const llIp = extractedData.landlordSignedIp || null;
    const tSig = extractedData.tenantSignature || null;
    const tDate = extractedData.tenantSignedAt || null;
    const tIp = extractedData.tenantSignedIp || null;

    const result = await pool.query(
      `INSERT INTO documents (user_id, status, title, data,
        landlord_sign_token, tenant_sign_token,
        landlord_signature, landlord_signed_at, landlord_signed_ip,
        tenant_signature, tenant_signed_at, tenant_signed_ip)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [req.user.id, docStatus, finalTitle, JSON.stringify(docData),
       uuidv4(), uuidv4(),
       llSig, llDate, llIp,
       tSig, tDate, tIp]
    );

    const doc = docRowToObject(result.rows[0]);
    await logAudit(doc.id, 'PDF_IMPORTED', req.user.email, req, { filename, extractedFields: Object.keys(extractedData).filter(k => !k.startsWith('_')) });
    res.json(doc);
  } catch (e) {
    console.error('PDF import error:', e);
    res.status(500).json({ error: e.message || 'Failed to import PDF' });
  }
});

// Serve the uploaded PDF for a document
app.get('/api/documents/:id/uploaded-pdf', auth, async (req, res) => {
  const result = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'Document not found' });
  }

  const doc = docRowToObject(result.rows[0]);
  const pdfPath = doc.uploadedPdf;

  if (!pdfPath || !fs.existsSync(pdfPath)) {
    return res.status(404).json({ error: 'No uploaded PDF found for this document' });
  }

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="${doc.uploadedPdfName || 'lease.pdf'}"`);
  fs.createReadStream(pdfPath).pipe(res);
});

// ==================== SIGNATURE WORKFLOW ====================

app.post('/api/documents/:id/send', auth, async (req, res) => {
  try {
    const docResult = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (docResult.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const doc = docRowToObject(docResult.rows[0]);

    // Set link expiration (7 days from now)
    const linkExpiresAt = new Date(Date.now() + LINK_EXPIRATION_MS);

    // Update status and expiration
    const result = await pool.query(
      `UPDATE documents SET status = 'pending', link_expires_at = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *`,
      [linkExpiresAt, req.params.id]
    );
    const updated = docRowToObject(result.rows[0]);

    // Send email to landlord
    const signUrl = `${APP_URL}/sign/${doc.landlordSignToken}`;
    await mailer.sendMail({
      from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
      to: doc.landlordEmail,
      subject: `[Action Required] Sign Lease for ${doc.propertyAddress}`,
      text: `Please sign the lease agreement: ${signUrl}`,
      html: generateSignEmail(updated, 'landlord', signUrl)
    });

    // Send SMS if phone number available
    if (doc.landlordPhone) {
      await sendSMS(doc.landlordPhone, `LeaseSign: Please sign the lease for ${doc.propertyAddress}. Link: ${signUrl}`);
    }

    await logAudit(doc.id, 'SENT_FOR_SIGNATURE', req.user.email, req, { to: doc.landlordEmail });
    await createNotification(req.user.id, 'sent', 'Document Sent', `Lease for ${doc.propertyAddress} sent to ${doc.landlordEmail}`, doc.id);
    res.json(updated);
  } catch (e) {
    console.error('Send error:', e);
    res.status(500).json({ error: 'Failed to send document' });
  }
});

// Public signing endpoint - get document
app.get('/api/sign/:token', async (req, res) => {
  const result = await pool.query(
    `SELECT * FROM documents
     WHERE landlord_sign_token = $1
        OR tenant_sign_token = $1
        OR (jsonb_typeof(data->'additionalTenants') = 'array'
            AND data->'additionalTenants' @> jsonb_build_array(jsonb_build_object('signToken', $1)))`,
    [req.params.token]
  );

  if (result.rows.length === 0) return res.status(404).json({ error: 'Document not found or link expired' });

  const doc = docRowToObject(result.rows[0]);

  // Check if document is voided or declined
  if (doc.status === 'voided' || doc.status === 'declined') {
    return res.status(410).json({ error: 'This document has been voided or declined.', expired: true });
  }

  // Check if link has expired
  if (doc.linkExpiresAt && new Date(doc.linkExpiresAt) < new Date()) {
    return res.status(410).json({ error: 'This signing link has expired. Please contact the sender to request a new link.', expired: true });
  }

  let signerType, tenantIndex = -1;
  if (doc.landlordSignToken === req.params.token) {
    signerType = 'landlord';
  } else if (doc.tenantSignToken === req.params.token) {
    signerType = 'tenant';
  } else {
    tenantIndex = (doc.additionalTenants || []).findIndex(t => t.signToken === req.params.token);
    signerType = 'additional_tenant';
  }

  if (signerType === 'landlord' && doc.landlordSignedAt)
    return res.status(400).json({ error: 'Already signed by landlord' });
  if (signerType === 'tenant' && doc.tenantSignedAt)
    return res.status(400).json({ error: 'Already signed by tenant' });
  if (signerType === 'additional_tenant' && doc.additionalTenants[tenantIndex]?.signedAt)
    return res.status(400).json({ error: 'Already signed' });

  // Remove sensitive tokens
  const safeDoc = { ...doc };
  delete safeDoc.landlordSignToken;
  delete safeDoc.tenantSignToken;
  delete safeDoc.userId;
  if (Array.isArray(safeDoc.additionalTenants)) {
    safeDoc.additionalTenants = safeDoc.additionalTenants.map(({ signToken, ...t }) => t);
  }

  const response = { document: safeDoc, signerType };
  if (signerType === 'additional_tenant') response.tenantIndex = tenantIndex;
  res.json(response);
});

// Public signing endpoint - submit signature
app.post('/api/sign/:token', async (req, res) => {
  try {
    const { signature } = req.body;
    if (!signature) return res.status(400).json({ error: 'Signature required' });

    const result = await pool.query(
      `SELECT * FROM documents
       WHERE landlord_sign_token = $1
          OR tenant_sign_token = $1
          OR (jsonb_typeof(data->'additionalTenants') = 'array'
              AND data->'additionalTenants' @> jsonb_build_array(jsonb_build_object('signToken', $1)))`,
      [req.params.token]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: 'Document not found' });

    const doc = docRowToObject(result.rows[0]);
    const rawData = result.rows[0].data || {};

    // Check if document is voided or declined
    if (doc.status === 'voided' || doc.status === 'declined') {
      return res.status(410).json({ error: 'This document has been voided or declined.', expired: true });
    }

    if (doc.linkExpiresAt && new Date(doc.linkExpiresAt) < new Date()) {
      return res.status(410).json({ error: 'This signing link has expired. Please contact the sender to request a new link.', expired: true });
    }

    let signerType, tenantIndex = -1;
    if (doc.landlordSignToken === req.params.token) {
      signerType = 'landlord';
    } else if (doc.tenantSignToken === req.params.token) {
      signerType = 'tenant';
    } else {
      tenantIndex = (doc.additionalTenants || []).findIndex(t => t.signToken === req.params.token);
      signerType = 'additional_tenant';
    }

    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    const now = new Date();
    let updateResult = null;

    if (signerType === 'landlord') {
      const newExpiration = new Date(Date.now() + LINK_EXPIRATION_MS);

      updateResult = await pool.query(
        `UPDATE documents SET
          landlord_signature = $1, landlord_signed_at = $2, landlord_signed_ip = $3,
          link_expires_at = $4, status = 'partial', updated_at = CURRENT_TIMESTAMP
         WHERE id = $5 RETURNING *`,
        [signature, now, ip, newExpiration, doc.id]
      );

      await logAudit(doc.id, 'LANDLORD_SIGNED', doc.landlordEmail, req);
      const updatedDoc = docRowToObject(updateResult.rows[0]);

      // Send email to primary tenant
      const tenantSignUrl = `${APP_URL}/sign/${doc.tenantSignToken}`;
      await mailer.sendMail({
        from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
        to: doc.tenantEmail,
        subject: `[Action Required] Sign Lease for ${doc.propertyAddress}`,
        text: `Please sign the lease agreement: ${tenantSignUrl}`,
        html: generateSignEmail(updatedDoc, 'tenant', tenantSignUrl)
      });
      if (doc.tenantPhone) {
        await sendSMS(doc.tenantPhone, `LeaseSign: The landlord has signed! Please sign the lease for ${doc.propertyAddress}. Link: ${tenantSignUrl}`);
      }

      // Send email to each additional tenant
      for (const t of (doc.additionalTenants || [])) {
        if (t.email && t.signToken) {
          const addSignUrl = `${APP_URL}/sign/${t.signToken}`;
          await mailer.sendMail({
            from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
            to: t.email,
            subject: `[Action Required] Sign Lease for ${doc.propertyAddress}`,
            text: `Please sign the lease agreement: ${addSignUrl}`,
            html: generateSignEmail({ ...updatedDoc, tenantName: t.name }, 'tenant', addSignUrl)
          });
        }
      }

      await createNotification(doc.userId, 'signed', 'Landlord Signed', `${doc.landlordName} signed the lease for ${doc.propertyAddress}`, doc.id);
    } else if (signerType === 'tenant') {
      const allAdditionalSigned = !(doc.additionalTenants?.length) ||
        doc.additionalTenants.every(t => t.signedAt);
      const newStatus = (doc.landlordSignedAt && allAdditionalSigned) ? 'completed' : 'partial';

      updateResult = await pool.query(
        `UPDATE documents SET
          tenant_signature = $1, tenant_signed_at = $2, tenant_signed_ip = $3,
          status = $4, updated_at = CURRENT_TIMESTAMP
         WHERE id = $5 RETURNING *`,
        [signature, now, ip, newStatus, doc.id]
      );

      await logAudit(doc.id, 'TENANT_SIGNED', doc.tenantEmail, req);
      await createNotification(doc.userId, 'signed', 'Tenant Signed', `${doc.tenantName} signed the lease for ${doc.propertyAddress}`, doc.id);
    } else {
      // Additional tenant signing — update their entry in the JSONB data
      const updatedTenants = doc.additionalTenants.map((t, i) =>
        i === tenantIndex ? { ...t, signature, signedAt: now.toISOString(), signedIp: ip } : t
      );
      const updatedData = { ...rawData, additionalTenants: updatedTenants };
      const allAdditionalSigned = updatedTenants.every(t => t.signedAt);
      const newStatus = (doc.landlordSignedAt && doc.tenantSignedAt && allAdditionalSigned) ? 'completed' : 'partial';

      updateResult = await pool.query(
        `UPDATE documents SET data = $1, status = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3 RETURNING *`,
        [JSON.stringify(updatedData), newStatus, doc.id]
      );

      const tenant = doc.additionalTenants[tenantIndex];
      await logAudit(doc.id, 'ADDITIONAL_TENANT_SIGNED', tenant.email, req);
      await createNotification(doc.userId, 'signed', 'Co-Tenant Signed', `${tenant.name} signed the lease for ${doc.propertyAddress}`, doc.id);
    }

    if (!updateResult) {
      return res.status(500).json({ error: 'Signing failed — internal error' });
    }
    const updated = docRowToObject(updateResult.rows[0]);

    if (updated.status === 'completed') {
      await sendCompletionEmails(updated);
      await createNotification(doc.userId, 'completed', 'Lease Completed', `The lease for ${doc.propertyAddress} has been fully executed!`, doc.id);
    }

    res.json({ success: true, status: updated.status });
  } catch (e) {
    console.error('Sign error:', e);
    res.status(500).json({ error: 'Signing failed' });
  }
});

// ==================== PDF GENERATION ====================

app.get('/api/documents/:id/pdf', auth, async (req, res) => {
  const result = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'Document not found' });
  }

  generatePDF(docRowToObject(result.rows[0]), res);
});

function generatePDF(doc, res) {
  const pdf = new PDFDocument({ size: 'LETTER', margins: { top: 50, bottom: 50, left: 60, right: 60 } });

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="Lease_${(doc.propertyAddress || 'document').replace(/[^a-zA-Z0-9]/g, '_')}.pdf"`);

  pdf.pipe(res);

  generatePDFContent(pdf, doc);
}

function generatePDFContent(pdf, doc) {
  // Page dimensions: LETTER = 612 x 792 points
  // Margins: 60 left, 60 right = 492 usable width
  const leftMargin = 60;
  const textWidth = 492;

  // Helper functions
  const field = (val) => val || '________________________';
  const money = (val) => val ? `$${parseFloat(val).toLocaleString('en-US', { minimumFractionDigits: 2 })}` : '$____________';
  const checkbox = (checked) => checked ? '[X]' : '[ ]';
  let pageNum = 1;

  const resetX = () => { pdf.x = leftMargin; };

  const addHeader = () => {
    pdf.font('Helvetica').fontSize(8).fillColor('#666666');
    pdf.text('RESIDENTIAL LEASE - TAR 2001', leftMargin, 30, { width: textWidth });
    pdf.text(`Page ${pageNum}`, 500, 30);
    pdf.fillColor('#000000');
    resetX();
    pageNum++;
  };

  const addFooter = () => {
    const y = pdf.page.height - 40;
    pdf.font('Helvetica').fontSize(7).fillColor('#666666');
    pdf.text(`${doc.propertyAddress || 'Property'} | Landlord: ${doc.landlordName || ''} | Tenant: ${doc.tenantName || ''}`, leftMargin, y, { width: textWidth, align: 'center' });
    pdf.fillColor('#000000');
    resetX();
  };

  const newPage = () => {
    addFooter();
    pdf.addPage();
    addHeader();
    pdf.y = 60;
    resetX();
  };

  // Only use checkSpace for signature section - let PDFKit handle normal content flow
  const checkSpace = (needed) => {
    if (pdf.y > pdf.page.height - 50 - needed) newPage();
  };

  const sectionTitle = (num, title) => {
    resetX();
    pdf.font('Helvetica-Bold').fontSize(10).fillColor('#000000');
    pdf.text(`${num}. ${title}`, { width: textWidth });
    pdf.font('Helvetica').fontSize(9);
    pdf.moveDown(0.3);
    resetX();
  };

  const paragraph = (text) => {
    resetX();
    pdf.text(text, { width: textWidth });
  };

  const subSection = (letter, text) => {
    resetX();
    pdf.font('Helvetica-Bold').fontSize(9).text(`${letter}. `, { continued: true, width: textWidth });
    pdf.font('Helvetica').fontSize(9).text(text, { width: textWidth - 20 });
    pdf.moveDown(0.3);
    resetX();
  };

  // ===== PAGE 1 - HEADER =====
  addHeader();
  pdf.y = 50;
  resetX();

  // Title Block
  pdf.font('Helvetica-Bold').fontSize(16).text('RESIDENTIAL LEASE', leftMargin, pdf.y, { width: textWidth, align: 'center' });
  resetX();
  pdf.font('Helvetica').fontSize(8).text('USE OF THIS FORM BY PERSONS WHO ARE NOT MEMBERS OF THE TEXAS ASSOCIATION OF REALTORS IS NOT AUTHORIZED.', { width: textWidth, align: 'center' });
  resetX();
  pdf.text('Texas Association of REALTORS, Inc. 2022', { width: textWidth, align: 'center' });
  pdf.moveDown(1.5);
  resetX();

  // Section 1: PARTIES
  sectionTitle('1', 'PARTIES');
  const allTenantNames = [doc.tenantName, ...(doc.additionalTenants || []).map(t => t.name)]
    .filter(Boolean).join(', ');
  paragraph(`The parties to this lease are: the owner of the Property (Landlord): ${field(doc.landlordName)}; and the following tenant(s) (collectively referred to as "Tenant"): ${field(allTenantNames)}.`);
  pdf.moveDown();

  // Section 2: PROPERTY
  sectionTitle('2', 'PROPERTY');
  paragraph(`Landlord leases to Tenant the real property described below together with all its improvements (collectively the "Property"):`);
  pdf.moveDown(0.3);
  subSection('A', `Address: ${field(doc.propertyAddress)}, ${field(doc.propertyCity)}, TX ${field(doc.propertyZip)}`);
  subSection('B', `Legal Description: ${field(doc.legalDescription)}`);
  subSection('C', `County: ${field(doc.propertyCounty)}`);
  subSection('D', `Non-Real-Property Items: ${field(doc.nonRealPropertyItems || 'refrigerator, range/oven, dishwasher, disposal, microwave')}`);
  pdf.moveDown();

  // Section 3: TERM
  sectionTitle('3', 'TERM');
  subSection('A', 'Primary Term:');
  paragraph(`   Commencement Date: ${field(doc.commencementDate)}`);
  paragraph(`   Expiration Date: ${field(doc.expirationDate)} at 11:59 p.m.`);
  subSection('B', 'Delay of Occupancy: If Tenant cannot occupy the Property on the Commencement Date because of construction, Tenant may terminate this lease by written notice before the Property is available.');
  pdf.moveDown();

  // Section 4: AUTOMATIC RENEWAL
  sectionTitle('4', 'AUTOMATIC RENEWAL');
  paragraph(`This lease automatically renews on a month-to-month basis unless either party provides written notice of termination at least ${field(doc.terminationNoticeDays || '30')} days before the Expiration Date.`);
  pdf.moveDown();

  // Section 5: RENT
  sectionTitle('5', 'RENT');
  subSection('A', `Monthly Rent: ${money(doc.monthlyRent)} due on or before the 1st day of each month.`);
  if (doc.proratedRent) {
    subSection('B', `Prorated Rent: ${money(doc.proratedRent)} due on or before ${field(doc.proratedDueDate)}.`);
  }
  subSection('C', 'Payment Method: ' + ([
    doc.paymentCashiersCheck ? 'Cashier\'s Check' : '',
    doc.paymentMoneyOrder ? 'Money Order' : '',
    doc.paymentPersonalCheck ? 'Personal Check' : '',
    doc.paymentElectronic ? 'Electronic Payment' : ''
  ].filter(Boolean).join(', ') || 'Any acceptable form'));
  subSection('D', `Place of Payment: ${field(doc.paymentName || doc.landlordName)}, ${field(doc.paymentAddress)}`);
  pdf.moveDown();

  // Section 6: LATE CHARGES
  sectionTitle('6', 'LATE CHARGES');
  paragraph(`If rent is not received by the ${field(doc.gracePeriodDay || '3')}rd day of each month at 11:59 p.m., Tenant will pay:`);
  paragraph(`   (1) Initial late charge: ${money(doc.initialLateFee || 50)}`);
  paragraph(`   (2) Additional daily charge: ${money(doc.dailyLateFee || 25)} per day until paid`);
  pdf.moveDown();

  // Section 7: RETURNED PAYMENTS
  sectionTitle('7', 'RETURNED PAYMENTS');
  paragraph(`Tenant will pay ${money(doc.returnedPaymentFee || 75)} for each returned or dishonored payment.`);
  pdf.moveDown();

  // Section 8: APPLICATION OF PAYMENTS
  sectionTitle('8', 'APPLICATION OF PAYMENTS');
  paragraph('Payments applied first to non-rent obligations (late charges, repairs, etc.), then to rent.');
  pdf.moveDown();

  // Section 9: ANIMALS
  sectionTitle('9', 'ANIMALS');
  paragraph(`${checkbox(!doc.petsAllowed)} No animals permitted  ${checkbox(doc.petsAllowed)} Animals permitted: ${field(doc.allowedPets)}`);
  paragraph(`Unauthorized animal fee: ${money(doc.unauthorizedPetFee || 100)} per animal per day.`);
  pdf.moveDown();

  // Section 10: SECURITY DEPOSIT
  sectionTitle('10', 'SECURITY DEPOSIT');
  subSection('A', `Amount: ${money(doc.securityDeposit)}`);
  subSection('B', 'Return within 30 days after Tenant surrenders Property, less lawful deductions.');
  subSection('C', 'Deductions may include: unpaid rent, utilities, late charges, repairs, cleaning, key replacement.');
  pdf.moveDown();

  // Section 11: UTILITIES
  sectionTitle('11', 'UTILITIES');
  paragraph(`Tenant pays all utilities except: ${field(doc.landlordPaysUtilities || 'None')}`);
  pdf.moveDown();

  // Section 12: USE AND OCCUPANCY
  sectionTitle('12', 'USE AND OCCUPANCY');
  subSection('A', `Occupants: ${field(doc.occupants)}`);
  subSection('B', 'Use: Residential purposes only. No business operations.');
  subSection('C', `HOA: ${doc.hoaName ? 'Subject to ' + doc.hoaName : 'Not subject to HOA'}`);
  subSection('D', `Guests: Maximum ${field(doc.maxGuestDays || '14')} consecutive days without written consent.`);
  pdf.moveDown();

  // Section 13: PARKING
  sectionTitle('13', 'PARKING RULES');
  paragraph(`Maximum ${field(doc.maxVehicles || '4')} vehicles. All must be operable with current registration. No commercial vehicles, trailers, or RVs without consent.`);
  pdf.moveDown();

  // Section 14: ACCESS BY LANDLORD
  sectionTitle('14', 'ACCESS BY LANDLORD');
  paragraph(`Landlord may enter at reasonable times with ${field(doc.accessNoticeHours || '24')} hours notice (except emergencies).`);
  subSection('A', `Trip Charge: ${money(doc.tripCharge || 75)} if Tenant fails to permit access.`);
  subSection('B', `Keybox: ${checkbox(doc.keyboxAuthorized)} Authorized during last ${field(doc.keyboxDays || '30')} days of lease.`);
  pdf.moveDown();

  // Section 15: MOVE-IN CONDITION
  sectionTitle('15', 'MOVE-IN CONDITION');
  paragraph(`${checkbox(doc.asIsCondition)} Tenant accepts Property as-is.`);
  paragraph(`Inventory form due within ${field(doc.inventoryDays || '3')} days of possession.`);
  pdf.moveDown();

  // Section 16: MOVE-OUT
  sectionTitle('16', 'MOVE-OUT');
  paragraph('Tenant will: return all keys; remove personal property; leave Property in good condition; provide forwarding address.');
  pdf.moveDown();

  // Section 17: PROPERTY MAINTENANCE
  sectionTitle('17', 'PROPERTY MAINTENANCE');
  subSection('A', 'Tenant will: keep Property clean; dispose garbage; comply with laws and HOA rules; notify Landlord of needed repairs.');
  subSection('B', `Yard: ${checkbox(doc.yardMaintenance === 'landlord')} Landlord ${checkbox(doc.yardMaintenance !== 'landlord')} Tenant maintains.`);
  subSection('C', `Smoking: ${checkbox(doc.smokingAllowed)} Permitted ${checkbox(!doc.smokingAllowed)} NOT Permitted`);
  subSection('D', 'HVAC Filters: Replace monthly or as directed.');
  pdf.moveDown();

  // Section 18: REPAIRS
  sectionTitle('18', 'REPAIRS');
  subSection('A', `Contact for repairs: ${field(doc.emergencyContact || doc.landlordName)} at ${field(doc.landlordPhone || doc.landlordEmail)}`);
  subSection('B', 'Tenant pays for repairs caused by Tenant, guests, or animals.');
  pdf.moveDown();

  // Section 19-25: Condensed legal sections
  sectionTitle('19', 'SECURITY DEVICES');
  paragraph('Per Texas Property Code 92.153. Rekeying costs paid by: ' + (doc.rekeyPaidByLandlord ? 'Landlord' : 'Tenant'));
  pdf.moveDown();

  sectionTitle('20', 'SMOKE ALARMS');
  paragraph('Landlord installs per code. Tenant tests monthly and replaces batteries.');
  pdf.moveDown();

  sectionTitle('21', 'LIABILITY');
  paragraph('Landlord not liable for damages from utility failure, weather, crime, or Property conditions. Tenant releases Landlord.');
  pdf.moveDown();

  sectionTitle('22', 'HOLDOVER');
  paragraph(`If Tenant remains after expiration: ${money(doc.holdoverRent || (doc.monthlyRent ? doc.monthlyRent * 3 : 0))} per month until surrender.`);
  pdf.moveDown();

  sectionTitle('23', 'LANDLORD\'S LIEN');
  paragraph('Per Texas Property Code 54.021. Certain items exempt.');
  pdf.moveDown();

  sectionTitle('24', 'SUBORDINATION');
  paragraph('This lease subordinate to existing or future mortgages and liens.');
  pdf.moveDown();

  sectionTitle('25', 'CASUALTY LOSS');
  paragraph('Per Texas Property Code 92.054 if Property becomes unfit.');
  pdf.moveDown();

  // Section 26: SPECIAL PROVISIONS
  sectionTitle('26', 'SPECIAL PROVISIONS');
  if (doc.specialProvisions) {
    doc.specialProvisions.split('\n').filter(p => p.trim()).forEach((p, i) => {
      paragraph(`${String.fromCharCode(97 + i)}. ${p.trim()}`);
    });
  } else {
    paragraph('None.');
  }
  pdf.moveDown();

  // Section 27-30: Legal condensed
  sectionTitle('27', 'DEFAULT');
  paragraph('Tenant default includes: nonpayment, abandonment, lease violations, false statements. Landlord may terminate, accelerate rent, sue for damages and attorney\'s fees. Interest at 18% on past-due amounts.');
  pdf.moveDown();

  sectionTitle('28', 'EARLY TERMINATION');
  paragraph('Permitted for: military deployment (30 days notice), family violence (per Texas Property Code Ch. 92), sex offenses/stalking victims.');
  pdf.moveDown();

  sectionTitle('29', 'ATTORNEY\'S FEES');
  paragraph('Prevailing party may recover reasonable attorney\'s fees.');
  pdf.moveDown();

  sectionTitle('30', 'REPRESENTATIONS');
  paragraph('False statements by Tenant may result in lease termination.');
  pdf.moveDown();

  // Section 31: ADDENDA
  sectionTitle('31', 'ADDENDA');
  paragraph([
    doc.addendumFlood ? '[X] Flood Disclosure' : '[ ] Flood Disclosure',
    doc.addendumLeadPaint ? '[X] Lead-Based Paint' : '[ ] Lead-Based Paint',
    doc.addendumInventory ? '[X] Inventory Form' : '[ ] Inventory Form',
    doc.addendumPets ? '[X] Pet Agreement' : '[ ] Pet Agreement',
  ].join('  '));
  pdf.moveDown();

  // Section 32: NOTICES
  sectionTitle('32', 'NOTICES');
  paragraph(`Landlord: ${field(doc.landlordName)}, ${field(doc.landlordAddress || doc.paymentAddress)}, ${field(doc.landlordEmail)}`);
  paragraph(`Tenant: ${field(doc.propertyAddress)}, ${field(doc.tenantEmail)}`);
  pdf.moveDown();

  // Section 33: AGREEMENT
  sectionTitle('33', 'AGREEMENT OF PARTIES');
  paragraph('Entire agreement. Binding on heirs/successors. Joint and several liability. Texas law governs.');
  pdf.moveDown();

  // ===== SIGNATURE SECTION =====
  resetX();
  pdf.font('Helvetica-Bold').fontSize(12).text('EXECUTION', leftMargin, pdf.y, { width: textWidth, align: 'center' });
  resetX();
  pdf.font('Helvetica').fontSize(9).text('By signing, each party acknowledges this lease is binding and enforceable.', { width: textWidth, align: 'center' });
  pdf.moveDown();
  resetX();

  // Signature helper: render as image (base64) or cursive text
  const renderSignature = (sigValue, name) => {
    if (!sigValue) return false;
    if (sigValue.startsWith('data:image/')) {
      try {
        const imgData = sigValue.replace(/^data:image\/\w+;base64,/, '');
        pdf.image(Buffer.from(imgData, 'base64'), leftMargin, pdf.y, { width: 150, height: 45 });
        pdf.y += 50;
        return true;
      } catch (e) { /* fall through to text */ }
    }
    // Text-based signature — render in cursive
    pdf.font('Times-Italic').fontSize(22).fillColor('#1e40af');
    pdf.text(sigValue, leftMargin, pdf.y, { width: textWidth });
    pdf.fillColor('#000000');
    pdf.moveDown(0.5);
    return true;
  };

  // Landlord Signature
  pdf.font('Helvetica-Bold').fontSize(10).text('LANDLORD:', { width: textWidth });
  resetX();
  if (renderSignature(doc.landlordSignature, doc.landlordName)) {
    resetX();
    pdf.font('Helvetica').fontSize(8);
    paragraph(`Signed: ${doc.landlordName} on ${doc.landlordSignedAt ? new Date(doc.landlordSignedAt).toLocaleString() : 'N/A'} | IP: ${doc.landlordSignedIp || 'N/A'}`);
  } else {
    paragraph('________________________________________     ________________');
    paragraph('Signature                                                              Date');
  }
  paragraph(`Name: ${field(doc.landlordName)}`);
  pdf.moveDown();

  // Tenant Signature
  resetX();
  pdf.font('Helvetica-Bold').fontSize(10).text('TENANT:', { width: textWidth });
  resetX();
  if (renderSignature(doc.tenantSignature, doc.tenantName)) {
    resetX();
    pdf.font('Helvetica').fontSize(8);
    paragraph(`Signed: ${doc.tenantName} on ${doc.tenantSignedAt ? new Date(doc.tenantSignedAt).toLocaleString() : 'N/A'} | IP: ${doc.tenantSignedIp || 'N/A'}`);
  } else {
    paragraph('________________________________________     ________________');
    paragraph('Signature                                                              Date');
  }
  paragraph(`Name: ${field(doc.tenantName)}`);

  // Additional tenant signature blocks
  for (const [i, t] of (doc.additionalTenants || []).entries()) {
    pdf.moveDown();
    resetX();
    pdf.font('Helvetica-Bold').fontSize(10).text(`CO-TENANT ${i + 1}:`, { width: textWidth });
    resetX();
    if (renderSignature(t.signature, t.name)) {
      resetX();
      pdf.font('Helvetica').fontSize(8);
      paragraph(`Signed: ${t.name} on ${t.signedAt ? new Date(t.signedAt).toLocaleString() : 'N/A'} | IP: ${t.signedIp || 'N/A'}`);
    } else {
      paragraph('________________________________________     ________________');
      paragraph('Signature                                                              Date');
    }
    paragraph(`Name: ${field(t.name)}`);
  }

  // E-Sign Certificate
  pdf.moveDown();
  resetX();
  pdf.font('Helvetica-Bold').fontSize(10).text('CERTIFICATE OF ELECTRONIC SIGNING', leftMargin, pdf.y, { width: textWidth, align: 'center' });
  resetX();
  pdf.font('Helvetica').fontSize(8).fillColor('#444444');
  pdf.text('This document was signed electronically via LeaseSign. Electronic signatures are legally binding under ESIGN Act and UETA.', { width: textWidth, align: 'center' });
  pdf.moveDown();
  resetX();
  pdf.fillColor('#666666');
  pdf.text(`Document ID: ${doc.id}`, { width: textWidth, align: 'center' });
  resetX();
  pdf.text(`Generated: ${new Date().toISOString()}`, { width: textWidth, align: 'center' });
  resetX();
  pdf.text(`Status: ${doc.status === 'completed' ? 'FULLY EXECUTED' : 'PENDING SIGNATURES'}`, { width: textWidth, align: 'center' });

  addFooter();
  pdf.end();
}

// ==================== EMAIL TEMPLATES ====================

function generateSignEmail(doc, signerType, signUrl) {
  const signerName = signerType === 'landlord' ? doc.landlordName : doc.tenantName;
  const primaryColor = '#4f46e5';
  const expiresDate = doc.linkExpiresAt ? new Date(doc.linkExpiresAt).toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' }) : null;

  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f3f4f6;">
  <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <tr>
      <td style="background: linear-gradient(135deg, ${primaryColor} 0%, #818cf8 100%); padding: 40px 30px; text-align: center; border-radius: 12px 12px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 28px;">LeaseSign</h1>
        <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0;">Residential Lease Agreement</p>
      </td>
    </tr>
    <tr>
      <td style="background: white; padding: 40px 30px; border: 1px solid #e5e7eb; border-top: none;">
        <h2 style="color: #111827; margin: 0 0 20px;">Hello ${signerName},</h2>
        <p style="color: #4b5563; line-height: 1.6; margin: 0 0 20px;">
          A residential lease agreement is ready for your electronic signature. Please review the document carefully before signing.
        </p>

        <table width="100%" style="background: #f9fafb; border-radius: 8px; padding: 20px; margin: 20px 0; border-left: 4px solid ${primaryColor};">
          <tr><td style="padding: 8px 0;"><strong style="color: #374151;">Property:</strong> <span style="color: #6b7280;">${doc.propertyAddress || 'N/A'}</span></td></tr>
          <tr><td style="padding: 8px 0;"><strong style="color: #374151;">Monthly Rent:</strong> <span style="color: #6b7280;">$${doc.monthlyRent?.toLocaleString() || 'N/A'}</span></td></tr>
          <tr><td style="padding: 8px 0;"><strong style="color: #374151;">Lease Term:</strong> <span style="color: #6b7280;">${doc.commencementDate || 'N/A'} to ${doc.expirationDate || 'N/A'}</span></td></tr>
        </table>

        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td style="text-align: center; padding: 20px 0;">
              <a href="${signUrl}" style="display: inline-block; background: ${primaryColor}; color: white; padding: 16px 40px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 16px;">
                Review & Sign Document
              </a>
            </td>
          </tr>
        </table>

        ${expiresDate ? `
        <div style="background: #fef3c7; border: 1px solid #fbbf24; border-radius: 8px; padding: 12px 16px; margin: 16px 0; text-align: center;">
          <span style="color: #92400e; font-size: 14px;">This link expires on <strong>${expiresDate}</strong></span>
        </div>
        ` : ''}

        <p style="color: #9ca3af; font-size: 13px; margin: 20px 0 0; padding-top: 20px; border-top: 1px solid #e5e7eb;">
          This link is unique to you. Do not share this link with others.
        </p>
      </td>
    </tr>
    <tr>
      <td style="background: #f9fafb; padding: 20px 30px; text-align: center; border-radius: 0 0 12px 12px; border: 1px solid #e5e7eb; border-top: none;">
        <p style="color: #9ca3af; font-size: 12px; margin: 0;">
          This is an automated message from LeaseSign.<br>
          Questions? Contact your landlord or property manager.
        </p>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

// Generate PDF as buffer for email attachment (reuses generatePDFContent)
function generatePDFBuffer(doc) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    const pdf = new PDFDocument({ size: 'LETTER', margins: { top: 50, bottom: 50, left: 60, right: 60 } });

    pdf.on('data', chunk => chunks.push(chunk));
    pdf.on('end', () => resolve(Buffer.concat(chunks)));
    pdf.on('error', reject);

    generatePDFContent(pdf, doc);
  });
}

async function sendCompletionEmails(doc) {
  // Generate PDF attachment
  let pdfBuffer;
  try {
    pdfBuffer = await generatePDFBuffer(doc);
  } catch (e) {
    console.error('Failed to generate PDF for email:', e);
  }

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f3f4f6;">
  <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <tr>
      <td style="background: linear-gradient(135deg, #10b981 0%, #34d399 100%); padding: 40px 30px; text-align: center; border-radius: 12px 12px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 28px;">Lease Signed Successfully!</h1>
      </td>
    </tr>
    <tr>
      <td style="background: white; padding: 40px 30px; border: 1px solid #e5e7eb; border-top: none;">
        <p style="color: #4b5563; line-height: 1.6;">
          Great news! The residential lease agreement has been fully executed by all parties.
        </p>

        <table width="100%" style="background: #f9fafb; border-radius: 8px; padding: 20px; margin: 20px 0; border-left: 4px solid #10b981;">
          <tr><td style="padding: 8px 0;"><strong>Property:</strong> ${doc.propertyAddress}</td></tr>
          <tr><td style="padding: 8px 0;"><strong>Landlord:</strong> ${doc.landlordName}</td></tr>
          <tr><td style="padding: 8px 0;"><strong>Tenant:</strong> ${doc.tenantName}</td></tr>
          <tr><td style="padding: 8px 0;"><strong>Completed:</strong> ${new Date().toLocaleDateString()}</td></tr>
        </table>

        <p style="color: #6b7280; font-size: 14px;">
          ${pdfBuffer ? 'The signed lease agreement is attached to this email as a PDF.' : 'You can download a PDF copy from your LeaseSign dashboard.'}
        </p>
      </td>
    </tr>
  </table>
</body>
</html>`;

  const filename = `Signed_Lease_${(doc.propertyAddress || 'document').replace(/[^a-zA-Z0-9]/g, '_')}.pdf`;

  const emailOptions = {
    from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
    subject: `Lease Completed: ${doc.propertyAddress}`,
    html,
    attachments: pdfBuffer ? [{
      filename,
      content: pdfBuffer,
      contentType: 'application/pdf'
    }] : []
  };

  const allRecipients = [
    doc.landlordEmail,
    doc.tenantEmail,
    ...(doc.additionalTenants || []).map(t => t.email)
  ].filter(Boolean);

  await Promise.all(allRecipients.map(to => mailer.sendMail({ ...emailOptions, to })));
}

// ==================== AUDIT LOG ====================

app.get('/api/documents/:id/audit', auth, async (req, res) => {
  const docResult = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
  if (docResult.rows.length === 0) {
    return res.status(404).json({ error: 'Document not found' });
  }

  const result = await pool.query(
    'SELECT * FROM audit_logs WHERE document_id = $1 ORDER BY timestamp DESC',
    [req.params.id]
  );
  res.json(result.rows);
});

// ==================== HEALTH & STATS ====================

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      status: 'healthy',
      database: 'connected',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: '1.0.0'
    });
  } catch (err) {
    res.status(500).json({
      status: 'unhealthy',
      database: 'disconnected',
      error: err.message
    });
  }
});

app.get('/api/stats', auth, async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM documents WHERE user_id = $1 AND (is_template = FALSE OR is_template IS NULL)',
    [req.user.id]
  );
  const userDocs = result.rows.map(docRowToObject);

  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

  // Basic counts
  const draft = userDocs.filter(d => d.status === 'draft').length;
  const pending = userDocs.filter(d => d.status === 'pending').length;
  const partial = userDocs.filter(d => d.status === 'partial').length;
  const completed = userDocs.filter(d => d.status === 'completed').length;
  const voided = userDocs.filter(d => d.status === 'voided').length;

  // Completion rate
  const sentDocs = userDocs.filter(d => d.status !== 'draft');
  const completionRate = sentDocs.length > 0 ? Math.round((completed / sentDocs.length) * 100) : 0;

  // Average time to complete (in hours)
  const completedDocs = userDocs.filter(d => d.status === 'completed' && d.tenantSignedAt && d.createdAt);
  let avgTimeToComplete = 0;
  if (completedDocs.length > 0) {
    const totalHours = completedDocs.reduce((sum, d) => {
      const created = new Date(d.createdAt);
      const signed = new Date(d.tenantSignedAt);
      return sum + (signed - created) / (1000 * 60 * 60);
    }, 0);
    avgTimeToComplete = Math.round(totalHours / completedDocs.length);
  }

  // Monthly trends (last 6 months)
  const monthlyTrends = [];
  for (let i = 5; i >= 0; i--) {
    const monthStart = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const monthEnd = new Date(now.getFullYear(), now.getMonth() - i + 1, 0);
    const monthName = monthStart.toLocaleString('en-US', { month: 'short' });
    const created = userDocs.filter(d => {
      const date = new Date(d.createdAt);
      return date >= monthStart && date <= monthEnd;
    }).length;
    const signed = userDocs.filter(d => {
      if (d.status !== 'completed') return false;
      const date = new Date(d.tenantSignedAt || d.updatedAt);
      return date >= monthStart && date <= monthEnd;
    }).length;
    monthlyTrends.push({ month: monthName, created, signed });
  }

  // Signing funnel
  const totalSent = pending + partial + completed + voided;
  const landlordSigned = partial + completed;
  const fullySigned = completed;

  // Recent activity
  const recentActivity = userDocs
    .filter(d => new Date(d.updatedAt) >= sevenDaysAgo)
    .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))
    .slice(0, 5)
    .map(d => ({
      id: d.id,
      title: d.title || d.propertyAddress,
      status: d.status,
      updatedAt: d.updatedAt
    }));

  res.json({
    total: userDocs.length,
    draft,
    pending,
    partial,
    completed,
    voided,
    last30Days: userDocs.filter(d => new Date(d.createdAt) >= thirtyDaysAgo).length,
    completedLast30Days: userDocs.filter(d => d.status === 'completed' && new Date(d.updatedAt) >= thirtyDaysAgo).length,
    completionRate,
    avgTimeToComplete,
    monthlyTrends,
    signingFunnel: { totalSent, landlordSigned, fullySigned },
    recentActivity
  });
});

// ==================== DOCUMENT ACTIONS ====================

app.post('/api/documents/:id/resend', auth, async (req, res) => {
  try {
    const docResult = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (docResult.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const doc = docRowToObject(docResult.rows[0]);

    if (doc.status === 'completed' || doc.status === 'voided') {
      return res.status(400).json({ error: 'Cannot resend completed or voided document' });
    }

    if (!doc.landlordSignedAt) {
      const signUrl = `${APP_URL}/sign/${doc.landlordSignToken}`;
      await mailer.sendMail({
        from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
        to: doc.landlordEmail,
        subject: `[Reminder] Please Sign: Lease for ${doc.propertyAddress}`,
        text: `Reminder: Please sign the lease agreement: ${signUrl}`,
        html: generateReminderEmail(doc, 'landlord', signUrl)
      });
      await logAudit(doc.id, 'SIGNATURE_REMINDER_SENT', req.user.email, req, { to: doc.landlordEmail });
      return res.json({ success: true, sentTo: doc.landlordEmail });
    }

    // Collect all unsigned tenants (primary + additional)
    const unsigned = [];
    if (!doc.tenantSignedAt)
      unsigned.push({ email: doc.tenantEmail, signToken: doc.tenantSignToken, name: doc.tenantName });
    for (const t of (doc.additionalTenants || [])) {
      if (!t.signedAt) unsigned.push({ email: t.email, signToken: t.signToken, name: t.name });
    }

    if (unsigned.length === 0)
      return res.status(400).json({ error: 'All signatures collected' });

    for (const r of unsigned) {
      const signUrl = `${APP_URL}/sign/${r.signToken}`;
      await mailer.sendMail({
        from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
        to: r.email,
        subject: `[Reminder] Please Sign: Lease for ${doc.propertyAddress}`,
        text: `Reminder: Please sign the lease agreement: ${signUrl}`,
        html: generateReminderEmail({ ...doc, tenantName: r.name }, 'tenant', signUrl)
      });
      await logAudit(doc.id, 'SIGNATURE_REMINDER_SENT', req.user.email, req, { to: r.email });
    }
    res.json({ success: true, sentTo: unsigned.map(r => r.email).join(', ') });
  } catch (e) {
    console.error('Resend error:', e);
    res.status(500).json({ error: 'Failed to resend' });
  }
});

app.post('/api/documents/:id/duplicate', auth, async (req, res) => {
  try {
    const docResult = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (docResult.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const original = docRowToObject(docResult.rows[0]);
    const originalData = { ...(docResult.rows[0].data || {}) };
    if (Array.isArray(originalData.additionalTenants)) {
      originalData.additionalTenants = originalData.additionalTenants.map(t => ({
        name: t.name || '',
        email: t.email || '',
        phone: t.phone || '',
        signToken: uuidv4(),
        signature: null,
        signedAt: null,
        signedIp: null
      }));
    }

    const result = await pool.query(
      `INSERT INTO documents (user_id, status, title, data, landlord_sign_token, tenant_sign_token)
       VALUES ($1, 'draft', $2, $3, $4, $5) RETURNING *`,
      [req.user.id, `Copy of ${original.title || 'Lease'}`, JSON.stringify(originalData), uuidv4(), uuidv4()]
    );

    const newDoc = docRowToObject(result.rows[0]);
    await logAudit(newDoc.id, 'DOCUMENT_DUPLICATED', req.user.email, req, { fromId: original.id });
    res.json(newDoc);
  } catch (e) {
    console.error('Duplicate error:', e);
    res.status(500).json({ error: 'Failed to duplicate document' });
  }
});

app.post('/api/documents/:id/void', auth, async (req, res) => {
  try {
    const docResult = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (docResult.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const doc = docRowToObject(docResult.rows[0]);

    if (doc.status === 'completed') {
      return res.status(400).json({ error: 'Cannot void completed document' });
    }

    const result = await pool.query(
      `UPDATE documents SET status = 'voided', voided_at = CURRENT_TIMESTAMP, void_reason = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *`,
      [req.body.reason || 'Voided by user', req.params.id]
    );

    await logAudit(doc.id, 'DOCUMENT_VOIDED', req.user.email, req, { reason: req.body.reason });
    res.json(docRowToObject(result.rows[0]));
  } catch (e) {
    console.error('Void error:', e);
    res.status(500).json({ error: 'Failed to void document' });
  }
});

// ==================== TEMPLATES ====================

app.post('/api/templates', auth, async (req, res) => {
  try {
    const { documentId, name } = req.body;

    let templateData = req.body;

    if (documentId) {
      const docResult = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [documentId, req.user.id]);
      if (docResult.rows.length === 0) {
        return res.status(404).json({ error: 'Document not found' });
      }
      templateData = { ...(docResult.rows[0].data || {}) };
    }
    // Clear party-specific info for template
    templateData.tenantEmail = '';
    templateData.tenantPhone = '';
    if (Array.isArray(templateData.additionalTenants)) {
      templateData.additionalTenants = templateData.additionalTenants.map(t => ({
        name: t.name || '',
        email: '',
        phone: t.phone || '',
        signToken: undefined,
        signature: null,
        signedAt: null,
        signedIp: null
      }));
    }

    const result = await pool.query(
      `INSERT INTO documents (user_id, status, title, template_name, is_template, data, landlord_sign_token, tenant_sign_token)
       VALUES ($1, 'template', $2, $2, TRUE, $3, $4, $5) RETURNING *`,
      [req.user.id, name || 'Untitled Template', JSON.stringify(templateData), uuidv4(), uuidv4()]
    );

    res.json(docRowToObject(result.rows[0]));
  } catch (e) {
    console.error('Template error:', e);
    res.status(500).json({ error: 'Failed to save template' });
  }
});

app.get('/api/templates', auth, async (req, res) => {
  const result = await pool.query('SELECT * FROM documents WHERE user_id = $1 AND is_template = TRUE', [req.user.id]);
  res.json(result.rows.map(docRowToObject));
});

app.post('/api/templates/:id/use', auth, async (req, res) => {
  try {
    const templateResult = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2 AND is_template = TRUE', [req.params.id, req.user.id]);
    if (templateResult.rows.length === 0) {
      return res.status(404).json({ error: 'Template not found' });
    }

    const template = templateResult.rows[0];
    const templateData = template.data || {};
    const overrideData = req.body;
    const mergedData = { ...templateData, ...overrideData };
    // Generate fresh sign tokens for additional tenants
    const sourceTenants = overrideData.additionalTenants || templateData.additionalTenants || [];
    mergedData.additionalTenants = sourceTenants.map(t => ({
      name: t.name || '',
      email: t.email || '',
      phone: t.phone || '',
      signToken: uuidv4(),
      signature: null,
      signedAt: null,
      signedIp: null
    }));

    const result = await pool.query(
      `INSERT INTO documents (user_id, status, title, data, landlord_sign_token, tenant_sign_token)
       VALUES ($1, 'draft', $2, $3, $4, $5) RETURNING *`,
      [req.user.id, overrideData.title || template.title, JSON.stringify(mergedData), uuidv4(), uuidv4()]
    );

    const newDoc = docRowToObject(result.rows[0]);
    await logAudit(newDoc.id, 'DOCUMENT_CREATED_FROM_TEMPLATE', req.user.email, req, { templateId: template.id });
    res.json(newDoc);
  } catch (e) {
    console.error('Use template error:', e);
    res.status(500).json({ error: 'Failed to create from template' });
  }
});

// ==================== BULK OPERATIONS ====================

app.post('/api/documents/bulk-remind', auth, async (req, res) => {
  try {
    const { documentIds } = req.body;
    if (!documentIds || !Array.isArray(documentIds)) {
      return res.status(400).json({ error: 'Document IDs required' });
    }

    const results = [];
    for (const id of documentIds) {
      const docResult = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [id, req.user.id]);
      if (docResult.rows.length === 0) continue;

      const doc = docRowToObject(docResult.rows[0]);
      if (doc.status === 'completed' || doc.status === 'voided' || doc.status === 'draft') continue;

      try {
        if (!doc.landlordSignedAt) {
          const signUrl = `${APP_URL}/sign/${doc.landlordSignToken}`;
          await mailer.sendMail({
            from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
            to: doc.landlordEmail,
            subject: `[Reminder] Please Sign: Lease for ${doc.propertyAddress}`,
            text: `Reminder: Please sign the lease agreement: ${signUrl}`,
            html: generateReminderEmail(doc, 'landlord', signUrl)
          });
          results.push({ id, success: true, sentTo: doc.landlordEmail });
          await logAudit(doc.id, 'BULK_REMINDER_SENT', req.user.email, req, { to: doc.landlordEmail });
        } else {
          const unsigned = [];
          if (!doc.tenantSignedAt)
            unsigned.push({ email: doc.tenantEmail, signToken: doc.tenantSignToken, name: doc.tenantName });
          for (const t of (doc.additionalTenants || [])) {
            if (!t.signedAt) unsigned.push({ email: t.email, signToken: t.signToken, name: t.name });
          }
          for (const r of unsigned) {
            const signUrl = `${APP_URL}/sign/${r.signToken}`;
            await mailer.sendMail({
              from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
              to: r.email,
              subject: `[Reminder] Please Sign: Lease for ${doc.propertyAddress}`,
              text: `Reminder: Please sign the lease agreement: ${signUrl}`,
              html: generateReminderEmail({ ...doc, tenantName: r.name }, 'tenant', signUrl)
            });
            await logAudit(doc.id, 'BULK_REMINDER_SENT', req.user.email, req, { to: r.email });
          }
          results.push({ id, success: true, sentTo: unsigned.map(r => r.email).join(', ') });
        }
      } catch (e) {
        results.push({ id, success: false, error: e.message });
      }
    }

    res.json({ results });
  } catch (e) {
    console.error('Bulk remind error:', e);
    res.status(500).json({ error: 'Failed to send reminders' });
  }
});

function generateReminderEmail(doc, signerType, signUrl) {
  const signerName = signerType === 'landlord' ? doc.landlordName : doc.tenantName;

  return `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f3f4f6;">
  <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: 0 auto; padding: 20px;">
    <tr>
      <td style="background: linear-gradient(135deg, #f59e0b 0%, #fbbf24 100%); padding: 40px 30px; text-align: center; border-radius: 12px 12px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 28px;">Reminder</h1>
        <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0;">Your signature is still needed</p>
      </td>
    </tr>
    <tr>
      <td style="background: white; padding: 40px 30px; border: 1px solid #e5e7eb; border-top: none;">
        <h2 style="color: #111827; margin: 0 0 20px;">Hello ${signerName},</h2>
        <p style="color: #4b5563; line-height: 1.6;">
          This is a friendly reminder that a residential lease agreement is waiting for your signature.
        </p>

        <table width="100%" style="background: #fef3c7; border-radius: 8px; padding: 20px; margin: 20px 0; border-left: 4px solid #f59e0b;">
          <tr><td style="padding: 8px 0;"><strong>Property:</strong> ${doc.propertyAddress || 'N/A'}</td></tr>
          <tr><td style="padding: 8px 0;"><strong>Monthly Rent:</strong> $${doc.monthlyRent?.toLocaleString() || 'N/A'}</td></tr>
          <tr><td style="padding: 8px 0;"><strong>Lease Term:</strong> ${doc.commencementDate || 'N/A'} to ${doc.expirationDate || 'N/A'}</td></tr>
        </table>

        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td style="text-align: center; padding: 20px 0;">
              <a href="${signUrl}" style="display: inline-block; background: #f59e0b; color: white; padding: 16px 40px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 16px;">
                Review & Sign Now
              </a>
            </td>
          </tr>
        </table>

        <p style="color: #9ca3af; font-size: 13px; margin: 20px 0 0; padding-top: 20px; border-top: 1px solid #e5e7eb;">
          If you have questions about this lease, please contact your landlord or property manager.
        </p>
      </td>
    </tr>
    <tr>
      <td style="background: #f9fafb; padding: 20px 30px; text-align: center; border-radius: 0 0 12px 12px; border: 1px solid #e5e7eb; border-top: none;">
        <p style="color: #9ca3af; font-size: 12px; margin: 0;">
          This is an automated reminder from LeaseSign.
        </p>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

// ==================== REGENERATE LINK ====================

app.post('/api/documents/:id/regenerate-link', auth, async (req, res) => {
  try {
    const docResult = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (docResult.rows.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const doc = docRowToObject(docResult.rows[0]);

    if (doc.status === 'completed' || doc.status === 'voided' || doc.status === 'draft') {
      return res.status(400).json({ error: 'Cannot regenerate link for this document status' });
    }

    const linkExpiresAt = new Date(Date.now() + LINK_EXPIRATION_MS);
    const result = await pool.query(
      'UPDATE documents SET link_expires_at = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *',
      [linkExpiresAt, req.params.id]
    );
    const updated = docRowToObject(result.rows[0]);

    let recipient, signUrl, signerType;
    if (!doc.landlordSignedAt) {
      recipient = doc.landlordEmail;
      signUrl = `${APP_URL}/sign/${doc.landlordSignToken}`;
      signerType = 'landlord';
    } else if (!doc.tenantSignedAt) {
      recipient = doc.tenantEmail;
      signUrl = `${APP_URL}/sign/${doc.tenantSignToken}`;
      signerType = 'tenant';
    }

    if (recipient) {
      await mailer.sendMail({
        from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
        to: recipient,
        subject: `[New Link] Sign Lease for ${doc.propertyAddress}`,
        text: `Your previous signing link has been renewed: ${signUrl}`,
        html: generateSignEmail(updated, signerType, signUrl)
      });
    }

    await logAudit(doc.id, 'LINK_REGENERATED', req.user.email, req, { to: recipient });
    res.json({ success: true, linkExpiresAt, sentTo: recipient });
  } catch (e) {
    console.error('Regenerate link error:', e);
    res.status(500).json({ error: 'Failed to regenerate link' });
  }
});

// ==================== BULK DELETE ====================

app.post('/api/documents/bulk-delete', auth, async (req, res) => {
  try {
    const { documentIds } = req.body;
    if (!documentIds || !Array.isArray(documentIds)) {
      return res.status(400).json({ error: 'Document IDs required' });
    }

    const results = [];
    for (const id of documentIds) {
      const docResult = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [id, req.user.id]);
      if (docResult.rows.length === 0) {
        results.push({ id, success: false, error: 'Not found' });
        continue;
      }

      const doc = docRowToObject(docResult.rows[0]);
      if (doc.status !== 'draft') {
        results.push({ id, success: false, error: 'Can only delete drafts' });
        continue;
      }

      await pool.query('DELETE FROM documents WHERE id = $1', [id]);
      results.push({ id, success: true });
    }

    res.json({ results, deletedCount: results.filter(r => r.success).length });
  } catch (e) {
    console.error('Bulk delete error:', e);
    res.status(500).json({ error: 'Failed to delete documents' });
  }
});

// ==================== NOTIFICATIONS ====================

app.get('/api/notifications', auth, async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM notifications WHERE user_id = $1 ORDER BY timestamp DESC LIMIT 50',
    [req.user.id]
  );

  const notifications = result.rows;
  const unreadCount = notifications.filter(n => !n.read).length;
  res.json({ notifications, unreadCount });
});

app.patch('/api/notifications/:id/read', auth, async (req, res) => {
  const result = await pool.query(
    'UPDATE notifications SET read = TRUE WHERE id = $1 AND user_id = $2 RETURNING *',
    [req.params.id, req.user.id]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'Notification not found' });
  }

  res.json(result.rows[0]);
});

app.post('/api/notifications/mark-all-read', auth, async (req, res) => {
  const result = await pool.query(
    'UPDATE notifications SET read = TRUE WHERE user_id = $1 AND read = FALSE',
    [req.user.id]
  );
  res.json({ success: true, updated: result.rowCount });
});

// ==================== DECLINE SIGNING ====================

app.post('/api/sign/:token/decline', async (req, res) => {
  try {
    const { reason } = req.body;

    const result = await pool.query(
      `SELECT * FROM documents
       WHERE landlord_sign_token = $1
          OR tenant_sign_token = $1
          OR (jsonb_typeof(data->'additionalTenants') = 'array'
              AND data->'additionalTenants' @> jsonb_build_array(jsonb_build_object('signToken', $1)))`,
      [req.params.token]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: 'Document not found' });

    const doc = docRowToObject(result.rows[0]);

    if (doc.status === 'completed' || doc.status === 'voided' || doc.status === 'declined') {
      return res.status(400).json({ error: 'Document cannot be declined in its current state' });
    }

    if (doc.linkExpiresAt && new Date(doc.linkExpiresAt) < new Date()) {
      return res.status(410).json({ error: 'This signing link has expired.' });
    }

    let declinedBy;
    if (doc.landlordSignToken === req.params.token) {
      declinedBy = doc.landlordName || 'Landlord';
    } else if (doc.tenantSignToken === req.params.token) {
      declinedBy = doc.tenantName || 'Tenant';
    } else {
      const idx = (doc.additionalTenants || []).findIndex(t => t.signToken === req.params.token);
      declinedBy = doc.additionalTenants?.[idx]?.name || 'Co-Tenant';
    }

    const rawData = result.rows[0].data || {};
    const updatedData = { ...rawData, declinedBy, declineReason: reason || '', declinedAt: new Date().toISOString() };

    await pool.query(
      `UPDATE documents SET status = 'declined', data = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`,
      [JSON.stringify(updatedData), doc.id]
    );

    await logAudit(doc.id, 'DOCUMENT_DECLINED', declinedBy, req, { reason });
    await createNotification(doc.userId, 'declined', 'Document Declined',
      `${declinedBy} declined to sign the lease for ${doc.propertyAddress}`, doc.id);

    if (mailer) {
      try {
        await mailer.sendMail({
          from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
          to: doc.landlordEmail,
          subject: `[Alert] Lease Declined: ${doc.propertyAddress}`,
          html: `<p style="font-family:sans-serif"><strong>${declinedBy}</strong> has declined to sign the lease for <strong>${doc.propertyAddress}</strong>.</p>${reason ? `<p style="font-family:sans-serif">Reason provided: ${reason}</p>` : '<p style="font-family:sans-serif">No reason was provided.</p>'}`
        });
      } catch (e) { console.error('Decline notification email failed:', e.message); }
    }

    res.json({ success: true });
  } catch (e) {
    console.error('Decline error:', e);
    res.status(500).json({ error: 'Failed to decline document' });
  }
});

// ==================== CATCH-ALL ROUTE ====================

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ==================== RENEWAL BACKGROUND JOB ====================

const sendRenewalNotice = async (doc, daysRemaining, threshold) => {
  const rawResult = await pool.query('SELECT * FROM documents WHERE id = $1', [doc.id]);
  if (rawResult.rows.length === 0) return;
  const rawData = rawResult.rows[0].data || {};
  const sentNotices = rawData.renewalNotices || [];

  const alreadySent = sentNotices.some(n => n.threshold === threshold);
  if (alreadySent) return;

  const renewalRentAmount = rawData.renewalRentAmount || doc.monthlyRent;
  const renewalTermMonths = rawData.renewalTermMonths || 12;

  const noticeDays = Number(rawData.renewalNoticeDays || 60);
  const isEarlyWarning = threshold > noticeDays;
  const landlordUrl = `${APP_URL}`;
  const subject = isEarlyWarning
    ? `Early Renewal Heads-Up: ${doc.propertyAddress} — ${daysRemaining} days remaining`
    : `Lease Renewal Notice: ${doc.propertyAddress} — ${daysRemaining} days remaining`;
  const bodyHtml = (recipientRole) => `
    <div style="font-family:sans-serif;max-width:600px;margin:0 auto">
      <h2 style="color:${isEarlyWarning ? '#92400e' : '#1e40af'}">${isEarlyWarning ? '⚠️ Early Renewal Heads-Up' : 'Lease Renewal Notice'}</h2>
      ${isEarlyWarning ? `<p style="background:#fffbeb;border:1px solid #fcd34d;padding:0.75rem;border-radius:6px;margin-bottom:1rem">Action required within the next <strong>${daysRemaining - noticeDays} days</strong> — your ${noticeDays}-day notice period begins soon.</p>` : ''}
      <p>Your lease for <strong>${doc.propertyAddress}, ${doc.propertyCity}, TX ${doc.propertyZip}</strong> expires in <strong>${daysRemaining} days</strong>.</p>
      <table style="width:100%;border-collapse:collapse;margin:1rem 0">
        <tr><td style="padding:8px;border:1px solid #e5e7eb;background:#f9fafb"><strong>Current Rent</strong></td><td style="padding:8px;border:1px solid #e5e7eb">$${doc.monthlyRent}/month</td></tr>
        <tr><td style="padding:8px;border:1px solid #e5e7eb;background:#f9fafb"><strong>Proposed Renewal Rent</strong></td><td style="padding:8px;border:1px solid #e5e7eb">$${renewalRentAmount}/month</td></tr>
        <tr><td style="padding:8px;border:1px solid #e5e7eb;background:#f9fafb"><strong>Renewal Term</strong></td><td style="padding:8px;border:1px solid #e5e7eb">${renewalTermMonths} months</td></tr>
        <tr><td style="padding:8px;border:1px solid #e5e7eb;background:#f9fafb"><strong>Lease Expires</strong></td><td style="padding:8px;border:1px solid #e5e7eb">${doc.leaseEndDate}</td></tr>
      </table>
      ${recipientRole === 'landlord' ? `<p><a href="${landlordUrl}" style="background:#1e40af;color:white;padding:10px 20px;border-radius:6px;text-decoration:none;display:inline-block;margin-top:0.5rem">Manage Renewal in LeaseSign</a></p>` : '<p>Please contact your landlord to discuss renewal terms.</p>'}
      <hr style="border:none;border-top:1px solid #e5e7eb;margin:1.5rem 0"/>
      <p style="color:#6b7280;font-size:0.875rem">LeaseSign — Automated Renewal Notice</p>
    </div>`;

  const allTenantEmails = [doc.tenantEmail, ...(doc.additionalTenants || []).map(t => t.email)].filter(Boolean);

  if (mailer) {
    try {
      await mailer.sendMail({ from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>', to: doc.landlordEmail, subject, html: bodyHtml('landlord') });
      for (const email of allTenantEmails) {
        await mailer.sendMail({ from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>', to: email, subject, html: bodyHtml('tenant') });
      }
    } catch (e) { console.error('[Renewal] Email failed:', e.message); }
  }

  await createNotification(doc.userId, 'renewal', 'Lease Renewal Notice',
    `Lease for ${doc.propertyAddress} expires in ${daysRemaining} days. Renewal rent: $${renewalRentAmount}/mo.`, doc.id);

  const updatedNotices = [...sentNotices, { threshold, daysRemaining, sentAt: new Date().toISOString() }];
  await pool.query(
    `UPDATE documents SET data = data || $1::jsonb, updated_at = CURRENT_TIMESTAMP WHERE id = $2`,
    [JSON.stringify({ renewalNotices: updatedNotices }), doc.id]
  );

  await logAudit(doc.id, 'RENEWAL_NOTICE_SENT', 'system', null, { daysRemaining, threshold, to: [doc.landlordEmail, ...allTenantEmails] });
  console.log(`[Renewal] Notice sent for doc ${doc.id} (${daysRemaining} days remaining)`);
};

const checkRenewals = async () => {
  console.log('[Renewal] Running scheduled renewal check...');
  try {
    const result = await pool.query(`
      SELECT * FROM documents
      WHERE status = 'completed'
        AND (data->>'autoRenew')::boolean = true
        AND data->>'leaseEndDate' IS NOT NULL
        AND data->>'renewedDocumentId' IS NULL
    `);

    const today = new Date();
    for (const row of result.rows) {
      const doc = docRowToObject(row);
      if (!doc.leaseEndDate) continue;
      const leaseEnd = new Date(doc.leaseEndDate);
      const daysRemaining = Math.ceil((leaseEnd - today) / (1000 * 60 * 60 * 24));
      if (daysRemaining <= 0) continue;

      const noticeDays = Number(row.data?.renewalNoticeDays || 60);
      // Three tiers: early warning (before the notice window opens), notice start, and mid-notice reminder
      const thresholds = [noticeDays + 30, noticeDays, Math.round(noticeDays / 2)].filter(t => t > 0);
      for (const threshold of thresholds) {
        if (daysRemaining <= threshold) {
          await sendRenewalNotice(doc, daysRemaining, threshold);
        }
      }
    }
    console.log(`[Renewal] Check complete. Processed ${result.rows.length} eligible document(s).`);
  } catch (e) {
    console.error('[Renewal] Check failed:', e.message);
  }
};

// Run 30s after startup, then every 24 hours (skip on Vercel serverless)
if (!isVercel) {
  setTimeout(checkRenewals, 30000);
  setInterval(checkRenewals, 24 * 60 * 60 * 1000);
}

// ==================== RENEWAL API ====================

// Save renewal settings for a document
app.put('/api/documents/:id/renewal', auth, async (req, res) => {
  try {
    const { autoRenew, renewalNoticeDays, renewalRentAmount, renewalTermMonths } = req.body;
    const docResult = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (docResult.rows.length === 0) return res.status(404).json({ error: 'Document not found' });

    const patch = {
      autoRenew: !!autoRenew,
      renewalNoticeDays: Number(renewalNoticeDays) || 60,
      renewalRentAmount: renewalRentAmount ? Number(renewalRentAmount) : null,
      renewalTermMonths: Number(renewalTermMonths) || 12
    };

    const updated = await pool.query(
      `UPDATE documents SET data = data || $1::jsonb, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *`,
      [JSON.stringify(patch), req.params.id]
    );

    await logAudit(req.params.id, 'RENEWAL_SETTINGS_UPDATED', req.user.email, req, patch);
    res.json(docRowToObject(updated.rows[0]));
  } catch (e) {
    console.error('Renewal settings error:', e);
    res.status(500).json({ error: 'Failed to save renewal settings' });
  }
});

// Create a renewal draft document from a completed lease
app.post('/api/documents/:id/renew', auth, async (req, res) => {
  try {
    const { renewalRentAmount, renewalTermMonths } = req.body;
    const docResult = await pool.query('SELECT * FROM documents WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    if (docResult.rows.length === 0) return res.status(404).json({ error: 'Document not found' });

    const original = docRowToObject(docResult.rows[0]);
    if (original.status !== 'completed') return res.status(400).json({ error: 'Only completed leases can be renewed' });

    const termMonths = Number(renewalTermMonths) || Number(original.renewalTermMonths) || 12;
    const newRent = renewalRentAmount ? Number(renewalRentAmount) : (original.renewalRentAmount || original.monthlyRent);

    const oldEnd = original.leaseEndDate ? new Date(original.leaseEndDate) : new Date();
    const newStart = new Date(oldEnd);
    newStart.setDate(newStart.getDate() + 1);
    const newEnd = new Date(newStart);
    newEnd.setMonth(newEnd.getMonth() + termMonths);

    const fmt = d => d.toISOString().split('T')[0];

    const originalData = { ...(docResult.rows[0].data || {}) };
    // Reset signing state for the new lease
    delete originalData.landlordSignature;
    delete originalData.tenantSignature;
    delete originalData.declinedBy;
    delete originalData.declineReason;
    delete originalData.declinedAt;
    delete originalData.renewedDocumentId;
    delete originalData.renewalNotices;

    if (Array.isArray(originalData.additionalTenants)) {
      originalData.additionalTenants = originalData.additionalTenants.map(t => ({
        name: t.name || '', email: t.email || '', phone: t.phone || '',
        signToken: uuidv4(), signature: null, signedAt: null, signedIp: null
      }));
    }

    originalData.monthlyRent = newRent;
    originalData.leaseStartDate = fmt(newStart);
    originalData.leaseEndDate = fmt(newEnd);
    originalData.renewedFromId = original.id;

    const result = await pool.query(
      `INSERT INTO documents (user_id, status, title, data, landlord_sign_token, tenant_sign_token)
       VALUES ($1, 'draft', $2, $3, $4, $5) RETURNING *`,
      [req.user.id, `Renewal — ${original.propertyAddress || original.title || 'Lease'}`, JSON.stringify(originalData), uuidv4(), uuidv4()]
    );

    const newDoc = docRowToObject(result.rows[0]);

    // Mark original doc as having a renewal pending
    await pool.query(
      `UPDATE documents SET data = data || $1::jsonb, updated_at = CURRENT_TIMESTAMP WHERE id = $2`,
      [JSON.stringify({ renewedDocumentId: newDoc.id }), original.id]
    );

    await logAudit(newDoc.id, 'RENEWAL_CREATED', req.user.email, req, { fromId: original.id, newRent, termMonths });
    res.json(newDoc);
  } catch (e) {
    console.error('Renew error:', e);
    res.status(500).json({ error: 'Failed to create renewal document' });
  }
});

// ==================== START SERVER ====================

// Only listen when NOT on Vercel (Vercel invokes the exported app directly)
if (!isVercel) {
  app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   LeaseSign - Texas Residential Lease E-Signature Platform     ║
║                                                                ║
║   Server running at: http://localhost:${PORT}                    ║
║   Database: PostgreSQL                                         ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
    `);
  });
}

module.exports = app;
