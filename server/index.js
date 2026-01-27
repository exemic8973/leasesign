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

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'leasesign-secret-key-change-in-production-' + crypto.randomBytes(16).toString('hex');
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

// Data storage paths (for uploads and generated files)
const UPLOADS_DIR = path.join(__dirname, '../uploads');
const GENERATED_DIR = path.join(__dirname, '../generated');

// Ensure directories exist
[UPLOADS_DIR, GENERATED_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// PostgreSQL connection - handle various SSL configurations
let sslConfig = false;
if (process.env.DATABASE_SSL === 'true') {
  sslConfig = { rejectUnauthorized: false };
} else if (process.env.DATABASE_SSL === 'no-verify') {
  sslConfig = { rejectUnauthorized: false };
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: sslConfig
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

// Initialize database on startup
initDatabase();

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
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, '../public')));

// Email transporter
let mailer = null;

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
  mailer = await createMailer();
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
    const { email, password, name, company, phone } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
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
    'SELECT * FROM documents WHERE landlord_sign_token = $1 OR tenant_sign_token = $1',
    [req.params.token]
  );

  if (result.rows.length === 0) return res.status(404).json({ error: 'Document not found or link expired' });

  const doc = docRowToObject(result.rows[0]);

  // Check if link has expired
  if (doc.linkExpiresAt && new Date(doc.linkExpiresAt) < new Date()) {
    return res.status(410).json({ error: 'This signing link has expired. Please contact the sender to request a new link.', expired: true });
  }

  const signerType = doc.landlordSignToken === req.params.token ? 'landlord' : 'tenant';

  // Check if already signed
  if (signerType === 'landlord' && doc.landlordSignedAt) {
    return res.status(400).json({ error: 'Already signed by landlord' });
  }
  if (signerType === 'tenant' && doc.tenantSignedAt) {
    return res.status(400).json({ error: 'Already signed by tenant' });
  }

  // Remove sensitive tokens
  const safeDoc = { ...doc };
  delete safeDoc.landlordSignToken;
  delete safeDoc.tenantSignToken;
  delete safeDoc.userId;

  res.json({ document: safeDoc, signerType });
});

// Public signing endpoint - submit signature
app.post('/api/sign/:token', async (req, res) => {
  try {
    const { signature } = req.body;
    if (!signature) return res.status(400).json({ error: 'Signature required' });

    const result = await pool.query(
      'SELECT * FROM documents WHERE landlord_sign_token = $1 OR tenant_sign_token = $1',
      [req.params.token]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: 'Document not found' });

    const doc = docRowToObject(result.rows[0]);

    // Check if link has expired
    if (doc.linkExpiresAt && new Date(doc.linkExpiresAt) < new Date()) {
      return res.status(410).json({ error: 'This signing link has expired. Please contact the sender to request a new link.', expired: true });
    }

    const signerType = doc.landlordSignToken === req.params.token ? 'landlord' : 'tenant';
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    const now = new Date();

    let updateResult;

    if (signerType === 'landlord') {
      // Reset expiration for tenant (7 more days)
      const newExpiration = new Date(Date.now() + LINK_EXPIRATION_MS);
      const newStatus = doc.tenantSignedAt ? 'completed' : 'partial';

      updateResult = await pool.query(
        `UPDATE documents SET
          landlord_signature = $1, landlord_signed_at = $2, landlord_signed_ip = $3,
          link_expires_at = $4, status = $5, updated_at = CURRENT_TIMESTAMP
         WHERE id = $6 RETURNING *`,
        [signature, now, ip, newExpiration, newStatus, doc.id]
      );

      await logAudit(doc.id, 'LANDLORD_SIGNED', doc.landlordEmail, req);

      // Send email to tenant
      const tenantSignUrl = `${APP_URL}/sign/${doc.tenantSignToken}`;
      const updatedDoc = docRowToObject(updateResult.rows[0]);
      await mailer.sendMail({
        from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
        to: doc.tenantEmail,
        subject: `[Action Required] Sign Lease for ${doc.propertyAddress}`,
        text: `Please sign the lease agreement: ${tenantSignUrl}`,
        html: generateSignEmail(updatedDoc, 'tenant', tenantSignUrl)
      });

      // Send SMS to tenant if phone available
      if (doc.tenantPhone) {
        await sendSMS(doc.tenantPhone, `LeaseSign: The landlord has signed! Please sign the lease for ${doc.propertyAddress}. Link: ${tenantSignUrl}`);
      }

      // Notify document owner
      await createNotification(doc.userId, 'signed', 'Landlord Signed', `${doc.landlordName} signed the lease for ${doc.propertyAddress}`, doc.id);
    } else {
      const newStatus = doc.landlordSignedAt ? 'completed' : 'partial';

      updateResult = await pool.query(
        `UPDATE documents SET
          tenant_signature = $1, tenant_signed_at = $2, tenant_signed_ip = $3,
          status = $4, updated_at = CURRENT_TIMESTAMP
         WHERE id = $5 RETURNING *`,
        [signature, now, ip, newStatus, doc.id]
      );

      await logAudit(doc.id, 'TENANT_SIGNED', doc.tenantEmail, req);

      // Notify document owner
      await createNotification(doc.userId, 'signed', 'Tenant Signed', `${doc.tenantName} signed the lease for ${doc.propertyAddress}`, doc.id);
    }

    const updated = docRowToObject(updateResult.rows[0]);

    // If completed, send completion emails and notify
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

  // Helper functions
  const field = (val) => val || '________________________';
  const money = (val) => val ? `$${parseFloat(val).toLocaleString('en-US', { minimumFractionDigits: 2 })}` : '$____________';
  const checkbox = (checked) => checked ? '[X]' : '[ ]';
  let pageNum = 1;

  const addHeader = () => {
    pdf.font('Helvetica').fontSize(8).fillColor('#666666');
    pdf.text('RESIDENTIAL LEASE - TAR 2001', 60, 30);
    pdf.text(`Page ${pageNum}`, 500, 30);
    pdf.fillColor('#000000');
    pageNum++;
  };

  const addFooter = () => {
    const y = pdf.page.height - 40;
    pdf.font('Helvetica').fontSize(7).fillColor('#666666');
    pdf.text(`${doc.propertyAddress || 'Property'} | Landlord: ${doc.landlordName || ''} | Tenant: ${doc.tenantName || ''}`, 60, y, { width: 500, align: 'center' });
    pdf.fillColor('#000000');
  };

  const newPage = () => {
    addFooter();
    pdf.addPage();
    addHeader();
    pdf.y = 60;
  };

  const checkSpace = (needed = 100) => {
    if (pdf.y > pdf.page.height - 100 - needed) newPage();
  };

  const sectionTitle = (num, title) => {
    checkSpace(80);
    pdf.font('Helvetica-Bold').fontSize(10).fillColor('#000000');
    pdf.text(`${num}. ${title}`);
    pdf.font('Helvetica').fontSize(9);
    pdf.moveDown(0.3);
  };

  const subSection = (letter, text) => {
    checkSpace(40);
    pdf.font('Helvetica-Bold').fontSize(9).text(`${letter}. `, { continued: true });
    pdf.font('Helvetica').fontSize(9).text(text);
    pdf.moveDown(0.3);
  };

  // ===== PAGE 1 - HEADER =====
  addHeader();
  pdf.y = 50;

  // Title Block
  pdf.font('Helvetica-Bold').fontSize(16).text('RESIDENTIAL LEASE', { align: 'center' });
  pdf.font('Helvetica').fontSize(8).text('USE OF THIS FORM BY PERSONS WHO ARE NOT MEMBERS OF THE TEXAS ASSOCIATION OF REALTORS IS NOT AUTHORIZED.', { align: 'center' });
  pdf.text('Texas Association of REALTORS, Inc. 2022', { align: 'center' });
  pdf.moveDown(1.5);

  // Section 1: PARTIES
  sectionTitle('1', 'PARTIES');
  pdf.text(`The parties to this lease are: the owner of the Property (Landlord): ${field(doc.landlordName)}; and the following tenant(s) (collectively referred to as "Tenant"): ${field(doc.tenantName)}.`);
  pdf.moveDown();

  // Section 2: PROPERTY
  sectionTitle('2', 'PROPERTY');
  pdf.text(`Landlord leases to Tenant the real property described below together with all its improvements (collectively the "Property"):`);
  pdf.moveDown(0.3);
  subSection('A', `Address: ${field(doc.propertyAddress)}, ${field(doc.propertyCity)}, TX ${field(doc.propertyZip)}`);
  subSection('B', `Legal Description: ${field(doc.legalDescription)}`);
  subSection('C', `County: ${field(doc.propertyCounty)}`);
  subSection('D', `Non-Real-Property Items: ${field(doc.nonRealPropertyItems || 'refrigerator, range/oven, dishwasher, disposal, microwave')}`);
  pdf.moveDown();

  // Section 3: TERM
  sectionTitle('3', 'TERM');
  subSection('A', 'Primary Term:');
  pdf.text(`   Commencement Date: ${field(doc.commencementDate)}`);
  pdf.text(`   Expiration Date: ${field(doc.expirationDate)} at 11:59 p.m.`);
  subSection('B', 'Delay of Occupancy: If Tenant cannot occupy the Property on the Commencement Date because of construction, Tenant may terminate this lease by written notice before the Property is available.');
  pdf.moveDown();

  // Section 4: AUTOMATIC RENEWAL
  sectionTitle('4', 'AUTOMATIC RENEWAL');
  pdf.text(`This lease automatically renews on a month-to-month basis unless either party provides written notice of termination at least ${field(doc.terminationNoticeDays || '30')} days before the Expiration Date.`);
  pdf.moveDown();

  // Section 5: RENT
  sectionTitle('5', 'RENT');
  subSection('A', `Monthly Rent: ${money(doc.monthlyRent)} due on or before the 1st day of each month.`);
  if (doc.proratedRent) {
    subSection('B', `Prorated Rent: ${money(doc.proratedRent)} due on or before ${field(doc.proratedDueDate)}.`);
  }
  subSection('C', 'Payment Method: ' + [
    doc.paymentCashiersCheck ? 'Cashier\'s Check' : '',
    doc.paymentMoneyOrder ? 'Money Order' : '',
    doc.paymentPersonalCheck ? 'Personal Check' : '',
    doc.paymentElectronic ? 'Electronic Payment' : ''
  ].filter(Boolean).join(', ') || 'Any acceptable form');
  subSection('D', `Place of Payment: ${field(doc.paymentName || doc.landlordName)}, ${field(doc.paymentAddress)}`);
  pdf.moveDown();

  // Section 6: LATE CHARGES
  sectionTitle('6', 'LATE CHARGES');
  pdf.text(`If rent is not received by the ${field(doc.gracePeriodDay || '3')}rd day of each month at 11:59 p.m., Tenant will pay:`);
  pdf.text(`   (1) Initial late charge: ${money(doc.initialLateFee || 50)}`);
  pdf.text(`   (2) Additional daily charge: ${money(doc.dailyLateFee || 25)} per day until paid`);
  pdf.moveDown();

  // Section 7: RETURNED PAYMENTS
  sectionTitle('7', 'RETURNED PAYMENTS');
  pdf.text(`Tenant will pay ${money(doc.returnedPaymentFee || 75)} for each returned or dishonored payment.`);
  pdf.moveDown();

  // Section 8: APPLICATION OF PAYMENTS
  sectionTitle('8', 'APPLICATION OF PAYMENTS');
  pdf.text('Payments applied first to non-rent obligations (late charges, repairs, etc.), then to rent.');
  pdf.moveDown();

  // Section 9: ANIMALS
  sectionTitle('9', 'ANIMALS');
  pdf.text(`${checkbox(!doc.petsAllowed)} No animals permitted  ${checkbox(doc.petsAllowed)} Animals permitted: ${field(doc.allowedPets)}`);
  pdf.text(`Unauthorized animal fee: ${money(doc.unauthorizedPetFee || 100)} per animal per day.`);
  pdf.moveDown();

  // Section 10: SECURITY DEPOSIT
  sectionTitle('10', 'SECURITY DEPOSIT');
  subSection('A', `Amount: ${money(doc.securityDeposit)}`);
  subSection('B', 'Return within 30 days after Tenant surrenders Property, less lawful deductions.');
  subSection('C', 'Deductions may include: unpaid rent, utilities, late charges, repairs, cleaning, key replacement.');
  pdf.moveDown();

  // Section 11: UTILITIES
  sectionTitle('11', 'UTILITIES');
  pdf.text(`Tenant pays all utilities except: ${field(doc.landlordPaysUtilities || 'None')}`);
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
  pdf.text(`Maximum ${field(doc.maxVehicles || '4')} vehicles. All must be operable with current registration. No commercial vehicles, trailers, or RVs without consent.`);
  pdf.moveDown();

  // Section 14: ACCESS BY LANDLORD
  sectionTitle('14', 'ACCESS BY LANDLORD');
  pdf.text(`Landlord may enter at reasonable times with ${field(doc.accessNoticeHours || '24')} hours notice (except emergencies).`);
  subSection('A', `Trip Charge: ${money(doc.tripCharge || 75)} if Tenant fails to permit access.`);
  subSection('B', `Keybox: ${checkbox(doc.keyboxAuthorized)} Authorized during last ${field(doc.keyboxDays || '30')} days of lease.`);
  pdf.moveDown();

  // Section 15: MOVE-IN CONDITION
  sectionTitle('15', 'MOVE-IN CONDITION');
  pdf.text(`${checkbox(doc.asIsCondition)} Tenant accepts Property as-is.`);
  pdf.text(`Inventory form due within ${field(doc.inventoryDays || '3')} days of possession.`);
  pdf.moveDown();

  // Section 16: MOVE-OUT
  sectionTitle('16', 'MOVE-OUT');
  pdf.text('Tenant will: return all keys; remove personal property; leave Property in good condition; provide forwarding address.');
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
  pdf.text('Per Texas Property Code 92.153. Rekeying costs paid by: ' + (doc.rekeyPaidByLandlord ? 'Landlord' : 'Tenant'));
  pdf.moveDown();

  sectionTitle('20', 'SMOKE ALARMS');
  pdf.text('Landlord installs per code. Tenant tests monthly and replaces batteries.');
  pdf.moveDown();

  sectionTitle('21', 'LIABILITY');
  pdf.text('Landlord not liable for damages from utility failure, weather, crime, or Property conditions. Tenant releases Landlord.');
  pdf.moveDown();

  sectionTitle('22', 'HOLDOVER');
  pdf.text(`If Tenant remains after expiration: ${money(doc.holdoverRent || (doc.monthlyRent ? doc.monthlyRent * 3 : 0))} per month until surrender.`);
  pdf.moveDown();

  sectionTitle('23', 'LANDLORD\'S LIEN');
  pdf.text('Per Texas Property Code 54.021. Certain items exempt.');
  pdf.moveDown();

  sectionTitle('24', 'SUBORDINATION');
  pdf.text('This lease subordinate to existing or future mortgages and liens.');
  pdf.moveDown();

  sectionTitle('25', 'CASUALTY LOSS');
  pdf.text('Per Texas Property Code 92.054 if Property becomes unfit.');
  pdf.moveDown();

  // Section 26: SPECIAL PROVISIONS
  sectionTitle('26', 'SPECIAL PROVISIONS');
  if (doc.specialProvisions) {
    doc.specialProvisions.split('\n').filter(p => p.trim()).forEach((p, i) => {
      pdf.text(`${String.fromCharCode(97 + i)}. ${p.trim()}`);
    });
  } else {
    pdf.text('None.');
  }
  pdf.moveDown();

  // Section 27-30: Legal condensed
  sectionTitle('27', 'DEFAULT');
  pdf.text('Tenant default includes: nonpayment, abandonment, lease violations, false statements. Landlord may terminate, accelerate rent, sue for damages and attorney\'s fees. Interest at 18% on past-due amounts.');
  pdf.moveDown();

  sectionTitle('28', 'EARLY TERMINATION');
  pdf.text('Permitted for: military deployment (30 days notice), family violence (per Texas Property Code Ch. 92), sex offenses/stalking victims.');
  pdf.moveDown();

  sectionTitle('29', 'ATTORNEY\'S FEES');
  pdf.text('Prevailing party may recover reasonable attorney\'s fees.');
  pdf.moveDown();

  sectionTitle('30', 'REPRESENTATIONS');
  pdf.text('False statements by Tenant may result in lease termination.');
  pdf.moveDown();

  // Section 31: ADDENDA
  sectionTitle('31', 'ADDENDA');
  pdf.text([
    doc.addendumFlood ? '[X] Flood Disclosure' : '[ ] Flood Disclosure',
    doc.addendumLeadPaint ? '[X] Lead-Based Paint' : '[ ] Lead-Based Paint',
    doc.addendumInventory ? '[X] Inventory Form' : '[ ] Inventory Form',
    doc.addendumPets ? '[X] Pet Agreement' : '[ ] Pet Agreement',
  ].join('  '));
  pdf.moveDown();

  // Section 32: NOTICES
  sectionTitle('32', 'NOTICES');
  pdf.text(`Landlord: ${field(doc.landlordName)}, ${field(doc.landlordAddress || doc.paymentAddress)}, ${field(doc.landlordEmail)}`);
  pdf.text(`Tenant: ${field(doc.propertyAddress)}, ${field(doc.tenantEmail)}`);
  pdf.moveDown();

  // Section 33: AGREEMENT
  sectionTitle('33', 'AGREEMENT OF PARTIES');
  pdf.text('Entire agreement. Binding on heirs/successors. Joint and several liability. Texas law governs.');
  pdf.moveDown(2);

  // ===== SIGNATURE PAGE =====
  checkSpace(300);
  pdf.font('Helvetica-Bold').fontSize(14).text('EXECUTION', { align: 'center' });
  pdf.moveDown(0.5);
  pdf.font('Helvetica').fontSize(9).text('By signing, each party acknowledges this lease is binding and enforceable.', { align: 'center' });
  pdf.moveDown(2);

  // Landlord Signature
  pdf.font('Helvetica-Bold').fontSize(11).text('LANDLORD:');
  pdf.moveDown(0.5);
  if (doc.landlordSignature) {
    try {
      const imgData = doc.landlordSignature.replace(/^data:image\/\w+;base64,/, '');
      pdf.image(Buffer.from(imgData, 'base64'), { width: 200, height: 60 });
    } catch (e) {
      pdf.font('Helvetica-Oblique').fontSize(10).text('[Electronic Signature on file]');
    }
    pdf.font('Helvetica').fontSize(9);
    pdf.text(`Signed: ${doc.landlordName} on ${new Date(doc.landlordSignedAt).toLocaleString()}`);
    pdf.text(`IP: ${doc.landlordSignedIp}`);
  } else {
    pdf.text('________________________________________     ________________');
    pdf.text('Signature                                                              Date');
  }
  pdf.text(`Name: ${field(doc.landlordName)}`);
  pdf.moveDown(2);

  // Tenant Signature
  pdf.font('Helvetica-Bold').fontSize(11).text('TENANT:');
  pdf.moveDown(0.5);
  if (doc.tenantSignature) {
    try {
      const imgData = doc.tenantSignature.replace(/^data:image\/\w+;base64,/, '');
      pdf.image(Buffer.from(imgData, 'base64'), { width: 200, height: 60 });
    } catch (e) {
      pdf.font('Helvetica-Oblique').fontSize(10).text('[Electronic Signature on file]');
    }
    pdf.font('Helvetica').fontSize(9);
    pdf.text(`Signed: ${doc.tenantName} on ${new Date(doc.tenantSignedAt).toLocaleString()}`);
    pdf.text(`IP: ${doc.tenantSignedIp}`);
  } else {
    pdf.text('________________________________________     ________________');
    pdf.text('Signature                                                              Date');
  }
  pdf.text(`Name: ${field(doc.tenantName)}`);

  // E-Sign Certificate
  pdf.moveDown(3);
  pdf.font('Helvetica-Bold').fontSize(10).text('CERTIFICATE OF ELECTRONIC SIGNING', { align: 'center' });
  pdf.font('Helvetica').fontSize(8).fillColor('#444444');
  pdf.text('This document was signed electronically via LeaseSign. Electronic signatures are legally binding under ESIGN Act and UETA.', { align: 'center' });
  pdf.moveDown();
  pdf.fillColor('#666666');
  pdf.text(`Document ID: ${doc.id}`, { align: 'center' });
  pdf.text(`Generated: ${new Date().toISOString()}`, { align: 'center' });
  pdf.text(`Status: ${doc.status === 'completed' ? 'FULLY EXECUTED' : 'PENDING SIGNATURES'}`, { align: 'center' });

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

async function sendCompletionEmails(doc) {
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
          Please keep this document for your records. You can download a PDF copy from your LeaseSign dashboard.
        </p>
      </td>
    </tr>
  </table>
</body>
</html>`;

  await Promise.all([
    mailer.sendMail({
      from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
      to: doc.landlordEmail,
      subject: `Lease Completed: ${doc.propertyAddress}`,
      html
    }),
    mailer.sendMail({
      from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
      to: doc.tenantEmail,
      subject: `Lease Completed: ${doc.propertyAddress}`,
      html
    })
  ]);
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

    let recipient, signUrl, signerType;

    if (!doc.landlordSignedAt) {
      recipient = doc.landlordEmail;
      signUrl = `${APP_URL}/sign/${doc.landlordSignToken}`;
      signerType = 'landlord';
    } else if (!doc.tenantSignedAt) {
      recipient = doc.tenantEmail;
      signUrl = `${APP_URL}/sign/${doc.tenantSignToken}`;
      signerType = 'tenant';
    } else {
      return res.status(400).json({ error: 'All signatures collected' });
    }

    await mailer.sendMail({
      from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
      to: recipient,
      subject: `[Reminder] Please Sign: Lease for ${doc.propertyAddress}`,
      text: `Reminder: Please sign the lease agreement: ${signUrl}`,
      html: generateReminderEmail(doc, signerType, signUrl)
    });

    await logAudit(doc.id, 'SIGNATURE_REMINDER_SENT', req.user.email, req, { to: recipient });
    res.json({ success: true, sentTo: recipient });
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
    const originalData = docResult.rows[0].data || {};

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
      templateData = docResult.rows[0].data || {};
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

      let recipient, signUrl, signerType;
      if (!doc.landlordSignedAt) {
        recipient = doc.landlordEmail;
        signUrl = `${APP_URL}/sign/${doc.landlordSignToken}`;
        signerType = 'landlord';
      } else if (!doc.tenantSignedAt) {
        recipient = doc.tenantEmail;
        signUrl = `${APP_URL}/sign/${doc.tenantSignToken}`;
        signerType = 'tenant';
      } else continue;

      try {
        await mailer.sendMail({
          from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
          to: recipient,
          subject: `[Reminder] Please Sign: Lease for ${doc.propertyAddress}`,
          text: `Reminder: Please sign the lease agreement: ${signUrl}`,
          html: generateReminderEmail(doc, signerType, signUrl)
        });
        results.push({ id, success: true, sentTo: recipient });
        await logAudit(doc.id, 'BULK_REMINDER_SENT', req.user.email, req, { to: recipient });
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

// ==================== CATCH-ALL ROUTE ====================

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ==================== START SERVER ====================

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

module.exports = app;
