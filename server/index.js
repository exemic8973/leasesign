/**
 * LeaseSign Production Server
 * Texas Residential Lease E-Signature Platform
 *
 * Features:
 * - JWT authentication with refresh tokens
 * - DocuSign integration for lease signing
 * - Stripe payments with Texas-specific tax handling
 * - SendGrid email notifications
 * - AWS S3 document storage
 * - Redis session management
 * - Comprehensive audit logging
 * - Rate limiting and security middleware
 * - WebSocket support for real-time updates
 */

'use strict';

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const { createServer } = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult, param, query } = require('express-validator');
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const sgMail = require('@sendgrid/mail');
const AWS = require('aws-sdk');
const redis = require('redis');
const { Pool } = require('pg');
const docusign = require('docusign-esign');
const winston = require('winston');
const { RateLimiterRedis } = require('rate-limiter-flexible');
const xss = require('xss');
const sanitizeHtml = require('sanitize-html');
require('dotenv').config();

// ==================== CONFIGURATION ====================

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m';
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// Texas tax configuration
const TEXAS_TAX_RATE = 0.0825; // 8.25% state + local
const TEXAS_COUNTIES = {
  harris: { name: 'Harris County', taxRate: 0.0825, city: 'Houston' },
  dallas: { name: 'Dallas County', taxRate: 0.0825, city: 'Dallas' },
  tarrant: { name: 'Tarrant County', taxRate: 0.0825, city: 'Fort Worth' },
  travis: { name: 'Travis County', taxRate: 0.0825, city: 'Austin' },
  bexar: { name: 'Bexar County', taxRate: 0.0825, city: 'San Antonio' },
  collin: { name: 'Collin County', taxRate: 0.0825, city: 'Plano' },
  hidalgo: { name: 'Hidalgo County', taxRate: 0.0825, city: 'McAllen' },
  denton: { name: 'Denton County', taxRate: 0.0825, city: 'Denton' },
  fortbend: { name: 'Fort Bend County', taxRate: 0.0825, city: 'Sugar Land' },
  montgomery: { name: 'Montgomery County', taxRate: 0.0625, city: 'Conroe' },
};

// ==================== LOGGING ====================

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'leasesign-server' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
  ],
});

if (NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    ),
  }));
}

// ==================== DATABASE ====================

const db = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'leasesign',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

db.on('error', (err) => {
  logger.error('Unexpected database error', { error: err.message });
});

// ==================== REDIS ====================

let redisClient;
let rateLimiter;

async function initRedis() {
  try {
    redisClient = redis.createClient({
      url: process.env.REDIS_URL || 'redis://localhost:6379',
      socket: {
        reconnectStrategy: (retries) => Math.min(retries * 100, 3000),
      },
    });
    
    redisClient.on('error', (err) => logger.error('Redis error', { error: err.message }));
    redisClient.on('connect', () => logger.info('Redis connected'));
    
    await redisClient.connect();
    
    rateLimiter = new RateLimiterRedis({
      storeClient: redisClient,
      keyPrefix: 'ratelimit',
      points: 100,
      duration: 60,
    });
    
    return true;
  } catch (err) {
    logger.warn('Redis connection failed, using memory fallback', { error: err.message });
    return false;
  }
}

// ==================== AWS S3 ====================

const s3 = new AWS.S3({
  region: process.env.AWS_REGION || 'us-east-1',
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const S3_BUCKET = process.env.S3_BUCKET || 'leasesign-documents';

// ==================== SENDGRID ====================

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// ==================== EXPRESS APP ====================

const app = express();
const httpServer = createServer(app);

// ==================== SOCKET.IO ====================

const io = new Server(httpServer, {
  cors: {
    origin: FRONTEND_URL,
    methods: ['GET', 'POST'],
    credentials: true,
  },
  transports: ['websocket', 'polling'],
});

// ==================== MIDDLEWARE ====================

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'", FRONTEND_URL],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// CORS
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = [
      FRONTEND_URL,
      'http://localhost:3000',
      'http://localhost:3001',
      process.env.ADMIN_URL,
    ].filter(Boolean);
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
}));

// Compression
app.use(compression());

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Logging
app.use(morgan('combined', {
  stream: { write: (message) => logger.info(message.trim()) },
}));

// Rate limiting
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', globalLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many authentication attempts' },
  skipSuccessfulRequests: true,
});

const paymentLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  message: { error: 'Too many payment requests' },
});

// ==================== FILE UPLOAD ====================

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png', 'image/gif'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only PDF, JPEG, PNG, and GIF are allowed.'));
    }
  },
});

// ==================== AUTHENTICATION MIDDLEWARE ====================

const auth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.substring(7);
    
    // Check token blacklist
    if (redisClient) {
      const isBlacklisted = await redisClient.get(`blacklist:${token}`);
      if (isBlacklisted) {
        return res.status(401).json({ error: 'Token has been revoked' });
      }
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Get user from database
    const result = await db.query(
      'SELECT id, email, role, is_active, full_name FROM users WHERE id = $1',
      [decoded.userId]
    );
    
    if (!result.rows[0] || !result.rows[0].is_active) {
      return res.status(401).json({ error: 'User not found or inactive' });
    }
    
    req.user = result.rows[0];
    req.token = token;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  next();
};

// ==================== UTILITY FUNCTIONS ====================

function sanitizeInput(input) {
  if (typeof input === 'string') {
    return sanitizeHtml(xss(input.trim()), {
      allowedTags: [],
      allowedAttributes: {},
    });
  }
  return input;
}

function calculateTax(amount, county = 'harris') {
  const countyData = TEXAS_COUNTIES[county.toLowerCase()] || TEXAS_COUNTIES.harris;
  const taxAmount = Math.round(amount * countyData.taxRate * 100) / 100;
  return {
    subtotal: amount,
    taxRate: countyData.taxRate,
    taxAmount,
    total: amount + taxAmount,
    county: countyData.name,
  };
}

async function uploadToS3(buffer, filename, contentType) {
  const key = `documents/${uuidv4()}/${filename}`;
  const params = {
    Bucket: S3_BUCKET,
    Key: key,
    Body: buffer,
    ContentType: contentType,
    ServerSideEncryption: 'AES256',
    Metadata: {
      uploadedAt: new Date().toISOString(),
    },
  };
  
  await s3.upload(params).promise();
  return key;
}

async function getSignedUrl(key, expiresIn = 3600) {
  return s3.getSignedUrlPromise('getObject', {
    Bucket: S3_BUCKET,
    Key: key,
    Expires: expiresIn,
  });
}

async function sendEmail(to, subject, html, text) {
  try {
    await sgMail.send({
      to,
      from: {
        email: process.env.FROM_EMAIL || 'noreply@leasesign.com',
        name: 'LeaseSign',
      },
      subject,
      html,
      text,
    });
    logger.info('Email sent', { to, subject });
  } catch (err) {
    logger.error('Email send failed', { error: err.message, to, subject });
    throw err;
  }
}

async function logAuditEvent(userId, action, resourceType, resourceId, details = {}) {
  try {
    await db.query(
      `INSERT INTO audit_logs (user_id, action, resource_type, resource_id, details, ip_address, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
      [userId, action, resourceType, resourceId, JSON.stringify(details), details.ip || null]
    );
  } catch (err) {
    logger.error('Audit log failed', { error: err.message });
  }
}

// ==================== DOCUSIGN INTEGRATION ====================

const docusignConfig = {
  accountId: process.env.DOCUSIGN_ACCOUNT_ID,
  clientId: process.env.DOCUSIGN_CLIENT_ID,
  clientSecret: process.env.DOCUSIGN_CLIENT_SECRET,
  redirectUri: process.env.DOCUSIGN_REDIRECT_URI || `${FRONTEND_URL}/docusign/callback`,
  baseUrl: process.env.DOCUSIGN_BASE_URL || 'https://demo.docusign.net',
};

async function getDocuSignApiClient() {
  const apiClient = new docusign.ApiClient();
  apiClient.setBasePath(`${docusignConfig.baseUrl}/restapi`);
  
  // Use JWT authentication
  const token = await getDocuSignToken();
  apiClient.addDefaultHeader('Authorization', `Bearer ${token}`);
  
  return apiClient;
}

async function getDocuSignToken() {
  // Check cache
  if (redisClient) {
    const cached = await redisClient.get('docusign:token');
    if (cached) return cached;
  }
  
  const apiClient = new docusign.ApiClient();
  apiClient.setBasePath(`${docusignConfig.baseUrl}/restapi`);
  apiClient.setOAuthBasePath(docusignConfig.baseUrl.replace('https://', ''));
  
  const results = await apiClient.requestJWTUserToken(
    docusignConfig.clientId,
    process.env.DOCUSIGN_USER_ID,
    ['signature', 'impersonation'],
    Buffer.from(process.env.DOCUSIGN_PRIVATE_KEY || '', 'base64'),
    3600
  );
  
  const token = results.body.access_token;
  
  // Cache token
  if (redisClient) {
    await redisClient.setEx('docusign:token', 3500, token);
  }
  
  return token;
}

async function createLeaseEnvelope(leaseData, signers) {
  const apiClient = await getDocuSignApiClient();
  const envelopesApi = new docusign.EnvelopesApi(apiClient);
  
  // Create document
  const document = new docusign.Document();
  document.documentBase64 = leaseData.documentBase64;
  document.name = `Lease Agreement - ${leaseData.propertyAddress}`;
  document.fileExtension = 'pdf';
  document.documentId = '1';
  
  // Create envelope definition
  const envelopeDefinition = new docusign.EnvelopeDefinition();
  envelopeDefinition.emailSubject = `Please sign your lease for ${leaseData.propertyAddress}`;
  envelopeDefinition.documents = [document];
  envelopeDefinition.recipients = {
    signers: signers.map((signer, index) => {
      const s = new docusign.Signer();
      s.email = signer.email;
      s.name = signer.name;
      s.recipientId = String(index + 1);
      s.routingOrder = String(index + 1);
      s.tabs = {
        signHereTabs: [{
          anchorString: `[SIGNATURE_${index + 1}]`,
          anchorUnits: 'pixels',
          anchorXOffset: '0',
          anchorYOffset: '0',
        }],
        dateSignedTabs: [{
          anchorString: `[DATE_${index + 1}]`,
          anchorUnits: 'pixels',
        }],
      };
      return s;
    }),
  };
  envelopeDefinition.status = 'sent';
  
  const results = await envelopesApi.createEnvelope(
    docusignConfig.accountId,
    { envelopeDefinition }
  );
  
  return results;
}

// ==================== HEALTH CHECK ====================

app.get('/health', async (req, res) => {
  const health = {
    status: 'ok',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0',
    environment: NODE_ENV,
    services: {},
  };
  
  // Check database
  try {
    await db.query('SELECT 1');
    health.services.database = 'connected';
  } catch (err) {
    health.services.database = 'error';
    health.status = 'degraded';
  }
  
  // Check Redis
  if (redisClient) {
    try {
      await redisClient.ping();
      health.services.redis = 'connected';
    } catch (err) {
      health.services.redis = 'error';
      health.status = 'degraded';
    }
  } else {
    health.services.redis = 'not configured';
  }
  
  // Check S3
  try {
    await s3.headBucket({ Bucket: S3_BUCKET }).promise();
    health.services.s3 = 'connected';
  } catch (err) {
    health.services.s3 = 'error';
    health.status = 'degraded';
  }
  
  res.status(health.status === 'ok' ? 200 : 207).json(health);
});

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', authLimiter, [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/),
  body('fullName').isLength({ min: 2, max: 100 }).trim(),
  body('role').optional().isIn(['landlord', 'tenant', 'agent']),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { email, password, fullName, role = 'tenant', phone, company } = req.body;
    
    // Check if email exists
    const existing = await db.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows[0]) {
      return res.status(409).json({ error: 'Email already registered' });
    }
    
    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);
    
    // Generate verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    
    // Create user
    const result = await db.query(
      `INSERT INTO users (email, password_hash, full_name, role, phone, company, verification_token, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
       RETURNING id, email, full_name, role`,
      [email, passwordHash, sanitizeInput(fullName), role, phone, company, verificationToken]
    );
    
    const user = result.rows[0];
    
    // Send verification email
    const verifyUrl = `${FRONTEND_URL}/verify-email?token=${verificationToken}`;
    await sendEmail(
      email,
      'Verify your LeaseSign account',
      `<h2>Welcome to LeaseSign!</h2><p>Click <a href="${verifyUrl}">here</a> to verify your email.</p>`,
      `Welcome to LeaseSign! Verify your email: ${verifyUrl}`
    );
    
    await logAuditEvent(user.id, 'REGISTER', 'user', user.id, { ip: req.ip });
    
    res.status(201).json({
      message: 'Registration successful. Please check your email to verify your account.',
      userId: user.id,
    });
  } catch (err) {
    logger.error('Registration error', { error: err.message });
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', authLimiter, [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { email, password } = req.body;
    
    const result = await db.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );
    
    const user = result.rows[0];
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    if (!user.is_verified) {
      return res.status(401).json({ error: 'Please verify your email first', code: 'EMAIL_NOT_VERIFIED' });
    }
    
    if (!user.is_active) {
      return res.status(401).json({ error: 'Account has been deactivated' });
    }
    
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      // Increment failed attempts
      await db.query(
        'UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = $1',
        [user.id]
      );
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Reset failed attempts
    await db.query(
      'UPDATE users SET failed_login_attempts = 0, last_login = NOW() WHERE id = $1',
      [user.id]
    );
    
    // Generate tokens
    const accessToken = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
    
    const refreshToken = jwt.sign(
      { userId: user.id, tokenVersion: user.token_version || 0 },
      JWT_REFRESH_SECRET,
      { expiresIn: JWT_REFRESH_EXPIRES_IN }
    );
    
    // Store refresh token in Redis
    if (redisClient) {
      await redisClient.setEx(
        `refresh:${user.id}`,
        7 * 24 * 60 * 60,
        refreshToken
      );
    }
    
    // Set httpOnly cookie for refresh token
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    
    await logAuditEvent(user.id, 'LOGIN', 'user', user.id, { ip: req.ip });
    
    res.json({
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        role: user.role,
        company: user.company,
      },
    });
  } catch (err) {
    logger.error('Login error', { error: err.message });
    res.status(500).json({ error: 'Login failed' });
  }
});

// Refresh token
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
    
    if (!refreshToken) {
      return res.status(401).json({ error: 'No refresh token' });
    }
    
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    
    // Verify against Redis
    if (redisClient) {
      const stored = await redisClient.get(`refresh:${decoded.userId}`);
      if (stored !== refreshToken) {
        return res.status(401).json({ error: 'Invalid refresh token' });
      }
    }
    
    const result = await db.query(
      'SELECT id, email, role, is_active FROM users WHERE id = $1',
      [decoded.userId]
    );
    
    const user = result.rows[0];
    if (!user || !user.is_active) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    const accessToken = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
    
    res.json({ accessToken });
  } catch (err) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// Logout
app.post('/api/auth/logout', auth, async (req, res) => {
  try {
    // Blacklist current token
    if (redisClient) {
      const decoded = jwt.decode(req.token);
      const ttl = decoded.exp - Math.floor(Date.now() / 1000);
      if (ttl > 0) {
        await redisClient.setEx(`blacklist:${req.token}`, ttl, '1');
      }
      
      // Remove refresh token
      await redisClient.del(`refresh:${req.user.id}`);
    }
    
    res.clearCookie('refreshToken');
    await logAuditEvent(req.user.id, 'LOGOUT', 'user', req.user.id, { ip: req.ip });
    
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Verify email
app.get('/api/auth/verify-email', [
  query('token').notEmpty(),
], async (req, res) => {
  try {
    const { token } = req.query;
    
    const result = await db.query(
      'UPDATE users SET is_verified = true, verification_token = null WHERE verification_token = $1 RETURNING id',
      [token]
    );
    
    if (!result.rows[0]) {
      return res.status(400).json({ error: 'Invalid or expired verification token' });
    }
    
    res.json({ message: 'Email verified successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Request password reset
app.post('/api/auth/forgot-password', authLimiter, [
  body('email').isEmail().normalizeEmail(),
], async (req, res) => {
  try {
    const { email } = req.body;
    
    const result = await db.query('SELECT id FROM users WHERE email = $1', [email]);
    
    // Always return success to prevent email enumeration
    if (!result.rows[0]) {
      return res.json({ message: 'If that email exists, a reset link has been sent' });
    }
    
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpiry = new Date(Date.now() + 3600000); // 1 hour
    
    await db.query(
      'UPDATE users SET password_reset_token = $1, password_reset_expiry = $2 WHERE id = $3',
      [resetToken, resetExpiry, result.rows[0].id]
    );
    
    const resetUrl = `${FRONTEND_URL}/reset-password?token=${resetToken}`;
    await sendEmail(
      email,
      'Reset your LeaseSign password',
      `<p>Click <a href="${resetUrl}">here</a> to reset your password. This link expires in 1 hour.</p>`,
      `Reset your password: ${resetUrl}`
    );
    
    res.json({ message: 'If that email exists, a reset link has been sent' });
  } catch (err) {
    logger.error('Password reset request error', { error: err.message });
    res.status(500).json({ error: 'Failed to process request' });
  }
});

// Reset password
app.post('/api/auth/reset-password', authLimiter, [
  body('token').notEmpty(),
  body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/),
], async (req, res) => {
  try {
    const { token, password } = req.body;
    
    const result = await db.query(
      'SELECT id FROM users WHERE password_reset_token = $1 AND password_reset_expiry > NOW()',
      [token]
    );
    
    if (!result.rows[0]) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    
    const passwordHash = await bcrypt.hash(password, 12);
    
    await db.query(
      'UPDATE users SET password_hash = $1, password_reset_token = null, password_reset_expiry = null, token_version = token_version + 1 WHERE id = $2',
      [passwordHash, result.rows[0].id]
    );
    
    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ==================== USER ROUTES ====================

// Get current user
app.get('/api/users/me', auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, email, full_name, role, phone, company, is_verified, created_at, last_login,
              stripe_customer_id IS NOT NULL as has_payment_method
       FROM users WHERE id = $1`,
      [req.user.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// Update profile
app.put('/api/users/me', auth, [
  body('fullName').optional().isLength({ min: 2, max: 100 }).trim(),
  body('phone').optional().isMobilePhone(),
  body('company').optional().isLength({ max: 200 }).trim(),
], async (req, res) => {
  try {
    const { fullName, phone, company } = req.body;
    
    await db.query(
      'UPDATE users SET full_name = COALESCE($1, full_name), phone = COALESCE($2, phone), company = COALESCE($3, company), updated_at = NOW() WHERE id = $4',
      [sanitizeInput(fullName), phone, sanitizeInput(company), req.user.id]
    );
    
    res.json({ message: 'Profile updated' });
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

// Change password
app.put('/api/users/me/password', auth, [
  body('currentPassword').notEmpty(),
  body('newPassword').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/),
], async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    const result = await db.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
    
    const isValid = await bcrypt.compare(currentPassword, result.rows[0].password_hash);
    if (!isValid) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }
    
    const newHash = await bcrypt.hash(newPassword, 12);
    await db.query(
      'UPDATE users SET password_hash = $1, token_version = token_version + 1 WHERE id = $2',
      [newHash, req.user.id]
    );
    
    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// Get all users (admin)
app.get('/api/users', auth, requireRole('admin'), async (req, res) => {
  try {
    const { page = 1, limit = 20, role, search } = req.query;
    const offset = (page - 1) * limit;
    
    let queryStr = 'SELECT id, email, full_name, role, is_active, created_at FROM users WHERE 1=1';
    const params = [];
    
    if (role) {
      params.push(role);
      queryStr += ` AND role = $${params.length}`;
    }
    
    if (search) {
      params.push(`%${search}%`);
      queryStr += ` AND (email ILIKE $${params.length} OR full_name ILIKE $${params.length})`;
    }
    
    queryStr += ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);
    
    const result = await db.query(queryStr, params);
    const count = await db.query('SELECT COUNT(*) FROM users');
    
    res.json({
      users: result.rows,
      total: parseInt(count.rows[0].count),
      page: parseInt(page),
      limit: parseInt(limit),
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get users' });
  }
});

// ==================== PROPERTY ROUTES ====================

// Get properties
app.get('/api/properties', auth, async (req, res) => {
  try {
    const { page = 1, limit = 20, status, county } = req.query;
    const offset = (page - 1) * limit;
    
    let queryStr = `SELECT p.*, u.full_name as owner_name
                   FROM properties p
                   JOIN users u ON p.owner_id = u.id
                   WHERE 1=1`;
    const params = [];
    
    // Landlords see their own properties, tenants see available ones
    if (req.user.role === 'landlord') {
      params.push(req.user.id);
      queryStr += ` AND p.owner_id = $${params.length}`;
    } else if (req.user.role === 'tenant') {
      queryStr += ` AND p.status = 'available'`;
    }
    
    if (status) {
      params.push(status);
      queryStr += ` AND p.status = $${params.length}`;
    }
    
    if (county) {
      params.push(county);
      queryStr += ` AND p.county = $${params.length}`;
    }
    
    queryStr += ` ORDER BY p.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);
    
    const result = await db.query(queryStr, params);
    const count = await db.query('SELECT COUNT(*) FROM properties');
    
    res.json({
      properties: result.rows,
      total: parseInt(count.rows[0].count),
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get properties' });
  }
});

// Create property
app.post('/api/properties', auth, requireRole('landlord', 'admin'), [
  body('address').notEmpty().isLength({ max: 500 }),
  body('city').notEmpty().isLength({ max: 100 }),
  body('county').isIn(Object.keys(TEXAS_COUNTIES)),
  body('zipCode').matches(/^\d{5}(-\d{4})?$/),
  body('rentAmount').isFloat({ min: 0 }),
  body('bedrooms').isInt({ min: 0, max: 20 }),
  body('bathrooms').isFloat({ min: 0.5, max: 20 }),
  body('squareFeet').optional().isInt({ min: 1 }),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const {
      address, city, county, state = 'TX', zipCode,
      rentAmount, bedrooms, bathrooms, squareFeet,
      description, amenities, petPolicy,
    } = req.body;
    
    const result = await db.query(
      `INSERT INTO properties (owner_id, address, city, county, state, zip_code, rent_amount,
       bedrooms, bathrooms, square_feet, description, amenities, pet_policy, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
       RETURNING *`,
      [req.user.id, sanitizeInput(address), sanitizeInput(city), county, state,
       zipCode, rentAmount, bedrooms, bathrooms, squareFeet,
       sanitizeInput(description), JSON.stringify(amenities || []), sanitizeInput(petPolicy)]
    );
    
    await logAuditEvent(req.user.id, 'CREATE_PROPERTY', 'property', result.rows[0].id, { ip: req.ip });
    
    res.status(201).json(result.rows[0]);
  } catch (err) {
    logger.error('Create property error', { error: err.message });
    res.status(500).json({ error: 'Failed to create property' });
  }
});

// Get property by ID
app.get('/api/properties/:id', auth, [
  param('id').isUUID(),
], async (req, res) => {
  try {
    const result = await db.query(
      `SELECT p.*, u.full_name as owner_name, u.email as owner_email
       FROM properties p
       JOIN users u ON p.owner_id = u.id
       WHERE p.id = $1`,
      [req.params.id]
    );
    
    if (!result.rows[0]) {
      return res.status(404).json({ error: 'Property not found' });
    }
    
    // Get signed URLs for images
    if (result.rows[0].images) {
      result.rows[0].imageUrls = await Promise.all(
        result.rows[0].images.map(key => getSignedUrl(key))
      );
    }
    
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get property' });
  }
});

// Update property
app.put('/api/properties/:id', auth, requireRole('landlord', 'admin'), async (req, res) => {
  try {
    const result = await db.query('SELECT owner_id FROM properties WHERE id = $1', [req.params.id]);
    
    if (!result.rows[0]) {
      return res.status(404).json({ error: 'Property not found' });
    }
    
    if (result.rows[0].owner_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    const { address, city, rentAmount, status, description, amenities, petPolicy } = req.body;
    
    await db.query(
      `UPDATE properties SET
       address = COALESCE($1, address),
       city = COALESCE($2, city),
       rent_amount = COALESCE($3, rent_amount),
       status = COALESCE($4, status),
       description = COALESCE($5, description),
       amenities = COALESCE($6, amenities),
       pet_policy = COALESCE($7, pet_policy),
       updated_at = NOW()
       WHERE id = $8`,
      [sanitizeInput(address), sanitizeInput(city), rentAmount, status,
       sanitizeInput(description), JSON.stringify(amenities), sanitizeInput(petPolicy), req.params.id]
    );
    
    res.json({ message: 'Property updated' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update property' });
  }
});

// Upload property images
app.post('/api/properties/:id/images', auth, requireRole('landlord', 'admin'),
  upload.array('images', 10), async (req, res) => {
  try {
    const property = await db.query(
      'SELECT owner_id, images FROM properties WHERE id = $1',
      [req.params.id]
    );
    
    if (!property.rows[0]) {
      return res.status(404).json({ error: 'Property not found' });
    }
    
    if (property.rows[0].owner_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    const uploadPromises = req.files.map(file =>
      uploadToS3(file.buffer, file.originalname, file.mimetype)
    );
    
    const keys = await Promise.all(uploadPromises);
    const currentImages = property.rows[0].images || [];
    const allImages = [...currentImages, ...keys];
    
    await db.query(
      'UPDATE properties SET images = $1 WHERE id = $2',
      [JSON.stringify(allImages), req.params.id]
    );
    
    const urls = await Promise.all(keys.map(key => getSignedUrl(key)));
    res.json({ message: 'Images uploaded', urls });
  } catch (err) {
    res.status(500).json({ error: 'Upload failed' });
  }
});

// ==================== LEASE DOCUMENT ROUTES ====================

// Get lease documents
app.get('/api/leases', auth, async (req, res) => {
  try {
    const { page = 1, limit = 20, status } = req.query;
    const offset = (page - 1) * limit;
    
    let queryStr = `
      SELECT l.*, 
             p.address as property_address,
             landlord.full_name as landlord_name,
             tenant.full_name as tenant_name
      FROM leases l
      JOIN properties p ON l.property_id = p.id
      JOIN users landlord ON l.landlord_id = landlord.id
      JOIN users tenant ON l.tenant_id = tenant.id
      WHERE 1=1`;
    const params = [];
    
    if (req.user.role === 'landlord') {
      params.push(req.user.id);
      queryStr += ` AND l.landlord_id = $${params.length}`;
    } else if (req.user.role === 'tenant') {
      params.push(req.user.id);
      queryStr += ` AND l.tenant_id = $${params.length}`;
    }
    
    if (status) {
      params.push(status);
      queryStr += ` AND l.status = $${params.length}`;
    }
    
    queryStr += ` ORDER BY l.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);
    
    const result = await db.query(queryStr, params);
    res.json({ leases: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get leases' });
  }
});

// Create lease document
app.post('/api/leases', auth, requireRole('landlord', 'admin'), [
  body('propertyId').isUUID(),
  body('tenantEmail').isEmail(),
  body('startDate').isISO8601(),
  body('endDate').isISO8601(),
  body('rentAmount').isFloat({ min: 0 }),
  body('securityDeposit').isFloat({ min: 0 }),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const {
      propertyId, tenantEmail, startDate, endDate,
      rentAmount, securityDeposit, terms, specialClauses,
    } = req.body;
    
    // Get tenant
    const tenantResult = await db.query('SELECT id FROM users WHERE email = $1', [tenantEmail]);
    if (!tenantResult.rows[0]) {
      return res.status(404).json({ error: 'Tenant not found' });
    }
    
    // Get property
    const propertyResult = await db.query(
      'SELECT * FROM properties WHERE id = $1 AND owner_id = $2',
      [propertyId, req.user.id]
    );
    if (!propertyResult.rows[0]) {
      return res.status(404).json({ error: 'Property not found' });
    }
    
    const property = propertyResult.rows[0];
    const tenant = tenantResult.rows[0];
    const taxInfo = calculateTax(rentAmount, property.county);
    
    // Create lease record
    const leaseResult = await db.query(
      `INSERT INTO leases (landlord_id, tenant_id, property_id, start_date, end_date,
       rent_amount, security_deposit, tax_info, terms, special_clauses, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'draft', NOW())
       RETURNING *`,
      [req.user.id, tenant.id, propertyId, startDate, endDate,
       rentAmount, securityDeposit, JSON.stringify(taxInfo),
       sanitizeInput(terms), sanitizeInput(specialClauses)]
    );
    
    const lease = leaseResult.rows[0];
    
    // Send notification to tenant
    await sendEmail(
      tenantEmail,
      'Lease Agreement Ready for Review',
      `<p>Your landlord has prepared a lease agreement for ${property.address}. Please log in to LeaseSign to review and sign.</p>`,
      `A lease agreement has been prepared for ${property.address}. Log in to review.`
    );
    
    await logAuditEvent(req.user.id, 'CREATE_LEASE', 'lease', lease.id, { ip: req.ip });
    
    res.status(201).json(lease);
  } catch (err) {
    logger.error('Create lease error', { error: err.message });
    res.status(500).json({ error: 'Failed to create lease' });
  }
});

// Get lease by ID
app.get('/api/leases/:id', auth, [
  param('id').isUUID(),
], async (req, res) => {
  try {
    const result = await db.query(
      `SELECT l.*,
              p.address as property_address, p.city, p.county,
              landlord.full_name as landlord_name, landlord.email as landlord_email,
              tenant.full_name as tenant_name, tenant.email as tenant_email
       FROM leases l
       JOIN properties p ON l.property_id = p.id
       JOIN users landlord ON l.landlord_id = landlord.id
       JOIN users tenant ON l.tenant_id = tenant.id
       WHERE l.id = $1`,
      [req.params.id]
    );
    
    if (!result.rows[0]) {
      return res.status(404).json({ error: 'Lease not found' });
    }
    
    const lease = result.rows[0];
    
    // Check access
    if (lease.landlord_id !== req.user.id && lease.tenant_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not authorized' });
    }
    
    // Get signed document URL if exists
    if (lease.document_s3_key) {
      lease.documentUrl = await getSignedUrl(lease.document_s3_key);
    }
    
    res.json(lease);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get lease' });
  }
});

// Send lease for signing via DocuSign
app.post('/api/leases/:id/send-for-signing', auth, requireRole('landlord', 'admin'), async (req, res) => {
  try {
    const leaseResult = await db.query(
      `SELECT l.*, p.address, landlord.full_name as landlord_name, landlord.email as landlord_email,
              tenant.full_name as tenant_name, tenant.email as tenant_email
       FROM leases l
       JOIN properties p ON l.property_id = p.id
       JOIN users landlord ON l.landlord_id = landlord.id
       JOIN users tenant ON l.tenant_id = tenant.id
       WHERE l.id = $1 AND l.landlord_id = $2`,
      [req.params.id, req.user.id]
    );
    
    if (!leaseResult.rows[0]) {
      return res.status(404).json({ error: 'Lease not found' });
    }
    
    const lease = leaseResult.rows[0];
    
    if (lease.status !== 'draft') {
      return res.status(400).json({ error: 'Lease is not in draft status' });
    }
    
    // Generate PDF (simplified - in production use a PDF library)
    const documentBase64 = Buffer.from(`LEASE AGREEMENT\n${JSON.stringify(lease, null, 2)}`).toString('base64');
    
    // Create DocuSign envelope
    const envelope = await createLeaseEnvelope(
      { documentBase64, propertyAddress: lease.address },
      [
        { email: lease.landlord_email, name: lease.landlord_name },
        { email: lease.tenant_email, name: lease.tenant_name },
      ]
    );
    
    // Update lease
    await db.query(
      `UPDATE leases SET status = 'pending_signatures', docusign_envelope_id = $1,
       sent_for_signing_at = NOW() WHERE id = $2`,
      [envelope.envelopeId, lease.id]
    );
    
    await logAuditEvent(req.user.id, 'SEND_FOR_SIGNING', 'lease', lease.id, { envelopeId: envelope.envelopeId });
    
    res.json({ message: 'Lease sent for signing', envelopeId: envelope.envelopeId });
  } catch (err) {
    logger.error('Send for signing error', { error: err.message });
    res.status(500).json({ error: 'Failed to send for signing' });
  }
});

// DocuSign webhook
app.post('/api/webhooks/docusign', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const event = JSON.parse(req.body);
    const { envelopeId, status } = event;
    
    if (status === 'completed') {
      await db.query(
        `UPDATE leases SET status = 'signed', signed_at = NOW() WHERE docusign_envelope_id = $1`,
        [envelopeId]
      );
      
      // Download signed document and store in S3
      const leaseResult = await db.query(
        'SELECT * FROM leases WHERE docusign_envelope_id = $1',
        [envelopeId]
      );
      
      if (leaseResult.rows[0]) {
        // Notify both parties
        logger.info('Lease signed', { leaseId: leaseResult.rows[0].id });
      }
    }
    
    res.json({ received: true });
  } catch (err) {
    logger.error('DocuSign webhook error', { error: err.message });
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// ==================== PAYMENT ROUTES ====================

// Create payment intent
app.post('/api/payments/create-intent', auth, paymentLimiter, [
  body('leaseId').isUUID(),
  body('type').isIn(['first_month', 'security_deposit', 'monthly_rent', 'late_fee']),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { leaseId, type } = req.body;
    
    const leaseResult = await db.query(
      `SELECT l.*, p.county FROM leases l
       JOIN properties p ON l.property_id = p.id
       WHERE l.id = $1 AND (l.landlord_id = $2 OR l.tenant_id = $2)`,
      [leaseId, req.user.id]
    );
    
    if (!leaseResult.rows[0]) {
      return res.status(404).json({ error: 'Lease not found' });
    }
    
    const lease = leaseResult.rows[0];
    
    let amount;
    switch (type) {
      case 'first_month':
        amount = lease.rent_amount;
        break;
      case 'security_deposit':
        amount = lease.security_deposit;
        break;
      case 'monthly_rent':
        amount = lease.rent_amount;
        break;
      case 'late_fee':
        amount = lease.rent_amount * 0.1; // 10% late fee
        break;
    }
    
    const taxInfo = calculateTax(amount, lease.county);
    const totalAmount = Math.round(taxInfo.total * 100); // Convert to cents
    
    // Get or create Stripe customer
    let customerId = req.user.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: req.user.email,
        name: req.user.full_name,
        metadata: { userId: req.user.id },
      });
      customerId = customer.id;
      await db.query(
        'UPDATE users SET stripe_customer_id = $1 WHERE id = $2',
        [customerId, req.user.id]
      );
    }
    
    const paymentIntent = await stripe.paymentIntents.create({
      amount: totalAmount,
      currency: 'usd',
      customer: customerId,
      metadata: {
        leaseId,
        paymentType: type,
        userId: req.user.id,
        taxAmount: taxInfo.taxAmount,
        county: lease.county,
      },
      description: `LeaseSign: ${type} for lease ${leaseId}`,
    });
    
    // Record payment intent
    await db.query(
      `INSERT INTO payments (lease_id, user_id, amount, tax_amount, total_amount, type,
       stripe_payment_intent_id, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', NOW())`,
      [leaseId, req.user.id, amount, taxInfo.taxAmount, taxInfo.total,
       type, paymentIntent.id]
    );
    
    res.json({
      clientSecret: paymentIntent.client_secret,
      amount: taxInfo.total,
      breakdown: taxInfo,
    });
  } catch (err) {
    logger.error('Create payment intent error', { error: err.message });
    res.status(500).json({ error: 'Failed to create payment intent' });
  }
});

// Stripe webhook
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    return res.status(400).json({ error: `Webhook error: ${err.message}` });
  }
  
  try {
    switch (event.type) {
      case 'payment_intent.succeeded': {
        const { id: paymentIntentId, metadata } = event.data.object;
        
        await db.query(
          `UPDATE payments SET status = 'completed', completed_at = NOW()
           WHERE stripe_payment_intent_id = $1`,
          [paymentIntentId]
        );
        
        // Update lease payment status
        if (metadata.paymentType === 'first_month') {
          await db.query(
            `UPDATE leases SET first_month_paid = true, payment_status = 'paid' WHERE id = $1`,
            [metadata.leaseId]
          );
        }
        
        await logAuditEvent(metadata.userId, 'PAYMENT_SUCCESS', 'payment', paymentIntentId, metadata);
        
        // Notify parties
        const leaseResult = await db.query(
          `SELECT l.*, tenant.email as tenant_email, landlord.email as landlord_email
           FROM leases l
           JOIN users tenant ON l.tenant_id = tenant.id
           JOIN users landlord ON l.landlord_id = landlord.id
           WHERE l.id = $1`,
          [metadata.leaseId]
        );
        
        if (leaseResult.rows[0]) {
          await sendEmail(
            leaseResult.rows[0].landlord_email,
            'Payment Received',
            `<p>A payment of $${event.data.object.amount / 100} has been received for your lease.</p>`,
            `Payment received for your lease.`
          );
        }
        break;
      }
      
      case 'payment_intent.payment_failed': {
        const { id: paymentIntentId } = event.data.object;
        await db.query(
          `UPDATE payments SET status = 'failed' WHERE stripe_payment_intent_id = $1`,
          [paymentIntentId]
        );
        break;
      }
    }
    
    res.json({ received: true });
  } catch (err) {
    logger.error('Stripe webhook processing error', { error: err.message });
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Get payment history
app.get('/api/payments', auth, async (req, res) => {
  try {
    const { leaseId, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;
    
    let queryStr = `SELECT p.*, l.property_id FROM payments p
                   JOIN leases l ON p.lease_id = l.id
                   WHERE (l.landlord_id = $1 OR l.tenant_id = $1)`;
    const params = [req.user.id];
    
    if (leaseId) {
      params.push(leaseId);
      queryStr += ` AND p.lease_id = $${params.length}`;
    }
    
    queryStr += ` ORDER BY p.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);
    
    const result = await db.query(queryStr, params);
    res.json({ payments: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get payments' });
  }
});

// ==================== DOCUMENT ROUTES ====================

// Upload document
app.post('/api/documents', auth, upload.single('document'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const { leaseId, type, description } = req.body;
    
    const key = await uploadToS3(
      req.file.buffer,
      req.file.originalname,
      req.file.mimetype
    );
    
    const result = await db.query(
      `INSERT INTO documents (lease_id, uploaded_by, s3_key, filename, file_size, file_type, type, description, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
       RETURNING *`,
      [leaseId, req.user.id, key, req.file.originalname, req.file.size,
       req.file.mimetype, type, sanitizeInput(description)]
    );
    
    await logAuditEvent(req.user.id, 'UPLOAD_DOCUMENT', 'document', result.rows[0].id, {
      filename: req.file.originalname,
      size: req.file.size,
    });
    
    res.status(201).json(result.rows[0]);
  } catch (err) {
    logger.error('Document upload error', { error: err.message });
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Get documents
app.get('/api/documents', auth, async (req, res) => {
  try {
    const { leaseId } = req.query;
    
    const result = await db.query(
      `SELECT d.* FROM documents d
       JOIN leases l ON d.lease_id = l.id
       WHERE d.lease_id = $1 AND (l.landlord_id = $2 OR l.tenant_id = $2)`,
      [leaseId, req.user.id]
    );
    
    // Generate signed URLs
    const docs = await Promise.all(result.rows.map(async (doc) => ({
      ...doc,
      url: await getSignedUrl(doc.s3_key),
    })));
    
    res.json({ documents: docs });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get documents' });
  }
});

// Download document
app.get('/api/documents/:id/download', auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT d.* FROM documents d
       JOIN leases l ON d.lease_id = l.id
       WHERE d.id = $1 AND (l.landlord_id = $2 OR l.tenant_id = $2)`,
      [req.params.id, req.user.id]
    );
    
    if (!result.rows[0]) {
      return res.status(404).json({ error: 'Document not found' });
    }
    
    const url = await getSignedUrl(result.rows[0].s3_key, 60);
    res.redirect(url);
  } catch (err) {
    res.status(500).json({ error: 'Download failed' });
  }
});

// ==================== NOTIFICATION ROUTES ====================

// Get notifications
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const { unreadOnly = false, page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;
    
    let queryStr = 'SELECT * FROM notifications WHERE user_id = $1';
    const params = [req.user.id];
    
    if (unreadOnly === 'true') {
      queryStr += ' AND read_at IS NULL';
    }
    
    queryStr += ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);
    
    const result = await db.query(queryStr, params);
    const unreadCount = await db.query(
      'SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND read_at IS NULL',
      [req.user.id]
    );
    
    res.json({
      notifications: result.rows,
      unreadCount: parseInt(unreadCount.rows[0].count),
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get notifications' });
  }
});

// Mark notification as read
app.put('/api/notifications/:id/read', auth, async (req, res) => {
  try {
    await db.query(
      'UPDATE notifications SET read_at = NOW() WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );
    res.json({ message: 'Notification marked as read' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to mark notification' });
  }
});

// Mark all as read
app.put('/api/notifications/read-all', auth, async (req, res) => {
  try {
    await db.query(
      'UPDATE notifications SET read_at = NOW() WHERE user_id = $1 AND read_at IS NULL',
      [req.user.id]
    );
    res.json({ message: 'All notifications marked as read' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to mark notifications' });
  }
});

// ==================== ADMIN ROUTES ====================

// Get platform stats
app.get('/api/admin/stats', auth, requireRole('admin'), async (req, res) => {
  try {
    const [users, properties, leases, payments] = await Promise.all([
      db.query('SELECT COUNT(*) FROM users'),
      db.query('SELECT COUNT(*) FROM properties'),
      db.query('SELECT COUNT(*), status FROM leases GROUP BY status'),
      db.query('SELECT SUM(total_amount), COUNT(*) FROM payments WHERE status = \'completed\''),
    ]);
    
    res.json({
      totalUsers: parseInt(users.rows[0].count),
      totalProperties: parseInt(properties.rows[0].count),
      leasesByStatus: leases.rows,
      totalRevenue: parseFloat(payments.rows[0].sum) || 0,
      totalPayments: parseInt(payments.rows[0].count),
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// Get audit logs
app.get('/api/admin/audit-logs', auth, requireRole('admin'), async (req, res) => {
  try {
    const { page = 1, limit = 50, userId, action } = req.query;
    const offset = (page - 1) * limit;
    
    let queryStr = `SELECT al.*, u.email FROM audit_logs al
                   JOIN users u ON al.user_id = u.id
                   WHERE 1=1`;
    const params = [];
    
    if (userId) {
      params.push(userId);
      queryStr += ` AND al.user_id = $${params.length}`;
    }
    
    if (action) {
      params.push(action);
      queryStr += ` AND al.action = $${params.length}`;
    }
    
    queryStr += ` ORDER BY al.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);
    
    const result = await db.query(queryStr, params);
    res.json({ logs: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get audit logs' });
  }
});

// ==================== WEBSOCKET ====================

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) {
      return next(new Error('No token'));
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await db.query(
      'SELECT id, email, role FROM users WHERE id = $1',
      [decoded.userId]
    );
    
    if (!result.rows[0]) {
      return next(new Error('User not found'));
    }
    
    socket.user = result.rows[0];
    next();
  } catch (err) {
    next(new Error('Authentication failed'));
  }
});

io.on('connection', (socket) => {
  logger.info('WebSocket connected', { userId: socket.user.id });
  
  socket.join(`user:${socket.user.id}`);
  
  socket.on('join:lease', (leaseId) => {
    socket.join(`lease:${leaseId}`);
  });
  
  socket.on('leave:lease', (leaseId) => {
    socket.leave(`lease:${leaseId}`);
  });
  
  socket.on('disconnect', () => {
    logger.info('WebSocket disconnected', { userId: socket.user.id });
  });
});

// ==================== ERROR HANDLING ====================

app.use((err, req, res, next) => {
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
  });
  
  if (err.name === 'MulterError') {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum size is 10MB.' });
    }
    return res.status(400).json({ error: err.message });
  }
  
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'CORS policy violation' });
  }
  
  res.status(500).json({
    error: NODE_ENV === 'production' ? 'Internal server error' : err.message,
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ==================== LEASE RENEWAL ROUTES ====================

// Initiate lease renewal
app.post('/api/leases/:id/renew', auth, requireRole('landlord', 'admin'), [
  param('id').isUUID(),
  body('newEndDate').isISO8601(),
  body('newRentAmount').optional().isFloat({ min: 0 }),
  body('renewalTerms').optional().isLength({ max: 5000 }),
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    const { newEndDate, newRentAmount, renewalTerms } = req.body;
    
    // Get original lease
    const leaseResult = await db.query(
      `SELECT l.*, p.address, p.county,
              tenant.email as tenant_email, tenant.full_name as tenant_name
       FROM leases l
       JOIN properties p ON l.property_id = p.id
       JOIN users tenant ON l.tenant_id = tenant.id
       WHERE l.id = $1 AND l.landlord_id = $2`,
      [req.params.id, req.user.id]
    );
    
    if (!leaseResult.rows[0]) {
      return res.status(404).json({ error: 'Lease not found' });
    }
    
    const originalLease = leaseResult.rows[0];
    
    if (!['signed', 'active'].includes(originalLease.status)) {
      return res.status(400).json({ error: 'Can only renew signed or active leases' });
    }
    
    const rentAmount = newRentAmount || originalLease.rent_amount;
    const taxInfo = calculateTax(rentAmount, originalLease.county);
    
    // Create renewal lease
    const renewalResult = await db.query(
      `INSERT INTO leases (landlord_id, tenant_id, property_id, start_date, end_date,
       rent_amount, security_deposit, tax_info, terms, special_clauses, status,
       parent_lease_id, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'draft', $11, NOW())
       RETURNING *`,
      [
        req.user.id, originalLease.tenant_id, originalLease.property_id,
        originalLease.end_date, newEndDate, rentAmount,
        originalLease.security_deposit, JSON.stringify(taxInfo),
        sanitizeInput(renewalTerms) || originalLease.terms,
        originalLease.special_clauses, req.params.id
      ]
    );
    
    const renewal = renewalResult.rows[0];
    
    // Notify tenant
    await sendEmail(
      originalLease.tenant_email,
      'Lease Renewal Offer',
      `<p>Your landlord has offered a lease renewal for ${originalLease.address}. The new rent is $${rentAmount}/month. Please log in to review and sign.</p>`,
      `Lease renewal offer for ${originalLease.address}. New rent: $${rentAmount}/month.`
    );
    
    await logAuditEvent(req.user.id, 'CREATE_RENEWAL', 'lease', renewal.id, {
      originalLeaseId: req.params.id,
      newRentAmount: rentAmount,
    });
    
    res.status(201).json(renewal);
  } catch (e) {
    console.error('Renew error:', e);
    res.status(500).json({ error: 'Failed to create renewal document' });
  }
});

// ==================== START SERVER ====================

// ── HandyHub Integration ──────────────────────────────────────────────────────
// Proxy routes that let LeaseSign UI call HandyHub's external API.
// Set HANDYHUB_API_URL and HANDYHUB_API_KEY in .env to enable.

const HANDYHUB_API_URL = process.env.HANDYHUB_API_URL || '';
const HANDYHUB_API_KEY = process.env.HANDYHUB_API_KEY || '';

async function handyhubRequest(path, opts = {}) {
  if (!HANDYHUB_API_URL || !HANDYHUB_API_KEY) {
    throw new Error('HandyHub integration not configured. Set HANDYHUB_API_URL and HANDYHUB_API_KEY in .env');
  }
  return fetch(`${HANDYHUB_API_URL}${path}`, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': HANDYHUB_API_KEY,
      ...(opts.headers || {}),
    },
  });
}

// GET /api/handyhub/services — list available HandyHub services
app.get('/api/handyhub/services', auth, async (req, res) => {
  try {
    const r = await handyhubRequest('/api/external/services');
    const data = await r.json();
    res.status(r.status).json(data);
  } catch (e) {
    res.status(503).json({ error: e.message || 'HandyHub service unavailable' });
  }
});

// POST /api/handyhub/bookings — create a maintenance booking via HandyHub
app.post('/api/handyhub/bookings', auth, async (req, res) => {
  try {
    const r = await handyhubRequest('/api/external/bookings', {
      method: 'POST',
      body: JSON.stringify(req.body),
    });
    const data = await r.json();
    res.status(r.status).json(data);
  } catch (e) {
    res.status(503).json({ error: e.message || 'HandyHub service unavailable' });
  }
});

// GET /api/handyhub/bookings — list bookings (filter by customerEmail or leaseDocumentId)
app.get('/api/handyhub/bookings', auth, async (req, res) => {
  try {
    const params = new URLSearchParams();
    if (req.query.customerEmail) params.set('customerEmail', req.query.customerEmail);
    if (req.query.leaseDocumentId) params.set('leaseDocumentId', req.query.leaseDocumentId);
    const r = await handyhubRequest(`/api/external/bookings?${params}`);
    const data = await r.json();
    res.status(r.status).json(data);
  } catch (e) {
    res.status(503).json({ error: e.message || 'HandyHub service unavailable' });
  }
});

app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   LeaseSign - Texas Residential Lease E-Signature Platform     ║
║                                                                ║
╠════════════════════════════════════════════════════════════════╣
║                                                                ║
║   Server running on port ${PORT}                                  ║
║   Environment: ${NODE_ENV}                                    ║
║   Frontend URL: ${FRONTEND_URL}             ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
  `);
});

module.exports = app;
