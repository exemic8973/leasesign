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

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'leasesign-secret-key-change-in-production-' + crypto.randomBytes(16).toString('hex');
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

// Data storage paths
const DATA_DIR = path.join(__dirname, '../data');
const UPLOADS_DIR = path.join(__dirname, '../uploads');
const GENERATED_DIR = path.join(__dirname, '../generated');

// Ensure directories exist
[DATA_DIR, UPLOADS_DIR, GENERATED_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Simple JSON-based database (replace with PostgreSQL/MongoDB in production)
class Database {
  constructor(filename) {
    this.filepath = path.join(DATA_DIR, filename);
    this.data = this.load();
  }
  
  load() {
    try {
      if (fs.existsSync(this.filepath)) {
        return JSON.parse(fs.readFileSync(this.filepath, 'utf8'));
      }
    } catch (e) { console.error('DB load error:', e); }
    return [];
  }
  
  save() {
    fs.writeFileSync(this.filepath, JSON.stringify(this.data, null, 2));
  }
  
  findAll(filter = {}) {
    return this.data.filter(item => {
      return Object.entries(filter).every(([key, val]) => item[key] === val);
    });
  }
  
  findOne(filter = {}) {
    return this.data.find(item => {
      return Object.entries(filter).every(([key, val]) => item[key] === val);
    });
  }
  
  findById(id) {
    return this.data.find(item => item.id === id);
  }
  
  insert(item) {
    const newItem = { ...item, id: item.id || uuidv4(), createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
    this.data.push(newItem);
    this.save();
    return newItem;
  }
  
  update(id, updates) {
    const index = this.data.findIndex(item => item.id === id);
    if (index === -1) return null;
    this.data[index] = { ...this.data[index], ...updates, updatedAt: new Date().toISOString() };
    this.save();
    return this.data[index];
  }
  
  delete(id) {
    const index = this.data.findIndex(item => item.id === id);
    if (index === -1) return false;
    this.data.splice(index, 1);
    this.save();
    return true;
  }
}

// Initialize databases
const usersDB = new Database('users.json');
const documentsDB = new Database('documents.json');
const auditDB = new Database('audit.json');
const notificationsDB = new Database('notifications.json');

// Link expiration time (7 days in milliseconds)
const LINK_EXPIRATION_MS = 7 * 24 * 60 * 60 * 1000;

// Helper to create notification
const createNotification = (userId, type, title, message, documentId = null) => {
  notificationsDB.insert({
    userId,
    type,
    title,
    message,
    documentId,
    read: false,
    timestamp: new Date().toISOString()
  });
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
    console.log('📧 CUSTOM SMTP CONFIGURED');
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
      console.log('✅ SMTP connection verified successfully!\n');
    } catch (err) {
      console.error('❌ SMTP connection failed:', err.message);
      console.log('⚠️  Emails may not be delivered. Check your SMTP settings.\n');
    }

    // Wrap sendMail to log sent emails
    const originalSendMail = transporter.sendMail.bind(transporter);
    transporter.sendMail = async (opts) => {
      try {
        const info = await originalSendMail(opts);
        console.log('\n' + '='.repeat(60));
        console.log('📧 EMAIL SENT SUCCESSFULLY');
        console.log('='.repeat(60));
        console.log(`To: ${opts.to}`);
        console.log(`Subject: ${opts.subject}`);
        console.log(`Message ID: ${info.messageId}`);
        console.log('='.repeat(60) + '\n');
        return info;
      } catch (err) {
        console.error('\n' + '='.repeat(60));
        console.error('❌ EMAIL FAILED TO SEND');
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
  console.log('📧 No SMTP configured. Creating Ethereal test email account...');
  const testAccount = await nodemailer.createTestAccount();
  console.log('='.repeat(60));
  console.log('📧 ETHEREAL TEST EMAIL CONFIGURED');
  console.log('='.repeat(60));
  console.log(`View sent emails at: https://ethereal.email`);
  console.log(`Login: ${testAccount.user}`);
  console.log(`Password: ${testAccount.pass}`);
  console.log('='.repeat(60));
  console.log('💡 To use your own SMTP, create a .env file with:');
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
    console.log('📧 EMAIL SENT (Ethereal)');
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

// Auth middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = usersDB.findById(decoded.id);
    if (!req.user) return res.status(401).json({ error: 'User not found' });
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Audit logging
const logAudit = (documentId, action, actor, req, details = null) => {
  auditDB.insert({
    documentId,
    action,
    actor,
    ip: req.ip || req.connection?.remoteAddress || 'unknown',
    userAgent: req.headers['user-agent'],
    details,
    timestamp: new Date().toISOString()
  });
};

// ==================== AUTH ROUTES ====================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, company, phone } = req.body;
    
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
    }
    
    if (usersDB.findOne({ email })) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = usersDB.insert({
      email,
      password: hashedPassword,
      name,
      company: company || '',
      phone: phone || ''
    });
    
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
    
    const user = usersDB.findOne({ email });
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

// ==================== DOCUMENT ROUTES ====================

app.get('/api/documents', auth, (req, res) => {
  const docs = documentsDB.findAll({ userId: req.user.id })
    .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
  res.json(docs);
});

app.get('/api/documents/:id', auth, (req, res) => {
  const doc = documentsDB.findById(req.params.id);
  if (!doc || doc.userId !== req.user.id) {
    return res.status(404).json({ error: 'Document not found' });
  }
  res.json(doc);
});

app.post('/api/documents', auth, (req, res) => {
  try {
    const doc = documentsDB.insert({
      userId: req.user.id,
      status: 'draft',
      landlordSignToken: uuidv4(),
      tenantSignToken: uuidv4(),
      ...req.body
    });
    
    logAudit(doc.id, 'DOCUMENT_CREATED', req.user.email, req);
    res.json(doc);
  } catch (e) {
    console.error('Create error:', e);
    res.status(500).json({ error: 'Failed to create document' });
  }
});

app.put('/api/documents/:id', auth, (req, res) => {
  const doc = documentsDB.findById(req.params.id);
  if (!doc || doc.userId !== req.user.id) {
    return res.status(404).json({ error: 'Document not found' });
  }
  
  if (doc.status === 'completed') {
    return res.status(400).json({ error: 'Cannot modify completed document' });
  }
  
  const updated = documentsDB.update(req.params.id, req.body);
  logAudit(doc.id, 'DOCUMENT_UPDATED', req.user.email, req);
  res.json(updated);
});

app.delete('/api/documents/:id', auth, (req, res) => {
  const doc = documentsDB.findById(req.params.id);
  if (!doc || doc.userId !== req.user.id) {
    return res.status(404).json({ error: 'Document not found' });
  }
  
  documentsDB.delete(req.params.id);
  res.json({ success: true });
});

// ==================== SIGNATURE WORKFLOW ====================

app.post('/api/documents/:id/send', auth, async (req, res) => {
  try {
    const doc = documentsDB.findById(req.params.id);
    if (!doc || doc.userId !== req.user.id) {
      return res.status(404).json({ error: 'Document not found' });
    }

    // Set link expiration (7 days from now)
    const linkExpiresAt = new Date(Date.now() + LINK_EXPIRATION_MS).toISOString();

    // Update status and expiration
    const updated = documentsDB.update(req.params.id, { status: 'pending', linkExpiresAt });

    // Send email to landlord
    const signUrl = `${APP_URL}/sign/${doc.landlordSignToken}`;
    await mailer.sendMail({
      from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
      to: doc.landlordEmail,
      subject: `[Action Required] Sign Lease for ${doc.propertyAddress}`,
      text: `Please sign the lease agreement: ${signUrl}`,
      html: generateSignEmail(updated, 'landlord', signUrl)
    });

    logAudit(doc.id, 'SENT_FOR_SIGNATURE', req.user.email, req, { to: doc.landlordEmail });
    createNotification(req.user.id, 'sent', 'Document Sent', `Lease for ${doc.propertyAddress} sent to ${doc.landlordEmail}`, doc.id);
    res.json(updated);
  } catch (e) {
    console.error('Send error:', e);
    res.status(500).json({ error: 'Failed to send document' });
  }
});

// Public signing endpoint - get document
app.get('/api/sign/:token', (req, res) => {
  const doc = documentsDB.findOne({ landlordSignToken: req.params.token }) ||
              documentsDB.findOne({ tenantSignToken: req.params.token });

  if (!doc) return res.status(404).json({ error: 'Document not found or link expired' });

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

    const doc = documentsDB.findOne({ landlordSignToken: req.params.token }) ||
                documentsDB.findOne({ tenantSignToken: req.params.token });

    if (!doc) return res.status(404).json({ error: 'Document not found' });

    // Check if link has expired
    if (doc.linkExpiresAt && new Date(doc.linkExpiresAt) < new Date()) {
      return res.status(410).json({ error: 'This signing link has expired. Please contact the sender to request a new link.', expired: true });
    }

    const signerType = doc.landlordSignToken === req.params.token ? 'landlord' : 'tenant';
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    const now = new Date().toISOString();

    let updates = {};

    if (signerType === 'landlord') {
      // Reset expiration for tenant (7 more days)
      const newExpiration = new Date(Date.now() + LINK_EXPIRATION_MS).toISOString();
      updates = {
        landlordSignature: signature,
        landlordSignedAt: now,
        landlordSignedIp: ip,
        linkExpiresAt: newExpiration,
        status: doc.tenantSignedAt ? 'completed' : 'partial'
      };
      logAudit(doc.id, 'LANDLORD_SIGNED', doc.landlordEmail, req);

      // Send email to tenant
      const tenantSignUrl = `${APP_URL}/sign/${doc.tenantSignToken}`;
      const updatedDoc = { ...doc, linkExpiresAt: newExpiration };
      await mailer.sendMail({
        from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
        to: doc.tenantEmail,
        subject: `[Action Required] Sign Lease for ${doc.propertyAddress}`,
        text: `Please sign the lease agreement: ${tenantSignUrl}`,
        html: generateSignEmail(updatedDoc, 'tenant', tenantSignUrl)
      });

      // Notify document owner
      createNotification(doc.userId, 'signed', 'Landlord Signed', `${doc.landlordName} signed the lease for ${doc.propertyAddress}`, doc.id);
    } else {
      updates = {
        tenantSignature: signature,
        tenantSignedAt: now,
        tenantSignedIp: ip,
        status: doc.landlordSignedAt ? 'completed' : 'partial'
      };
      logAudit(doc.id, 'TENANT_SIGNED', doc.tenantEmail, req);

      // Notify document owner
      createNotification(doc.userId, 'signed', 'Tenant Signed', `${doc.tenantName} signed the lease for ${doc.propertyAddress}`, doc.id);
    }

    const updated = documentsDB.update(doc.id, updates);

    // If completed, send completion emails and notify
    if (updated.status === 'completed') {
      await sendCompletionEmails(updated);
      createNotification(doc.userId, 'completed', 'Lease Completed', `The lease for ${doc.propertyAddress} has been fully executed!`, doc.id);
    }

    res.json({ success: true, status: updated.status });
  } catch (e) {
    console.error('Sign error:', e);
    res.status(500).json({ error: 'Signing failed' });
  }
});

// ==================== PDF GENERATION ====================

app.get('/api/documents/:id/pdf', auth, (req, res) => {
  const doc = documentsDB.findById(req.params.id);
  if (!doc || doc.userId !== req.user.id) {
    return res.status(404).json({ error: 'Document not found' });
  }
  
  generatePDF(doc, res);
});

function generatePDF(doc, res) {
  const pdf = new PDFDocument({ size: 'LETTER', margins: { top: 50, bottom: 50, left: 60, right: 60 } });
  
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="Lease_${(doc.propertyAddress || 'document').replace(/[^a-zA-Z0-9]/g, '_')}.pdf"`);
  
  pdf.pipe(res);
  
  // Helper functions
  const field = (val) => val || '________________________';
  const money = (val) => val ? `$${parseFloat(val).toLocaleString('en-US', { minimumFractionDigits: 2 })}` : '$____________';
  const checkbox = (checked) => checked ? '☑' : '☐';
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
  pdf.font('Helvetica').fontSize(8).text('USE OF THIS FORM BY PERSONS WHO ARE NOT MEMBERS OF THE TEXAS ASSOCIATION OF REALTORS® IS NOT AUTHORIZED.', { align: 'center' });
  pdf.text('©Texas Association of REALTORS®, Inc. 2022', { align: 'center' });
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
  pdf.text('Per Texas Property Code §92.153. Rekeying costs paid by: ' + (doc.rekeyPaidByLandlord ? 'Landlord' : 'Tenant'));
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
  pdf.text('Per Texas Property Code §54.021. Certain items exempt.');
  pdf.moveDown();
  
  sectionTitle('24', 'SUBORDINATION');
  pdf.text('This lease subordinate to existing or future mortgages and liens.');
  pdf.moveDown();
  
  sectionTitle('25', 'CASUALTY LOSS');
  pdf.text('Per Texas Property Code §92.054 if Property becomes unfit.');
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
    doc.addendumFlood ? '☑ Flood Disclosure' : '☐ Flood Disclosure',
    doc.addendumLeadPaint ? '☑ Lead-Based Paint' : '☐ Lead-Based Paint',
    doc.addendumInventory ? '☑ Inventory Form' : '☐ Inventory Form',
    doc.addendumPets ? '☑ Pet Agreement' : '☐ Pet Agreement',
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
        <h1 style="color: white; margin: 0; font-size: 28px;">📝 LeaseSign</h1>
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
          <span style="color: #92400e; font-size: 14px;">⏰ This link expires on <strong>${expiresDate}</strong></span>
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
        <h1 style="color: white; margin: 0; font-size: 28px;">✅ Lease Signed Successfully!</h1>
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
      subject: `✅ Lease Completed: ${doc.propertyAddress}`,
      html
    }),
    mailer.sendMail({
      from: process.env.SMTP_FROM || '"LeaseSign" <noreply@leasesign.com>',
      to: doc.tenantEmail,
      subject: `✅ Lease Completed: ${doc.propertyAddress}`,
      html
    })
  ]);
}

// ==================== AUDIT LOG ====================

app.get('/api/documents/:id/audit', auth, (req, res) => {
  const doc = documentsDB.findById(req.params.id);
  if (!doc || doc.userId !== req.user.id) {
    return res.status(404).json({ error: 'Document not found' });
  }
  
  const logs = auditDB.findAll({ documentId: req.params.id })
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  res.json(logs);
});

// ==================== HEALTH & STATS ====================

// Health check endpoint for monitoring
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: '1.0.0'
  });
});

// Get statistics
app.get('/api/stats', auth, (req, res) => {
  const userDocs = documentsDB.findAll({ userId: req.user.id });
  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  
  res.json({
    total: userDocs.length,
    draft: userDocs.filter(d => d.status === 'draft').length,
    pending: userDocs.filter(d => d.status === 'pending').length,
    partial: userDocs.filter(d => d.status === 'partial').length,
    completed: userDocs.filter(d => d.status === 'completed').length,
    voided: userDocs.filter(d => d.status === 'voided').length,
    last30Days: userDocs.filter(d => new Date(d.createdAt) >= thirtyDaysAgo).length,
    completedLast30Days: userDocs.filter(d => d.status === 'completed' && new Date(d.updatedAt) >= thirtyDaysAgo).length
  });
});

// ==================== DOCUMENT ACTIONS ====================

// Resend signature request
app.post('/api/documents/:id/resend', auth, async (req, res) => {
  try {
    const doc = documentsDB.findById(req.params.id);
    if (!doc || doc.userId !== req.user.id) {
      return res.status(404).json({ error: 'Document not found' });
    }
    
    if (doc.status === 'completed' || doc.status === 'voided') {
      return res.status(400).json({ error: 'Cannot resend completed or voided document' });
    }
    
    // Determine who needs to sign
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
    
    logAudit(doc.id, 'SIGNATURE_REMINDER_SENT', req.user.email, req, { to: recipient });
    res.json({ success: true, sentTo: recipient });
  } catch (e) {
    console.error('Resend error:', e);
    res.status(500).json({ error: 'Failed to resend' });
  }
});

// Duplicate document (create from template)
app.post('/api/documents/:id/duplicate', auth, (req, res) => {
  try {
    const original = documentsDB.findById(req.params.id);
    if (!original || original.userId !== req.user.id) {
      return res.status(404).json({ error: 'Document not found' });
    }
    
    // Copy document without signatures and with new tokens
    const newDoc = documentsDB.insert({
      ...original,
      id: undefined, // Will be generated
      title: `Copy of ${original.title || 'Lease'}`,
      status: 'draft',
      landlordSignToken: uuidv4(),
      tenantSignToken: uuidv4(),
      landlordSignature: null,
      landlordSignedAt: null,
      landlordSignedIp: null,
      tenantSignature: null,
      tenantSignedAt: null,
      tenantSignedIp: null,
      createdAt: undefined,
      updatedAt: undefined
    });
    
    logAudit(newDoc.id, 'DOCUMENT_DUPLICATED', req.user.email, req, { fromId: original.id });
    res.json(newDoc);
  } catch (e) {
    console.error('Duplicate error:', e);
    res.status(500).json({ error: 'Failed to duplicate document' });
  }
});

// Void/cancel document
app.post('/api/documents/:id/void', auth, (req, res) => {
  try {
    const doc = documentsDB.findById(req.params.id);
    if (!doc || doc.userId !== req.user.id) {
      return res.status(404).json({ error: 'Document not found' });
    }
    
    if (doc.status === 'completed') {
      return res.status(400).json({ error: 'Cannot void completed document' });
    }
    
    const updated = documentsDB.update(req.params.id, {
      status: 'voided',
      voidedAt: new Date().toISOString(),
      voidReason: req.body.reason || 'Voided by user'
    });
    
    logAudit(doc.id, 'DOCUMENT_VOIDED', req.user.email, req, { reason: req.body.reason });
    res.json(updated);
  } catch (e) {
    console.error('Void error:', e);
    res.status(500).json({ error: 'Failed to void document' });
  }
});

// ==================== TEMPLATES ====================

// Save as template
app.post('/api/templates', auth, (req, res) => {
  try {
    const { documentId, name } = req.body;
    
    let templateData = req.body;
    
    // If duplicating from existing document
    if (documentId) {
      const doc = documentsDB.findById(documentId);
      if (!doc || doc.userId !== req.user.id) {
        return res.status(404).json({ error: 'Document not found' });
      }
      templateData = { ...doc };
    }
    
    // Create template (stored as special document)
    const template = documentsDB.insert({
      ...templateData,
      id: undefined,
      isTemplate: true,
      templateName: name || 'Untitled Template',
      userId: req.user.id,
      status: 'template',
      // Clear party-specific info
      tenantName: '',
      tenantEmail: '',
      tenantPhone: '',
      landlordSignature: null,
      tenantSignature: null
    });
    
    res.json(template);
  } catch (e) {
    console.error('Template error:', e);
    res.status(500).json({ error: 'Failed to save template' });
  }
});

// List templates
app.get('/api/templates', auth, (req, res) => {
  const templates = documentsDB.findAll({ userId: req.user.id, isTemplate: true });
  res.json(templates);
});

// Create from template
app.post('/api/templates/:id/use', auth, (req, res) => {
  try {
    const template = documentsDB.findById(req.params.id);
    if (!template || template.userId !== req.user.id || !template.isTemplate) {
      return res.status(404).json({ error: 'Template not found' });
    }
    
    // Create new document from template
    const newDoc = documentsDB.insert({
      ...template,
      ...req.body, // Override with provided data
      id: undefined,
      isTemplate: false,
      templateName: undefined,
      status: 'draft',
      landlordSignToken: uuidv4(),
      tenantSignToken: uuidv4(),
      createdAt: undefined,
      updatedAt: undefined
    });
    
    logAudit(newDoc.id, 'DOCUMENT_CREATED_FROM_TEMPLATE', req.user.email, req, { templateId: template.id });
    res.json(newDoc);
  } catch (e) {
    console.error('Use template error:', e);
    res.status(500).json({ error: 'Failed to create from template' });
  }
});

// ==================== BULK OPERATIONS ====================

// Send bulk reminders
app.post('/api/documents/bulk-remind', auth, async (req, res) => {
  try {
    const { documentIds } = req.body;
    if (!documentIds || !Array.isArray(documentIds)) {
      return res.status(400).json({ error: 'Document IDs required' });
    }
    
    const results = [];
    for (const id of documentIds) {
      const doc = documentsDB.findById(id);
      if (!doc || doc.userId !== req.user.id) continue;
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
        logAudit(doc.id, 'BULK_REMINDER_SENT', req.user.email, req, { to: recipient });
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

// Reminder email template
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
        <h1 style="color: white; margin: 0; font-size: 28px;">⏰ Reminder</h1>
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

// Regenerate expired signing link
app.post('/api/documents/:id/regenerate-link', auth, async (req, res) => {
  try {
    const doc = documentsDB.findById(req.params.id);
    if (!doc || doc.userId !== req.user.id) {
      return res.status(404).json({ error: 'Document not found' });
    }

    if (doc.status === 'completed' || doc.status === 'voided' || doc.status === 'draft') {
      return res.status(400).json({ error: 'Cannot regenerate link for this document status' });
    }

    // Generate new expiration (7 days)
    const linkExpiresAt = new Date(Date.now() + LINK_EXPIRATION_MS).toISOString();
    const updated = documentsDB.update(req.params.id, { linkExpiresAt });

    // Send new email to the pending signer
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

    logAudit(doc.id, 'LINK_REGENERATED', req.user.email, req, { to: recipient });
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
      const doc = documentsDB.findById(id);
      if (!doc || doc.userId !== req.user.id) {
        results.push({ id, success: false, error: 'Not found' });
        continue;
      }
      if (doc.status !== 'draft') {
        results.push({ id, success: false, error: 'Can only delete drafts' });
        continue;
      }

      documentsDB.delete(id);
      results.push({ id, success: true });
    }

    res.json({ results, deletedCount: results.filter(r => r.success).length });
  } catch (e) {
    console.error('Bulk delete error:', e);
    res.status(500).json({ error: 'Failed to delete documents' });
  }
});

// ==================== NOTIFICATIONS ====================

// Get notifications
app.get('/api/notifications', auth, (req, res) => {
  const notifications = notificationsDB.findAll({ userId: req.user.id })
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 50); // Return last 50

  const unreadCount = notifications.filter(n => !n.read).length;
  res.json({ notifications, unreadCount });
});

// Mark notification as read
app.patch('/api/notifications/:id/read', auth, (req, res) => {
  const notification = notificationsDB.findById(req.params.id);
  if (!notification || notification.userId !== req.user.id) {
    return res.status(404).json({ error: 'Notification not found' });
  }

  const updated = notificationsDB.update(req.params.id, { read: true });
  res.json(updated);
});

// Mark all notifications as read
app.post('/api/notifications/mark-all-read', auth, (req, res) => {
  const notifications = notificationsDB.findAll({ userId: req.user.id, read: false });
  notifications.forEach(n => notificationsDB.update(n.id, { read: true }));
  res.json({ success: true, updated: notifications.length });
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
║   🏠 LeaseSign - Texas Residential Lease E-Signature Platform  ║
║                                                                ║
║   Server running at: http://localhost:${PORT}                    ║
║                                                                ║
║   API Endpoints:                                               ║
║   ─────────────────────────────────────────────────────────    ║
║   Auth:                                                        ║
║     POST /api/auth/register      - Create account              ║
║     POST /api/auth/login         - Login                       ║
║     GET  /api/auth/me            - Get current user            ║
║                                                                ║
║   Documents:                                                   ║
║     GET  /api/documents          - List documents              ║
║     POST /api/documents          - Create document             ║
║     GET  /api/documents/:id      - Get document                ║
║     PUT  /api/documents/:id      - Update document             ║
║     DELETE /api/documents/:id    - Delete document             ║
║                                                                ║
║   Workflow:                                                    ║
║     POST /api/documents/:id/send - Send for signature          ║
║     POST /api/documents/:id/resend - Resend reminder           ║
║     POST /api/documents/:id/void - Void document               ║
║     POST /api/documents/:id/duplicate - Duplicate              ║
║     GET  /api/documents/:id/pdf  - Download PDF                ║
║     GET  /api/documents/:id/audit - Audit log                  ║
║                                                                ║
║   Signing (Public):                                            ║
║     GET  /api/sign/:token        - Get doc for signing         ║
║     POST /api/sign/:token        - Submit signature            ║
║                                                                ║
║   Templates:                                                   ║
║     GET  /api/templates          - List templates              ║
║     POST /api/templates          - Save template               ║
║     POST /api/templates/:id/use  - Create from template        ║
║                                                                ║
║   Other:                                                       ║
║     GET  /api/health             - Health check                ║
║     GET  /api/stats              - Get statistics              ║
║     POST /api/documents/bulk-remind - Bulk reminders           ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
  `);
});

module.exports = app;
