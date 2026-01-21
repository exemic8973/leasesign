# LeaseSign - Texas Residential Lease E-Signature Platform

A production-ready DocuSign-style application for Texas residential leases (TAR TXR-2001 form), built with Node.js and React.

![CI](https://github.com/exemic8973/leasesign/workflows/CI/badge.svg)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Node](https://img.shields.io/badge/Node.js-18%2B-green)
![Docker](https://img.shields.io/badge/Docker-Ready-blue)

## Features

### 🔐 Authentication
- User registration and login
- JWT-based session management (7-day expiry)
- Secure password hashing with bcrypt (10 rounds)
- Protected API routes

### 📄 Document Management
- Create, read, update, delete lease documents
- Full TAR TXR-2001 form support with 33+ sections
- Document status tracking: Draft → Pending → Partial → Completed
- Void documents (cancel signing)
- Duplicate documents
- Save and use templates

### ✍️ E-Signature Workflow
1. **Create** - Fill out comprehensive lease details (4-step wizard)
2. **Send** - Initiate signature workflow via email
3. **Landlord Signs** - Unique signing link sent via email
4. **Tenant Signs** - Tenant receives link after landlord signs
5. **Complete** - Both parties notified with completed lease

### 📧 Email Notifications
- Professional HTML email templates
- Signing request notifications
- Reminder emails (resend functionality)
- Completion confirmations to all parties
- Configurable SMTP (Gmail, SendGrid, SES, etc.)
- Development mode: emails logged to console

### 📑 PDF Generation
- Full TAR TXR-2001 format (33 sections)
- Multi-page document with headers/footers
- Embedded signatures with timestamps
- IP address logging for legal compliance
- Electronic signing certificate
- Download completed leases

### 📊 Dashboard & Analytics
- Real-time statistics
- Document counts by status
- Recent activity feed
- Template management

### 🔒 Security & Compliance
- Password hashing (bcrypt)
- JWT authentication with expiration
- Unique signing tokens per party (UUID v4)
- IP address logging for signatures
- User agent tracking
- Complete audit trail
- CORS protection
- ESIGN Act & UETA compliance

## Quick Start

```bash
# Install dependencies
npm install

# Start the server
npm start

# Server runs at http://localhost:3000
```

## Project Structure

```
leasesign-prod/
├── server/
│   └── index.js       # Express API server
├── public/
│   └── index.html     # React frontend (single-file)
├── data/              # JSON database files (auto-created)
├── uploads/           # File uploads (auto-created)
├── generated/         # Generated PDFs (auto-created)
├── package.json
├── .env.example       # Environment config template
└── README.md
```

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Create new account |
| POST | `/api/auth/login` | Login |
| GET | `/api/auth/me` | Get current user |

### Documents
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/documents` | List all documents |
| GET | `/api/documents/:id` | Get single document |
| POST | `/api/documents` | Create document |
| PUT | `/api/documents/:id` | Update document |
| DELETE | `/api/documents/:id` | Delete document |
| POST | `/api/documents/:id/send` | Send for signature |
| GET | `/api/documents/:id/pdf` | Download PDF |
| GET | `/api/documents/:id/audit` | Get audit log |

### Signing (Public)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/sign/:token` | Get document for signing |
| POST | `/api/sign/:token` | Submit signature |

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
# Required
PORT=3000
APP_URL=https://yourdomain.com
JWT_SECRET=your-secret-key

# Email (optional but recommended)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
SMTP_FROM="LeaseSign" <noreply@yourdomain.com>
```

## Production Deployment

### Option 1: Docker

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

### Option 2: Railway/Render/Fly.io

1. Connect your GitHub repository
2. Set environment variables
3. Deploy automatically

### Option 3: Traditional VPS

```bash
# Install Node.js 18+
# Clone repository
git clone https://github.com/yourusername/leasesign.git
cd leasesign

# Install dependencies
npm ci --only=production

# Set up environment
cp .env.example .env
nano .env  # Edit configuration

# Run with PM2
npm install -g pm2
pm2 start server/index.js --name leasesign
pm2 save
pm2 startup
```

### Nginx Configuration

```nginx
server {
    listen 80;
    server_name leasesign.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name leasesign.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/leasesign.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/leasesign.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## Production Checklist

- [ ] Set strong `JWT_SECRET`
- [ ] Configure SMTP for emails
- [ ] Set up SSL/TLS (Let's Encrypt)
- [ ] Configure reverse proxy (Nginx)
- [ ] Set up database backups
- [ ] Enable rate limiting
- [ ] Add monitoring (PM2, New Relic, etc.)
- [ ] Review security headers

## Database Migration

The current implementation uses JSON file storage for simplicity. For production with higher volume:

### PostgreSQL Migration

```javascript
// Replace Database class with:
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
```

### MongoDB Migration

```javascript
// Replace Database class with:
const { MongoClient } = require('mongodb');
const client = new MongoClient(process.env.MONGODB_URI);
```

## Security Features

- Password hashing (bcrypt, 10 rounds)
- JWT authentication with expiration
- IP address logging for signatures
- User agent tracking
- CORS protection
- Input validation
- SQL injection prevention (parameterized queries)

## Legal Compliance

This application follows Texas Property Code requirements:
- Electronic signature compliance (ESIGN Act, UETA)
- Signature timestamp and IP logging
- Full audit trail
- Document integrity verification

## License

MIT License - Use freely for commercial purposes.

## Support

For issues or feature requests, please open a GitHub issue.
