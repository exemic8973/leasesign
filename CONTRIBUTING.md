# Contributing to LeaseSign

Thank you for your interest in contributing to LeaseSign! This document provides guidelines and instructions for contributing.

## 🚀 Quick Start

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/YOUR_USERNAME/leasesign.git`
3. **Install** dependencies: `npm install`
4. **Copy** environment file: `cp .env.example .env`
5. **Start** development server: `npm start`
6. **Open** http://localhost:3000

## 📁 Project Structure

```
leasesign/
├── server/
│   └── index.js        # Express API (all backend code)
├── public/
│   └── index.html      # React frontend (single-file app)
├── data/               # JSON database files (gitignored)
├── uploads/            # User uploads (gitignored)
├── generated/          # Generated PDFs (gitignored)
└── .github/workflows/  # CI/CD pipelines
```

## 🔧 Development Guidelines

### Code Style

- Use ES6+ JavaScript features
- Use `const` and `let`, never `var`
- Use async/await for asynchronous code
- Use meaningful variable and function names
- Add comments for complex logic

### Backend (server/index.js)

- All API routes should follow RESTful conventions
- Use the `auth` middleware for protected routes
- Always log audit events for document changes
- Return consistent JSON error responses: `{ error: "message" }`

### Frontend (public/index.html)

- Use React functional components with hooks
- Keep components small and focused
- Use the existing CSS variables for styling
- Follow the existing UI patterns

## 🧪 Testing Changes

Before submitting a PR, ensure:

1. **Server starts** without errors:
   ```bash
   node --check server/index.js
   npm start
   ```

2. **Health check** passes:
   ```bash
   curl http://localhost:3000/api/health
   ```

3. **Basic flow** works:
   - Register a new user
   - Create a lease document
   - Send for signature
   - Complete signing flow (use console for email links)

## 📝 Commit Messages

Follow conventional commits:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code refactoring
- `test:` Adding or updating tests
- `chore:` Maintenance tasks

Examples:
```
feat: add bulk document export
fix: signature pad not working on mobile
docs: update API documentation
```

## 🔀 Pull Request Process

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and commit them

3. **Push** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

4. **Open a Pull Request** with:
   - Clear title describing the change
   - Description of what was changed and why
   - Screenshots for UI changes
   - Link to related issues

5. **Wait for review** - maintainers will review and provide feedback

## 🐛 Reporting Bugs

When reporting bugs, include:

- Steps to reproduce
- Expected behavior
- Actual behavior
- Screenshots if applicable
- Browser/Node.js version
- Operating system

## 💡 Feature Requests

For feature requests, please include:

- Clear description of the feature
- Use case / why it's needed
- Mockups or examples if applicable

## 📋 Areas for Contribution

Looking to contribute? Here are some areas that need help:

### High Priority
- [ ] Add unit tests with Jest
- [ ] Add PostgreSQL database support
- [ ] Implement rate limiting
- [ ] Add input validation with express-validator

### Medium Priority
- [ ] Add document search/filter
- [ ] Implement document editing after creation
- [ ] Add multiple tenant support per lease
- [ ] Create mobile-responsive improvements

### Nice to Have
- [ ] Add dark mode
- [ ] Implement document templates marketplace
- [ ] Add webhook notifications
- [ ] Create Zapier/Make integration

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## ❓ Questions?

If you have questions, feel free to:
- Open an issue with the `question` label
- Start a discussion in the Discussions tab

Thank you for contributing! 🎉
