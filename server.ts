import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import os from 'os';
import crypto from 'crypto';

import {
  INITIAL_COMPANIES,
  INITIAL_PROJECTS,
  INITIAL_WORKERS,
  INITIAL_ATTENDANCE,
  INITIAL_DAILY_WORK,
  INITIAL_EXPENSES,
  INITIAL_INCOME,
  INITIAL_SALARIES,
  INITIAL_USERS,
  INITIAL_AUDIT_LOGS,
  INITIAL_SETTINGS,
  INITIAL_ITEM_MASTER,
  INITIAL_TEMPLATES,
  INITIAL_FORMULA_SETTINGS,
  INITIAL_IDM_RECORDS,
  INITIAL_MEASUREMENT_BILLS,
} from './src/lib/initialData';

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

app.use(express.json({ limit: '15mb' }));

// Persistent database path with writable fallback for read-only production containers
function resolveWritableDataDir(): string {
  const candidates = [
    path.join(process.cwd(), 'data'),
    path.join(os.tmpdir(), 'sr-group-erp-data'),
  ];
  for (const dir of candidates) {
    try {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.accessSync(dir, fs.constants.W_OK);
      return dir;
    } catch {
      // Try next candidate
    }
  }
  return os.tmpdir();
}

const DATA_DIR = resolveWritableDataDir();
const DB_FILE = path.join(DATA_DIR, 'db.json');

interface DatabaseSchema {
  companies: any[];
  projects: any[];
  workers: any[];
  attendance: any[];
  daily_work: any[];
  expenses: any[];
  income: any[];
  salaries: any[];
  users: any[];
  audit_logs: any[];
  settings: any;
  measurement_bills: any[];
  idm_records: any[];
  item_master: any[];
  measurement_templates: any[];
  formula_settings: any[];
}

const defaultSeedData: DatabaseSchema = {
  companies: INITIAL_COMPANIES,
  projects: INITIAL_PROJECTS,
  workers: INITIAL_WORKERS,
  attendance: INITIAL_ATTENDANCE,
  daily_work: INITIAL_DAILY_WORK,
  expenses: INITIAL_EXPENSES,
  income: INITIAL_INCOME,
  salaries: INITIAL_SALARIES,
  users: INITIAL_USERS,
  audit_logs: INITIAL_AUDIT_LOGS,
  settings: INITIAL_SETTINGS,
  measurement_bills: INITIAL_MEASUREMENT_BILLS,
  idm_records: INITIAL_IDM_RECORDS,
  item_master: INITIAL_ITEM_MASTER,
  measurement_templates: INITIAL_TEMPLATES,
  formula_settings: INITIAL_FORMULA_SETTINGS,
};

// Helper to read DB safely and backfill any missing collections
function readDb(): DatabaseSchema {
  try {
    if (fs.existsSync(DB_FILE)) {
      const data = fs.readFileSync(DB_FILE, 'utf-8');
      const parsed = JSON.parse(data);
      if (parsed.companies && parsed.companies.length > 0) {
        let changed = false;
        // Backfill new tables if they don't exist yet
        if (!parsed.measurement_bills) {
          parsed.measurement_bills = INITIAL_MEASUREMENT_BILLS;
          changed = true;
        }
        if (!parsed.idm_records) {
          parsed.idm_records = INITIAL_IDM_RECORDS;
          changed = true;
        }
        if (!parsed.item_master) {
          parsed.item_master = INITIAL_ITEM_MASTER;
          changed = true;
        }
        if (!parsed.measurement_templates) {
          parsed.measurement_templates = INITIAL_TEMPLATES;
          changed = true;
        }
        if (!parsed.formula_settings) {
          parsed.formula_settings = INITIAL_FORMULA_SETTINGS;
          changed = true;
        }
        if (changed) {
          writeDb(parsed);
        }
        return parsed;
      }
    }
  } catch (err) {
    console.error('Error reading db.json, falling back to seed state:', err);
  }
  writeDb(defaultSeedData);
  return defaultSeedData;
}

// Helper to write DB atomically
function writeDb(data: DatabaseSchema): void {
  try {
    const tempFile = `${DB_FILE}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(data, null, 2), 'utf-8');
    fs.renameSync(tempFile, DB_FILE);
  } catch (err) {
    console.error('Error writing db.json:', err);
  }
}

// User specific data storage directory: data/users/
const USERS_DIR = path.join(DATA_DIR, 'users');
if (!fs.existsSync(USERS_DIR)) {
  fs.mkdirSync(USERS_DIR, { recursive: true });
}

const AUTH_ACCOUNTS_FILE = path.join(DATA_DIR, 'auth_accounts.json');

interface StoredAuthAccount {
  id: string;
  name: string;
  email: string;
  role: string;
  provider: 'password' | 'google';
  passwordHash: string;
  securityQuestion?: string;
  recoveryHash?: string;
  createdAt: string;
  updatedAt?: string;
}

interface AuthTokenPayload {
  id: string;
  email: string;
  name: string;
  role: string;
  exp: number;
}

interface AuthenticatedRequest extends Request {
  authUser?: AuthTokenPayload;
}

const VALID_ROLES = new Set(['ADMIN', 'MANAGER', 'SUPERVISOR', 'ACCOUNTANT', 'VIEWER']);

function normalizeEmail(email: unknown): string {
  return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(password: string, storedHash: string): boolean {
  if (!storedHash || !storedHash.includes(':')) return false;
  const [salt, expectedHex] = storedHash.split(':');
  if (!salt || !expectedHex) return false;
  try {
    const derived = crypto.scryptSync(password, salt, 64);
    const expected = Buffer.from(expectedHex, 'hex');
    if (derived.length !== expected.length) return false;
    return crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

function signAuthToken(user: { id: string; email: string; name: string; role: string }): string {
  const payload: AuthTokenPayload = {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf-8').toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
  return `${encoded}.${sig}`;
}

function verifyAuthToken(token: string): AuthTokenPayload | null {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [encoded, sig] = parts;
  if (!encoded || !sig) return null;

  try {
    const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
    const sigBuf = Buffer.from(sig, 'utf-8');
    const expectedBuf = Buffer.from(expectedSig, 'utf-8');
    if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
      return null;
    }
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf-8')) as AuthTokenPayload;
    if (!payload || !payload.email || !payload.exp || payload.exp < Date.now()) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

function readAuthAccounts(): StoredAuthAccount[] {
  try {
    if (fs.existsSync(AUTH_ACCOUNTS_FILE)) {
      const raw = fs.readFileSync(AUTH_ACCOUNTS_FILE, 'utf-8');
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed;
    }
  } catch (err) {
    console.error('Error reading auth_accounts.json:', err);
  }
  return [];
}

function writeAuthAccounts(accounts: StoredAuthAccount[]): void {
  try {
    const tempFile = `${AUTH_ACCOUNTS_FILE}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(accounts, null, 2), 'utf-8');
    fs.renameSync(tempFile, AUTH_ACCOUNTS_FILE);
  } catch (err) {
    console.error('Error writing auth_accounts.json:', err);
  }
}

function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required. Please sign in.' });
  }
  const token = authHeader.slice('Bearer '.length).trim();
  const payload = verifyAuthToken(token);
  if (!payload) {
    return res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
  }
  req.authUser = payload;
  next();
}

function getUserDbPath(email: string): string {
  const safeEmail = email.toLowerCase().trim().replace(/[^a-z0-9_.-]/g, '_');
  if (!safeEmail) {
    throw new Error('Invalid email for user storage');
  }
  const usersDirResolved = path.resolve(USERS_DIR);
  const resolved = path.resolve(usersDirResolved, `${safeEmail}.json`);
  if (!resolved.startsWith(usersDirResolved + path.sep)) {
    throw new Error('Invalid storage path');
  }
  return resolved;
}

function readUserDb(email: string): DatabaseSchema {
  const filePath = getUserDbPath(email);
  if (fs.existsSync(filePath)) {
    try {
      const data = fs.readFileSync(filePath, 'utf-8');
      const parsed = JSON.parse(data);
      if (parsed && parsed.companies && parsed.companies.length > 0) return parsed;
    } catch (e) {
      console.error(`Error reading data for ${email}:`, e);
    }
  }
  // Initialize with seed data for this specific user
  const initial = JSON.parse(JSON.stringify(defaultSeedData));
  writeUserDb(email, initial);
  return initial;
}

function writeUserDb(email: string, data: DatabaseSchema): void {
  try {
    const filePath = getUserDbPath(email);
    const tempFile = `${filePath}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(data, null, 2), 'utf-8');
    fs.renameSync(tempFile, filePath);
  } catch (err) {
    console.error(`Error writing data for ${email}:`, err);
  }
}

// Initialize seed data if file does not exist or is empty
if (!fs.existsSync(DB_FILE)) {
  writeDb(defaultSeedData);
} else {
  const current = readDb();
  if (!current.companies || current.companies.length === 0) {
    writeDb(defaultSeedData);
  }
}

// -------------------------------------------------------------
// REST API ENDPOINTS
// -------------------------------------------------------------

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// -------------------------------------------------------------
// AUTHENTICATION ENDPOINTS
// -------------------------------------------------------------

const AUTH_ATTEMPT_WINDOW_MS = 5 * 60 * 1000;
const MAX_AUTH_ATTEMPTS = 15;
const authAttempts = new Map<string, { count: number; resetAt: number }>();

function checkAuthRateLimit(key: string): boolean {
  const now = Date.now();
  const entry = authAttempts.get(key);
  if (!entry || entry.resetAt <= now) {
    authAttempts.set(key, { count: 1, resetAt: now + AUTH_ATTEMPT_WINDOW_MS });
    return true;
  }
  if (entry.count >= MAX_AUTH_ATTEMPTS) {
    return false;
  }
  entry.count += 1;
  return true;
}

function clearAuthRateLimit(key: string): void {
  authAttempts.delete(key);
}

function normalizeSecurityAnswer(answer: unknown): string {
  return typeof answer === 'string' ? answer.trim().toLowerCase() : '';
}

// Register new user with email + password + recovery security answer
app.post('/api/auth/register', (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  const requestedRole = typeof req.body?.role === 'string' ? req.body.role.toUpperCase() : 'ADMIN';
  const role = VALID_ROLES.has(requestedRole) ? requestedRole : 'ADMIN';
  const provider = req.body?.provider === 'google' ? 'google' : 'password';
  const securityQuestion =
    typeof req.body?.securityQuestion === 'string' && req.body.securityQuestion.trim().length >= 4
      ? req.body.securityQuestion.trim()
      : 'What is your secret Recovery PIN or Birth City?';
  const securityAnswer = normalizeSecurityAnswer(req.body?.securityAnswer);

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  if (!name || name.length < 2) {
    return res.status(400).json({ error: 'Please enter your full name (at least 2 characters).' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
  }
  if (securityAnswer.length < 2) {
    return res.status(400).json({
      error: 'Please provide a Security Answer or Recovery PIN (at least 2 characters) for password recovery.',
    });
  }

  const accounts = readAuthAccounts();
  const existing = accounts.find((acc) => acc.email === email);
  if (existing) {
    return res.status(409).json({
      error: 'An account with this email already exists. Please switch to Sign In and enter your password.',
    });
  }

  const newAccount: StoredAuthAccount = {
    id: `usr-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
    name,
    email,
    role,
    provider,
    passwordHash: hashPassword(password),
    securityQuestion,
    recoveryHash: hashPassword(securityAnswer),
    createdAt: new Date().toISOString(),
  };

  accounts.push(newAccount);
  writeAuthAccounts(accounts);

  const publicUser = {
    id: newAccount.id,
    name: newAccount.name,
    email: newAccount.email,
    role: newAccount.role,
    status: 'Active',
    avatar: `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(newAccount.email)}`,
    createdAt: newAccount.createdAt,
  };

  const token = signAuthToken(publicUser);
  return res.status(201).json({ user: publicUser, token });
});

// Login with registered email + password
app.post('/api/auth/login', (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = typeof req.body?.password === 'string' ? req.body.password : '';

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  if (!password) {
    return res.status(400).json({ error: 'Please enter your password.' });
  }
  if (!checkAuthRateLimit(`login:${email}`)) {
    return res.status(429).json({
      error: 'Too many failed sign-in attempts. Please wait a few minutes or use Forgot Password.',
    });
  }

  const accounts = readAuthAccounts();
  const account = accounts.find((acc) => acc.email === email);

  if (!account) {
    return res.status(401).json({
      error: 'No account found with this email. Please create an account first using "Create Account".',
    });
  }

  if (!verifyPassword(password, account.passwordHash)) {
    return res.status(401).json({
      error: 'Incorrect password for this email. Please enter the correct password.',
    });
  }

  clearAuthRateLimit(`login:${email}`);

  const publicUser = {
    id: account.id,
    name: account.name,
    email: account.email,
    role: account.role,
    status: 'Active',
    avatar: `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(account.email)}`,
    createdAt: account.createdAt,
  };

  const token = signAuthToken(publicUser);
  return res.json({ user: publicUser, token });
});

// Forgot password step 1: look up account security question
app.post('/api/auth/forgot-password/lookup', (req, res) => {
  const email = normalizeEmail(req.body?.email);
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Please enter a valid registered email address.' });
  }

  const accounts = readAuthAccounts();
  const account = accounts.find((acc) => acc.email === email);
  if (!account) {
    return res.status(404).json({
      error: 'No account found with this email address. Please create an account first.',
    });
  }

  if (!account.recoveryHash) {
    return res.status(400).json({
      error:
        'Password recovery question was not configured for this legacy account. Please contact your system administrator or create a new account.',
    });
  }

  return res.json({
    email: account.email,
    name: account.name,
    securityQuestion: account.securityQuestion || 'What is your secret Recovery PIN or Birth City?',
  });
});

// Forgot password step 2: verify security answer and set new password
app.post('/api/auth/forgot-password/reset', (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const securityAnswer = normalizeSecurityAnswer(req.body?.securityAnswer);
  const newPassword = typeof req.body?.newPassword === 'string' ? req.body.newPassword : '';

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  if (!securityAnswer) {
    return res.status(400).json({ error: 'Please enter your Security Answer or Recovery PIN.' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters long.' });
  }
  if (!checkAuthRateLimit(`reset:${email}`)) {
    return res.status(429).json({
      error: 'Too many recovery attempts. Please wait a few minutes before trying again.',
    });
  }

  const accounts = readAuthAccounts();
  const accountIndex = accounts.findIndex((acc) => acc.email === email);
  if (accountIndex === -1) {
    return res.status(404).json({ error: 'No account found with this email address.' });
  }

  const account = accounts[accountIndex];
  if (!account.recoveryHash) {
    return res.status(400).json({
      error: 'Password recovery is not configured for this account.',
    });
  }

  if (!verifyPassword(securityAnswer, account.recoveryHash)) {
    return res.status(401).json({
      error: 'Incorrect Security Answer or Recovery PIN. Password was not changed.',
    });
  }

  clearAuthRateLimit(`reset:${email}`);
  clearAuthRateLimit(`login:${email}`);

  accounts[accountIndex] = {
    ...account,
    passwordHash: hashPassword(newPassword),
    updatedAt: new Date().toISOString(),
  };
  writeAuthAccounts(accounts);

  return res.json({
    success: true,
    message: 'Password updated successfully. You can now Sign In with your new password.',
  });
});

// Verify current session
app.get('/api/auth/me', requireAuth, (req: AuthenticatedRequest, res) => {
  return res.json({ user: req.authUser });
});

// Full state sync (strictly scoped to authenticated user's email)
app.get('/api/sync', requireAuth, (req: AuthenticatedRequest, res) => {
  const email = req.authUser!.email;
  const userDb = readUserDb(email);
  return res.json(userDb);
});

// Save complete user dataset for persistence (strictly scoped to authenticated user's email)
app.post('/api/user-sync', requireAuth, (req: AuthenticatedRequest, res) => {
  const email = req.authUser!.email;
  const data = req.body?.data || req.body;
  if (!data || typeof data !== 'object') {
    return res.status(400).json({ error: 'Invalid state payload' });
  }
  writeUserDb(email, data);
  res.json({ success: true, message: `Data for ${email} saved successfully` });
});

// Seed / Reset Database (strictly scoped to authenticated user)
app.post('/api/reset-data', requireAuth, (req: AuthenticatedRequest, res) => {
  const email = req.authUser!.email;
  const seedData = req.body;
  if (!seedData || typeof seedData !== 'object') {
    return res.status(400).json({ error: 'Invalid dataset' });
  }
  writeUserDb(email, seedData);
  res.json({ success: true, message: 'Database reset and seeded successfully' });
});

// Generic entity route helper (strictly scoped to authenticated user's isolated DB)
const COLLECTIONS = [
  'companies',
  'projects',
  'workers',
  'attendance',
  'daily_work',
  'expenses',
  'income',
  'salaries',
  'users',
  'audit_logs',
  'measurement_bills',
  'idm_records',
  'item_master',
  'measurement_templates',
  'formula_settings',
];

COLLECTIONS.forEach((collectionName) => {
  // GET all
  app.get(`/api/${collectionName}`, requireAuth, (req: AuthenticatedRequest, res) => {
    const db = readUserDb(req.authUser!.email);
    const items = (db as any)[collectionName] || [];
    res.json(items);
  });

  // POST create
  app.post(`/api/${collectionName}`, requireAuth, (req: AuthenticatedRequest, res) => {
    const email = req.authUser!.email;
    const db = readUserDb(email);
    const items = (db as any)[collectionName] || [];
    const newItem = {
      ...req.body,
      id: req.body.id || `${collectionName.slice(0, 3)}-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
      createdAt: req.body.createdAt || new Date().toISOString(),
    };
    items.unshift(newItem);
    (db as any)[collectionName] = items;
    writeUserDb(email, db);
    res.status(201).json(newItem);
  });

  // PUT update
  app.put(`/api/${collectionName}/:id`, requireAuth, (req: AuthenticatedRequest, res) => {
    const { id } = req.params;
    const email = req.authUser!.email;
    const db = readUserDb(email);
    const items = (db as any)[collectionName] || [];
    const index = items.findIndex((i: any) => i.id === id);
    if (index === -1) {
      return res.status(404).json({ error: `${collectionName} record not found` });
    }
    items[index] = { ...items[index], ...req.body, updatedAt: new Date().toISOString() };
    (db as any)[collectionName] = items;
    writeUserDb(email, db);
    res.json(items[index]);
  });

  // DELETE
  app.delete(`/api/${collectionName}/:id`, requireAuth, (req: AuthenticatedRequest, res) => {
    const { id } = req.params;
    const email = req.authUser!.email;
    const db = readUserDb(email);
    const items = (db as any)[collectionName] || [];
    const filtered = items.filter((i: any) => i.id !== id);
    (db as any)[collectionName] = filtered;
    writeUserDb(email, db);
    res.json({ success: true, id });
  });
});

// Bulk attendance entry
app.post('/api/attendance/bulk', requireAuth, (req: AuthenticatedRequest, res) => {
  const records = req.body;
  if (!Array.isArray(records)) {
    return res.status(400).json({ error: 'Expected array of attendance records' });
  }
  const email = req.authUser!.email;
  const db = readUserDb(email);
  const current = db.attendance || [];

  // Replace or append
  const updated = [...current];
  records.forEach((rec) => {
    const existingIndex = updated.findIndex(
      (a: any) => a.workerId === rec.workerId && a.date === rec.date
    );
    if (existingIndex >= 0) {
      updated[existingIndex] = { ...updated[existingIndex], ...rec, updatedAt: new Date().toISOString() };
    } else {
      updated.unshift({
        ...rec,
        id: rec.id || `att-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
        createdAt: new Date().toISOString(),
      });
    }
  });

  db.attendance = updated;
  writeUserDb(email, db);
  res.json({ success: true, count: records.length, records: updated });
});

// Settings GET & PUT
app.get('/api/settings', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = readUserDb(req.authUser!.email);
  res.json(db.settings || {});
});

app.put('/api/settings', requireAuth, (req: AuthenticatedRequest, res) => {
  const email = req.authUser!.email;
  const db = readUserDb(email);
  db.settings = { ...db.settings, ...req.body };
  writeUserDb(email, db);
  res.json(db.settings);
});

// Database Export / Backup
app.get('/api/backup', requireAuth, (req: AuthenticatedRequest, res) => {
  const db = readUserDb(req.authUser!.email);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="SR_GROUP_BACKUP_${new Date().toISOString().slice(0, 10)}.json"`);
  res.json(db);
});

// Database Import / Restore
app.post('/api/restore', requireAuth, (req: AuthenticatedRequest, res) => {
  const backup = req.body;
  if (!backup || typeof backup !== 'object') {
    return res.status(400).json({ error: 'Invalid backup format' });
  }
  writeUserDb(req.authUser!.email, backup);
  res.json({ success: true, message: 'Database successfully restored from backup' });
});

// Catch-all for unknown /api routes so they return JSON 404 rather than HTML
app.all('/api/*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

// -------------------------------------------------------------
// Vite Middleware / Static Serving
// -------------------------------------------------------------
function resolveDistPath(): string {
  const candidates = [
    path.join(process.cwd(), 'dist'),
    typeof __dirname !== 'undefined' ? __dirname : '',
    typeof __dirname !== 'undefined' ? path.resolve(__dirname, 'dist') : '',
  ].filter(Boolean);

  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, 'index.html'))) {
      return dir;
    }
  }
  return path.join(process.cwd(), 'dist');
}

async function startServer() {
  const isBundledCjs = typeof __filename !== 'undefined' && path.basename(__filename) === 'server.cjs';
  const isProduction = process.env.NODE_ENV === 'production' || isBundledCjs;

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = resolveDistPath();
    app.use(express.static(distPath, { index: 'index.html' }));
    app.get('*', (req, res) => {
      const indexFile = path.join(distPath, 'index.html');
      if (fs.existsSync(indexFile)) {
        res.sendFile(indexFile);
      } else {
        res.status(404).send('Production build not found. Please run npm run build.');
      }
    });
  }

  const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`SR GROUP ERP Server running on http://0.0.0.0:${PORT} (production=${isProduction})`);
  });

  server.on('error', (err: any) => {
    console.error('SR GROUP Server listen error:', err);
  });
}

startServer();
