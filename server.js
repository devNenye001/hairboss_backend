import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';

import { initDb, query } from './db.js';
import {
  sendWelcomeEmail,
  sendOrderConfirmationEmail,
  sendForgotPasswordEmail,
  sendAdminOrderNotificationEmail,
  sendOrderStatusUpdateEmail,
  getEmailHealth,
} from './mailer.js';

dotenv.config();

const ALLOWED_COLUMNS = {
  orders: ['id', 'user_id', 'full_name', 'email', 'phone', 'address', 'city', 'state', 'notes', 'total', 'status', 'payment_method', 'payment_proof', 'created_at'],
  products: ['id', 'name', 'price', 'description', 'images', 'category', 'is_featured', 'in_stock', 'stock_count', 'created_at'],
  site_content: ['key', 'value'],
  profiles: ['id', 'email', 'full_name', 'role', 'created_at'],
  order_items: ['id', 'order_id', 'product_id', 'product_name', 'product_image', 'quantity', 'price']
};

const isValidColumn = (table, column) => {
  return ALLOWED_COLUMNS[table]?.includes(column);
};

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'hairboss-super-secret-key-1234';

const requiredEnv = ['DATABASE_URL', 'JWT_SECRET'];
const missingEnv = requiredEnv.filter((key) => !process.env[key]);
if (missingEnv.length > 0) {
  console.warn(`Production hardening: missing env vars: ${missingEnv.join(', ')}`);
}
if (!process.env.FLUTTERWAVE_SECRET_KEY) {
  console.warn('Production hardening: FLUTTERWAVE_SECRET_KEY is missing. Payment verification will only be bypassed outside production.');
}

// Ensure uploads folder exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log('Created uploads directory:', uploadsDir);
}

// Security Configuration
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

const allowedOrigins = [
  'https://onlyonehairboss.vercel.app',
  'https://onlyonehairboss.com',
  'https://www.onlyonehairboss.com',
  'http://localhost:5173',
  'http://localhost:3000',
  ...(process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',').map(origin => origin.trim()).filter(Boolean) : []),
];

const corsCredentials = process.env.CORS_CREDENTIALS === 'true';

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS blocked origin: ${origin}`));
    }
  },
  credentials: corsCredentials,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'apikey', 'x-client-info'],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use(express.json());
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});
app.use((req, res, next) => {
  const startedAt = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - startedAt;
    console.log(`${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`);
  });
  next();
});

app.get('/api/health/email', (req, res) => {
  res.json({
    ok: true,
    email: getEmailHealth(),
  });
});

// Auth rate limiter to protect logins
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many authentication attempts. Please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/auth/login', authLimiter);
app.use('/api/auth/signup', authLimiter);
app.use('/api/auth/change-password', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);

app.use(express.urlencoded({ extended: true }));

// ── Auth Middleware ──────────────────────────────────────────────────────────

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    req.user = null;
    return next();
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Fetch profile role directly from database to be absolutely secure and up to date
    const profileRes = await query('SELECT role FROM profiles WHERE id = $1', [decoded.id]);
    const role = profileRes.rows[0]?.role || 'customer';
    
    req.user = {
      id: decoded.id,
      email: decoded.email,
      role: role,
      isReset: Boolean(decoded.isReset),
    };
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token.' });
  }
};

const requireAuth = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied. Administrator privileges required.' });
  }
  next();
};

const requireResetToken = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Reset link is missing or expired. Please request a new one.' });
  }
  if (!req.user.isReset) {
    return res.status(403).json({ error: 'Invalid reset link. Please request a new one.' });
  }
  next();
};

// ── Google Auth Setup ────────────────────────────────────────────────────────

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || `http://localhost:${PORT}/api/auth/google/callback`;

// ── Auth Routes ──────────────────────────────────────────────────────────────

// SignUp
app.post('/api/auth/signup', async (req, res) => {
  const { email, password, fullName } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const userExists = await query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'User already registered' });
    }

    const userId = crypto.randomUUID();
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    await query('BEGIN');
    await query(
      'INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)',
      [userId, email, passwordHash]
    );
    await query(
      'INSERT INTO profiles (id, email, full_name, role) VALUES ($1, $2, $3, $4)',
      [userId, email, fullName || '', 'customer']
    );
    await query('COMMIT');

    const token = jwt.sign({ id: userId, email, role: 'customer' }, JWT_SECRET, { expiresIn: '7d' });
    const user = { id: userId, email };
    const profile = { id: userId, email, full_name: fullName || '', role: 'customer' };

    // Send Welcome Email (Fire-and-forget but logged)
    sendWelcomeEmail(email, fullName || email).catch(err => console.error('Failed to send signup email:', err));

    res.status(201).json({ token, user, profile });
  } catch (error) {
    await query('ROLLBACK');
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error during registration.' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const userRes = await query('SELECT * FROM users WHERE email = $1', [email]);
    if (userRes.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid login credentials' });
    }

    const user = userRes.rows[0];
    if (!user.password_hash) {
      return res.status(400).json({ error: 'Account created with Google OAuth. Please sign in with Google.' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid login credentials' });
    }

    const profileRes = await query('SELECT * FROM profiles WHERE id = $1', [user.id]);
    const profile = profileRes.rows[0] || {};

    const token = jwt.sign({ id: user.id, email: user.email, role: profile.role || 'customer' }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: { id: user.id, email: user.email },
      profile,
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error during login.' });
  }
});

// Get User (Me)
app.get('/api/auth/me', authenticateToken, requireAuth, async (req, res) => {
  try {
    const profileRes = await query('SELECT * FROM profiles WHERE id = $1', [req.user.id]);
    if (profileRes.rows.length === 0) {
      return res.status(404).json({ error: 'Profile not found.' });
    }
    res.json({
      user: { id: req.user.id, email: req.user.email },
      profile: profileRes.rows[0],
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Forgot Password Request
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email, redirectTo } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }

  try {
    const userRes = await query('SELECT * FROM users WHERE email = $1', [email]);
    if (userRes.rows.length === 0) {
      // Security standard: don't reveal if account exists, just say sent
      return res.json({ message: 'Reset link sent! Check your email inbox.' });
    }

    const user = userRes.rows[0];
    const resetToken = jwt.sign({ id: user.id, email: user.email, isReset: true }, JWT_SECRET, { expiresIn: '1h' });

    const resetBaseUrl = redirectTo || `${process.env.FRONTEND_URL || 'http://localhost:5173'}/reset-password`;
    const frontendResetUrl = `${resetBaseUrl}${resetBaseUrl.includes('?') ? '&' : '?'}token=${encodeURIComponent(resetToken)}`;

    // Queue Forgot Password Email. Delivery failures are logged by the mailer
    // and must not block password reset requests.
    sendForgotPasswordEmail(email, frontendResetUrl)
      .catch(err => console.error('Failed to queue forgot password email:', err));

    res.json({ message: 'Reset link sent! Check your email inbox.' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Reset Password Execution
app.post('/api/auth/reset-password', authenticateToken, requireResetToken, async (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    await query('UPDATE users SET password_hash = $1 WHERE id = $2', [passwordHash, req.user.id]);
    res.json({ success: true, message: 'Password updated successfully.' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// POST /api/auth/change-password (Authenticated users)
app.post('/api/auth/change-password', authenticateToken, requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new passwords are required.' });
  }

  try {
    const userRes = await query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const currentHash = userRes.rows[0].password_hash;
    if (currentHash) {
      const match = await bcrypt.compare(currentPassword, currentHash);
      if (!match) {
        return res.status(400).json({ error: 'Incorrect current password.' });
      }
    }

    const salt = await bcrypt.genSalt(10);
    const newHash = await bcrypt.hash(newPassword, salt);
    await query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, req.user.id]);

    res.json({ success: true, message: 'Password updated successfully!' });
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ error: 'Failed to update password.' });
  }
});

// Google OAuth Redirection
app.get('/api/auth/google', (req, res) => {
  const redirectTo = req.query.redirectTo || 'http://localhost:5173';
  if (!GOOGLE_CLIENT_ID) {
    return res.status(400).json({ error: 'Google Client ID is not configured on the server.' });
  }

  const oauthUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${GOOGLE_CLIENT_ID}&redirect_uri=${encodeURIComponent(GOOGLE_REDIRECT_URI)}&response_type=code&scope=email%20profile&state=${encodeURIComponent(redirectTo)}&prompt=select_account`;
  res.redirect(oauthUrl);
});

// Google OAuth Callback
app.get('/api/auth/google/callback', async (req, res) => {
  const { code, state } = req.query;

  if (!code) {
    return res.status(400).json({ error: 'Authorization code is missing.' });
  }

  try {
    // 1. Exchange authorization code for token
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code',
      }),
    });

    const tokens = await tokenRes.json();
    if (!tokenRes.ok) {
      throw new Error(tokens.error_description || tokens.error || 'Failed to exchange Google OAuth code.');
    }

    // 2. Fetch User Profile from Google
    const userinfoRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const googleUser = await userinfoRes.json();
    if (!userinfoRes.ok) {
      throw new Error('Failed to fetch Google user details.');
    }

    const { email, name, id: googleId } = googleUser;

    // 3. Upsert User in database
    const userRes = await query('SELECT * FROM users WHERE email = $1', [email]);
    let userId;
    let role = 'customer';

    if (userRes.rows.length === 0) {
      // Create user
      userId = crypto.randomUUID();
      await query('BEGIN');
      await query('INSERT INTO users (id, email) VALUES ($1, $2)', [userId, email]);
      await query(
        'INSERT INTO profiles (id, email, full_name, role) VALUES ($1, $2, $3, $4)',
        [userId, email, name || '', 'customer']
      );
      await query('COMMIT');
      
      // Send Welcome Email
      sendWelcomeEmail(email, name || email).catch(err => console.error('Failed to send welcome email:', err));
    } else {
      userId = userRes.rows[0].id;
      // Get role
      const profileRes = await query('SELECT role FROM profiles WHERE id = $1', [userId]);
      role = profileRes.rows[0]?.role || 'customer';
    }

    // 4. Generate JWT Token
    const jwtToken = jwt.sign({ id: userId, email, role }, JWT_SECRET, { expiresIn: '7d' });

    // 5. Redirect back to frontend with token in query params
    res.redirect(`${state || 'http://localhost:5173'}?token=${jwtToken}`);
  } catch (error) {
    console.error('Google OAuth callback error:', error);
    res.status(500).json({ error: `Google sign-in failed: ${error.message}` });
  }
});

// ── Database REST Endpoints ──────────────────────────────────────────────────

// GET products
app.get('/api/db/products', async (req, res) => {
  const { eq_field, eq_value, ilike_field, ilike_value, order_field, order_ascending, limit, single, maybe_single } = req.query;

  try {
    let sql = 'SELECT * FROM products';
    const params = [];
    let paramIndex = 1;

    if (eq_field && !isValidColumn('products', eq_field)) {
      return res.status(400).json({ error: 'Invalid query field.' });
    }
    if (ilike_field && !isValidColumn('products', ilike_field)) {
      return res.status(400).json({ error: 'Invalid search field.' });
    }
    if (order_field && !isValidColumn('products', order_field)) {
      return res.status(400).json({ error: 'Invalid order field.' });
    }

    const conditions = [];

    if (eq_field && eq_value) {
      conditions.push(`${eq_field} = $${paramIndex}`);
      params.push(eq_value);
      paramIndex++;
    }

    if (ilike_field && ilike_value) {
      conditions.push(`${ilike_field} ILIKE $${paramIndex}`);
      params.push(ilike_value);
      paramIndex++;
    }

    if (conditions.length > 0) {
      sql += ` WHERE ${conditions.join(' AND ')}`;
    }

    if (order_field) {
      const dir = order_ascending === 'false' ? 'DESC' : 'ASC';
      sql += ` ORDER BY ${order_field} ${dir}`;
    } else {
      sql += ' ORDER BY created_at DESC';
    }

    if (limit) {
      sql += ` LIMIT $${paramIndex}`;
      params.push(parseInt(limit, 10));
      paramIndex++;
    }

    const result = await query(sql, params);
    const data = single === 'true' || maybe_single === 'true'
      ? result.rows[0] || null
      : result.rows;
    res.json({ data });
  } catch (error) {
    console.error('DB query error (products):', error);
    res.status(500).json({ error: 'Failed to retrieve products.' });
  }
});

// POST products (Admin only)
app.post('/api/db/products', authenticateToken, requireAdmin, async (req, res) => {
  const { payload } = req.body;
  if (!payload || !payload.name || payload.price === undefined) {
    return res.status(400).json({ error: 'Product name and price are required.' });
  }

  const id = crypto.randomUUID();
  try {
    const sql = `
      INSERT INTO products (id, name, price, description, images, category, is_featured, in_stock, stock_count)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
    `;
    const params = [
      id,
      payload.name,
      payload.price,
      payload.description || '',
      payload.images || [],
      payload.category || 'general',
      payload.is_featured || false,
      payload.in_stock !== false,
      payload.stock_count || 0,
    ];
    const result = await query(sql, params);
    res.status(201).json({ data: result.rows[0] });
  } catch (error) {
    console.error('DB insert error (products):', error);
    res.status(500).json({ error: 'Failed to add product.' });
  }
});

// PUT products update (Admin only)
app.put('/api/db/products/update', authenticateToken, requireAdmin, async (req, res) => {
  const { payload, field, value } = req.body;
  if (field !== 'id') {
    return res.status(400).json({ error: 'Can only update products by id.' });
  }

  try {
    // Dynamically build the update fields to be safe and clean
    const allowedFields = ['name', 'price', 'description', 'images', 'category', 'is_featured', 'in_stock', 'stock_count'];
    const updateSets = [];
    const params = [];
    let counter = 1;

    for (const key of allowedFields) {
      if (payload[key] !== undefined) {
        updateSets.push(`${key} = $${counter}`);
        params.push(payload[key]);
        counter++;
      }
    }

    if (updateSets.length === 0) {
      return res.status(400).json({ error: 'No fields to update.' });
    }

    params.push(value); // product ID is the final parameter
    const sql = `UPDATE products SET ${updateSets.join(', ')} WHERE id = $${counter} RETURNING *`;

    const result = await query(sql, params);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found.' });
    }

    res.json({ data: result.rows[0] });
  } catch (error) {
    console.error('DB update error (products):', error);
    res.status(500).json({ error: 'Failed to update product.' });
  }
});

// DELETE products (Admin only)
app.delete('/api/db/products/delete', authenticateToken, requireAdmin, async (req, res) => {
  const { field, value } = req.body;
  if (field !== 'id') {
    return res.status(400).json({ error: 'Can only delete products by id.' });
  }

  try {
    const result = await query('DELETE FROM products WHERE id = $1 RETURNING *', [value]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found.' });
    }
    res.json({ data: result.rows[0] });
  } catch (error) {
    console.error('DB delete error (products):', error);
    res.status(500).json({ error: 'Failed to delete product.' });
  }
});

// GET orders
app.get('/api/db/orders', authenticateToken, requireAuth, async (req, res) => {
  const { eq_field, eq_value, order_field, order_ascending, limit, single, maybe_single } = req.query;

  if (eq_field && !isValidColumn('orders', eq_field)) {
    return res.status(400).json({ error: 'Invalid query field.' });
  }
  if (order_field && !isValidColumn('orders', order_field)) {
    return res.status(400).json({ error: 'Invalid order field.' });
  }

  try {
    let sql = 'SELECT * FROM orders';
    const params = [];
    let paramIndex = 1;

    // Security check: Customer can only view their own orders
    if (req.user.role !== 'admin') {
      sql += ` WHERE user_id = $${paramIndex}`;
      params.push(req.user.id);
      paramIndex++;
      
      if (eq_field === 'user_id' && eq_value !== req.user.id) {
        return res.status(403).json({ error: 'Access denied. Cannot view other user\'s orders.' });
      }
    } else if (eq_field && eq_value) {
      sql += ` WHERE ${eq_field} = $${paramIndex}`;
      params.push(eq_value);
      paramIndex++;
    }

    if (order_field) {
      const dir = order_ascending === 'false' ? 'DESC' : 'ASC';
      sql += ` ORDER BY ${order_field} ${dir}`;
    } else {
      sql += ' ORDER BY created_at DESC';
    }

    if (limit) {
      sql += ` LIMIT $${paramIndex}`;
      params.push(parseInt(limit, 10));
      paramIndex++;
    }

    const result = await query(sql, params);
    if (single === 'true' || maybe_single === 'true') {
      return res.json({ data: result.rows[0] || null });
    }
    res.json({ data: result.rows });
  } catch (error) {
    console.error('DB query error (orders):', error);
    res.status(500).json({ error: 'Failed to retrieve orders.' });
  }
});

// POST orders (Allows guest checkout or authenticated user checkout)
app.post('/api/db/orders', authenticateToken, async (req, res) => {
  const { payload } = req.body;
  if (!payload || !payload.full_name || !payload.email || !payload.total) {
    return res.status(400).json({ error: 'Invalid order payload details.' });
  }

  const orderId = crypto.randomUUID();
  const userId = req.user ? req.user.id : null; // logged-in user or guest

  try {
    const sql = `
      INSERT INTO orders (id, user_id, full_name, email, phone, address, city, state, total, status, payment_method, payment_proof, notes)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING *
    `;
    const params = [
      orderId,
      userId,
      payload.full_name,
      payload.email,
      payload.phone,
      payload.address,
      payload.city,
      payload.state,
      payload.total,
      payload.status || 'pending',
      payload.payment_method || 'transfer',
      payload.payment_proof || '',
      payload.notes || '',
    ];

    const result = await query(sql, params);
    res.status(201).json({ data: result.rows[0] });
  } catch (error) {
    console.error('DB insert error (orders):', error);
    res.status(500).json({ error: 'Failed to create order.' });
  }
});

// POST /api/checkout/verify-payment
app.post('/api/checkout/verify-payment', authenticateToken, async (req, res) => {
  const { transaction_id, payload } = req.body;
  const items = Array.isArray(payload?.items) ? payload.items : [];
  const total = Number(payload?.total);

  if (!transaction_id || !payload || !payload.full_name || !payload.email || !Number.isFinite(total) || total <= 0 || items.length === 0) {
    return res.status(400).json({ error: 'Invalid checkout request parameters.' });
  }

  try {
    // 1. Prevent duplicate orders
    const transactionId = transaction_id.toString();
    const duplicateCheck = await query('SELECT * FROM orders WHERE payment_proof = $1', [transactionId]);
    if (duplicateCheck.rows.length > 0) {
      return res.status(200).json({ data: duplicateCheck.rows[0], message: 'Order already processed.' });
    }

    // 2. Verify payment server-side
    const FLUTTERWAVE_SECRET_KEY = process.env.FLUTTERWAVE_SECRET_KEY;
    let verifiedPayment = {
      status: 'successful',
      amount: total,
      currency: 'NGN',
      tx_ref: payload.tx_ref || '',
      raw: {},
    };

    if (FLUTTERWAVE_SECRET_KEY) {
      const flwResponse = await fetch(`https://api.flutterwave.com/v3/transactions/${transaction_id}/verify`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${FLUTTERWAVE_SECRET_KEY}`,
          'Content-Type': 'application/json'
        }
      });
      const flwData = await flwResponse.json();
      const flwAmount = Number(flwData?.data?.amount);
      const flwCurrency = flwData?.data?.currency || 'NGN';
      const flwStatus = flwData?.data?.status;
      if (!flwResponse.ok || flwData.status !== 'success' || flwStatus !== 'successful' || flwAmount < total || flwCurrency !== 'NGN') {
        return res.status(400).json({ error: 'Flutterwave payment verification failed.' });
      }
      verifiedPayment = {
        status: flwStatus,
        amount: flwAmount,
        currency: flwCurrency,
        tx_ref: flwData?.data?.tx_ref || payload.tx_ref || '',
        raw: flwData,
      };
    } else {
      if (process.env.NODE_ENV === 'production') {
        return res.status(500).json({ error: 'Payment verification is not configured.' });
      }
      console.warn('Flutterwave: Secret key not defined. Bypassing verification for development only.');
    }

    // 3. Create the order
    const orderId = crypto.randomUUID();
    const userId = req.user ? req.user.id : null;

    const orderSql = `
      INSERT INTO orders (id, user_id, full_name, email, phone, address, city, state, total, status, payment_method, payment_proof, notes, shipping_method, shipping_fee)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
      RETURNING *
    `;
    const orderParams = [
      orderId,
      userId,
      payload.full_name,
      payload.email,
      payload.phone,
      payload.address,
      payload.city,
      payload.state,
      total,
      'pending',
      'flutterwave',
      transactionId,
      payload.notes || '',
      payload.shipping_method || 'local',
      Number(payload.shipping_fee) || 0,
    ];

    await query('BEGIN');
    const orderResult = await query(orderSql, orderParams);
    const order = orderResult.rows[0];

    // 4. Create order items
    for (const item of items) {
      const itemId = crypto.randomUUID();
      const itemSql = `
        INSERT INTO order_items (id, order_id, product_id, product_name, product_image, quantity, price)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `;
      const itemParams = [
        itemId,
        orderId,
        typeof item.id === 'string' && item.id.includes('-') ? item.id : null,
        item.name || 'OnlyOne Hairboss item',
        item.image || '',
        Number(item.quantity) > 0 ? Number(item.quantity) : 1,
        Number(item.price) || 0
      ];
      await query(itemSql, itemParams);
    }

    await query(
      `INSERT INTO payment_transactions (id, order_id, provider, transaction_id, tx_ref, amount, currency, status, raw_response)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (transaction_id) DO UPDATE
       SET order_id = EXCLUDED.order_id,
           status = EXCLUDED.status,
           raw_response = EXCLUDED.raw_response`,
      [
        crypto.randomUUID(),
        orderId,
        'flutterwave',
        transactionId,
        verifiedPayment.tx_ref,
        verifiedPayment.amount,
        verifiedPayment.currency,
        verifiedPayment.status,
        JSON.stringify(verifiedPayment.raw),
      ]
    );

    await query('COMMIT');

    // 5. Queue order confirmation and admin alert emails in background.
    sendOrderConfirmationEmail(payload.email, {
        name: payload.full_name,
        orderId: order.id,
        total,
        items,
        address: payload.address,
        city: payload.city,
        state: payload.state,
        shippingMethod: order.shipping_method,
        shippingFee: Number(order.shipping_fee) || 0
      })
      .catch(err => console.error('Failed to queue order confirmation email:', err));

    sendAdminOrderNotificationEmail({
        name: payload.full_name,
        email: payload.email,
        orderId: order.id,
        total,
        items,
        address: payload.address,
        city: payload.city,
        state: payload.state,
        shippingMethod: order.shipping_method,
        shippingFee: Number(order.shipping_fee) || 0
      })
      .catch(err => console.error('Failed to queue admin order email:', err));

    res.status(201).json({ data: order });
  } catch (error) {
    await query('ROLLBACK').catch(() => {});
    console.error('Checkout verification error:', error);
    res.status(500).json({ error: 'Failed to process and save checkout order details.' });
  }
});

// PUT orders status update (Admin only)
app.put('/api/db/orders/update', authenticateToken, requireAdmin, async (req, res) => {
  const { payload, field, value } = req.body;
  if (field !== 'id') {
    return res.status(400).json({ error: 'Can only update orders by id.' });
  }
  const allowedStatuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled'];
  if (!allowedStatuses.includes(payload?.status)) {
    return res.status(400).json({ error: 'Invalid order status.' });
  }

  try {
    const existing = await query('SELECT * FROM orders WHERE id = $1', [value]);
    if (existing.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found.' });
    }

    const result = await query(
      'UPDATE orders SET status = $1 WHERE id = $2 RETURNING *',
      [payload.status, value]
    );
    const updatedOrder = result.rows[0];

    if (existing.rows[0].status !== updatedOrder.status) {
      sendOrderStatusUpdateEmail(updatedOrder.email, {
        name: updatedOrder.full_name,
        orderId: updatedOrder.id,
        oldStatus: existing.rows[0].status,
        newStatus: updatedOrder.status,
      }).catch(err => console.error('Failed to send order status email:', err));
    }

    res.json({ data: updatedOrder });
  } catch (error) {
    console.error('DB update error (orders):', error);
    res.status(500).json({ error: 'Failed to update order.' });
  }
});

// GET order_items
app.get('/api/db/order_items', authenticateToken, requireAuth, async (req, res) => {
  const { eq_field, eq_value } = req.query;

  if (eq_field !== 'order_id') {
    return res.status(400).json({ error: 'Must query order_items by order_id.' });
  }

  try {
    // Security check: Check if order exists and belongs to req.user (unless user is admin)
    const orderRes = await query('SELECT user_id FROM orders WHERE id = $1', [eq_value]);
    if (orderRes.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found.' });
    }

    if (req.user.role !== 'admin' && orderRes.rows[0].user_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied. This order does not belong to you.' });
    }

    const itemsRes = await query('SELECT * FROM order_items WHERE order_id = $1', [eq_value]);
    res.json({ data: itemsRes.rows });
  } catch (error) {
    console.error('DB query error (order_items):', error);
    res.status(500).json({ error: 'Failed to retrieve order items.' });
  }
});

// POST order_items
app.post('/api/db/order_items', authenticateToken, async (req, res) => {
  const { payload } = req.body;
  
  // payload is either an object or an array of objects
  const items = Array.isArray(payload) ? payload : [payload];

  try {
    await query('BEGIN');
    const insertedItems = [];

    for (const item of items) {
      const id = crypto.randomUUID();
      const sql = `
        INSERT INTO order_items (id, order_id, product_id, product_name, product_image, quantity, price)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
      `;
      const params = [
        id,
        item.order_id,
        item.product_id || null,
        item.product_name,
        item.product_image || '',
        item.quantity || 1,
        item.price,
      ];
      const result = await query(sql, params);
      insertedItems.push(result.rows[0]);
    }

    await query('COMMIT');
    res.status(201).json({ data: insertedItems });
  } catch (error) {
    await query('ROLLBACK');
    console.error('DB insert error (order_items):', error);
    res.status(500).json({ error: 'Failed to save order items.' });
  }
});

// GET profiles
app.get('/api/db/profiles', authenticateToken, requireAuth, async (req, res) => {
  const { eq_field, eq_value, single } = req.query;

  if (eq_field && !isValidColumn('profiles', eq_field)) {
    return res.status(400).json({ error: 'Invalid query field.' });
  }

  try {
    // If specific ID is requested, user must be that profile or admin
    if (eq_field === 'id') {
      if (req.user.role !== 'admin' && eq_value !== req.user.id) {
        return res.status(403).json({ error: 'Access denied.' });
      }
      const result = await query('SELECT * FROM profiles WHERE id = $1', [eq_value]);
      const data = single === 'true' ? result.rows[0] || null : result.rows;
      return res.json({ data });
    }

    // Listing all profiles: Admin only
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied.' });
    }

    const result = await query('SELECT * FROM profiles ORDER BY created_at DESC');
    res.json({ data: result.rows });
  } catch (error) {
    console.error('DB query error (profiles):', error);
    res.status(500).json({ error: 'Failed to query profiles.' });
  }
});

// GET billing_info
app.get('/api/db/billing_info', authenticateToken, requireAuth, async (req, res) => {
  try {
    const result = await query('SELECT * FROM billing_info WHERE user_id = $1', [req.user.id]);
    res.json({ data: result.rows[0] || null });
  } catch (error) {
    console.error('DB query error (billing_info):', error);
    res.status(500).json({ error: 'Failed to retrieve billing info.' });
  }
});

// GET site_content
app.get('/api/db/site_content', async (req, res) => {
  const { eq_field, eq_value, single } = req.query;

  if (eq_field && !isValidColumn('site_content', eq_field)) {
    return res.status(400).json({ error: 'Invalid query field.' });
  }

  try {
    let sql = 'SELECT * FROM site_content';
    const params = [];
    if (eq_field && eq_value) {
      sql += ` WHERE ${eq_field} = $1`;
      params.push(eq_value);
    }
    const result = await query(sql, params);
    
    // Parse value fields
    const data = result.rows.map(row => ({
      key: row.key,
      value: typeof row.value === 'string' ? JSON.parse(row.value) : row.value
    }));

    if (single === 'true' || req.query.maybe_single === 'true') {
      res.json({ data: data[0] || null });
    } else {
      res.json({ data });
    }
  } catch (error) {
    console.error('DB query error (site_content):', error);
    res.status(500).json({ error: 'Failed to retrieve site content.' });
  }
});

// POST site_content (Admin only)
app.post('/api/db/site_content', authenticateToken, requireAdmin, async (req, res) => {
  const { payload } = req.body;
  if (!payload || !payload.key || payload.value === undefined) {
    return res.status(400).json({ error: 'Key and value payload details are required.' });
  }
  try {
    const sql = `
      INSERT INTO site_content (key, value)
      VALUES ($1, $2)
      ON CONFLICT (key) DO UPDATE
      SET value = EXCLUDED.value
      RETURNING *
    `;
    const result = await query(sql, [payload.key, JSON.stringify(payload.value)]);
    res.status(201).json({ data: result.rows[0] });
  } catch (error) {
    console.error('DB insert error (site_content):', error);
    res.status(500).json({ error: 'Failed to save site content.' });
  }
});

// GET stats (Admin only)
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    // Metrics 1: Revenue & Orders count
    const ordersRes = await query('SELECT SUM(total) as revenue, COUNT(*) as count FROM orders WHERE status != $1', ['cancelled']);
    const revenue = parseFloat(ordersRes.rows[0]?.revenue || 0);
    const totalOrders = parseInt(ordersRes.rows[0]?.count || 0);

    // Metrics 2: Total products
    const productsRes = await query('SELECT COUNT(*) as count FROM products');
    const totalProducts = parseInt(productsRes.rows[0]?.count || 0);

    // Average Order Value
    const averageOrderValue = totalOrders > 0 ? (revenue / totalOrders) : 0;

    // Sales by category
    const categorySalesRes = await query(`
      SELECT p.category, SUM(oi.price * oi.quantity) as sales
      FROM order_items oi
      JOIN products p ON p.id = oi.product_id
      JOIN orders o ON o.id = oi.order_id
      WHERE o.status != 'cancelled'
      GROUP BY p.category
      ORDER BY sales DESC
    `);

    // Recent orders
    const recentOrdersRes = await query('SELECT id, full_name, email, total, status, created_at FROM orders ORDER BY created_at DESC LIMIT 5');

    // Monthly sales simulation (for graphs)
    const monthlySalesRes = await query(`
      SELECT TO_CHAR(created_at, 'Mon') as month, SUM(total) as sales
      FROM orders
      WHERE status != 'cancelled'
      GROUP BY TO_CHAR(created_at, 'Mon'), DATE_TRUNC('month', created_at)
      ORDER BY DATE_TRUNC('month', created_at) LIMIT 6
    `);

    res.json({
      revenue,
      totalOrders,
      totalProducts,
      averageOrderValue,
      categorySales: categorySalesRes.rows,
      recentOrders: recentOrdersRes.rows,
      monthlySales: monthlySalesRes.rows
    });
  } catch (error) {
    console.error('Stats query error:', error);
    res.status(500).json({ error: 'Failed to retrieve admin stats.' });
  }
});

// ── Edge Functions Mock ──────────────────────────────────────────────────────

// Save Billing Function
app.post('/api/functions/save-billing', authenticateToken, requireAuth, async (req, res) => {
  const { full_name, email, phone, address, city, state, country } = req.body;
  if (!full_name || !email) {
    return res.status(400).json({ error: 'Full name and email are required.' });
  }

  try {
    const id = crypto.randomUUID();
    const sql = `
      INSERT INTO billing_info (id, user_id, full_name, email, phone, address, city, state, country, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
      ON CONFLICT (user_id) DO UPDATE
      SET full_name = EXCLUDED.full_name,
          email = EXCLUDED.email,
          phone = EXCLUDED.phone,
          address = EXCLUDED.address,
          city = EXCLUDED.city,
          state = EXCLUDED.state,
          country = EXCLUDED.country,
          updated_at = NOW()
      RETURNING *
    `;
    const params = [
      id,
      req.user.id,
      full_name,
      email,
      phone || '',
      address || '',
      city || '',
      state || '',
      country || 'Nigeria',
    ];

    const result = await query(sql, params);
    res.json({ data: result.rows[0] });
  } catch (error) {
    console.error('Save billing function error:', error);
    res.status(500).json({ error: error.message || 'Failed to save billing info.' });
  }
});

// Handle Signup Metadata Function
app.post('/api/functions/handle-signup-metadata', authenticateToken, requireAuth, async (req, res) => {
  const { full_name } = req.body;

  try {
    if (full_name) {
      await query(
        'UPDATE profiles SET full_name = $1 WHERE id = $2',
        [full_name, req.user.id]
      );
    }
    
    // Fetch updated profile
    const profileRes = await query('SELECT * FROM profiles WHERE id = $1', [req.user.id]);
    const profile = profileRes.rows[0];

    res.json({ success: true, user_id: req.user.id, full_name: profile?.full_name || '' });
  } catch (error) {
    console.error('Handle signup metadata error:', error);
    res.status(500).json({ error: 'Failed to update user profile metadata.' });
  }
});

// Admin-only manual email queue endpoint. Storefront email events are backend-owned.
app.post('/api/functions/send-email', authenticateToken, requireAdmin, async (req, res) => {
  const { type, data } = req.body;

  if (!type || !data || !data.email) {
    return res.status(400).json({ error: 'Email destination and trigger type are required.' });
  }

  try {
    if (type === 'welcome') {
      await sendWelcomeEmail(data.email, data.name || data.email);
    } else if (type === 'order_confirmation') {
      await sendOrderConfirmationEmail(data.email, data);
      await sendAdminOrderNotificationEmail(data).catch(err => console.error('Failed to queue admin order email:', err));
    } else if (type === 'forgot_password') {
      await sendForgotPasswordEmail(data.email, data.resetUrl || 'http://localhost:5173/reset-password');
    } else {
      console.warn(`Mailer: Unknown custom email function trigger: ${type}`);
    }
    res.status(202).json({ success: true, queued: true });
  } catch (error) {
    console.error('Send email function error:', error);
    res.status(500).json({ error: 'Failed to dispatch email alert.' });
  }
});

// ── Image Storage Upload Handler ─────────────────────────────────────────────

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const uniqueName = `${Date.now()}-${crypto.randomBytes(5).toString('hex')}${ext}`;
    cb(null, uniqueName);
  },
});

const fileFilter = (req, file, cb) => {
  // Allow images and video files
  const filetypes = /jpeg|jpg|png|webp|gif|mp4|webm|ogg|quicktime|mov/;
  const mimetype = filetypes.test(file.mimetype) || file.mimetype.startsWith('video/');
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

  if (mimetype || extname) {
    return cb(null, true);
  }
  cb(new Error('Images and video loops (jpeg, jpg, png, webp, gif, mp4, webm, ogg, mov) only!'));
};

const upload = multer({
  storage,
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB limit for video support
  fileFilter,
});

// Image upload route (Admin only)
app.post('/api/storage/upload', authenticateToken, requireAdmin, upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No image file uploaded.' });
  }
  res.json({ path: req.file.filename });
});

// Chunked resumable upload endpoint (Admin only)
app.post('/api/storage/upload/chunk', authenticateToken, requireAdmin, multer().single('chunk'), async (req, res) => {
  const { chunkIndex, totalChunks, fileName } = req.body;
  if (!req.file) {
    return res.status(400).json({ error: 'No chunk file uploaded.' });
  }

  const safeFileName = path.basename(fileName || '');
  if (!safeFileName || safeFileName !== fileName) {
    return res.status(400).json({ error: 'Invalid upload file name.' });
  }

  const tempDir = path.join(__dirname, 'uploads', 'temp');
  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
  }

  const tempFilePath = path.join(tempDir, safeFileName);

  try {
    // Append chunk buffer to temp file
    fs.appendFileSync(tempFilePath, req.file.buffer);

    const parsedIndex = parseInt(chunkIndex, 10);
    const parsedTotal = parseInt(totalChunks, 10);

    if (parsedIndex + 1 === parsedTotal) {
      const finalPath = path.join(uploadsDir, safeFileName);
      
      // Remove file if it already exists in final folder to avoid locks
      if (fs.existsSync(finalPath)) {
        fs.unlinkSync(finalPath);
      }
      
      fs.renameSync(tempFilePath, finalPath);

      // Verify file size is <= 20MB
      const stats = fs.statSync(finalPath);
      if (stats.size > 20 * 1024 * 1024) {
        fs.unlinkSync(finalPath);
        return res.status(400).json({ error: 'File size exceeds maximum limit of 20MB.' });
      }

      return res.json({ path: safeFileName, completed: true });
    }

    res.json({ completed: false, nextIndex: parsedIndex + 1 });
  } catch (err) {
    console.error('Chunk upload error:', err);
    if (fs.existsSync(tempFilePath)) {
      try { fs.unlinkSync(tempFilePath); } catch (e) {}
    }
    res.status(500).json({ error: 'Failed to process upload chunk.' });
  }
});

// Serve images statically
app.use('/api/storage/files', express.static(uploadsDir, {
  maxAge: '7d',
  immutable: true,
}));

// ── Error handling ───────────────────────────────────────────────────────────

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: `Multer upload error: ${err.message}` });
  } else if (err) {
    console.error('Unhandled app error:', err);
    return res.status(500).json({ error: err.message || 'An unexpected error occurred.' });
  }
  next();
});

// Start Server
initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`OnlyOne Hairboss backend listening at http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to start server due to database issue:', err);
  });
