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

import { initDb, query } from './db.js';
import {
  sendWelcomeEmail,
  sendOrderConfirmationEmail,
  sendForgotPasswordEmail,
} from './mailer.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'hairboss-super-secret-key-1234';

// Ensure uploads folder exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log('Created uploads directory:', uploadsDir);
}

app.use(cors({
  origin: '*', // Allow all origins for API, adjust as needed
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'apikey'],
}));

app.use(express.json());
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

    const frontendResetUrl = redirectTo
      ? `${redirectTo}?token=${resetToken}`
      : `${process.env.FRONTEND_URL || 'http://localhost:5173'}/reset-password?token=${resetToken}`;

    // Send Forgot Password Email
    await sendForgotPasswordEmail(email, frontendResetUrl);

    res.json({ message: 'Reset link sent! Check your email inbox.' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Reset Password Execution
app.post('/api/auth/reset-password', authenticateToken, requireAuth, async (req, res) => {
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

// Google OAuth Redirection
app.get('/api/auth/google', (req, res) => {
  const redirectTo = req.query.redirectTo || 'http://localhost:5173';
  if (!GOOGLE_CLIENT_ID) {
    return res.status(400).json({ error: 'Google Client ID is not configured on the server.' });
  }

  const oauthUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${GOOGLE_CLIENT_ID}&redirect_uri=${encodeURIComponent(GOOGLE_REDIRECT_URI)}&response_type=code&scope=email%20profile&state=${encodeURIComponent(redirectTo)}`;
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
  const { eq_field, eq_value, order_field, order_ascending, limit } = req.query;

  try {
    let sql = 'SELECT * FROM products';
    const params = [];
    let paramIndex = 1;

    if (eq_field && eq_value) {
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
    res.json({ data: result.rows });
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
  const { eq_field, eq_value, order_field, order_ascending, limit } = req.query;

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

// PUT orders status update (Admin only)
app.put('/api/db/orders/update', authenticateToken, requireAdmin, async (req, res) => {
  const { payload, field, value } = req.body;
  if (field !== 'id') {
    return res.status(400).json({ error: 'Can only update orders by id.' });
  }

  try {
    const result = await query(
      'UPDATE orders SET status = $1 WHERE id = $2 RETURNING *',
      [payload.status, value]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found.' });
    }
    res.json({ data: result.rows[0] });
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

// Send Email Function (from frontend trigger)
app.post('/api/functions/send-email', async (req, res) => {
  const { type, data } = req.body;

  if (!type || !data || !data.email) {
    return res.status(400).json({ error: 'Email destination and trigger type are required.' });
  }

  try {
    if (type === 'welcome') {
      await sendWelcomeEmail(data.email, data.name || data.email);
    } else if (type === 'order_confirmation') {
      await sendOrderConfirmationEmail(data.email, data);
    } else {
      console.warn(`Mailer: Unknown custom email function trigger: ${type}`);
    }
    res.json({ success: true });
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
    const uniqueName = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}${ext}`;
    cb(null, uniqueName);
  },
});

const fileFilter = (req, file, cb) => {
  const filetypes = /jpeg|jpg|png|webp|gif/;
  const mimetype = filetypes.test(file.mimetype);
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

  if (mimetype && extname) {
    return cb(null, true);
  }
  cb(new Error('Images only (jpeg, jpg, png, webp, gif) are allowed!'));
};

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter,
});

// Image upload route (Admin only)
app.post('/api/storage/upload', authenticateToken, requireAdmin, upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No image file uploaded.' });
  }
  res.json({ path: req.file.filename });
});

// Serve images statically
app.use('/api/storage/files', express.static(uploadsDir));

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
