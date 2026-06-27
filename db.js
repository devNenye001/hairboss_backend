import pg from 'pg';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

const isProduction = process.env.NODE_ENV === 'production';

// Render provides DATABASE_URL. In development, we can configure it manually.
const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  console.warn('WARNING: DATABASE_URL is not set. Database operations will fail.');
}

export const pool = new Pool({
  connectionString,
  ssl: isProduction ? { rejectUnauthorized: false } : false,
});

export const query = (text, params) => pool.query(text, params);

export const initDb = async () => {
  try {
    console.log('Connecting to database and running migrations...');

    // 1. Enable UUID extension if supported
    try {
      await query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp";');
    } catch (e) {
      console.log('uuid-ossp extension check/creation skipped or not supported (falling back to application-side UUID generation)');
    }

    // 2. Create users table
    await query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // 3. Create profiles table
    await query(`
      CREATE TABLE IF NOT EXISTS profiles (
        id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        full_name VARCHAR(255) DEFAULT '',
        email VARCHAR(255) DEFAULT '',
        phone VARCHAR(255) DEFAULT '',
        role VARCHAR(50) DEFAULT 'customer',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // 4. Create products table
    await query(`
      CREATE TABLE IF NOT EXISTS products (
        id UUID PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        price NUMERIC NOT NULL,
        description TEXT DEFAULT '',
        images TEXT[] DEFAULT '{}'::TEXT[],
        category VARCHAR(100) DEFAULT 'general',
        is_featured BOOLEAN DEFAULT FALSE,
        in_stock BOOLEAN DEFAULT TRUE,
        stock_count INT DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // 5. Create orders table
    await query(`
      CREATE TABLE IF NOT EXISTS orders (
        id UUID PRIMARY KEY,
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        full_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        phone VARCHAR(255) NOT NULL,
        address TEXT NOT NULL,
        city VARCHAR(255) NOT NULL,
        state VARCHAR(255) NOT NULL,
        total NUMERIC NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        payment_method VARCHAR(100) DEFAULT 'transfer',
        payment_proof VARCHAR(255) DEFAULT '',
        notes TEXT DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // 6. Create order_items table
    await query(`
      CREATE TABLE IF NOT EXISTS order_items (
        id UUID PRIMARY KEY,
        order_id UUID REFERENCES orders(id) ON DELETE CASCADE,
        product_id UUID REFERENCES products(id) ON DELETE SET NULL,
        product_name VARCHAR(255) NOT NULL,
        product_image VARCHAR(255) DEFAULT '',
        quantity INT NOT NULL DEFAULT 1,
        price NUMERIC NOT NULL
      );
    `);

    // 7. Create billing_info table
    await query(`
      CREATE TABLE IF NOT EXISTS billing_info (
        id UUID PRIMARY KEY,
        user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        full_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        phone VARCHAR(255) DEFAULT '',
        address TEXT DEFAULT '',
        city VARCHAR(255) DEFAULT '',
        state VARCHAR(255) DEFAULT '',
        country VARCHAR(255) DEFAULT 'Nigeria',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    console.log('Database tables verified/created successfully.');

    // 8. Seed Admin Account
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@onlyonehairboss.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'AdminPass123!';
    const adminFullName = process.env.ADMIN_NAME || 'Admin Hairboss';

    const adminCheck = await query('SELECT * FROM profiles WHERE role = $1 LIMIT 1', ['admin']);
    if (adminCheck.rows.length === 0) {
      console.log(`No admin account found. Creating default admin account: ${adminEmail}`);
      const userId = crypto.randomUUID();
      const salt = await bcrypt.genSalt(10);
      const passwordHash = await bcrypt.hash(adminPassword, salt);

      // Begin transaction
      await query('BEGIN');
      await query(
        'INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)',
        [userId, adminEmail, passwordHash]
      );
      await query(
        'INSERT INTO profiles (id, email, full_name, role) VALUES ($1, $2, $3, $4)',
        [userId, adminEmail, adminFullName, 'admin']
      );
      await query('COMMIT');
      console.log('Default admin seeded successfully.');
    } else {
      console.log(`Admin account exists: ${adminCheck.rows[0].email}`);
    }

  } catch (error) {
    console.error('Database migration/init failed:', error);
    throw error;
  }
};
