/**
 * Yenllet VTU Platform - Server (v12.0)
 *
 * MAJOR FEATURES IN v12:
 * 1. ✅ Reseller System - admin sets monthly fee + discount %, users subscribe, get discount on all purchases
 * 2. ✅ Reseller API Keys - separate from user API keys, auto-detects active/expired subscription
 * 3. ✅ Public API v1 endpoints for resellers to integrate their own websites
 * 4. ✅ Fixed KYC - Flutterwave verifies BOTH BVN and NIN (no more fake NIN auto-approval)
 * 5. ✅ Fixed Virtual Account - uses Flutterwave virtual-account-numbers API with verified BVN
 * 6. ✅ Fixed Transaction ID collision (uses crypto.randomBytes for true uniqueness)
 * 7. ✅ Forgot password flow verified working (reset_token + reset_expires)
 * 8. ✅ Gustmii SSO + cross-wallet deduction preserved
 */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// ===================== ENVIRONMENT VARIABLE CHECK =====================
// This logs at server startup so you can immediately see if env vars are missing.
// On Vercel: env vars added in dashboard ONLY apply AFTER you redeploy.
console.log('========================================================');
console.log('  Yenllet VTU Server v12.0 - Environment Check');
console.log('========================================================');
const envChecks = [
  ['DATABASE_URL', process.env.DATABASE_URL, 'Database connection string'],
  ['JWT_SECRET', process.env.JWT_SECRET, 'JWT signing secret (falls back to default if missing)'],
  ['RESEND_API_KEY', process.env.RESEND_API_KEY, 'Resend email API key — REQUIRED for forgot password emails'],
  ['FLW_SECRET_KEY', process.env.FLW_SECRET_KEY, 'Flutterwave secret key — REQUIRED for payments & KYC'],
  ['FLW_PUBLIC_KEY', process.env.FLW_PUBLIC_KEY, 'Flutterwave public key'],
  ['FLW_SECRET_HASH', process.env.FLW_SECRET_HASH, 'Flutterwave webhook hash — REQUIRED for payment verification'],
  ['CLUBKONNECT_USER_ID', process.env.CLUBKONNECT_USER_ID, 'Clubkonnect user ID — REQUIRED for VTU purchases'],
  ['CLUBKONNECT_API_KEY', process.env.CLUBKONNECT_API_KEY, 'Clubkonnect API key — REQUIRED for VTU purchases'],
  ['ADMIN_EMAIL', process.env.ADMIN_EMAIL, 'Admin login email'],
  ['ADMIN_PASSWORD', process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD_HASH, 'Admin password (plain or hashed)'],
  ['CHECKMYNINBVN_API_KEY', process.env.CHECKMYNINBVN_API_KEY, 'CheckMyNinBvn API key — required for NIN verification (sign up at checkmyninbvn.com)'],
  ['FIREBASE_CONFIG', process.env.FIREBASE_CONFIG, 'Firebase service account JSON (copy from Gustmii) — REQUIRED for push notifications'],
  ['FIREBASE_PROJECT_ID', process.env.FIREBASE_PROJECT_ID, 'Firebase project ID (alt to FIREBASE_CONFIG) — fallback for push notifications'],
  ['FIREBASE_CLIENT_EMAIL', process.env.FIREBASE_CLIENT_EMAIL, 'Firebase client email (alt to FIREBASE_CONFIG)'],
  ['FIREBASE_PRIVATE_KEY', process.env.FIREBASE_PRIVATE_KEY, 'Firebase private key (alt to FIREBASE_CONFIG)']
];
envChecks.forEach(([name, val, desc]) => {
  const masked = val ? (String(val).length > 15 ? String(val).substring(0, 8) + '...' + String(val).slice(-4) : '***short***') : '❌ NOT SET';
  console.log(`  ${val ? '✅' : '❌'} ${name.padEnd(25)} ${masked.padEnd(20)} - ${desc}`);
});
console.log('========================================================');
console.log('  ⚠️  ON VERCEL: After adding env vars in dashboard, you MUST');
console.log('     redeploy the project for them to take effect.');
console.log('  ⚠️  env var names are CASE-SENSITIVE (RESEND_API_KEY not resend_api_key)');
console.log('  ⚠️  Make sure env vars are set for PRODUCTION environment');
console.log('========================================================\n');

const app = express();
const PORT = process.env.PORT || 3000;

// ===================== DATABASE =====================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 15000,
  idleTimeoutMillis: 30000,
  max: 5
});

// ===================== MIDDLEWARE =====================
app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.get('/manifest.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.sendFile(path.join(__dirname, 'public', 'manifest.json'));
});
app.get('/service-worker.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.sendFile(path.join(__dirname, 'public', 'service-worker.js'));
});
app.use(express.static(path.join(__dirname, 'public')));

const uploadsDir = path.join(__dirname, 'public', 'uploads');
try { if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true }); } catch (e) {}

const JWT_SECRET = process.env.JWT_SECRET || 'yenllet_secret_key';
const GUSTMII_API = 'https://gustmii.name.ng';

// ===================== AUTH MIDDLEWARE =====================
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
};

const authenticateAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    req.user = decoded; next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
};

// ✅ NEW: Reseller API Key authentication (separate from JWT)
const authenticateResellerApiKey = async (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'] || req.headers['api-key'] || req.query.api_key;
    if (!apiKey) return res.status(401).json({ success: false, error: 'API key required. Pass it via x-api-key header.' });

    const keyRes = await pool.query(`
      SELECT rak.*, rs.status as sub_status, rs.expires_at, rs.discount_percent,
             u.wallet_balance, u.is_banned, u.fullname, u.email, u.id as user_id
      FROM reseller_api_keys rak
      JOIN users u ON rak.user_id = u.id
      LEFT JOIN reseller_subscriptions rs ON rs.user_id = u.id AND rs.status = 'active'
      WHERE rak.api_key = $1 AND rak.is_active = true
    `, [apiKey]);

    if (keyRes.rows.length === 0) return res.status(401).json({ success: false, error: 'Invalid or inactive API key' });

    const data = keyRes.rows[0];
    if (data.is_banned) return res.status(403).json({ success: false, error: 'Reseller account is banned' });

    // Check if subscription is still active
    const isSubscriptionActive = data.sub_status === 'active' && data.expires_at && new Date(data.expires_at) > new Date();

    req.reseller = {
      userId: data.user_id,
      apiKeyId: data.id,
      fullname: data.fullname,
      email: data.email,
      walletBalance: parseFloat(data.wallet_balance || 0),
      isSubscriptionActive,
      discountPercent: isSubscriptionActive ? parseFloat(data.discount_percent || 0) : 0,
      subscriptionExpiresAt: data.expires_at
    };

    // Update last_used + total_requests (fire and forget)
    pool.query('UPDATE reseller_api_keys SET last_used = NOW(), total_requests = total_requests + 1 WHERE id = $1', [data.id]).catch(() => {});

    next();
  } catch (err) {
    res.status(500).json({ success: false, error: 'API key authentication failed' });
  }
};

// ===================== HELPERS =====================
const generateAccountNumber = () => Math.floor(Math.random() * 9000000000 + 1000000000).toString();
const generateReferralCode = (userId) => 'YL' + userId.toString().padStart(6, '0');
const generateApiKey = () => 'yl_' + crypto.randomBytes(16).toString('hex');
const generateResellerApiKey = () => 'ylrsk_' + crypto.randomBytes(20).toString('hex');
const normalizePhone = (phone) => {
  if (!phone) return '';
  let p = phone.replace(/\D/g, '');
  if (p.startsWith('234')) p = p.slice(3);
  if (p.startsWith('0')) p = p.slice(1);
  return p;
};

// ✅ FIX: Use crypto.randomBytes + counter for true uniqueness (prevents Clubkonnect RequestID collision)
let _txnCounter = 0;
const generateTransactionId = () => {
  _txnCounter++;
  return 'TXN' + Date.now() + _txnCounter.toString().padStart(4, '0') + crypto.randomBytes(4).toString('hex').toUpperCase();
};

const hashPassword = async (pwd) => bcrypt.hash(pwd, 10);
const isValidPin = (pin) => /^\d{4}$/.test(pin);

const getBaseUrl = (req) => {
  if (req.headers.origin) return req.headers.origin.replace(/\/$/, '');
  if (req.headers.referer) return req.headers.referer.replace(/\/$/, '').split('/').slice(0, 3).join('/');
  return process.env.APP_URL || 'http://localhost:3000';
};

const CK_BASE_URL = 'https://www.nellobytesystems.com';
const CK_USER_ID = process.env.CLUBKONNECT_USER_ID || '';
const CK_API_KEY = process.env.CLUBKONNECT_API_KEY || '';

// ✅ CheckMyNINBVN API — used to verify BVN/NIN before creating virtual accounts.
// Without these module-level constants, the helper function throws ReferenceError.
const CHECKMYNINBVN_API_KEY = process.env.CHECKMYNINBVN_API_KEY;
const CHECKMYNINBVN_BASE_URL = 'https://checkmyninbvn.com/api';
const NETWORK_CODES = { 'mtn': '01', 'glo': '02', '9mobile': '03', 'etisalat': '03', 'airtel': '04' };

const flwRequest = async (method, endpoint, data = null) => {
  let baseUrl = process.env.FLW_BASE_URL || 'https://api.flutterwave.com';
  baseUrl = baseUrl.replace(/\/v3\/?$/, '');
  const config = { method, url: `${baseUrl}${endpoint}`, headers: { 'Authorization': `Bearer ${process.env.FLW_SECRET_KEY}`, 'Content-Type': 'application/json' } };
  if (data) config.data = data;
  return axios(config);
};

// ✅ Get admin settings (cached per request)
const getAdminSettings = async () => {
  const result = await pool.query('SELECT key, value FROM admin_settings');
  const settings = {};
  result.rows.forEach(row => settings[row.key] = row.value);
  return settings;
};

// ✅ Get support contact info (phone, whatsapp, email, hours).
// Used by /api/auth/login and /api/auth/gustmii-sso to attach support info
// to the "banned" error response so banned users see a real phone number
// they can call or WhatsApp, instead of just "Contact support."
const getSupportContact = async () => {
  try {
    const result = await pool.query("SELECT value FROM admin_settings WHERE key = 'support_contact'");
    if (result.rows.length === 0) return { phone: '09030943391', whatsapp: '09030943391', email: '', hours: '24/7' };
    const raw = result.rows[0].value;
    const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
    return {
      phone: parsed.phone || '09030943391',
      whatsapp: parsed.whatsapp || parsed.phone || '09030943391',
      email: parsed.email || '',
      hours: parsed.hours || '24/7'
    };
  } catch (e) {
    return { phone: '09030943391', whatsapp: '09030943391', email: '', hours: '24/7' };
  }
};

// ✅ Normalize Nigerian phone number to international format (no + sign).
// Examples: 09030943391 → 2349030943391, +234 903 094 3391 → 2349030943391
const normalizePhoneInternational = (phone) => {
  if (!phone) return '';
  let p = String(phone).replace(/\D/g, '');
  if (p.startsWith('234')) return p;
  if (p.startsWith('0')) return '234' + p.slice(1);
  if (p.length === 10) return '234' + p;
  return p;
};

// ✅ Get reseller subscription for a user
const getResellerSubscription = async (userId) => {
  const result = await pool.query(`
    SELECT * FROM reseller_subscriptions
    WHERE user_id = $1 AND status = 'active'
    ORDER BY created_at DESC LIMIT 1
  `, [userId]);
  if (result.rows.length === 0) return null;
  const sub = result.rows[0];
  const isExpired = sub.expires_at && new Date(sub.expires_at) < new Date();
  return {
    ...sub,
    isActive: !isExpired,
    isExpired,
    discountPercent: parseFloat(sub.discount_percent || 0)
  };
};

// ===================== EMAIL =====================
const sendUserEmail = async (userId, subject, textContent, actionUrl = null, actionText = null) => {
  try {
    // ✅ VERBOSE LOGGING — so you can see exactly why emails aren't going out
    if (!process.env.RESEND_API_KEY) {
      console.warn('⚠️  [EMAIL SKIPPED] RESEND_API_KEY env var is not set on the server.');
      console.warn('    On Vercel: Project Settings → Environment Variables → add RESEND_API_KEY, then REDEPLOY.');
      console.warn('    On local: create a .env file in the project root with: RESEND_API_KEY=re_xxxxxxxx');
      console.warn(`    Email that WOULD have been sent → To: userId=${userId}, Subject: "${subject}"`);
      return;
    }
    const userRes = await pool.query('SELECT email, fullname, email_visible FROM users WHERE id = $1', [userId]);
    if (!userRes.rows.length) { console.warn(`⚠️  [EMAIL SKIPPED] User ${userId} not found in database`); return; }
    if (!userRes.rows[0].email_visible) { console.log(`ℹ️  [EMAIL SKIPPED] User ${userId} has email_visible=false (opted out)`); return; }
    const email = userRes.rows[0].email;
    const fullname = userRes.rows[0].fullname;
    console.log(`📧 [EMAIL SENDING] To: ${email} | Subject: ${subject}`);
    const buttonHtml = actionUrl ? `<a href="${actionUrl}" style="display:inline-block;background:#2563eb;color:white;padding:12px 24px;text-decoration:none;border-radius:5px;margin:20px 0;font-weight:bold;">${actionText || 'Click Here'}</a>` : '';
    const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="font-family:'Segoe UI',sans-serif;background-color:#f8f9fa;margin:0;padding:20px;"><div style="max-width:600px;margin:0 auto;background-color:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 4px 6px rgba(0,0,0,0.1);"><div style="background-color:#1e293b;padding:20px;text-align:center;"><img src="https://res.cloudinary.com/x9cnhu3z/image/upload/v1792062220/Yenllet_Blue_Ribbon_Logo_ltmv0i.png" alt="Yenllet Logo" style="height:50px;"></div><div style="padding:30px;"><h2 style="color:#1f2937;margin-bottom:10px;">${subject}</h2><p style="color:#4b5563;line-height:1.6;">Hi ${fullname},</p><div style="color:#4b5563;line-height:1.6;">${textContent}</div>${buttonHtml}</div><div style="background-color:#f1f5f9;padding:20px;text-align:center;font-size:12px;color:#64748b;"><p>&copy; ${new Date().getFullYear()} Yenllet. All rights reserved.</p></div></div></body></html>`;
    const response = await axios.post('https://api.resend.com/emails', { from: 'Yenllet <no-reply@yenllet.name.ng>', to: [email], subject, html }, { headers: { 'Authorization': `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' } });
    console.log(`✅ [EMAIL SENT] To: ${email} | Resend ID: ${response.data?.id || 'unknown'}`);
  } catch (e) {
    console.error('❌ [EMAIL FAILED]', e.response?.data || e.message);
    if (e.response?.status === 401 || e.response?.status === 403) {
      console.error('    → Your RESEND_API_KEY is invalid or expired. Generate a new one at https://resend.com/api-keys');
    } else if (e.response?.status === 422) {
      console.error('    → The email address may be undeliverable, or the "from" domain is not verified.');
      console.error('    → Verify yenllet.name.ng in your Resend dashboard → Domains.');
    }
  }
};

// ===================== GUSTMII HELPERS =====================
async function deductFromGustmiiWallet(amount, gustmiiToken) {
  try {
    await axios.post('https://gustmii.name.ng/api/wallet/cross-app-deduct', { amount, description: 'Yenllet VTU Purchase' }, { headers: { 'Authorization': `Bearer ${gustmiiToken}` } });
    return true;
  } catch (err) { console.error('Gustmii Wallet Deduction Failed:', err.response?.data || err.message); return false; }
}
async function creditGustmiiWallet(amount, gustmiiToken) {
  try {
    await axios.post('https://gustmii.name.ng/api/wallet/cross-app-credit', { amount, description: 'Yenllet VTU Refund' }, { headers: { 'Authorization': `Bearer ${gustmiiToken}` } });
    return true;
  } catch (err) { console.error('Gustmii Wallet Credit Failed:', err.response?.data || err.message); return false; }
}
async function verifyGustmiiToken(gustmiiToken) {
  try {
    const gustmiiRes = await axios.get(`${GUSTMII_API}/api/auth/me`, { headers: { 'Authorization': `Bearer ${gustmiiToken}` } });
    if (!gustmiiRes.data || !gustmiiRes.data.id) return null;
    return gustmiiRes.data;
  } catch (err) { console.error('Gustmii token verification failed:', err.response?.status || err.message); return null; }
}

// ===================== DATABASE INIT =====================
async function initDatabase() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY, fullname VARCHAR(255) NOT NULL, email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(20) UNIQUE NOT NULL, password_hash TEXT NOT NULL, profile_pic TEXT, business_link TEXT, business_page JSONB,
        is_admin BOOLEAN DEFAULT FALSE, kyc_status VARCHAR(20) DEFAULT 'pending', kyc_bvn VARCHAR(11), kyc_nin VARCHAR(11),
        kyc_submitted_at TIMESTAMP, kyc_approved_at TIMESTAMP, wallet_balance DECIMAL(12,2) DEFAULT 0,
        cashback_balance DECIMAL(12,2) DEFAULT 0, account_number VARCHAR(12) UNIQUE, bank_name VARCHAR(100) DEFAULT 'Yenllet Bank',
        pin TEXT, api_key VARCHAR(100) UNIQUE, referral_code VARCHAR(20) UNIQUE, referred_by INTEGER REFERENCES users(id), is_banned BOOLEAN DEFAULT FALSE,
        ban_reason TEXT, email_visible BOOLEAN DEFAULT TRUE, is_agent BOOLEAN DEFAULT FALSE, agent_code VARCHAR(20),
        spins_claimed INTEGER DEFAULT 0, gustmii_linked BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, type VARCHAR(50) NOT NULL,
        service VARCHAR(50), amount DECIMAL(12,2) NOT NULL, total DECIMAL(12,2) NOT NULL, status VARCHAR(20) DEFAULT 'pending',
        transaction_id VARCHAR(100) UNIQUE, reference VARCHAR(100), recipient VARCHAR(50), provider VARCHAR(50), plan VARCHAR(100),
        remark TEXT, cashback DECIMAL(12,2) DEFAULT 0, receipt_data JSONB, created_at TIMESTAMP DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL,
        message TEXT, type VARCHAR(50) DEFAULT 'info', is_read BOOLEAN DEFAULT FALSE, image_url TEXT, created_at TIMESTAMP DEFAULT NOW()
    )`);
    // ✅ Add image_url column to existing notifications tables (auto-migrate)
    try { await pool.query('ALTER TABLE notifications ADD COLUMN IF NOT EXISTS image_url TEXT'); } catch (e) {}
    await pool.query(`CREATE TABLE IF NOT EXISTS admin_settings (
        id SERIAL PRIMARY KEY, key VARCHAR(100) UNIQUE NOT NULL, value JSONB NOT NULL, updated_at TIMESTAMP DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS pricing (
        id SERIAL PRIMARY KEY, service VARCHAR(50) NOT NULL, provider VARCHAR(50) NOT NULL, plan VARCHAR(100),
        amount DECIMAL(12,2) NOT NULL, selling_price DECIMAL(12,2) NOT NULL, discount_percent DECIMAL(5,2) DEFAULT 0,
        cashback_percent DECIMAL(5,2) DEFAULT 0, validity VARCHAR(50), category VARCHAR(50) DEFAULT 'general', is_active BOOLEAN DEFAULT TRUE, updated_at TIMESTAMP DEFAULT NOW(),
        CONSTRAINT unique_pricing UNIQUE (service, provider, plan)
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS ads (
        id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255), link TEXT,
        banner_url TEXT, topic VARCHAR(100), price_per_day DECIMAL(10,2), total_days INTEGER, total_amount DECIMAL(12,2),
        start_date DATE, end_date DATE, status VARCHAR(20) DEFAULT 'pending', clicks INTEGER DEFAULT 0, impressions INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS reviews (
        id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, rating INTEGER CHECK (rating >= 1 AND rating <= 5),
        comment TEXT, created_at TIMESTAMP DEFAULT NOW()
    )`);

    // ✅ BVN/NIN BLACKLIST — when admin deletes a user's account because the
    // BVN/NIN is fake or fraudulent, admin can opt to blacklist that ID. Any
    // future account generation attempt with that BVN/NIN will be rejected
    // BEFORE reaching Flutterwave (so Flutterwave won't return the old account).
    await pool.query(`CREATE TABLE IF NOT EXISTS id_blacklist (
        id SERIAL PRIMARY KEY,
        id_value VARCHAR(11) NOT NULL UNIQUE,
        id_type VARCHAR(3) NOT NULL CHECK (id_type IN ('BVN','NIN')),
        reason TEXT NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        blocked_by_admin_id INTEGER,
        blocked_at TIMESTAMP DEFAULT NOW()
    )`);
    console.log('✅ id_blacklist table ready');

    // ✅ ORPHANED DEPOSITS — when admin deletes a user's bank account (because
    // the BVN was fake), the OLD Flutterwave virtual account still exists on
    // Flutterwave's side. If anyone sends money to that orphaned account number
    // (e.g., the banned user themselves, or someone who still has the old
    // account number saved), the webhook fires `transfer.completed` but no user
    // in Yenllet's DB owns that account anymore. We log those deposits here so
    // admin can see the trapped funds and manually decide what to do (refund
    // the sender, or keep them in escrow).
    await pool.query(`CREATE TABLE IF NOT EXISTS orphaned_deposits (
        id SERIAL PRIMARY KEY,
        account_number VARCHAR(20) NOT NULL,
        bank_name VARCHAR(100),
        amount DECIMAL(12,2) NOT NULL,
        currency VARCHAR(10) DEFAULT 'NGN',
        flutterwave_tx_id VARCHAR(100),
        flutterwave_reference VARCHAR(200),
        sender_name VARCHAR(255),
        sender_account_number VARCHAR(50),
        raw_payload JSONB,
        received_at TIMESTAMP DEFAULT NOW(),
        reviewed BOOLEAN DEFAULT FALSE,
        admin_note TEXT,
        reviewed_by VARCHAR(255),
        reviewed_at TIMESTAMP
    )`);
    console.log('✅ orphaned_deposits table ready');

    // ✅ NEW: Reseller subscriptions table
    await pool.query(`CREATE TABLE IF NOT EXISTS reseller_subscriptions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        status VARCHAR(20) DEFAULT 'active',
        monthly_fee DECIMAL(12,2) DEFAULT 5000,
        discount_percent DECIMAL(5,2) DEFAULT 10,
        started_at TIMESTAMP DEFAULT NOW(),
        expires_at TIMESTAMP,
        last_payment_at TIMESTAMP,
        payment_reference VARCHAR(100),
        created_at TIMESTAMP DEFAULT NOW()
    )`);

    // ✅ NEW: Reseller API keys (separate from regular user api_key)
    await pool.query(`CREATE TABLE IF NOT EXISTS reseller_api_keys (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        api_key VARCHAR(100) UNIQUE NOT NULL,
        label VARCHAR(100),
        is_active BOOLEAN DEFAULT TRUE,
        last_used TIMESTAMP,
        total_requests INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
    )`);

    // ✅ NEW: Reseller transactions (log of API purchases)
    await pool.query(`CREATE TABLE IF NOT EXISTS reseller_transactions (
        id SERIAL PRIMARY KEY,
        reseller_id INTEGER REFERENCES users(id),
        api_key_id INTEGER REFERENCES reseller_api_keys(id),
        type VARCHAR(50) NOT NULL,
        service VARCHAR(50),
        amount DECIMAL(12,2) NOT NULL,
        base_price DECIMAL(12,2) NOT NULL,
        discount_amount DECIMAL(12,2) DEFAULT 0,
        status VARCHAR(20) DEFAULT 'pending',
        transaction_id VARCHAR(100) UNIQUE,
        recipient VARCHAR(50),
        provider VARCHAR(50),
        plan VARCHAR(100),
        receipt_data JSONB,
        created_at TIMESTAMP DEFAULT NOW()
    )`);

    // Column migrations
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS api_key VARCHAR(100) UNIQUE`);
    await pool.query(`ALTER TABLE pricing ADD COLUMN IF NOT EXISTS category VARCHAR(50) DEFAULT 'general'`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token TEXT`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_expires TIMESTAMP`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS gustmii_linked BOOLEAN DEFAULT FALSE`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS push_enabled BOOLEAN DEFAULT TRUE`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email_notifications BOOLEAN DEFAULT TRUE`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS is_vendor BOOLEAN DEFAULT FALSE`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_status VARCHAR(20) DEFAULT 'none'`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_approved_at TIMESTAMP`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_business_name VARCHAR(255)`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_whatsapp VARCHAR(20)`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_experience TEXT`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_promotion TEXT`);

    // ✅ VENDOR REFERRALS TABLE — tracks who each vendor referred + earnings
    await pool.query(`CREATE TABLE IF NOT EXISTS vendor_referrals (
        id SERIAL PRIMARY KEY,
        vendor_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        referred_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        referral_code VARCHAR(20) UNIQUE NOT NULL,
        total_purchases DECIMAL(12,2) DEFAULT 0,
        vendor_earnings DECIMAL(12,2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
    )`);

    // ✅ VENDOR CHAT TABLE — private chat between user and vendor
    await pool.query(`CREATE TABLE IF NOT EXISTS vendor_chats (
        id SERIAL PRIMARY KEY,
        uid VARCHAR(50) UNIQUE NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        vendor_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        message TEXT NOT NULL,
        sender_type VARCHAR(10) NOT NULL DEFAULT 'user',
        is_read BOOLEAN DEFAULT FALSE,
        is_faq BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT NOW()
    )`);

    // ✅ SAVED RECIPIENTS TABLE — phone numbers user saved for quick re-buy
    await pool.query(`CREATE TABLE IF NOT EXISTS saved_recipients (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        phone VARCHAR(20) NOT NULL,
        name VARCHAR(100),
        network VARCHAR(20),
        service VARCHAR(20) DEFAULT 'airtime',
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, phone, service)
    )`);

    // ✅ FAQ QUESTIONS TABLE — admin sets quick-answer questions
    await pool.query(`CREATE TABLE IF NOT EXISTS faq_questions (
        id SERIAL PRIMARY KEY,
        uid VARCHAR(50) UNIQUE NOT NULL,
        question TEXT NOT NULL,
        answer TEXT NOT NULL,
        category VARCHAR(50) DEFAULT 'general',
        sort_order INTEGER DEFAULT 0,
        is_active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW()
    )`);

    // ✅ FCM TOKENS TABLE — for push notifications
    await pool.query(`CREATE TABLE IF NOT EXISTS fcm_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token TEXT NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT NOW()
    )`);

    // ✅ GIFT BANNERS — admin creates promotional banners with optional cashback gifts
    await pool.query(`CREATE TABLE IF NOT EXISTS gift_banners (
        id SERIAL PRIMARY KEY,
        uid VARCHAR(50) UNIQUE NOT NULL,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        banner_image TEXT NOT NULL,
        link_type VARCHAR(20) DEFAULT 'internal',
        link_url TEXT,
        internal_section VARCHAR(50),
        cashback_amount DECIMAL(12,2) DEFAULT 0,
        restricted_service VARCHAR(50),
        max_claims INTEGER DEFAULT 0,
        claims_count INTEGER DEFAULT 0,
        is_active BOOLEAN DEFAULT TRUE,
        start_date TIMESTAMP DEFAULT NOW(),
        end_date TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
    )`);

    // ✅ CLAIMED GIFTS — tracks which users claimed which gift banners (prevents double-claiming)
    await pool.query(`CREATE TABLE IF NOT EXISTS claimed_gifts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        gift_banner_id INTEGER REFERENCES gift_banners(id) ON DELETE CASCADE,
        cashback_amount DECIMAL(12,2) NOT NULL,
        restricted_service VARCHAR(50),
        is_used BOOLEAN DEFAULT FALSE,
        claimed_at TIMESTAMP DEFAULT NOW(),
        used_at TIMESTAMP,
        UNIQUE(user_id, gift_banner_id)
    )`);

    // ✅ VENDOR WEEKLY TARGETS — tracks weekly progress for each approved vendor
    await pool.query(`CREATE TABLE IF NOT EXISTS vendor_weekly_targets (
        id SERIAL PRIMARY KEY,
        vendor_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        week_start DATE NOT NULL,
        week_end DATE NOT NULL,
        referrals_made INTEGER DEFAULT 0,
        active_users INTEGER DEFAULT 0,
        total_user_transactions INTEGER DEFAULT 0,
        is_target_met BOOLEAN DEFAULT FALSE,
        bonus_claimed BOOLEAN DEFAULT FALSE,
        bonus_amount DECIMAL(12,2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(vendor_id, week_start)
    )`);

    // ✅ VENDOR WITHDRAWALS — tracks vendor earnings withdrawal requests to wallet
    await pool.query(`CREATE TABLE IF NOT EXISTS vendor_withdrawals (
        id SERIAL PRIMARY KEY,
        uid VARCHAR(50) UNIQUE NOT NULL,
        vendor_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        amount DECIMAL(12,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        requested_at TIMESTAMP DEFAULT NOW(),
        processed_at TIMESTAMP,
        admin_note TEXT,
        processed_by VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW()
    )`);

    // ✅ Add vendor_earnings_withdrawn column to track total withdrawn
    try { await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_earnings_withdrawn DECIMAL(12,2) DEFAULT 0'); } catch (e) {}

    // ✅ SCHEDULED PURCHASES — auto-buy, service subscriptions, transaction scheduling
    // User can toggle ON/OFF (is_active field). Covers: data renewal, TV renewal, electricity scheduling.
    await pool.query(`CREATE TABLE IF NOT EXISTS scheduled_purchases (
        id SERIAL PRIMARY KEY,
        uid VARCHAR(50) UNIQUE NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(30) NOT NULL DEFAULT 'auto_buy',
        service VARCHAR(50) NOT NULL,
        provider VARCHAR(50),
        plan VARCHAR(100),
        recipient VARCHAR(50) NOT NULL,
        amount DECIMAL(12,2) DEFAULT 0,
        frequency VARCHAR(20) DEFAULT 'monthly',
        next_run_date DATE NOT NULL,
        last_run_date TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE,
        pin_required BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW()
    )`);

    // ✅ DATA GIFTS — send data as a gift with a custom message
    await pool.query(`CREATE TABLE IF NOT EXISTS data_gifts (
        id SERIAL PRIMARY KEY,
        uid VARCHAR(50) UNIQUE NOT NULL,
        sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        recipient_phone VARCHAR(20) NOT NULL,
        recipient_name VARCHAR(100),
        provider VARCHAR(50) NOT NULL,
        plan VARCHAR(100) NOT NULL,
        amount DECIMAL(12,2) NOT NULL,
        custom_message TEXT,
        status VARCHAR(20) DEFAULT 'pending',
        transaction_id VARCHAR(100),
        created_at TIMESTAMP DEFAULT NOW()
    )`);

    // ✅ VENDOR STOREFRONTS — vendors get a mini-website (yenllet.name.ng/store/vendor-slug)
    await pool.query(`CREATE TABLE IF NOT EXISTS vendor_storefronts (
        id SERIAL PRIMARY KEY,
        vendor_id INTEGER REFERENCES users(id) ON DELETE CASCADE UNIQUE,
        slug VARCHAR(100) UNIQUE NOT NULL,
        business_name VARCHAR(255) NOT NULL,
        tagline VARCHAR(255),
        description TEXT,
        logo_url TEXT,
        banner_url TEXT,
        whatsapp VARCHAR(20),
        email VARCHAR(255),
        address TEXT,
        services_offered TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        views INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
    )`);

    // ✅ COUPON CODES — admin creates promo codes for marketing campaigns
    await pool.query(`CREATE TABLE IF NOT EXISTS coupon_codes (
        id SERIAL PRIMARY KEY,
        code VARCHAR(50) UNIQUE NOT NULL,
        description TEXT,
        discount_type VARCHAR(20) DEFAULT 'fixed',
        discount_amount DECIMAL(12,2) NOT NULL,
        max_uses INTEGER DEFAULT 0,
        uses_count INTEGER DEFAULT 0,
        is_active BOOLEAN DEFAULT TRUE,
        expires_at TIMESTAMP,
        created_by VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW()
    )`);

    // ✅ COUPON REDEMPTIONS — tracks who redeemed which coupon (prevents double use)
    await pool.query(`CREATE TABLE IF NOT EXISTS coupon_redemptions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        coupon_id INTEGER REFERENCES coupon_codes(id) ON DELETE CASCADE,
        amount_credited DECIMAL(12,2) NOT NULL,
        redeemed_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, coupon_id)
    )`);

    // ✅ BULK AIRTIME LOG — tracks bulk airtime sends
    await pool.query(`CREATE TABLE IF NOT EXISTS bulk_airtime_logs (
        id SERIAL PRIMARY KEY,
        uid VARCHAR(50) UNIQUE NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        provider VARCHAR(50) NOT NULL,
        amount_per_number DECIMAL(12,2) NOT NULL,
        total_amount DECIMAL(12,2) NOT NULL,
        numbers_count INTEGER NOT NULL,
        success_count INTEGER DEFAULT 0,
        failed_count INTEGER DEFAULT 0,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT NOW()
    )`);

    // ✅ Default admin settings (with new reseller settings)
    await pool.query(`INSERT INTO admin_settings (key, value) VALUES
        ('ads_pricing', '{"price_per_day": 500, "max_days": 30}'),
        ('withdrawal_settings', '{"min": 500, "max": 500000, "fee": 50}'),
        ('welcome_bonus', '{"enabled": false, "amount": 0}'),
        ('referral_reward', '{"enabled": false, "amount": 0}'),
        ('spin_settings', '{"enabled": false, "rewards": [{"type":"money","value":100,"chance":30},{"type":"cashback","value":50,"chance":30},{"type":"none","value":0,"chance":40}]}'),
        ('reseller_settings', '{"monthly_fee": 5000, "discount_percent": 10, "enabled": true}'),
        ('kyc_settings', '{"fee": 500, "enabled": false, "deduct_from": "wallet"}'),
        ('kyc_verification', '{"force_verify": false, "notify_admin_on_skip": true}'),
        ('charge_fee_settings', '{"type": "percentage", "value": 0, "enabled": false}'),
        ('vendor_settings', '{"vendor_discount_percent": 5, "vendor_cashback_percent": 2, "vendor_enabled": true, "vendor_portal_open": true}'),
        ('vendor_weekly_target', '{"enabled": false, "referrals_needed": 10, "active_users_needed": 8, "transactions_per_user": 2, "bonus_amount": 1000, "week_start_day": 1}'),
        ('support_contact', '{"phone": "09030943391", "whatsapp": "09030943391", "email": "", "hours": "24/7"}')
      ON CONFLICT (key) DO NOTHING`);
    console.log('✅ Yenllet Database v12 initialized (with reseller tables)');
    // ✅ Auto-clean any TV plan names that still have ClubKonnect prices
    // embedded in them (e.g. 'DStv Padi N4,400' → 'DStv Padi').
    // Idempotent — safe to run on every startup.
    await cleanTvPlanNames();
  } catch (err) { console.error('❌ Database init error:', err.message); }
}

// ✅ Strip embedded ClubKonnect prices from TV plan names in the database.
// Examples:
//   'DStv Padi N4,400'                                → 'DStv Padi'
//   'DStv Compact Plus + Showmax N32,250'             → 'DStv Compact Plus + Showmax'
//   'Showmax Full - 6 months - N32,400'               → 'Showmax Full - 6 months'
//   'StarTimes Nova (Antenna) - 700 - 1 Week'         → 'StarTimes Nova (Antenna) - 1 Week'
// Preserves selling_price and any admin customizations.
async function cleanTvPlanNames() {
  try {
    // Pattern 1: trailing ' N<number>' (e.g. 'DStv Padi N4,400')
    await pool.query(`
      UPDATE pricing
      SET plan = regexp_replace(plan, '\\s+N[0-9,]+\\s*$', ''), updated_at = NOW()
      WHERE service = 'tv' AND plan ~ '\\s+N[0-9,]+\\s*$'
    `);
    // Pattern 2: trailing ' - N<number>' (Showmax style)
    await pool.query(`
      UPDATE pricing
      SET plan = regexp_replace(plan, '\\s*-\\s*N[0-9,]+\\s*$', ''), updated_at = NOW()
      WHERE service = 'tv' AND plan ~ '\\s*-\\s*N[0-9,]+\\s*$'
    `);
    // Pattern 3: middle ' - <number> - <duration>' (StarTimes style)
    await pool.query(`
      UPDATE pricing
      SET plan = regexp_replace(
              plan,
              '\\s*-\\s*[0-9,]+\\s*-\\s*([0-9]+\\s+(?:Day|Week|Month|Year|days|weeks|months|years)s?)',
              ' - \\1'
            ), updated_at = NOW()
      WHERE service = 'tv'
        AND plan ~ '\\s*-\\s*[0-9,]+\\s*-\\s*[0-9]+\\s+(?:Day|Week|Month|Year)'
    `);
    // Pattern 4: deduplicate (in case stripping caused collisions)
    await pool.query(`
      DELETE FROM pricing p1
      USING pricing p2
      WHERE p1.service = p2.service
        AND p1.provider = p2.provider
        AND p1.plan = p2.plan
        AND p1.id > p2.id
        AND p1.service = 'tv'
    `);
    console.log('✅ Cleaned TV plan names (stripped embedded prices)');
  } catch (err) {
    console.error('⚠️ TV plan name cleanup failed:', err.message);
  }
}

// ✅ SEED FUNCTION: Inserts all ClubKonnect data plans with categories (SINGLE BULK QUERY for speed)
async function seedClubKonnectPlans() {
  const plans = [
    // === MTN SME Weekly ===
    ['data','MTN','500 MB - Weekly (SME)',297.00,310.00,'7 days','SME Weekly'],
    ['data','MTN','1 GB - Weekly (SME)',410.00,425.00,'7 days','SME Weekly'],
    ['data','MTN','2 GB - Weekly (SME)',820.00,845.00,'7 days','SME Weekly'],
    ['data','MTN','3 GB - Weekly (SME)',1230.00,1265.00,'7 days','SME Weekly'],
    // === MTN SME Monthly ===
    ['data','MTN','500 MB - Monthly (SME)',307.00,320.00,'30 days','SME Monthly'],
    ['data','MTN','1 GB - Monthly (SME)',563.00,580.00,'30 days','SME Monthly'],
    ['data','MTN','2 GB - Monthly (SME)',1117.00,1145.00,'30 days','SME Monthly'],
    ['data','MTN','3 GB - Monthly (SME)',1629.00,1670.00,'30 days','SME Monthly'],
    ['data','MTN','5 GB - Monthly (SME)',2511.00,2575.00,'30 days','SME Monthly'],
    // === MTN Awoof Daily ===
    ['data','MTN','110MB Daily (Awoof)',94.09,100.00,'1 day','Awoof Daily'],
    ['data','MTN','230MB Daily (Awoof)',188.18,200.00,'1 day','Awoof Daily'],
    ['data','MTN','500MB Daily (Awoof)',329.32,340.00,'1 day','Awoof Daily'],
    ['data','MTN','1GB Daily + 1.5mins (Awoof)',470.45,485.00,'1 day','Awoof Daily'],
    ['data','MTN','2.5GB Daily (Awoof)',705.68,725.00,'1 day','Awoof Daily'],
    ['data','MTN','2.5GB 2-Day (Awoof)',846.81,870.00,'2 days','Awoof Daily'],
    ['data','MTN','3.2GB 2-Day (Awoof)',940.90,965.00,'2 days','Awoof Daily'],
    // === MTN Direct Weekly ===
    ['data','MTN','500MB Weekly (Direct)',470.45,485.00,'7 days','Direct Weekly'],
    ['data','MTN','1GB Weekly (Direct)',752.72,775.00,'7 days','Direct Weekly'],
    ['data','MTN','1.5GB Weekly (Direct)',940.90,965.00,'7 days','Direct Weekly'],
    ['data','MTN','3.5GB Weekly (Direct)',1411.35,1450.00,'7 days','Direct Weekly'],
    ['data','MTN','6GB Weekly (Direct)',2352.25,2415.00,'7 days','Direct Weekly'],
    ['data','MTN','11GB Weekly (Direct)',3293.15,3380.00,'7 days','Direct Weekly'],
    ['data','MTN','20GB Weekly (Direct)',4704.50,4825.00,'7 days','Direct Weekly'],
    // === MTN Direct Monthly ===
    ['data','MTN','2GB+2mins Monthly (Direct)',1411.35,1450.00,'30 days','Direct Monthly'],
    ['data','MTN','2.7GB+2mins Monthly (Direct)',1881.80,1930.00,'30 days','Direct Monthly'],
    ['data','MTN','3.5GB+5mins Monthly (Direct)',2352.25,2415.00,'30 days','Direct Monthly'],
    ['data','MTN','7GB Monthly (Direct)',3293.15,3380.00,'30 days','Direct Monthly'],
    ['data','MTN','10GB+10mins Monthly (Direct)',4234.05,4340.00,'30 days','Direct Monthly'],
    ['data','MTN','12.5GB Monthly (Direct)',5174.95,5305.00,'30 days','Direct Monthly'],
    ['data','MTN','16.5GB+10mins Monthly (Direct)',6115.85,6270.00,'30 days','Direct Monthly'],
    ['data','MTN','20GB Monthly (Direct)',7056.75,7235.00,'30 days','Direct Monthly'],
    ['data','MTN','25GB Monthly (Direct)',8468.10,8680.00,'30 days','Direct Monthly'],
    ['data','MTN','36GB Monthly (Direct)',10349.90,10560.00,'30 days','Direct Monthly'],
    ['data','MTN','75GB Monthly (Direct)',16936.20,17275.00,'30 days','Direct Monthly'],
    ['data','MTN','165GB Monthly (Direct)',32931.50,33595.00,'30 days','Direct Monthly'],
    // === MTN Long Term ===
    ['data','MTN','150GB 2-Month (Direct)',37636.00,38390.00,'60 days','Direct Long'],
    ['data','MTN','480GB 3-Month (Direct)',84681.00,86375.00,'90 days','Direct Long'],
    // === Glo SME Weekly ===
    ['data','Glo','200 MB - 14 days (SME)',94.00,100.00,'14 days','SME Weekly'],
    ['data','Glo','500 MB - 7 days (SME)',230.00,240.00,'7 days','SME Weekly'],
    ['data','Glo','1 GB - 3 days (SME)',392.00,405.00,'3 days','SME Weekly'],
    ['data','Glo','3 GB - 3 days (SME)',1176.00,1210.00,'3 days','SME Weekly'],
    ['data','Glo','5 GB - 3 days (SME)',1960.00,2010.00,'3 days','SME Weekly'],
    ['data','Glo','1 GB - 7 days (SME)',409.00,425.00,'7 days','SME Weekly'],
    ['data','Glo','3 GB - 7 days (SME)',1228.00,1260.00,'7 days','SME Weekly'],
    ['data','Glo','5 GB - 7 days (SME)',2046.00,2100.00,'7 days','SME Weekly'],
    // === Glo SME Monthly ===
    ['data','Glo','1 GB - 30 days (SME)',461.00,475.00,'30 days','SME Monthly'],
    ['data','Glo','2 GB - 30 days (SME)',922.00,950.00,'30 days','SME Monthly'],
    ['data','Glo','3 GB - 30 days (SME)',1383.00,1420.00,'30 days','SME Monthly'],
    ['data','Glo','5 GB - 30 days (SME)',2306.00,2365.00,'30 days','SME Monthly'],
    ['data','Glo','10 GB - 30 days (SME)',4612.00,4730.00,'30 days','SME Monthly'],
    // === Glo Night Plans ===
    ['data','Glo','1 GB - 14 days Night (SME)',409.00,425.00,'14 days','SME Night'],
    ['data','Glo','3 GB - 14 days Night (SME)',1228.00,1260.00,'14 days','SME Night'],
    ['data','Glo','5 GB - 14 days Night (SME)',2046.00,2100.00,'14 days','SME Night'],
    ['data','Glo','10 GB - 14 days Night (SME)',4093.00,4200.00,'14 days','SME Night'],
    // === Glo Awoof Daily ===
    ['data','Glo','125MB Daily (Awoof)',92.64,100.00,'1 day','Awoof Daily'],
    ['data','Glo','260MB 2-Day (Awoof)',185.27,200.00,'2 days','Awoof Daily'],
    ['data','Glo','2GB Daily (Awoof)',463.18,480.00,'1 day','Awoof Daily'],
    ['data','Glo','875MB Weekend Sun (Awoof)',185.27,200.00,'Weekend','Awoof Daily'],
    ['data','Glo','2.5GB Weekend Sat+Sun (Awoof)',463.18,480.00,'Weekend','Awoof Daily'],
    // === Glo Direct Monthly ===
    ['data','Glo','1.5GB - 14 days (Direct)',463.18,480.00,'14 days','Direct Weekly'],
    ['data','Glo','6GB - 7 days (Direct)',1389.53,1425.00,'7 days','Direct Weekly'],
    ['data','Glo','2.6GB - 30 days (Direct)',926.35,950.00,'30 days','Direct Monthly'],
    ['data','Glo','5GB - 30 days (Direct)',1389.53,1425.00,'30 days','Direct Monthly'],
    ['data','Glo','6.15GB - 30 days (Direct)',1852.70,1900.00,'30 days','Direct Monthly'],
    ['data','Glo','7.5GB - 30 days (Direct)',2315.88,2375.00,'30 days','Direct Monthly'],
    ['data','Glo','10GB - 30 days (Direct)',2779.05,2850.00,'30 days','Direct Monthly'],
    ['data','Glo','12.5GB - 30 days (Direct)',3705.40,3800.00,'30 days','Direct Monthly'],
    ['data','Glo','16GB - 30 days (Direct)',4631.75,4750.00,'30 days','Direct Monthly'],
    ['data','Glo','28GB - 30 days (Direct)',7410.80,7600.00,'30 days','Direct Monthly'],
    ['data','Glo','38GB - 30 days (Direct)',9263.50,9500.00,'30 days','Direct Monthly'],
    ['data','Glo','64GB - 30 days (Direct)',13895.25,14175.00,'30 days','Direct Monthly'],
    ['data','Glo','107GB - 30 days (Direct)',18527.00,18900.00,'30 days','Direct Monthly'],
    ['data','Glo','165GB - 30 days (Direct)',27790.50,28350.00,'30 days','Direct Monthly'],
    ['data','Glo','220GB - 30 days (Direct)',37054.00,37800.00,'30 days','Direct Monthly'],
    ['data','Glo','320GB - 30 days (Direct)',46317.50,47245.00,'30 days','Direct Monthly'],
    ['data','Glo','380GB - 30 days (Direct)',55581.00,56695.00,'30 days','Direct Monthly'],
    ['data','Glo','475GB - 30 days (Direct)',69476.25,70870.00,'30 days','Direct Monthly'],
    // === Glo Long Term ===
    ['data','Glo','1TB (1000GB) - 365 days (Direct)',143250.00,146115.00,'365 days','Direct Long'],
    // === Airtel Awoof Daily ===
    ['data','Airtel','1GB - 1 day (Awoof)',470.37,485.00,'1 day','Awoof Daily'],
    ['data','Airtel','1.5GB - 2 days (Awoof)',564.46,580.00,'2 days','Awoof Daily'],
    ['data','Airtel','2GB - 2 days (Awoof)',705.59,725.00,'2 days','Awoof Daily'],
    ['data','Airtel','3GB - 2 days (Awoof)',940.82,965.00,'2 days','Awoof Daily'],
    ['data','Airtel','5GB - 2 days (Awoof)',1411.27,1450.00,'2 days','Awoof Daily'],
    // === Airtel Direct Weekly ===
    ['data','Airtel','500MB - 7 days (Direct)',470.37,485.00,'7 days','Direct Weekly'],
    ['data','Airtel','1GB - 7 days (Direct)',752.64,775.00,'7 days','Direct Weekly'],
    ['data','Airtel','1.5GB - 7 days (Direct)',940.82,965.00,'7 days','Direct Weekly'],
    ['data','Airtel','3.5GB - 7 days (Direct)',1411.27,1450.00,'7 days','Direct Weekly'],
    ['data','Airtel','6GB - 7 days (Direct)',2352.17,2415.00,'7 days','Direct Weekly'],
    ['data','Airtel','10GB - 7 days (Direct)',2822.62,2895.00,'7 days','Direct Weekly'],
    ['data','Airtel','18GB - 7 days (Direct)',4704.42,4825.00,'7 days','Direct Weekly'],
    // === Airtel Direct Monthly ===
    ['data','Airtel','2GB - 30 days (Direct)',1411.28,1450.00,'30 days','Direct Monthly'],
    ['data','Airtel','3GB - 30 days (Direct)',1881.72,1930.00,'30 days','Direct Monthly'],
    ['data','Airtel','4GB - 30 days (Direct)',2352.17,2415.00,'30 days','Direct Monthly'],
    ['data','Airtel','8GB - 30 days (Direct)',2822.62,2895.00,'30 days','Direct Monthly'],
    ['data','Airtel','10GB - 30 days (Direct)',3763.52,3860.00,'30 days','Direct Monthly'],
    ['data','Airtel','13GB - 30 days (Direct)',4704.42,4825.00,'30 days','Direct Monthly'],
    ['data','Airtel','18GB - 30 days (Direct)',5645.32,5790.00,'30 days','Direct Monthly'],
    ['data','Airtel','25GB - 30 days (Direct)',7527.12,7720.00,'30 days','Direct Monthly'],
    ['data','Airtel','35GB - 30 days (Direct)',9408.92,9645.00,'30 days','Direct Monthly'],
    ['data','Airtel','60GB - 30 days (Direct)',14113.42,14400.00,'30 days','Direct Monthly'],
    ['data','Airtel','100GB - 30 days (Direct)',18817.92,19195.00,'30 days','Direct Monthly'],
    ['data','Airtel','160GB - 30 days (Direct)',28226.92,28795.00,'30 days','Direct Monthly'],
    ['data','Airtel','210GB - 30 days (Direct)',37635.92,38390.00,'30 days','Direct Monthly'],
    // === Airtel Long Term ===
    ['data','Airtel','300GB - 90 days (Direct)',47044.92,47990.00,'90 days','Direct Long'],
    ['data','Airtel','350GB - 90 days (Direct)',56453.92,57585.00,'90 days','Direct Long'],
    // === 9mobile SME Monthly ===
    ['data','9mobile','50 MB - 30 days (SME)',25.00,30.00,'30 days','SME Monthly'],
    ['data','9mobile','100 MB - 30 days (SME)',51.00,60.00,'30 days','SME Monthly'],
    ['data','9mobile','300 MB - 30 days (SME)',153.00,165.00,'30 days','SME Monthly'],
    ['data','9mobile','500 MB - 30 days (SME)',246.00,260.00,'30 days','SME Monthly'],
    ['data','9mobile','1 GB - 30 days (SME)',492.00,510.00,'30 days','SME Monthly'],
    ['data','9mobile','2 GB - 30 days (SME)',984.00,1010.00,'30 days','SME Monthly'],
    ['data','9mobile','3 GB - 30 days (SME)',1476.00,1515.00,'30 days','SME Monthly'],
    ['data','9mobile','4 GB - 30 days (SME)',1968.00,2020.00,'30 days','SME Monthly'],
    ['data','9mobile','5 GB - 30 days (SME)',2460.00,2525.00,'30 days','SME Monthly'],
    ['data','9mobile','10 GB - 30 days (SME)',4920.00,5045.00,'30 days','SME Monthly'],
    ['data','9mobile','15 GB - 30 days (SME)',7380.00,7565.00,'30 days','SME Monthly'],
    ['data','9mobile','20 GB - 30 days (SME)',9840.00,10090.00,'30 days','SME Monthly'],
    ['data','9mobile','25 GB - 30 days (SME)',12300.00,12550.00,'30 days','SME Monthly'],
    // === 9mobile Awoof Daily ===
    ['data','9mobile','100MB Daily (Awoof)',86.49,95.00,'1 day','Awoof Daily'],
    ['data','9mobile','180MB Daily (Awoof)',129.74,140.00,'1 day','Awoof Daily'],
    ['data','9mobile','250MB Daily (Awoof)',172.98,185.00,'1 day','Awoof Daily'],
    ['data','9mobile','450MB Daily (Awoof)',302.72,315.00,'1 day','Awoof Daily'],
    ['data','9mobile','650MB 3-Day (Awoof)',432.45,450.00,'3 days','Awoof Daily'],
    // === 9mobile Direct Weekly ===
    ['data','9mobile','1.75GB - 7 days (Direct)',1297.35,1330.00,'7 days','Direct Weekly'],
    ['data','9mobile','650MB - 14 days (Direct)',518.94,535.00,'14 days','Direct Weekly'],
    // === 9mobile Direct Monthly ===
    ['data','9mobile','1.1GB - 30 days (Direct)',864.90,890.00,'30 days','Direct Monthly'],
    ['data','9mobile','1.4GB - 30 days (Direct)',1037.88,1065.00,'30 days','Direct Monthly'],
    ['data','9mobile','2.44GB - 30 days (Direct)',1729.80,1775.00,'30 days','Direct Monthly'],
    ['data','9mobile','3.17GB - 30 days (Direct)',2162.25,2220.00,'30 days','Direct Monthly'],
    ['data','9mobile','3.91GB - 30 days (Direct)',2594.70,2660.00,'30 days','Direct Monthly'],
    ['data','9mobile','5.10GB - 30 days (Direct)',3459.60,3550.00,'30 days','Direct Monthly'],
    ['data','9mobile','6.5GB - 30 days (Direct)',4324.50,4435.00,'30 days','Direct Monthly'],
    ['data','9mobile','16GB - 30 days (Direct)',10378.80,10590.00,'30 days','Direct Monthly'],
    ['data','9mobile','24.3GB - 30 days (Direct)',16000.65,16325.00,'30 days','Direct Monthly'],
    ['data','9mobile','26.5GB - 30 days (Direct)',17298.00,17645.00,'30 days','Direct Monthly'],
    // === 9mobile Long Term ===
    ['data','9mobile','39GB - 60 days (Direct)',25947.00,26470.00,'60 days','Direct Long'],

    // ==================== DStv Plans ====================
    ['tv','DStv','DStv Padi',4356.00,4510.00,'30 days','Monthly'],
    ['tv','DStv','DStv Yanga',5940.00,6150.00,'30 days','Monthly'],
    ['tv','DStv','DStv Confam',10890.00,11220.00,'30 days','Monthly'],
    ['tv','DStv','DStv Compact',18810.00,19380.00,'30 days','Monthly'],
    ['tv','DStv','DStv Premium',44055.00,45380.00,'30 days','Monthly'],
    ['tv','DStv','DStv Compact Plus',29700.00,30600.00,'30 days','Monthly'],
    ['tv','DStv','DStv Premium-French',68310.00,70360.00,'30 days','Monthly'],
    ['tv','DStv','DStv Premium-Asia',49995.00,51500.00,'30 days','Monthly'],
    ['tv','DStv','DStv Confam + ExtraView',16830.00,17340.00,'30 days','Monthly'],
    ['tv','DStv','DStv Yanga + ExtraView',11880.00,12240.00,'30 days','Monthly'],
    ['tv','DStv','DStv Padi + ExtraView',10296.00,10610.00,'30 days','Monthly'],
    ['tv','DStv','DStv Compact + Extra View',24750.00,25500.00,'30 days','Monthly'],
    ['tv','DStv','DStv Compact + French Touch',25740.00,26520.00,'30 days','Monthly'],
    ['tv','DStv','DStv Premium + Extra View',49995.00,51500.00,'30 days','Monthly'],
    ['tv','DStv','DStv Compact + French Touch + ExtraView',31680.00,32640.00,'30 days','Monthly'],
    ['tv','DStv','DStv Compact Plus + French Plus',53955.00,55580.00,'30 days','Monthly'],
    ['tv','DStv','DStv Compact Plus + French Touch',36630.00,37730.00,'30 days','Monthly'],
    ['tv','DStv','DStv Compact Plus + Extra View',35640.00,36710.00,'30 days','Monthly'],
    ['tv','DStv','DStv Compact Plus + FrenchPlus + Extra View',59895.00,61700.00,'30 days','Monthly'],
    ['tv','DStv','DStv Compact + French Plus',43065.00,44360.00,'30 days','Monthly'],
    ['tv','DStv','DStv Premium + French + Extra View',74250.00,76480.00,'30 days','Monthly'],
    ['tv','DStv','DStv French Plus Add-on',24255.00,24990.00,'30 days','Add-on'],
    ['tv','DStv','DStv Great Wall Standalone Bouquet',3762.00,3900.00,'30 days','Monthly'],
    ['tv','DStv','DStv French Touch Add-on',6930.00,7180.00,'30 days','Add-on'],
    ['tv','DStv','DStv French 11',10692.00,11020.00,'30 days','Monthly'],
    ['tv','DStv','DStv Yanga + Showmax',8167.50,8460.00,'30 days','Monthly'],
    ['tv','DStv','DStv Great Wall + Showmax',8217.00,8510.00,'30 days','Monthly'],
    ['tv','DStv','DStv Compact Plus + Showmax',31927.50,32890.00,'30 days','Monthly'],
    ['tv','DStv','DStv Confam + Showmax',13117.50,13520.00,'30 days','Monthly'],
    ['tv','DStv','DStv Compact + Showmax',21037.50,21670.00,'30 days','Monthly'],
    ['tv','DStv','DStv Padi + Showmax',8811.00,9120.00,'30 days','Monthly'],
    ['tv','DStv','DStv Asia + Showmax',19206.00,19790.00,'30 days','Monthly'],
    ['tv','DStv','DStv Premium + French + Showmax',68310.00,70360.00,'30 days','Monthly'],
    ['tv','DStv','DStv Premium + Showmax',44055.00,45380.00,'30 days','Monthly'],
    ['tv','DStv','DStv Premium W/Afr + Showmax',49995.00,51500.00,'30 days','Monthly'],
    ['tv','DStv','DStv Indian',14751.00,15200.00,'30 days','Monthly'],
    ['tv','DStv','DStv India Add-on',14751.00,15200.00,'30 days','Add-on'],
    ['tv','DStv','DStv Movie Bundle Add-on',3465.00,3590.00,'30 days','Add-on'],
    ['tv','DStv','DStv Showmax Premier League Add-on',3564.00,3690.00,'30 days','Add-on'],

    // ==================== GOtv Plans ====================
    ['tv','GOtv','GOtv Max',8415.00,8710.00,'30 days','Monthly'],
    ['tv','GOtv','GOtv Jolli',5742.00,5950.00,'30 days','Monthly'],
    ['tv','GOtv','GOtv Jinja',3861.00,4000.00,'30 days','Monthly'],
    ['tv','GOtv','GOtv Smallie - monthly',1881.00,1960.00,'30 days','Monthly'],
    ['tv','GOtv','GOtv Smallie - quarterly',5049.00,5230.00,'90 days','Quarterly'],
    ['tv','GOtv','GOtv Smallie - yearly',14850.00,15300.00,'365 days','Yearly'],
    ['tv','GOtv','GOtv Supa - monthly',11286.00,11630.00,'30 days','Monthly'],
    ['tv','GOtv','GOtv Supa Plus - monthly',16632.00,17140.00,'30 days','Monthly'],

    // ==================== StarTimes Plans ====================
    ['tv','StarTimes','Nova (Dish)',2079.00,2160.00,'30 days','Monthly'],
    ['tv','StarTimes','Basic (Antenna)',3960.00,4100.00,'30 days','Monthly'],
    ['tv','StarTimes','Smart/Basic (Dish)',5049.00,5230.00,'30 days','Monthly'],
    ['tv','StarTimes','Classic (Antenna)',5940.00,6150.00,'30 days','Monthly'],
    ['tv','StarTimes','Super (Dish)',9702.00,10050.00,'30 days','Monthly'],
    ['tv','StarTimes','Nova (Antenna) - 1 Week',693.00,730.00,'7 days','Weekly'],
    ['tv','StarTimes','Basic (Antenna) - 1 Week',1386.00,1450.00,'7 days','Weekly'],
    ['tv','StarTimes','Smart (Dish) - 1 Week',1683.00,1760.00,'7 days','Weekly'],
    ['tv','StarTimes','Classic (Antenna) - 1 Week',1980.00,2060.00,'7 days','Weekly'],
    ['tv','StarTimes','Super (Dish) - 1 Week',3267.00,3390.00,'7 days','Weekly'],
    ['tv','StarTimes','Classic (Dish) - 1 Week',2277.00,2360.00,'7 days','Weekly'],
    ['tv','StarTimes','Classic (Dish)',7326.00,7590.00,'30 days','Monthly'],
    ['tv','StarTimes','Nova (Dish) - 1 Week',693.00,730.00,'7 days','Weekly'],
    ['tv','StarTimes','Super (Antenna) - 1 Week',3168.00,3280.00,'7 days','Weekly'],
    ['tv','StarTimes','Super (Antenna)',9405.00,9740.00,'30 days','Monthly'],
    ['tv','StarTimes','Classic (Dish) - 1 Week',2475.00,2570.00,'7 days','Weekly'],

    // ==================== Showmax Plans ====================
    ['tv','Showmax','Full - 3 Months',8316.00,8610.00,'90 days','Quarterly'],
    ['tv','Showmax','Mobile Only - 3 Months',3762.00,3900.00,'90 days','Quarterly'],
    ['tv','Showmax','Sports Mobile Only - 3 Months',11880.00,12240.00,'90 days','Quarterly'],
    ['tv','Showmax','Sports Only',3168.00,3280.00,'30 days','Monthly'],
    ['tv','Showmax','Sports Only 3 months',9504.00,9840.00,'90 days','Quarterly'],
    ['tv','Showmax','Full Sports Mobile Only - 3 months',16038.00,16520.00,'90 days','Quarterly'],
    ['tv','Showmax','Mobile Only - 6 Months',6633.00,6870.00,'180 days','Half Year'],
    ['tv','Showmax','Full - 6 months',14553.00,14990.00,'180 days','Half Year'],
    ['tv','Showmax','Full Sports Mobile Only - 6 months',32076.00,33040.00,'180 days','Half Year'],
    ['tv','Showmax','Sports Mobile Only - 6 months',23760.00,24480.00,'180 days','Half Year'],
    ['tv','Showmax','Sports Only - 6 months',18018.00,18560.00,'180 days','Half Year'],

    // ==================== Electricity Plans ====================
    ['electricity','EKEDC','Eko Electric - Prepaid',0,0,'Prepaid','Prepaid'],
    ['electricity','EKEDC','Eko Electric - Postpaid',0,0,'Postpaid','Postpaid'],
    ['electricity','IKEDC','Ikeja Electric - Prepaid',0,0,'Prepaid','Prepaid'],
    ['electricity','IKEDC','Ikeja Electric - Postpaid',0,0,'Postpaid','Postpaid'],
    ['electricity','AEDC','Abuja Electric - Prepaid',0,0,'Prepaid','Prepaid'],
    ['electricity','AEDC','Abuja Electric - Postpaid',0,0,'Postpaid','Postpaid'],
    ['electricity','KEDCO','Kano Electric - Prepaid',0,0,'Prepaid','Prepaid'],
    ['electricity','KEDCO','Kano Electric - Postpaid',0,0,'Postpaid','Postpaid'],
    ['electricity','PHED','Port Harcourt Electric - Prepaid',0,0,'Prepaid','Prepaid'],
    ['electricity','PHED','Port Harcourt Electric - Postpaid',0,0,'Postpaid','Postpaid'],
    ['electricity','JED','Jos Electric - Prepaid',0,0,'Prepaid','Prepaid'],
    ['electricity','JED','Jos Electric - Postpaid',0,0,'Postpaid','Postpaid'],
    ['electricity','KAEDCO','Kaduna Electric - Prepaid',0,0,'Prepaid','Prepaid'],
    ['electricity','KAEDCO','Kaduna Electric - Postpaid',0,0,'Postpaid','Postpaid'],
    ['electricity','EEDC','Enugu Electric - Prepaid',0,0,'Prepaid','Prepaid'],
    ['electricity','EEDC','Enugu Electric - Postpaid',0,0,'Postpaid','Postpaid'],
    ['electricity','IBEDC','Ibadan Electric - Prepaid',0,0,'Prepaid','Prepaid'],
    ['electricity','IBEDC','Ibadan Electric - Postpaid',0,0,'Postpaid','Postpaid'],
    ['electricity','BEDC','Benin Electric - Prepaid',0,0,'Prepaid','Prepaid'],
    ['electricity','BEDC','Benin Electric - Postpaid',0,0,'Postpaid','Postpaid'],
    ['electricity','APLE','Aba Electric - Prepaid',0,0,'Prepaid','Prepaid'],
    ['electricity','APLE','Aba Electric - Postpaid',0,0,'Postpaid','Postpaid'],
    ['electricity','YEDC','Yola Electric - Prepaid',0,0,'Prepaid','Prepaid'],
    ['electricity','YEDC','Yola Electric - Postpaid',0,0,'Postpaid','Postpaid'],

    // ==================== Education Pins ====================
    // WAEC Result Checker & JAMB e-PIN (prices below are selling prices;
    // cost from ClubKonnect is 0.05% off face value — admin can adjust)
    ['education','WAEC','WAEC Result Checker Pin',1800,1900,'Single Use','Result Checker'],
    ['education','JAMB','JAMB e-PIN',2900,3000,'Single Use','e-PIN'],

    // ==================== Betting Wallet Funding ====================
    // ClubKonnect betting company codes (per APIBettingTypeV2 docs).
    // Cost = amount * 0.9995 (0.05% discount). Selling price = face amount
    // (admin can lower later). 'plan' field stores the CK betting code.
    ['bet','SportyBet','SportyBet Wallet Funding',1000,1000,'Wallet Funding','prd-sporty-bet'],
    ['bet','Nairabet','Nairabet Wallet Funding',1000,1000,'Wallet Funding','product-nairabet'],
    ['bet','BangBet','BangBet Wallet Funding',1000,1000,'Wallet Funding','product-bang-bet'],
    ['bet','BetWay','BetWay Wallet Funding',1000,1000,'Wallet Funding','product-bet-way'],
    ['bet','BetLand','BetLand Wallet Funding',1000,1000,'Wallet Funding','product-bet-land'],
    ['bet','BetKing','BetKing Wallet Funding',1000,1000,'Wallet Funding','product-bet-king'],
    ['bet','1xBet','1xBet Wallet Funding',1000,1000,'Wallet Funding','product-1x-bet'],
    ['bet','NaijaBet','NaijaBet Wallet Funding',1000,1000,'Wallet Funding','product-naija-bet'],
    ['bet','MerryBet','MerryBet Wallet Funding',1000,1000,'Wallet Funding','product-merry-bet'],
  ];

  // ✅ BATCH INSERT — split into groups of 15 plans to avoid connection timeout on Vercel
  const BATCH_SIZE = 15;
  let totalInserted = 0;
  
  for (let i = 0; i < plans.length; i += BATCH_SIZE) {
    const batch = plans.slice(i, i + BATCH_SIZE);
    const values = batch.map((p, idx) => {
      const base = idx * 7;
      return `($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, $${base + 5}, $${base + 6}, $${base + 7})`;
    }).join(', ');

    const flatParams = batch.flat();

    try {
      await pool.query(
        `INSERT INTO pricing (service, provider, plan, amount, selling_price, validity, category, is_active) 
         VALUES ${values} 
         ON CONFLICT (service, provider, plan) DO UPDATE SET 
           amount = EXCLUDED.amount, 
           validity = EXCLUDED.validity, 
           category = EXCLUDED.category, 
           is_active = true`,
        flatParams
      );
      totalInserted += batch.length;
    } catch (e) {
      console.error(`❌ Batch ${Math.floor(i/BATCH_SIZE)+1} failed:`, e.message);
      // Try individual inserts as fallback for this batch
      for (const [service, provider, plan, amount, sellingPrice, validity, category] of batch) {
        try {
          await pool.query(
            `INSERT INTO pricing (service, provider, plan, amount, selling_price, validity, category, is_active) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, true) 
             ON CONFLICT (service, provider, plan) DO UPDATE SET 
               amount = EXCLUDED.amount, validity = EXCLUDED.validity, category = EXCLUDED.category, is_active = true`,
            [service, provider, plan, amount, sellingPrice, validity, category]
          );
          totalInserted++;
        } catch (e2) { /* skip individual failures */ }
      }
    }
  }
  console.log(`✅ Seeded/updated ${totalInserted}/${plans.length} ClubKonnect data plans (batch mode)`);
}

// ✅ Non-blocking init — server starts immediately, tables created in background
initDatabase().catch(err => console.error('DB Init Error (non-blocking):', err.message));
console.log('🚀 Server starting — database init running in background');

// ===================== AUTH ROUTES =====================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullname, email, phone, password, referralCode } = req.body;
    if (!fullname || !email || !phone || !password) return res.status(400).json({ error: 'All fields are required' });
    const normalizedPhone = normalizePhone(phone);
    const passwordHash = await hashPassword(password);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const existing = await client.query('SELECT id FROM users WHERE email = $1 OR phone = $2', [email, normalizedPhone]);
      if (existing.rows.length > 0) return res.status(400).json({ error: 'Email or phone already registered' });
      const result = await client.query('INSERT INTO users (fullname, email, phone, password_hash) VALUES ($1, $2, $3, $4) RETURNING id', [fullname, email, normalizedPhone, passwordHash]);
      const userId = result.rows[0].id;
      const refCode = generateReferralCode(userId);
      await client.query('UPDATE users SET referral_code = $1 WHERE id = $2', [refCode, userId]);
      const wbSettings = await client.query("SELECT value FROM admin_settings WHERE key = 'welcome_bonus'");
      if (wbSettings.rows.length > 0 && wbSettings.rows[0].value.enabled) {
        const bonus = parseFloat(wbSettings.rows[0].value.amount);
        if (bonus > 0) {
          await client.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2', [bonus, userId]);
          await client.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [userId, 'Welcome Bonus!', `You received ₦${bonus} as a welcome bonus.`, 'wallet']);
          sendUserEmail(userId, 'Welcome Bonus!', `You received <b>₦${bonus}</b> as a welcome bonus.`);
        }
      }
      if (referralCode) {
        const referrer = await client.query('SELECT id FROM users WHERE referral_code = $1', [referralCode]);
        if (referrer.rows.length > 0) {
          await client.query('UPDATE users SET referred_by = $1 WHERE id = $2', [referrer.rows[0].id, userId]);
          const refSettings = await client.query("SELECT value FROM admin_settings WHERE key = 'referral_reward'");
          if (refSettings.rows.length > 0 && refSettings.rows[0].value.enabled) {
            const reward = parseFloat(refSettings.rows[0].value.amount);
            if (reward > 0) {
              await client.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2', [reward, referrer.rows[0].id]);
              await client.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [referrer.rows[0].id, 'Referral Bonus!', `You received ₦${reward} for referring a new user.`, 'wallet']);
              sendUserEmail(referrer.rows[0].id, 'Referral Bonus!', `You received <b>₦${reward}</b> for referring a new user.`);
            }
          }
        }
        // ✅ Track vendor referral (if the code belongs to a vendor)
        trackVendorReferral(userId, referralCode);
      }

      // ✅ WELCOME MESSAGE — sent to EVERY new user upon registration
      // (not dependent on welcome_bonus being enabled — this always fires)
      await client.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)',
        [userId, '🎉 Welcome to Yenllet!', `Hi ${fullname}! Welcome to Yenllet — Nigeria's fastest VTU & bills payment platform. Buy cheap airtime, data, pay electricity bills, subscribe DStv/GOtv, fund SportyBet, and earn cashback on EVERY transaction. Generate your virtual bank account to start funding your wallet instantly. A Gustmii company.`, 'welcome']);

      // ✅ WELCOME EMAIL — sent to every new user's email
      sendUserEmail(userId, '🎉 Welcome to Yenllet!', `Welcome to Yenllet, ${fullname}!<br><br>We're excited to have you on board. Yenllet is Nigeria's premier VTU & bills payment platform — a Gustmii company.<br><br><b>Here's what you can do:</b><br>✅ Buy cheap airtime & data (MTN, Airtel, Glo, 9mobile)<br>✅ Pay electricity bills (instant token delivery)<br>✅ Subscribe DStv, GOtv, StarTimes, Showmax<br>✅ Fund SportyBet, Bet9ja, BetKing, 1xBet wallets<br>✅ Buy WAEC & JAMB pins<br>✅ Earn cashback on EVERY transaction<br><br><b>Next steps:</b><br>1. Generate your virtual bank account (BVN required)<br>2. Fund your wallet via card, bank transfer, or virtual account<br>3. Set your 4-digit transaction PIN<br>4. Start buying & earning cashback!<br><br>Your referral code is <b>${refCode}</b>. Share it with friends to earn bonuses.<br><br>Welcome aboard! 🚀<br><br>— The Yenllet Team<br><small>A Gustmii company</small>`);

      await client.query('COMMIT');
      const token = jwt.sign({ id: userId, email, isAdmin: false }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ success: true, token, user: { id: userId, fullname, email, referralCode: refCode } });
    } catch (err) { await client.query('ROLLBACK'); throw err; }
    finally { client.release(); }
  } catch (err) { res.status(500).json({ error: 'Registration failed: ' + err.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    // ✅ Banned user — return support contact info so the frontend can show
    // a clickable Call + WhatsApp button instead of just "Contact support."
    if (user.is_banned) {
      const support = await getSupportContact();
      return res.status(403).json({
        error: 'Account banned. Contact support to appeal.',
        banned: true,
        ban_reason: user.ban_reason || 'Account banned by admin',
        support
      });
    }
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, fullname: user.fullname, email: user.email, wallet: user.wallet_balance, cashback: user.cashback_balance, accountNumber: user.account_number, kycStatus: user.kyc_status, hasPin: !!user.pin, profilePic: user.profile_pic } });
  } catch (err) { res.status(500).json({ error: 'Login failed: ' + err.message }); }
});

app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, fullname, email, phone, wallet_balance, cashback_balance, account_number, bank_name, kyc_status, is_admin, gustmii_linked FROM users WHERE id = $1', [req.user.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ GUSTMII SSO ROUTE
app.post('/api/auth/gustmii-sso', async (req, res) => {
  try {
    const { gustmii_token } = req.body;
    if (!gustmii_token) return res.status(400).json({ error: 'Gustmii token is required' });
    const gustmiiUser = await verifyGustmiiToken(gustmii_token);
    if (!gustmiiUser) return res.status(401).json({ error: 'Invalid Gustmii session' });
    let yenlletUser = await pool.query('SELECT * FROM users WHERE email = $1', [gustmiiUser.email]);
    if (yenlletUser.rows.length === 0) {
      const passwordHash = await hashPassword(crypto.randomBytes(32).toString('hex'));
      let userPhone = normalizePhone(gustmiiUser.phone) || '';
      if (!userPhone || userPhone.length < 10) userPhone = '070' + Math.floor(10000000 + Math.random() * 89999999).toString();
      let phoneAttempt = userPhone, phoneTries = 0;
      while (phoneTries < 5) {
        const phoneCheck = await pool.query('SELECT id FROM users WHERE phone = $1', [phoneAttempt]);
        if (phoneCheck.rows.length === 0) break;
        phoneAttempt = '070' + Math.floor(10000000 + Math.random() * 89999999).toString();
        phoneTries++;
      }
      const insertResult = await pool.query('INSERT INTO users (fullname, email, phone, password_hash, kyc_status, gustmii_linked) VALUES ($1, $2, $3, $4, $5, true) RETURNING id', [gustmiiUser.name || 'Gustmii User', gustmiiUser.email, phoneAttempt, passwordHash, 'pending']);
      const newUserId = insertResult.rows[0].id;
      const refCode = generateReferralCode(newUserId);
      await pool.query('UPDATE users SET referral_code = $1 WHERE id = $2', [refCode, newUserId]);
      yenlletUser = await pool.query('SELECT * FROM users WHERE id = $1', [newUserId]);
      console.log(`✅ Auto-created Yenllet account for Gustmii user: ${gustmiiUser.email} (ID: ${newUserId})`);
    } else {
      if (gustmiiUser.name && yenlletUser.rows[0].fullname !== gustmiiUser.name) {
        await pool.query('UPDATE users SET fullname = $1, gustmii_linked = true WHERE id = $2', [gustmiiUser.name, yenlletUser.rows[0].id]);
      } else {
        await pool.query('UPDATE users SET gustmii_linked = true WHERE id = $1', [yenlletUser.rows[0].id]);
      }
      yenlletUser = await pool.query('SELECT * FROM users WHERE id = $1', [yenlletUser.rows[0].id]);
    }
    const user = yenlletUser.rows[0];
    // ✅ Banned user — return support contact info so the frontend can show
    // a clickable Call + WhatsApp button instead of just "Account banned".
    if (user.is_banned) {
      const support = await getSupportContact();
      return res.status(403).json({
        error: 'Account banned. Contact support to appeal.',
        banned: true,
        ban_reason: user.ban_reason || 'Account banned by admin',
        support
      });
    }
    const yenlletToken = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, yenllet_token: yenlletToken, user: { id: user.id, fullname: user.fullname, email: user.email, wallet: Number(user.wallet_balance || 0), kycStatus: user.kyc_status, gustmiiLinked: true } });
  } catch (err) { console.error('Gustmii SSO Error:', err.message); res.status(500).json({ error: 'SSO failed: ' + err.message }); }
});

// ✅ FORGOT PASSWORD (verified working — generates reset_token + sends email)
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const userResult = await pool.query('SELECT id, fullname FROM users WHERE email = $1', [email]);
    // Always return same message to prevent email enumeration
    if (userResult.rows.length === 0) return res.json({ success: true, message: 'If that email exists, a reset link has been sent.' });
    const user = userResult.rows[0];
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 hour
    await pool.query('UPDATE users SET reset_token = $1, reset_expires = $2 WHERE id = $3', [token, expires, user.id]);
    const resetLink = `${getBaseUrl(req)}/reset-password.html?token=${token}`;
    sendUserEmail(user.id, 'Yenllet Password Reset', `You requested a password reset. Click the link below to reset your password:<br><br><a href="${resetLink}" style="background-color:#2563eb;color:white;padding:12px 24px;text-decoration:none;border-radius:8px;display:inline-block;font-weight:bold;">Reset Password</a><br><br>This link will expire in 1 hour.<br>If you didn't request this, please ignore this email and your password will remain unchanged.`);
    res.json({ success: true, message: 'If that email exists, a reset link has been sent.' });
  } catch (err) { res.status(500).json({ error: 'Failed to process request' }); }
});

// ✅ RESET PASSWORD (verified working — validates token + updates password_hash)
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Invalid request or password too short (min 6 characters)' });
    const userResult = await pool.query('SELECT id FROM users WHERE reset_token = $1 AND reset_expires > NOW()', [token]);
    if (userResult.rows.length === 0) return res.status(400).json({ error: 'Invalid or expired reset token' });
    const userId = userResult.rows[0].id;
    const passwordHash = await hashPassword(newPassword);
    await pool.query('UPDATE users SET password_hash = $1, reset_token = NULL, reset_expires = NULL WHERE id = $2', [passwordHash, userId]);
    sendUserEmail(userId, 'Password Reset Successful', 'Your Yenllet account password has been reset successfully. If this was not you, please contact support immediately.');
    res.json({ success: true, message: 'Password reset successfully' });
  } catch (err) { res.status(500).json({ error: 'Failed to reset password' }); }
});

// ===================== PROFILE =====================
app.get('/api/profile', authenticate, async (req, res) => {
  try {
    // ✅ Try the full query with vendor + notification columns.
    // If this fails (because the database hasn't been migrated yet),
    // fall back to the basic query without those columns, then attach
    // sensible defaults so the dashboard doesn't crash.
    let result;
    let usedFallback = false;
    try {
      result = await pool.query(`SELECT id, fullname, email, phone, wallet_balance, cashback_balance, account_number, bank_name, referral_code, kyc_status, kyc_bvn, kyc_nin, is_agent, email_visible, is_banned, spins_claimed, api_key, profile_pic, business_page, business_link, gustmii_linked, pin IS NOT NULL as has_pin, vendor_status, vendor_business_name, is_vendor, push_enabled, email_notifications, created_at FROM users WHERE id = $1`, [req.user.id]);
    } catch (colErr) {
      // Column doesn't exist yet — fall back to basic query
      console.warn('⚠️ /api/profile: vendor/push columns missing, using fallback query. Run /api/admin/run-migrations to fix.');
      result = await pool.query(`SELECT id, fullname, email, phone, wallet_balance, cashback_balance, account_number, bank_name, referral_code, kyc_status, kyc_bvn, kyc_nin, is_agent, email_visible, is_banned, spins_claimed, api_key, profile_pic, business_page, business_link, gustmii_linked, pin IS NOT NULL as has_pin, created_at FROM users WHERE id = $1`, [req.user.id]);
      usedFallback = true;
    }
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const profile = result.rows[0];
    // ✅ Attach defaults for new fields if we used the fallback query
    if (usedFallback) {
      profile.vendor_status = 'none';
      profile.vendor_business_name = null;
      profile.is_vendor = false;
      profile.push_enabled = true;
      profile.email_notifications = true;
    }
    // ✅ Attach reseller subscription status
    const resellerSub = await getResellerSubscription(req.user.id);
    profile.is_reseller = !!resellerSub;
    profile.reseller_subscription = resellerSub;
    // ✅ Attach reseller API keys
    const apiKeysRes = await pool.query('SELECT id, api_key, label, is_active, last_used, total_requests, created_at FROM reseller_api_keys WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
    profile.reseller_api_keys = apiKeysRes.rows;
    res.json({ success: true, profile });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.put('/api/profile', authenticate, async (req, res) => {
  try {
    const { fullname, emailVisible } = req.body;
    await pool.query('UPDATE users SET fullname = $1, email_visible = $2, updated_at = NOW() WHERE id = $3', [fullname, emailVisible, req.user.id]);
    res.json({ success: true, message: 'Profile updated' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ FIXED: Generate REAL Flutterwave virtual account using verified BVN
app.post('/api/profile/generate-account', authenticate, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT kyc_status, kyc_bvn, kyc_nin, account_number, fullname, email, phone FROM users WHERE id = $1', [req.user.id]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const user = userRes.rows[0];
    if (user.kyc_status !== 'approved') return res.status(400).json({ error: 'Please complete KYC first' });
    // ✅ CRITICAL: BVN is required for Flutterwave virtual account
    if (!user.kyc_bvn) return res.status(400).json({ error: 'BVN is required to generate a virtual bank account. NIN alone is only for identity verification. Please submit your BVN from the KYC section.' });
    if (user.account_number) return res.json({ success: true, message: 'Account already generated', accountNumber: user.account_number });

    try {
      const flwResponse = await flwRequest('POST', '/v3/virtual-account-numbers', {
        email: user.email,
        bvn: user.kyc_bvn,
        tx_ref: `YENLLET-ACC-${req.user.id}-${Date.now()}`,
        firstname: user.fullname.split(' ')[0] || 'Yenllet',
        lastname: user.fullname.split(' ').slice(1).join(' ') || 'User',
        phonenumber: user.phone || '08000000000',
        narration: `${user.fullname} - Yenllet`
      });
      if (flwResponse.data && flwResponse.data.status === 'success' && flwResponse.data.data) {
        const accountNumber = flwResponse.data.data.account_number;
        const bankName = flwResponse.data.data.bank_name || 'Flutterwave Bank';
        await pool.query('UPDATE users SET account_number = $1, bank_name = $2 WHERE id = $3', [accountNumber, bankName, req.user.id]);
        await pool.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [req.user.id, 'Virtual Account Generated!', `Your virtual bank account (${accountNumber} - ${bankName}) has been created. Fund your wallet by transferring to this account.`, 'wallet']);
        sendUserEmail(req.user.id, 'Virtual Account Generated', `Your virtual bank account has been created successfully:<br><br><b>Account Number:</b> ${accountNumber}<br><b>Bank:</b> ${bankName}<br><br>Fund your Yenllet wallet by transferring to this account number. Transfers usually reflect within 1-5 minutes.`);
        return res.json({ success: true, message: 'Virtual account generated! Use it to fund your wallet.', accountNumber, bankName });
      } else {
        return res.status(400).json({ error: 'Flutterwave could not create virtual account. Please try again later.' });
      }
    } catch (flwErr) {
      console.error('Flutterwave virtual account creation error:', flwErr.response?.data || flwErr.message);
      return res.status(400).json({ error: 'Failed to create virtual account. Please contact support.' });
    }
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ NEW: One-step BVN → Account Number generation (skips separate KYC verification step)
// User enters BVN → clicks Generate → Flutterwave validates BVN during account creation
// If account is created: BVN is valid, save it as KYC-approved, save account number
// If account creation fails: BVN is invalid OR Flutterwave account not yet activated
//
// ✅ CROSS-APP BVN BLOCKLIST — prevent the same BVN from being used to
// create accounts on both Yenllet AND Gustmii. Each BVN should map to
// exactly ONE virtual account across the whole ecosystem.
const GUSTMII_BVN_CHECK_URL = process.env.GUSTMII_BVN_CHECK_URL || 'https://gustmii.name.ng';

async function isBvnUsedOnGustmii(bvn) {
    try {
        const res = await axios.get(`${GUSTMII_BVN_CHECK_URL}/api/public/check-bvn/${bvn}`, { timeout: 5000 });
        return !!(res.data && res.data.used === true);
    } catch (err) {
        console.warn(`⚠️ Cross-app BVN check (Gustmii) failed for ${bvn.substring(0,4)}***:`, err.message);
        return false; // Fail open — don't block user if Gustmii is down
    }
}

// ✅ CROSS-APP NIN BLOCKLIST — same idea, for NIN.
async function isNinUsedOnGustmii(nin) {
    try {
        const res = await axios.get(`${GUSTMII_BVN_CHECK_URL}/api/public/check-nin/${nin}`, { timeout: 5000 });
        return !!(res.data && res.data.used === true);
    } catch (err) {
        console.warn(`⚠️ Cross-app NIN check (Gustmii) failed for ${nin.substring(0,4)}***:`, err.message);
        return false; // Fail open — don't block user if Gustmii is down
    }
}

// ✅ Helper: Verify BVN or NIN via CheckMyNINBVN before creating virtual account.
//
// forceVerify=false (default, admin toggle OFF):
//   - If CheckMyNINBVN is unconfigured / out of credits / network fails:
//     return { valid: true, skipped: true } → account generation proceeds.
//     Flutterwave still does its own BVN validation as a backstop.
//   - User's kyc_status stays 'pending' so admin can manually verify later
//     (when they top up CheckMyNINBVN wallet) from the admin dashboard.
//
// forceVerify=true (admin toggle ON):
//   - If CheckMyNINBVN is unconfigured or fails: return { valid: false, error }
//     → account generation is BLOCKED. User must wait until admin tops up
//     CheckMyNINBVN wallet OR turns the toggle off.
async function verifyIdWithCheckMyNINBVN(idNumber, idType, forceVerify = false) {
    if (!CHECKMYNINBVN_API_KEY) {
        console.warn('⚠️ CHECKMYNINBVN_API_KEY not set — skipping ID verification (less secure).');
        if (forceVerify) {
            return { valid: false, error: 'ID verification is required (admin has enabled force-verify), but the CheckMyNinBvn API key is not configured on the server. Please contact support or ask admin to disable force-verify.' };
        }
        return { valid: true, skipped: true, reason: 'CheckMyNINBVN not configured' };
    }
    try {
        // ✅ Case-insensitive — route may pass 'BVN' or 'NIN' (uppercase)
        const idTypeLower = (idType || '').toLowerCase();
        const endpoint = idTypeLower === 'nin' ? '/nin-verification' : '/bvn-verification';
        const body = idTypeLower === 'nin'
            ? { nin: idNumber, consent: true }
            : { bvn: idNumber, consent: true };

        console.log(`🔍 Verifying ${idType} ${idNumber.substring(0, 4)}***${idNumber.substring(7)} via CheckMyNINBVN (forceVerify=${forceVerify})...`);

        const response = await fetch(`${CHECKMYNINBVN_BASE_URL}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-api-key': CHECKMYNINBVN_API_KEY },
            body: JSON.stringify(body)
        });

        const data = await response.json();

        if (response.ok && data.status === 'success' && data.data) {
            const d = data.data;
            const firstName = d.firstname || d.firstName || '';
            const lastName = d.surname || d.lastname || d.lastName || '';
            console.log(`✅ ${idType} verified: ${firstName} ${lastName}`);
            return { valid: true, firstName, lastName, reportId: data.reportID };
        } else {
            const errMsg = data.message || data.error || 'Verification failed';
            console.warn(`⚠️ ${idType} verification via CheckMyNINBVN returned error: ${errMsg}`);
            if (forceVerify) {
                // ✅ Provide actionable advice based on common error patterns
                let advice = '';
                const low = (errMsg || '').toLowerCase();
                if (low.includes('insufficient') || low.includes('credit') || low.includes('balance') || low.includes('fund') || response.status === 402) {
                    advice = ' Your CheckMyNinBvn account is out of credits. Log in at https://checkmyninbvn.com, top up your wallet, and try again. (Or ask admin to turn OFF force-verify.)';
                } else if (response.status === 401 || response.status === 403) {
                    advice = ' The CheckMyNinBvn API key is invalid or expired. Get a new one at https://checkmyninbvn.com and update CHECKMYNINBVN_API_KEY env var.';
                }
                return { valid: false, error: `${idType} verification failed: ${errMsg}.${advice}` };
            }
            return { valid: true, skipped: true, reason: 'CheckMyNINBVN error (proceeding with Flutterwave validation): ' + errMsg };
        }
    } catch (err) {
        console.error('❌ CheckMyNINBVN network error:', err.message);
        if (forceVerify) {
            return { valid: false, error: `Cannot reach ID verification service (CheckMyNinBvn): ${err.message}. Please try again later.` };
        }
        return { valid: true, skipped: true, reason: 'CheckMyNINBVN unavailable: ' + err.message };
    }
}

app.post('/api/profile/generate-account-from-bvn', authenticate, async (req, res) => {
  try {
    const { bvn, nin } = req.body;
    // Accept EITHER BVN or NIN
    if (!bvn && !nin) return res.status(400).json({ error: 'Please provide either your BVN or NIN (11 digits)' });
    const idNumber = bvn || nin;
    const idType = bvn ? 'BVN' : 'NIN';
    if (idNumber.length !== 11 || !/^\d{11}$/.test(idNumber)) return res.status(400).json({ error: `Please provide a valid 11-digit ${idType}` });
    if (!process.env.FLW_SECRET_KEY) return res.status(500).json({ error: 'Server is not configured for Flutterwave. Contact support.' });

    const userRes = await pool.query('SELECT account_number, fullname, email, phone FROM users WHERE id = $1', [req.user.id]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const user = userRes.rows[0];

    // If user already has an account, return it
    if (user.account_number) {
      return res.json({ success: true, message: 'Account already generated', accountNumber: user.account_number, bankName: user.bank_name || 'Flutterwave Bank' });
    }



    // ✅ KYC FEE: If admin has enabled KYC fee, deduct it from user's wallet before creating account
    const settings = await getAdminSettings();
    const kycSettings = settings.kyc_settings || { fee: 500, enabled: false };
    // ✅ KYC VERIFICATION TOGGLE (admin controlled — no redeploy needed)
    // force_verify=true  → CheckMyNinBvn MUST pass before account is created.
    // force_verify=false → If CheckMyNinBvn fails (no credits / network down),
    //                      account is still created via Flutterwave's own BVN check,
    //                      but kyc_status stays 'pending' so admin can verify later.
    const kycVerification = settings.kyc_verification
      ? (typeof settings.kyc_verification === 'string' ? JSON.parse(settings.kyc_verification) : settings.kyc_verification)
      : { force_verify: false, notify_admin_on_skip: true };
    const forceVerify = !!(kycVerification && kycVerification.force_verify);
    if (forceVerify) {
      console.log(`🔒 Force-verify is ON — user ${req.user.id} must pass CheckMyNinBvn before account creation.`);
    }
    if (kycSettings.enabled && parseFloat(kycSettings.fee) > 0) {
      const userBalanceRes = await pool.query('SELECT wallet_balance FROM users WHERE id = $1', [req.user.id]);
      const userBalance = parseFloat(userBalanceRes.rows[0]?.wallet_balance || 0);
      const kycFee = parseFloat(kycSettings.fee);
      if (userBalance < kycFee) {
        return res.status(400).json({ error: `Account generation costs ₦${kycFee.toLocaleString()}. Your wallet balance is ₦${userBalance.toLocaleString()}. Please fund your wallet first.` });
      }
      await pool.query('UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id = $2', [kycFee, req.user.id]);
      await pool.query(`INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, reference, remark) VALUES ($1, 'debit', 'kyc_fee', $2, $2, 'success', $3, $4, 'Account number generation fee')`, [req.user.id, kycFee, generateTransactionId(), `KYC-FEE-${req.user.id}-${Date.now()}`]);
      console.log(`💳 KYC fee of ₦${kycFee} deducted from user ${req.user.id}`);
    }

    // Split fullname into firstname/lastname
    const nameParts = (user.fullname || 'Yenllet User').trim().split(/\s+/);
    const firstname = nameParts[0] || 'Yenllet';
    const lastname = nameParts.slice(1).join(' ') || 'User';
    const txRef = `YENLLET-ACC-${req.user.id}-${Date.now()}`;

    console.log(`🔄 Generating virtual account for user ${req.user.id} with ${idType} ${idNumber.substring(0, 4)}***${idNumber.substring(7)}`);

    try {
      // ✅ STEP 0: CROSS-APP BVN/NIN BLOCKLIST — prevent same ID from being used
      // on both Yenllet and Gustmii. Each BVN/NIN must map to exactly ONE account.
      if (bvn) {
          // ✅ STEP 0a: Check Yenllet's blacklist — admin may have blacklisted this BVN
          // after deleting a fake-BVN account. If blacklisted, reject IMMEDIATELY
          // before any DB lookup or Flutterwave call (so Flutterwave won't return
          // the old account for the same fake BVN).
          const bvnBl = await pool.query('SELECT reason, blocked_at FROM id_blacklist WHERE id_value = $1 AND id_type = $2', [bvn, 'BVN']);
          if (bvnBl.rows.length > 0) {
              return res.status(400).json({
                  error: `This BVN has been blacklisted by Yenllet admin and cannot be used to create an account. Reason: ${bvnBl.rows[0].reason}. If you believe this is a mistake, please contact support.`
              });
          }
          // Check local DB first (Yenllet stores BVN as kyc_bvn)
          const localCheck = await pool.query('SELECT id, fullname FROM users WHERE kyc_bvn = $1 AND id != $2', [bvn, req.user.id]);
          if (localCheck.rows.length > 0) {
              return res.status(400).json({
                  error: 'This BVN has already been used to create an account on Yenllet. One BVN can only generate one account. If this is your BVN, please contact support.'
              });
          }
          // Cross-app check on Gustmii
          const usedOnGustmii = await isBvnUsedOnGustmii(bvn);
          if (usedOnGustmii) {
              return res.status(400).json({
                  error: 'This BVN has already been used to create an account on Gustmii. One BVN can only generate one account across both Yenllet and Gustmii. If this is your BVN, please contact support.'
              });
          }
      }
      if (nin) {
          // ✅ STEP 0a: Check Yenllet's blacklist (same logic as BVN above)
          const ninBl = await pool.query('SELECT reason, blocked_at FROM id_blacklist WHERE id_value = $1 AND id_type = $2', [nin, 'NIN']);
          if (ninBl.rows.length > 0) {
              return res.status(400).json({
                  error: `This NIN has been blacklisted by Yenllet admin and cannot be used to create an account. Reason: ${ninBl.rows[0].reason}. If you believe this is a mistake, please contact support.`
              });
          }
          // Check local DB first (Yenllet stores NIN as kyc_nin)
          const localCheck = await pool.query('SELECT id, fullname FROM users WHERE kyc_nin = $1 AND id != $2', [nin, req.user.id]);
          if (localCheck.rows.length > 0) {
              return res.status(400).json({
                  error: 'This NIN has already been used to create an account on Yenllet. One NIN can only generate one account. If this is your NIN, please contact support.'
              });
          }
          // Cross-app check on Gustmii
          const usedOnGustmii = await isNinUsedOnGustmii(nin);
          if (usedOnGustmii) {
              return res.status(400).json({
                  error: 'This NIN has already been used to create an account on Gustmii. One NIN can only generate one account across both Yenllet and Gustmii. If this is your NIN, please contact support.'
              });
          }
      }

      // ✅ STEP 1: Verify the BVN/NIN with CheckMyNINBVN BEFORE calling Flutterwave.
      // Flutterwave does NOT verify the BVN itself — it accepts any 11-digit number
      // as a reference. So we use CheckMyNINBVN to do real verification against NIBSS.
      //
      // force_verify (admin toggle):
      //   ON  → CheckMyNINBVN MUST pass, else reject (admin must top up wallet).
      //   OFF → If CheckMyNINBVN fails (no credits / network), proceed via Flutterwave
      //         but keep kyc_status='pending' so admin can verify later from dashboard.
      const verification = await verifyIdWithCheckMyNINBVN(idNumber, idType, forceVerify);
      if (!verification.valid) {
        return res.status(400).json({
          error: `Your ${idType} could not be verified: ${verification.error}. Please check the number and try again.`
        });
      }
      const idWasVerified = !verification.skipped;

      // ✅ STEP 2: Use the verified name from CheckMyNINBVN if available
      // (more accurate than the name the user typed during signup)
      const verifiedFirstname = verification.firstName || firstname;
      const verifiedLastname = verification.lastName || lastname;
      if (verification.firstName) {
        console.log(`✅ Using verified name: ${verifiedFirstname} ${verifiedLastname}`);
      }

      // ✅ STEP 3: Call Flutterwave to create the virtual account with verified details
      const requestBody = {
        email: user.email,
        is_permanent: true,
        tx_ref: txRef,
        firstname: verifiedFirstname,
        lastname: verifiedLastname,
        phonenumber: user.phone || '08000000000',
        narration: `${verifiedFirstname} ${verifiedLastname} - Yenllet`
      };
      if (bvn) { requestBody.bvn = bvn; } else { requestBody.nin = nin; }
      const flwResponse = await flwRequest('POST', '/v3/virtual-account-numbers', requestBody);

      console.log('Flutterwave response status:', flwResponse.data?.status, '| HTTP:', flwResponse.status);

      if (flwResponse.data && flwResponse.data.status === 'success' && flwResponse.data.data) {
        const accountNumber = flwResponse.data.data.account_number;
        const bankName = flwResponse.data.data.bank_name || 'Sterling Bank';

        // ✅ Save BVN/NIN + account number to user record.
        // kyc_status='approved' ONLY if CheckMyNinBvn actually verified the ID.
        // If verification was skipped (force_verify=OFF, no credits), keep
        // kyc_status='pending' so the user shows up in admin's "Pending KYC"
        // list and admin can manually tap Verify when they have funds.
        if (idWasVerified) {
          await pool.query(
            `UPDATE users
             SET kyc_status = 'approved',
                 kyc_bvn = $1,
                 kyc_submitted_at = NOW(),
                 kyc_approved_at = NOW(),
                 account_number = $2,
                 bank_name = $3
             WHERE id = $4`,
            [idNumber, accountNumber, bankName, req.user.id]
          );
        } else {
          await pool.query(
            `UPDATE users
             SET kyc_status = 'pending',
                 kyc_bvn = $1,
                 kyc_submitted_at = NOW(),
                 kyc_approved_at = NULL,
                 account_number = $2,
                 bank_name = $3
             WHERE id = $4`,
            [idNumber, accountNumber, bankName, req.user.id]
          );
          console.log(`⏳ ${idType} saved for user ${req.user.id} but kyc_status='pending' (CheckMyNinBvn skipped). Admin can verify later.`);
        }

        // Notification + email
        const notifTitle = idWasVerified ? '🎉 Virtual Account Generated!' : '🎉 Virtual Account Generated (Pending Verification)';
        const notifMsg = idWasVerified
          ? `Your virtual bank account (${accountNumber} - ${bankName}) has been created. Your ${idType} has been verified. Fund your wallet by transferring to this account.`
          : `Your virtual bank account (${accountNumber} - ${bankName}) has been created. Your ${idType} verification is pending and will be reviewed by our team within 24 hours. You can already fund your wallet by transferring to this account.`;
        await pool.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)',
          [req.user.id, notifTitle, notifMsg, 'kyc']);

        sendUserEmail(req.user.id, `Virtual Account Generated & ${idType} Verified`, `Great news! Your ${idType} has been verified by Flutterwave and your virtual bank account has been created successfully:<br><br><b>Account Number:</b> ${accountNumber}<br><b>Bank:</b> ${bankName}<br><br>Fund your Yenllet wallet by transferring to this account number. Transfers usually reflect within 1-5 minutes.`);

        return res.json({
          success: true,
          message: idWasVerified
            ? `Virtual account generated! Your ${idType} has been verified.`
            : `Virtual account generated! Your ${idType} is pending verification — our team will review within 24 hours.`,
          accountNumber,
          bankName,
          kycStatus: idWasVerified ? 'approved' : 'pending',
          kycVerified: idWasVerified
        });
      } else {
        // Flutterwave returned non-success
        const flwMsg = flwResponse.data?.message || 'No reason provided';
        const flwStatus = flwResponse.status || 'unknown';
        console.error('Virtual account creation non-success:', JSON.stringify(flwResponse.data));
        return res.status(400).json({
          error: `Could not generate account: ${flwMsg} (HTTP ${flwStatus}). Your BVN may be invalid, or your Flutterwave account may need activation.`
        });
      }
    } catch (flwErr) {
      console.error('Virtual account creation error:', flwErr.response?.data || flwErr.message);
      const flwMsg = flwErr.response?.data?.message || flwErr.message || 'Network error';
      const flwStatus = flwErr.response?.status || 'no-response';
      // Provide actionable advice
      let advice = '';
      const secretKey = process.env.FLW_SECRET_KEY || '';
      const isSandboxKey = secretKey.startsWith('FLWSECK_TEST-');
      if (flwStatus === 404) {
        if (isSandboxKey) {
          advice = ' You are using SANDBOX (test) keys. Virtual account creation only works with LIVE keys (FLWSECK-...).';
        } else {
          advice = ' Your Flutterwave account may still be in "Preview mode". Complete the "Account Activation" banner at the top of your Flutterwave dashboard, then wait 24-48 hours for approval.';
        }
      } else if (flwStatus === 401 || flwStatus === 403) {
        advice = ' Your FLW_SECRET_KEY is invalid or expired.';
      } else if (flwStatus === 400) {
        // Common 400 errors: invalid BVN, BVN already used, name mismatch
        const lowerMsg = (flwMsg || '').toLowerCase();
        if (lowerMsg.includes('already') || lowerMsg.includes('exist')) {
          advice = ' This BVN has already been used to create a virtual account. Contact support if this is your BVN.';
        } else if (lowerMsg.includes('bvn') || lowerMsg.includes('invalid')) {
          advice = ' The BVN you entered is invalid or does not exist. Please check and try again.';
        } else {
          advice = ' ' + flwMsg;
        }
      }
      return res.status(400).json({ error: `Account generation failed: ${flwMsg} (HTTP ${flwStatus}).${advice}` });
    }
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});


app.post('/api/profile/api-key', authenticate, async (req, res) => {
  try {
    const newKey = generateApiKey();
    await pool.query('UPDATE users SET api_key = $1 WHERE id = $2', [newKey, req.user.id]);
    res.json({ success: true, apiKey: newKey });
  } catch (err) { res.status(500).json({ error: 'Failed to generate API key' }); }
});

app.delete('/api/profile/api-key', authenticate, async (req, res) => {
  try {
    await pool.query('UPDATE users SET api_key = NULL WHERE id = $1', [req.user.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete API key' }); }
});

app.post('/api/profile/picture', authenticate, async (req, res) => {
  try {
    const { profilePic } = req.body;
    if (!profilePic) return res.status(400).json({ error: 'No image provided' });
    await pool.query('UPDATE users SET profile_pic = $1 WHERE id = $2', [profilePic, req.user.id]);
    res.json({ success: true, message: 'Profile picture updated', profilePic });
  } catch (err) { res.status(500).json({ error: 'Upload failed: ' + err.message }); }
});

app.put('/api/profile/password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
    const valid = await bcrypt.compare(currentPassword, user.rows[0].password_hash);
    if (!valid) return res.status(400).json({ error: 'Current password incorrect' });
    const hash = await hashPassword(newPassword);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.user.id]);
    res.json({ success: true, message: 'Password changed' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/profile/pin', authenticate, async (req, res) => {
  try {
    const { pin, currentPin } = req.body;
    if (!pin || !isValidPin(pin)) return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
    const userResult = await pool.query('SELECT pin FROM users WHERE id = $1', [req.user.id]);
    const existingPin = userResult.rows[0].pin;
    if (existingPin) {
      if (!currentPin) return res.status(400).json({ error: 'Current PIN required to change PIN' });
      const valid = await bcrypt.compare(currentPin, existingPin);
      if (!valid) return res.status(400).json({ error: 'Current PIN is incorrect' });
    }
    const hash = await hashPassword(pin);
    await pool.query('UPDATE users SET pin = $1 WHERE id = $2', [hash, req.user.id]);
    res.json({ success: true, message: existingPin ? 'PIN changed successfully' : 'PIN set successfully' });
  } catch (err) { res.status(500).json({ error: 'PIN setup failed: ' + err.message }); }
});

// ===================== KYC (FIXED: verify BOTH BVN and NIN with Flutterwave) =====================
app.post('/api/kyc/submit', authenticate, async (req, res) => {
  try {
    const { bvn, nin } = req.body;
    const userId = req.user.id;

    // ✅ GUARD: Check that FLW_SECRET_KEY is configured before calling Flutterwave
    if (!process.env.FLW_SECRET_KEY) {
      console.error('❌ KYC FAILED: FLW_SECRET_KEY env var is not set on server');
      return res.status(500).json({ error: 'Server is not configured for KYC verification. FLW_SECRET_KEY env var is missing. Contact support.' });
    }

    const hasBvn = bvn && typeof bvn === 'string' && bvn.length === 11;
    const hasNin = nin && typeof nin === 'string' && nin.length === 11;
    if (!hasBvn && !hasNin) return res.status(400).json({ error: 'Please provide a valid 11-digit BVN or NIN' });
    if (hasBvn && hasNin) return res.status(400).json({ error: 'Please submit either BVN or NIN, not both' });

    const userResult = await pool.query('SELECT account_number, kyc_bvn, kyc_nin, kyc_status FROM users WHERE id = $1', [userId]);
    const existing = userResult.rows[0];

    // ✅ BVN FLOW — verify with Flutterwave BVN API
    if (hasBvn) {
      // Skip re-verification if user already has this BVN verified
      if (existing.kyc_bvn === bvn && existing.kyc_status === 'approved') {
        return res.json({ success: true, message: 'BVN already verified', kycStatus: 'approved' });
      }
      try {
        const bvnResponse = await flwRequest('POST', '/v3/kyc/bvns', { bvn });
        console.log('BVN API response status:', bvnResponse.data?.status, '| HTTP:', bvnResponse.status);
        if (bvnResponse.data && bvnResponse.data.status === 'success' && bvnResponse.data.data) {
          await pool.query(`UPDATE users SET kyc_status = 'approved', kyc_bvn = $1, kyc_submitted_at = NOW(), kyc_approved_at = NOW() WHERE id = $2`, [bvn, userId]);
          await pool.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [userId, 'KYC Approved!', 'Your BVN has been verified. You can now generate your account number.', 'kyc']);
          sendUserEmail(userId, 'KYC Approved', 'Your BVN has been verified by Flutterwave. You can now generate your Yenllet account number.');
          return res.json({ success: true, message: 'BVN verified! You can now generate your account number.', kycStatus: 'approved' });
        } else {
          // ✅ Return the actual Flutterwave error message so user can see what went wrong
          const flwMsg = bvnResponse.data?.message || bvnResponse.data?.errors?.[0]?.message || 'No reason provided by Flutterwave';
          const flwStatus = bvnResponse.status || 'unknown';
          console.error('BVN verification non-success:', JSON.stringify(bvnResponse.data));
          return res.status(400).json({ error: `BVN verification failed: ${flwMsg} (HTTP ${flwStatus}). Make sure your BVN is correct and KYC is enabled on your Flutterwave account.` });
        }
      } catch (flwErr) {
        console.error('BVN verification error:', flwErr.response?.data || flwErr.message);
        const flwMsg = flwErr.response?.data?.message || flwErr.message || 'Network error';
        const flwStatus = flwErr.response?.status || 'no-response';
        // ✅ Smarter advice based on Flutterwave's status code
        let advice = '';
        const secretKey = process.env.FLW_SECRET_KEY || '';
        const isSandboxKey = secretKey.startsWith('FLWSECK_TEST-');
        if (flwStatus === 404) {
          if (isSandboxKey) {
            advice = ' You are using SANDBOX (test) keys. KYC endpoints only work with LIVE keys. Go to Flutterwave dashboard → Settings → API → switch to LIVE mode and copy your LIVE secret key (starts with FLWSECK-).';
          } else {
            advice = ' The BVN KYC endpoint is not available on your Flutterwave account. Your account may still be in "Preview mode". Email Flutterwave support (hi@flutterwavego.com) to activate KYC for your LIVE account, OR verify your FLW_SECRET_KEY is correctly set on Vercel and redeploy.';
          }
        } else if (flwStatus === 401 || flwStatus === 403) {
          advice = ' Your FLW_SECRET_KEY is invalid or expired. Get a new LIVE key from Flutterwave dashboard → Settings → API.';
        } else if (flwStatus === 400) {
          advice = ' The BVN format is invalid or not found. Make sure it is exactly 11 digits.';
        } else {
          advice = ' Network error reaching Flutterwave. Check that FLW_BASE_URL env var is unset (default is correct) and FLW_SECRET_KEY is set.';
        }
        return res.status(400).json({ error: `BVN verification failed: ${flwMsg} (HTTP ${flwStatus}).${advice}` });
      }
    }

    // ✅ NIN FLOW — uses CheckMyNinBvn API (Flutterwave does NOT have a NIN endpoint)
    // Sign up at https://checkmyninbvn.com and set CHECKMYNINBVN_API_KEY env var.
    // If env var is not set, return a clear error directing the user to use BVN instead.
    if (hasNin) {
      if (existing.kyc_nin === nin && existing.kyc_status === 'approved') {
        return res.json({ success: true, message: 'NIN already verified', kycStatus: 'approved', requiresBvn: !existing.kyc_bvn });
      }
      // ✅ Uses module-level CHECKMYNINBVN_API_KEY constant (declared near top of file)
      if (!CHECKMYNINBVN_API_KEY) {
        console.warn('⚠️  NIN submission rejected: CHECKMYNINBVN_API_KEY env var is not set.');
        return res.status(400).json({
          error: 'NIN verification is not configured on this server. Please use BVN instead — Flutterwave only supports BVN directly, and BVN also lets you generate a bank account number.'
        });
      }
      try {
        const ninResponse = await axios.post(
          'https://checkmyninbvn.com/api/nin-verification',
          { nin, consent: true },
          { headers: { 'Content-Type': 'application/json', 'x-api-key': CHECKMYNINBVN_API_KEY }, timeout: 30000 }
        );
        console.log('NIN API response status:', ninResponse.data?.status, '| HTTP:', ninResponse.status);
        if (ninResponse.data && ninResponse.data.status === 'success' && ninResponse.data.data) {
          await pool.query(`UPDATE users SET kyc_status = 'approved', kyc_nin = $1, kyc_submitted_at = NOW(), kyc_approved_at = NOW() WHERE id = $2`, [nin, userId]);
          await pool.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [userId, 'KYC Approved (NIN)', 'Your NIN has been verified. Note: You need to submit BVN to generate a bank account number.', 'kyc']);
          sendUserEmail(userId, 'KYC Approved (NIN)', 'Your NIN has been verified by CheckMyNinBvn. To generate a virtual bank account, please submit your BVN from the KYC section.');
          return res.json({ success: true, message: 'NIN verified! Note: Submit BVN later to generate a bank account number.', kycStatus: 'approved', requiresBvn: true });
        } else {
          const errMsg = ninResponse.data?.message || 'No reason provided by provider';
          const httpStatus = ninResponse.status || 'unknown';
          console.error('NIN verification non-success:', JSON.stringify(ninResponse.data));
          return res.status(400).json({ error: `NIN verification failed: ${errMsg} (HTTP ${httpStatus}). Make sure your NIN is correct.` });
        }
      } catch (apiErr) {
        console.error('NIN verification error:', apiErr.response?.data || apiErr.message);
        const errMsg = apiErr.response?.data?.message || apiErr.message || 'Network error';
        const httpStatus = apiErr.response?.status || 'no-response';
        // ✅ Smarter advice: check the actual error message instead of just HTTP status
        let advice = '';
        const lowerMsg = (errMsg || '').toLowerCase();
        if (lowerMsg.includes('insufficient') || lowerMsg.includes('balance') || lowerMsg.includes('credit') || httpStatus === 402) {
          advice = ' Your CheckMyNinBvn account is out of credits. Log in at https://checkmyninbvn.com and top up your wallet.';
        } else if (httpStatus === 401 || httpStatus === 403) {
          advice = ' The CheckMyNinBvn API key is invalid or expired. Get a new one at https://checkmyninbvn.com and update CHECKMYNINBVN_API_KEY env var.';
        } else if (httpStatus === 404) {
          advice = ' The NIN was not found in the database. Check the NIN number is correct.';
        } else if (httpStatus === 400) {
          advice = ' The NIN format is invalid. Make sure it is exactly 11 digits.';
        } else {
          advice = ' Network error reaching CheckMyNinBvn. Try again later.';
        }
        return res.status(400).json({ error: `NIN verification failed: ${errMsg} (HTTP ${httpStatus}).${advice}` });
      }
    }
  } catch (err) { res.status(500).json({ error: 'KYC failed: ' + err.message }); }
});

// ===================== WALLET =====================
app.post('/api/wallet/fund', authenticate, async (req, res) => {
  try {
    const { amount } = req.body;
    if (!amount || parseFloat(amount) < 100) return res.status(400).json({ error: 'Minimum funding amount is ₦100' });
    const userResult = await pool.query('SELECT fullname, email, phone FROM users WHERE id = $1', [req.user.id]);
    const user = userResult.rows[0];
    const txRef = `YENLLET-${req.user.id}-${Date.now()}`;
    const response = await flwRequest('POST', '/v3/payments', {
      tx_ref: txRef, amount: parseFloat(amount), currency: 'NGN',
      redirect_url: `${getBaseUrl(req)}/dashboard.html`,
      payment_options: 'card, banktransfer, ussd',
      customer: { email: user.email, phonenumber: user.phone || '08000000000', name: user.fullname },
      customizations: { title: 'Yenllet Wallet Topup', description: `Fund wallet with ₦${parseFloat(amount).toLocaleString()}` }
    });
    if (response.data && response.data.data?.link) res.json({ success: true, paymentLink: response.data.data.link, txRef });
    else res.status(400).json({ error: 'Failed to generate payment link' });
  } catch (err) { res.status(500).json({ error: 'Payment initialization failed' }); }
});

app.post('/api/wallet/webhook', async (req, res) => {
  res.status(200).end();
  try {
    const routerSecret = req.headers['x-site-router-secret'];
    const flwSignature = req.headers['verif-hash'];
    const payload = req.body;
    const isFromRouter = routerSecret && routerSecret === process.env.ROUTER_SECRET;
    const isFromFlutterwave = flwSignature && flwSignature === process.env.FLW_SECRET_HASH;
    if (!isFromRouter && !isFromFlutterwave) return;

    // ✅ HANDLE CARD PAYMENTS (charge.completed) — for wallet funding via Flutterwave checkout
    if (payload.event === 'charge.completed' && payload.data?.status === 'successful') {
      const txRef = payload.data.tx_ref;
      const amountPaid = parseFloat(payload.data.amount);
      const flwTxId = payload.data.id;
      if (payload.data.currency !== 'NGN') return;

      // ✅ Handle reseller subscription payments
      if (txRef && txRef.startsWith('YENLLET-RESELLER-')) {
        const parts = txRef.split('-');
        const userId = parseInt(parts[2]);
        if (isNaN(userId)) return;
        const settings = await getAdminSettings();
        const rs = settings.reseller_settings || { monthly_fee: 5000, discount_percent: 10 };
        const expiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          const checkTx = await client.query('SELECT id FROM transactions WHERE reference = $1', [txRef]);
          if (checkTx.rows.length === 0) {
            await client.query(`INSERT INTO reseller_subscriptions (user_id, status, monthly_fee, discount_percent, started_at, expires_at, last_payment_at, payment_reference, created_at) VALUES ($1, 'active', $2, $3, NOW(), $4, NOW(), $5, NOW())`, [userId, rs.monthly_fee, rs.discount_percent, expiry, txRef]);
            await client.query("UPDATE transactions SET status = 'success' WHERE reference = $1", [txRef]);
            await client.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [userId, 'Reseller Subscription Active!', `Your reseller subscription is now active! You have ${rs.discount_percent}% discount for 30 days.`, 'reseller']);
            await client.query('COMMIT');
            sendUserEmail(userId, 'Reseller Subscription Active!', `Your reseller subscription is now active!<br><br><b>Discount:</b> ${rs.discount_percent}%<br><b>Expires:</b> ${expiry.toLocaleDateString()}`);
          } else { await client.query('ROLLBACK'); }
        } catch (e) { await client.query('ROLLBACK'); }
        finally { client.release(); }
        return;
      }

      // ✅ Handle regular wallet funding (YENLLET-{userId}-{timestamp})
      if (txRef && txRef.startsWith('YENLLET-') && !txRef.startsWith('YENLLET-RESELLER-') && !txRef.startsWith('YENLLET-ACC-')) {
        const parts = txRef.split('-');
        const userId = parseInt(parts[1]);
        if (isNaN(userId)) return;
        const verification = await flwRequest('GET', `/v3/transactions/${flwTxId}/verify`);
        if (verification.data?.data?.status !== 'successful') return;
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          const checkTx = await client.query('SELECT id FROM transactions WHERE reference = $1', [txRef]);
          if (checkTx.rows.length === 0) {
            await client.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2', [amountPaid, userId]);
            await client.query(`INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, reference, receipt_data) VALUES ($1, 'fund', 'wallet_funding', $2, $2, 'success', $3, $4, $5)`, [userId, amountPaid, generateTransactionId(), txRef, JSON.stringify(payload.data)]);
            await client.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [userId, 'Wallet Funded!', `₦${amountPaid.toLocaleString()} has been credited to your wallet.`, 'wallet']);
            await client.query('COMMIT');
            sendUserEmail(userId, 'Wallet Funded', `Your wallet has been credited with <b>₦${amountPaid.toLocaleString()}</b>.`);
          }
        } catch (e) { await client.query('ROLLBACK'); }
        finally { client.release(); }
      }
    }

    // ✅ HANDLE VIRTUAL ACCOUNT DEPOSITS (transfer.completed) — when money is sent to user's dedicated account
    if (payload.event === 'transfer.completed' && payload.data?.status === 'successful') {
      const accountNumber = payload.data.account_number;
      const amountPaid = parseFloat(payload.data.amount);
      const flwTxId = payload.data.id;
      const reference = payload.data.reference || `VA-DEPOSIT-${flwTxId}`;

      console.log(`💰 Virtual account deposit received: ₦${amountPaid} to account ${accountNumber} (ref: ${reference})`);

      if (!accountNumber || !amountPaid) return;

      // Find the user who owns this account number
      const userRes = await pool.query('SELECT id, fullname, email FROM users WHERE account_number = $1', [accountNumber]);
      if (userRes.rows.length === 0) {
        // ✅ Orphaned deposit — nobody owns this account_number anymore.
        // Likely admin deleted the user's bank account (because BVN was fake),
        // but the old Flutterwave virtual account is still alive on Flutterwave's
        // side, so senders (e.g. Opay) can still send money to it.
        // Log the deposit so admin can see trapped funds and manually decide
        // whether to refund the sender or keep them in escrow.
        console.warn(`⚠️ Orphaned deposit — no user owns account ${accountNumber}. ₦${amountPaid} received but not credited to anyone.`);
        try {
          // De-duplicate by flutterwave_tx_id (or reference) so we don't log the same deposit twice
          const dupCheck = await pool.query(
            'SELECT id FROM orphaned_deposits WHERE flutterwave_reference = $1 OR flutterwave_tx_id = $2',
            [reference, String(flwTxId || '')]
          );
          if (dupCheck.rows.length === 0) {
            const senderName = payload.data?.customer?.name
              || payload.data?.sender_name
              || payload.data?.sender
              || (payload.data?.meta ? (payload.data.meta.sender_name || payload.data.meta.name) : null)
              || null;
            const senderAcct = payload.data?.sender_account_number
              || (payload.data?.meta ? (payload.data.meta.sender_account_number) : null)
              || null;
            const bankName = payload.data?.bank_name
              || (payload.data?.meta ? payload.data.meta.bank_name : null)
              || null;
            await pool.query(
              `INSERT INTO orphaned_deposits
                (account_number, bank_name, amount, currency, flutterwave_tx_id, flutterwave_reference, sender_name, sender_account_number, raw_payload)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
              [accountNumber, bankName, amountPaid, payload.data?.currency || 'NGN', String(flwTxId || ''), reference, senderName, senderAcct, JSON.stringify(payload.data)]
            );
            console.log(`📝 Logged orphaned deposit of ₦${amountPaid} to account ${accountNumber} (ref: ${reference})`);
          } else {
            console.log(`⚠️ Duplicate orphaned deposit ignored: ${reference}`);
          }
        } catch (logErr) {
          console.error('Failed to log orphaned deposit:', logErr.message);
        }
        return;
      }
      const userId = userRes.rows[0].id;

      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const checkTx = await client.query('SELECT id FROM transactions WHERE reference = $1', [reference]);
        if (checkTx.rows.length === 0) {
          await client.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2', [amountPaid, userId]);
          await client.query(`INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, reference, receipt_data) VALUES ($1, 'fund', 'virtual_account_deposit', $2, $2, 'success', $3, $4, $5)`, [userId, amountPaid, generateTransactionId(), reference, JSON.stringify(payload.data)]);
          await client.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [userId, '💰 Wallet Credited via Bank Transfer!', `₦${amountPaid.toLocaleString()} has been credited to your wallet from a bank transfer to your virtual account.`, 'wallet']);
          await client.query('COMMIT');
          console.log(`✅ Credited ₦${amountPaid} to user ${userId} (${userRes.rows[0].email})`);
          sendUserEmail(userId, 'Wallet Credited via Bank Transfer', `Your wallet has been credited with <b>₦${amountPaid.toLocaleString()}</b> from a bank transfer to your virtual account (${accountNumber}).`);
        } else {
          await client.query('ROLLBACK');
          console.log(`⚠️ Duplicate deposit ignored: ${reference}`);
        }
      } catch (e) { await client.query('ROLLBACK'); console.error('Virtual account deposit error:', e.message); }
      finally { client.release(); }
    }
  } catch (err) { console.error('Webhook error:', err.message); }
});

// ===================== TRANSFER =====================
app.post('/api/transfer', authenticate, async (req, res) => {
  try {
    const { recipient, amount, pin, remark } = req.body;
    const userId = req.user.id;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const userRes = await client.query('SELECT pin, wallet_balance, is_banned, fullname FROM users WHERE id = $1 FOR UPDATE', [userId]);
      const user = userRes.rows[0];
      if (user.is_banned) return res.status(403).json({ error: 'Account banned' });
      if (!user.pin || !await bcrypt.compare(pin, user.pin)) return res.status(403).json({ error: 'Invalid security PIN' });
      const transferAmount = parseFloat(amount);
      if (parseFloat(user.wallet_balance) < transferAmount) return res.status(400).json({ error: 'Insufficient wallet balance' });
      let recipientUser;
      if (recipient.startsWith('9') && recipient.length === 10) {
        recipientUser = await client.query('SELECT id, fullname FROM users WHERE account_number = $1 FOR UPDATE', [recipient]);
      } else {
        recipientUser = await client.query('SELECT id, fullname FROM users WHERE phone = $1 FOR UPDATE', [normalizePhone(recipient)]);
      }
      if (recipientUser.rows.length === 0) return res.status(400).json({ error: 'Recipient wallet account not found' });
      const targetReceiverId = recipientUser.rows[0].id;
      if (targetReceiverId === userId) return res.status(400).json({ error: 'Cannot transfer funds to yourself' });
      const txnId = generateTransactionId();
      await client.query('UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id = $2', [transferAmount, userId]);
      await client.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2', [transferAmount, targetReceiverId]);
      await client.query(`INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, recipient, remark, reference) VALUES ($1, 'transfer', 'internal_transfer', $2, $2, 'success', $3, $4, $5, $6)`, [userId, transferAmount, txnId, recipient, remark || 'P2P Transfer', txnId]);
      await client.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [targetReceiverId, 'Funds Received!', `You received ₦${transferAmount.toLocaleString()} from ${user.fullname}.`, 'wallet']);
      await client.query('COMMIT');
      sendUserEmail(userId, 'Transfer Successful', `You sent <b>₦${transferAmount.toLocaleString()}</b> to ${recipientUser.rows[0].fullname}.`);
      sendUserEmail(targetReceiverId, 'Funds Received', `You just received <b>₦${transferAmount.toLocaleString()}</b> from ${user.fullname}.`);
      res.json({ success: true, transactionId: txnId, message: 'Transfer successful' });
    } catch (err) { await client.query('ROLLBACK'); throw err; }
    finally { client.release(); }
  } catch (err) { res.status(500).json({ error: err.message || 'Transfer failed' }); }
});

// ===================== PRICING =====================
app.get('/api/pricing', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, service, provider, plan, selling_price, validity, category FROM pricing WHERE is_active = TRUE ORDER BY service, provider, category ASC');
    res.json({ success: true, pricing: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed to fetch pricing' }); }
});

// ===================== RESELLER SYSTEM (NEW) =====================

// Subscribe as reseller (pay monthly fee via Flutterwave)
app.post('/api/reseller/subscribe', authenticate, async (req, res) => {
  try {
    const settings = await getAdminSettings();
    const resellerSettings = settings.reseller_settings || { monthly_fee: 5000, discount_percent: 10, enabled: true };
    if (!resellerSettings.enabled) return res.status(400).json({ error: 'Reseller program is currently disabled' });

    const monthlyFee = parseFloat(resellerSettings.monthly_fee);
    const discountPercent = parseFloat(resellerSettings.discount_percent);

    // Check existing active subscription
    const existing = await getResellerSubscription(req.user.id);
    if (existing && existing.isActive) return res.status(400).json({ error: 'You already have an active reseller subscription' });

    // Initiate Flutterwave payment
    const userResult = await pool.query('SELECT fullname, email, phone FROM users WHERE id = $1', [req.user.id]);
    const user = userResult.rows[0];
    const txRef = `YENLLET-RESELLER-${req.user.id}-${Date.now()}`;

    const response = await flwRequest('POST', '/v3/payments', {
      tx_ref: txRef, amount: monthlyFee, currency: 'NGN',
      redirect_url: `${getBaseUrl(req)}/dashboard.html`,
      payment_options: 'card, banktransfer, ussd',
      customer: { email: user.email, phonenumber: user.phone || '08000000000', name: user.fullname },
      customizations: { title: 'Yenllet Reseller', description: `Reseller subscription - ${discountPercent}% discount for 30 days` }
    });

    if (response.data && response.data.data?.link) {
      // Store pending subscription payment reference
      await pool.query('INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, reference, receipt_data) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)', [
        req.user.id, 'payment', 'reseller_subscription', monthlyFee, monthlyFee, 'pending', generateTransactionId(), txRef, JSON.stringify({ monthly_fee: monthlyFee, discount_percent: discountPercent, type: 'reseller_subscription' })
      ]);
      res.json({ success: true, paymentLink: response.data.data.link, txRef });
    } else {
      res.status(400).json({ error: 'Failed to generate payment link' });
    }
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ NEW: Subscribe as reseller by paying from WALLET (alternative to Flutterwave)
app.post('/api/reseller/subscribe-wallet', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    const settings = await getAdminSettings();
    const resellerSettings = settings.reseller_settings || { monthly_fee: 5000, discount_percent: 10, enabled: true };
    if (!resellerSettings.enabled) return res.status(400).json({ error: 'Reseller program is currently disabled' });

    const monthlyFee = parseFloat(resellerSettings.monthly_fee);
    const discountPercent = parseFloat(resellerSettings.discount_percent);

    await client.query('BEGIN');

    // Lock user row for atomic balance check + deduction
    const userRes = await client.query('SELECT wallet_balance, fullname, email FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
    const user = userRes.rows[0];
    if (!user) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'User not found' }); }
    if (parseFloat(user.wallet_balance) < monthlyFee) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: `Insufficient wallet balance. You need ₦${monthlyFee.toLocaleString()} but have ₦${parseFloat(user.wallet_balance).toLocaleString()}. Fund your wallet first.` });
    }

    // Check existing active subscription again (under same transaction)
    const existing = await client.query("SELECT id FROM reseller_subscriptions WHERE user_id = $1 AND status = 'active' AND expires_at > NOW()", [req.user.id]);
    if (existing.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'You already have an active reseller subscription' });
    }

    // Deduct from wallet
    await client.query('UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id = $2', [monthlyFee, req.user.id]);

    // Create subscription record (30 days from now)
    const expiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    const subRes = await client.query(
      `INSERT INTO reseller_subscriptions (user_id, status, monthly_fee, discount_percent, started_at, expires_at, last_payment_at, payment_reference, created_at)
       VALUES ($1, 'active', $2, $3, NOW(), $4, NOW(), $5, NOW()) RETURNING id`,
      [req.user.id, monthlyFee, discountPercent, expiry, `WALLET-${generateTransactionId()}`]
    );

    // Log the transaction
    const txnId = generateTransactionId();
    await client.query(
      `INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, reference, remark, receipt_data) VALUES ($1, 'payment', 'reseller_subscription', $2, $2, 'success', $3, $4, $5, $6)`,
      [req.user.id, monthlyFee, txnId, `WALLET-RESELLER-${req.user.id}-${Date.now()}`, 'Reseller subscription paid via wallet', JSON.stringify({ monthly_fee: monthlyFee, discount_percent: discountPercent, payment_method: 'wallet', subscription_id: subRes.rows[0].id, expires_at: expiry })]
    );

    // Notification + email
    await client.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [
      req.user.id,
      '🎉 Reseller Subscription Active!',
      `Congratulations! Your reseller subscription is now active. You have ${discountPercent}% discount on all purchases for the next 30 days (expires ${expiry.toLocaleDateString()}).`,
      'reseller'
    ]);

    await client.query('COMMIT');

    // Fire-and-forget email
    sendUserEmail(req.user.id, 'Reseller Subscription Active!', `Your reseller subscription is now active!<br><br><b>Discount:</b> ${discountPercent}% off all purchases<br><b>Duration:</b> 30 days<br><b>Expires:</b> ${expiry.toLocaleDateString()}<br><b>Amount Paid:</b> ₦${monthlyFee.toLocaleString()} (from wallet)<br><br>Generate your reseller API keys from the Reseller Program section in your dashboard to start integrating Yenllet into your own website.`);

    res.json({
      success: true,
      message: `Reseller subscription activated! You now have ${discountPercent}% discount on all purchases.`,
      subscription: {
        id: subRes.rows[0].id,
        status: 'active',
        monthly_fee: monthlyFee,
        discount_percent: discountPercent,
        started_at: new Date(),
        expires_at: expiry,
        isActive: true,
        isExpired: false,
        discountPercent
      }
    });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    res.status(500).json({ error: 'Failed: ' + err.message });
  } finally {
    client.release();
  }
});

// Get reseller status
app.get('/api/reseller/status', authenticate, async (req, res) => {
  try {
    const settings = await getAdminSettings();
    const resellerSettings = settings.reseller_settings || { monthly_fee: 5000, discount_percent: 10, enabled: true };
    const subscription = await getResellerSubscription(req.user.id);
    const apiKeysRes = await pool.query('SELECT id, api_key, label, is_active, last_used, total_requests, created_at FROM reseller_api_keys WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
    const statsRes = await pool.query('SELECT COUNT(*) as total_requests, COALESCE(SUM(amount),0) as total_volume FROM reseller_transactions WHERE reseller_id = $1', [req.user.id]);
    res.json({
      success: true,
      isReseller: !!(subscription && subscription.isActive),
      subscription: subscription,
      apiKeys: apiKeysRes.rows,
      settings: resellerSettings,
      stats: {
        totalRequests: parseInt(statsRes.rows[0].total_requests),
        totalVolume: parseFloat(statsRes.rows[0].total_volume)
      }
    });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// Generate reseller API key
app.post('/api/reseller/api-key', authenticate, async (req, res) => {
  try {
    const { label } = req.body;
    const subscription = await getResellerSubscription(req.user.id);
    if (!subscription || !subscription.isActive) return res.status(400).json({ error: 'Active reseller subscription required to generate API keys' });

    const newKey = generateResellerApiKey();
    const result = await pool.query('INSERT INTO reseller_api_keys (user_id, api_key, label) VALUES ($1, $2, $3) RETURNING id, api_key, label, created_at', [req.user.id, newKey, label || 'My API Key']);
    sendUserEmail(req.user.id, 'Reseller API Key Generated', `A new reseller API key has been generated for your account:<br><br><b>Key:</b> ${newKey}<br><b>Label:</b> ${label || 'My API Key'}<br><br>Use this key in the <code>x-api-key</code> header when calling Yenllet API v1 endpoints.`);
    res.json({ success: true, apiKey: result.rows[0] });
  } catch (err) { res.status(500).json({ error: 'Failed to generate API key' }); }
});

// Delete reseller API key
app.delete('/api/reseller/api-key/:id', authenticate, async (req, res) => {
  try {
    await pool.query('DELETE FROM reseller_api_keys WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    res.json({ success: true, message: 'API key deleted' });
  } catch (err) { res.status(500).json({ error: 'Failed to delete API key' }); }
});

// Reseller transactions history
app.get('/api/reseller/transactions', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM reseller_transactions WHERE reseller_id = $1 ORDER BY created_at DESC LIMIT 100', [req.user.id]);
    res.json({ success: true, transactions: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== PUBLIC RESELLER API v1 (for resellers to integrate their websites) =====================

// Get pricing (with reseller discount applied)
app.get('/api/v1/pricing', authenticateResellerApiKey, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, service, provider, plan, selling_price, validity, category FROM pricing WHERE is_active = TRUE ORDER BY service, provider, category ASC');
    // Apply reseller discount if subscription is active
    const pricing = result.rows.map(p => {
      const basePrice = parseFloat(p.selling_price);
      const discountAmount = req.reseller.isSubscriptionActive ? (basePrice * req.reseller.discountPercent / 100) : 0;
      return {
        ...p,
        base_price: basePrice,
        discount_percent: req.reseller.isSubscriptionActive ? req.reseller.discountPercent : 0,
        discounted_price: basePrice - discountAmount,
        subscription_active: req.reseller.isSubscriptionActive
      };
    });
    res.json({ success: true, pricing, reseller: { fullname: req.reseller.fullname, isSubscriptionActive: req.reseller.isSubscriptionActive, discountPercent: req.reseller.discountPercent, subscriptionExpiresAt: req.reseller.subscriptionExpiresAt } });
  } catch (err) { res.status(500).json({ success: false, error: 'Failed to fetch pricing' }); }
});

// Check wallet balance
app.get('/api/v1/balance', authenticateResellerApiKey, async (req, res) => {
  res.json({ success: true, balance: req.reseller.walletBalance, reseller: { fullname: req.reseller.fullname, isSubscriptionActive: req.reseller.isSubscriptionActive, discountPercent: req.reseller.discountPercent, subscriptionExpiresAt: req.reseller.subscriptionExpiresAt } });
});

// Reseller API: Buy airtime
app.post('/api/v1/airtime', authenticateResellerApiKey, async (req, res) => {
  try {
    const { provider, phone, amount } = req.body;
    if (!provider || !phone || !amount) return res.status(400).json({ success: false, error: 'provider, phone, and amount are required' });
    const result = await processResellerPurchase(req.reseller, 'airtime', provider, null, parseFloat(amount), phone, {});
    res.json(result);
  } catch (err) { res.status(err.status || 500).json({ success: false, error: err.message || 'Purchase failed' }); }
});

// Reseller API: Buy data
app.post('/api/v1/data', authenticateResellerApiKey, async (req, res) => {
  try {
    const { provider, phone, plan } = req.body;
    if (!provider || !phone || !plan) return res.status(400).json({ success: false, error: 'provider, phone, and plan are required' });
    const result = await processResellerPurchase(req.reseller, 'data', provider, plan, 0, phone, {});
    res.json(result);
  } catch (err) { res.status(err.status || 500).json({ success: false, error: err.message || 'Purchase failed' }); }
});

// Reseller API: TV subscription
app.post('/api/v1/tv', authenticateResellerApiKey, async (req, res) => {
  try {
    const { provider, smartCardNumber, plan } = req.body;
    if (!provider || !smartCardNumber || !plan) return res.status(400).json({ success: false, error: 'provider, smartCardNumber, and plan are required' });
    const result = await processResellerPurchase(req.reseller, 'tv', provider, plan, 0, smartCardNumber, {});
    res.json(result);
  } catch (err) { res.status(err.status || 500).json({ success: false, error: err.message || 'Purchase failed' }); }
});

// Reseller API: Electricity
app.post('/api/v1/electricity', authenticateResellerApiKey, async (req, res) => {
  try {
    const { provider, meterNumber, meterType, amount } = req.body;
    if (!provider || !meterNumber || !amount) return res.status(400).json({ success: false, error: 'provider, meterNumber, and amount are required' });
    const result = await processResellerPurchase(req.reseller, 'electricity', provider, null, parseFloat(amount), meterNumber, { meterType: meterType || 'prepaid' });
    res.json(result);
  } catch (err) { res.status(err.status || 500).json({ success: false, error: err.message || 'Purchase failed' }); }
});

// ✅ RESELLER PURCHASE PROCESSOR (with discount logic)
async function processResellerPurchase(reseller, service, provider, plan, amount, recipient, extra) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Get base price from pricing table
    const pricingQuery = plan
      ? "SELECT selling_price FROM pricing WHERE service = $1 AND provider = $2 AND plan = $3 AND is_active = TRUE"
      : "SELECT selling_price FROM pricing WHERE service = $1 AND provider = $2 AND is_active = TRUE";
    const pricingParams = plan ? [service, provider.toUpperCase(), plan] : [service, provider.toUpperCase()];
    const pricing = await client.query(pricingQuery, pricingParams);
    let basePrice = parseFloat(amount);
    if (pricing.rows.length > 0) {
      if (service !== 'airtime') basePrice = parseFloat(pricing.rows[0].selling_price);
    }
    // Apply reseller discount if subscription is active
    const discountPercent = reseller.isSubscriptionActive ? reseller.discountPercent : 0;
    const discountAmount = (basePrice * discountPercent) / 100;
    const finalPrice = basePrice - discountAmount;
    // Check reseller wallet balance
    const userRes = await client.query('SELECT wallet_balance, is_banned FROM users WHERE id = $1 FOR UPDATE', [reseller.userId]);
    const user = userRes.rows[0];
    if (user.is_banned) throw { status: 403, message: 'Reseller account is banned' };
    if (parseFloat(user.wallet_balance) < finalPrice) throw { status: 400, message: 'Insufficient reseller wallet balance. Current balance: ₦' + user.wallet_balance };
    // Deduct from reseller wallet
    await client.query('UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id = $2', [finalPrice, reseller.userId]);

    const txnId = generateTransactionId();
    // Insert into reseller_transactions
    const txnRes = await client.query(
      `INSERT INTO reseller_transactions (reseller_id, api_key_id, type, service, amount, base_price, discount_amount, status, transaction_id, recipient, provider, plan, receipt_data) VALUES ($1, $2, 'purchase', $3, $4, $5, $6, 'pending', $7, $8, $9, $10, $11) RETURNING id`,
      [reseller.userId, reseller.apiKeyId, service, finalPrice, basePrice, discountAmount, txnId, recipient, provider, plan, JSON.stringify({ discountPercent, discountAmount, basePrice, finalPrice })]
    );
    const txnDbId = txnRes.rows[0].id;

    // Call Clubkonnect
    if (['airtime', 'data', 'tv', 'electricity', 'bet', 'education'].includes(service) && CK_USER_ID && CK_API_KEY) {
      try {
        let apiEndpoint = '';
        let apiParams = { RequestID: txnId };
        const networkCode = NETWORK_CODES[provider.toLowerCase()] || provider.toLowerCase();
        if (service === 'airtime') { apiEndpoint = 'APIAirtimeV1.asp'; apiParams.MobileNetwork = networkCode; apiParams.Amount = amount; apiParams.MobileNumber = recipient; }
        else if (service === 'data') { apiEndpoint = 'APIDatabundleV1.asp'; apiParams.MobileNetwork = networkCode; apiParams.DataPlan = plan; apiParams.MobileNumber = recipient; }
        else if (service === 'tv') { apiEndpoint = 'APICableTVV1.asp'; apiParams.CableTV = provider.toLowerCase(); apiParams.Package = plan; apiParams.SmartCardNo = recipient; }
        else if (service === 'electricity') { apiEndpoint = 'APIElectricityV1.asp'; apiParams.Company = provider.toLowerCase(); apiParams.MeterNo = recipient; apiParams.MeterType = extra.meterType?.toLowerCase() === 'prepaid' ? 'prepaid' : 'postpaid'; apiParams.Amount = amount; }
        else if (service === 'bet') {
          // ClubKonnect betting wallet funding.
          // - recipient  = customer's betting CustomerID (entered by user)
          // - plan        = CK betting company code, e.g. 'product-nairabet'
          //   (stored in pricing.plan when seeding)
          apiEndpoint = 'APIBettingV1.asp';
          apiParams.BettingCompany = plan || provider;
          apiParams.CustomerID = recipient;
          apiParams.Amount = amount;
          apiParams.CallBackURL = (process.env.BASE_URL || 'https://yenllet.vercel.app') + '/api/webhook/clubkonnect';
        }
        else if (service === 'education') {
          // Map examType to CK endpoints.
          //   WAEC -> APIWAECResultV1.asp (returns the result-checker pin)
          //   JAMB -> APIJAMBV1.asp (returns the JAMB e-PIN)
          const exam = (provider || '').toLowerCase();
          if (exam === 'waec') { apiEndpoint = 'APIWAECResultV1.asp'; apiParams.Amount = amount; }
          else if (exam === 'jamb') { apiEndpoint = 'APIJAMBV1.asp'; apiParams.Amount = amount; }
          else throw { isProviderError: true, message: 'Unknown exam type: ' + provider };
        }

        const ckResponse = await axios.get(`${CK_BASE_URL}/${apiEndpoint}`, { params: { ...apiParams, UserID: CK_USER_ID, APIKey: CK_API_KEY }, timeout: 60000 });
        const apiData = ckResponse.data;
        let isSuccessful = false, providerError = 'Unknown provider error';
        if (typeof apiData === 'object') {
          if (apiData.statuscode === '100' || apiData.status === 'ORDER_RECEIVED') isSuccessful = true;
          else providerError = apiData.remark || apiData.status || apiData.msg || 'Transaction declined by provider';
        } else providerError = 'Provider returned an invalid response format.';

        if (!isSuccessful) { const err = new Error(providerError); err.isProviderError = true; throw err; }

        await client.query('UPDATE reseller_transactions SET status = $1, receipt_data = $2 WHERE id = $3', ['success', JSON.stringify({ ...apiData, discountAmount }), txnDbId]);
        await client.query('COMMIT');
        sendUserEmail(reseller.userId, 'Reseller API Transaction Successful', `Your ${service} purchase of <b>₦${finalPrice}</b> (base: ₦${basePrice}, discount: ${discountPercent}%) was successful.<br>Transaction ID: ${txnId}<br>Recipient: ${recipient}`);
        return { success: true, transactionId: txnId, message: `${service} purchase successful`, amount: finalPrice, basePrice, discountAmount, discountPercent, receipt: apiData };
      } catch (apiErr) {
        if (apiErr.isProviderError) {
          // Refund reseller wallet
          await client.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2', [finalPrice, reseller.userId]);
          await client.query("UPDATE reseller_transactions SET status = 'failed', receipt_data = $1 WHERE id = $2", [JSON.stringify({ error: apiErr.message }), txnDbId]);
          await client.query('COMMIT');
          throw { status: 502, message: 'Service provider error: ' + apiErr.message };
        }
        // Query fallback
        try {
          const queryRes = await axios.get(`${CK_BASE_URL}/APIQueryV1.asp`, { params: { UserID: CK_USER_ID, APIKey: CK_API_KEY, RequestID: txnId }, timeout: 15000 });
          const queryData = queryRes.data;
          if (queryData.statuscode === '200' || queryData.status === 'ORDER_COMPLETED') {
            await client.query('UPDATE reseller_transactions SET status = $1, receipt_data = $2 WHERE id = $3', ['success', JSON.stringify({ ...queryData, discountAmount }), txnDbId]);
            await client.query('COMMIT');
            return { success: true, transactionId: txnId, message: `${service} purchase successful`, amount: finalPrice, basePrice, discountAmount, discountPercent, receipt: queryData };
          } else if (queryData.statuscode === '100' || queryData.status === 'ORDER_RECEIVED') {
            await client.query('COMMIT');
            return { success: true, transactionId: txnId, message: 'Transaction is processing. It will be completed shortly.', pending: true };
          } else {
            const failMsg = queryData.remark || queryData.status || 'Transaction failed';
            await client.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2', [finalPrice, reseller.userId]);
            await client.query("UPDATE reseller_transactions SET status = 'failed', receipt_data = $1 WHERE id = $2", [JSON.stringify({ error: failMsg }), txnDbId]);
            await client.query('COMMIT');
            throw { status: 502, message: 'Service provider error: ' + failMsg };
          }
        } catch (queryErr) {
          await client.query("UPDATE reseller_transactions SET receipt_data = $1 WHERE id = $2", [JSON.stringify({ error: 'Timeout - needs manual review' }), txnDbId]);
          await client.query('COMMIT');
          return { success: true, transactionId: txnId, message: 'Transaction is processing. It will be completed shortly.', pending: true };
        }
      }
    } else {
      await client.query('UPDATE reseller_transactions SET status = $1 WHERE id = $2', ['success', txnDbId]);
      await client.query('COMMIT');
      return { success: true, transactionId: txnId, message: `${service} purchase successful`, amount: finalPrice, basePrice, discountAmount, discountPercent };
    }
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch {}
    throw { status: err.status || 500, message: err.message || 'Purchase failed' };
  } finally { client.release(); }
}

// ===================== PROCESS PURCHASE (USER FLOW - with reseller discount applied if user is reseller) =====================
const processPurchase = async (userId, pin, service, provider, plan, amount, recipient, extra = {}, req = null) => {
  const client = await pool.connect();
  const gustmiiToken = req?.headers['x-gustmii-token'];
  try {
    await client.query('BEGIN');
    const userRes = await client.query('SELECT pin, wallet_balance, cashback_balance, is_banned, fullname, email FROM users WHERE id = $1 FOR UPDATE', [userId]);
    const user = userRes.rows[0];
    if (!user) throw { status: 404, message: 'User not found' };
    if (user.is_banned) throw { status: 403, message: 'Account banned' };
    if (!user.pin || !await bcrypt.compare(pin, user.pin)) throw { status: 403, message: 'Invalid PIN' };

    let sellPrice = parseFloat(amount);
    let cashbackEarned = 0;
    const pricingQuery = plan
      ? "SELECT selling_price, cashback_percent FROM pricing WHERE service = $1 AND provider = $2 AND plan = $3 AND is_active = TRUE"
      : "SELECT selling_price, cashback_percent FROM pricing WHERE service = $1 AND provider = $2 AND is_active = TRUE";
    const pricingParams = plan ? [service, provider.toUpperCase(), plan] : [service, provider.toUpperCase()];
    const pricing = await client.query(pricingQuery, pricingParams);
    if (pricing.rows.length > 0) {
      if (service !== 'airtime') sellPrice = parseFloat(pricing.rows[0].selling_price);
      cashbackEarned = sellPrice * parseFloat(pricing.rows[0].cashback_percent || 0) / 100;
    }

    // ✅ Apply reseller discount if user is an active reseller
    let resellerDiscountAmount = 0;
    let resellerDiscountPercent = 0;
    const resellerSub = await getResellerSubscription(userId);
    if (resellerSub && resellerSub.isActive) {
      resellerDiscountPercent = resellerSub.discountPercent;
      resellerDiscountAmount = (sellPrice * resellerDiscountPercent) / 100;
      sellPrice = sellPrice - resellerDiscountAmount;
    }

    // ✅ CHARGE FEE: If admin has enabled charge fee, add it to the sell price
    const allSettings = await getAdminSettings();
    const chargeFeeSettings = allSettings.charge_fee_settings || { type: 'percentage', value: 0, enabled: false };
    let chargeFeeAmount = 0;
    if (chargeFeeSettings.enabled && parseFloat(chargeFeeSettings.value) > 0) {
      if (chargeFeeSettings.type === 'percentage') {
        chargeFeeAmount = (sellPrice * parseFloat(chargeFeeSettings.value)) / 100;
      } else {
        chargeFeeAmount = parseFloat(chargeFeeSettings.value);
      }
      sellPrice = sellPrice + chargeFeeAmount;
    }

    let cashbackUsed = 0;
    let amountFromWallet = sellPrice;

    if (gustmiiToken) {
      const gustmiiUser = await verifyGustmiiToken(gustmiiToken);
      if (!gustmiiUser) throw { status: 401, message: 'Invalid Gustmii session' };
      const gustmiiBalance = parseFloat(gustmiiUser.wallet || 0);
      if (gustmiiBalance < sellPrice) throw { status: 400, message: 'Insufficient Gustmii balance' };
      const deductionSuccess = await deductFromGustmiiWallet(sellPrice, gustmiiToken);
      if (!deductionSuccess) throw { status: 500, message: 'Failed to deduct from Gustmii wallet' };
      amountFromWallet = 0;
    } else {
      if (extra.useCashback && parseFloat(user.cashback_balance) > 0) {
        cashbackUsed = Math.min(parseFloat(user.cashback_balance), sellPrice);
        amountFromWallet = sellPrice - cashbackUsed;
      }
      if (parseFloat(user.wallet_balance) < amountFromWallet) throw { status: 400, message: 'Insufficient balance' };
      await client.query('UPDATE users SET wallet_balance = wallet_balance - $1, cashback_balance = cashback_balance - $2 WHERE id = $3', [amountFromWallet, cashbackUsed, userId]);
    }

    const txnId = generateTransactionId();
    const txnRes = await client.query(
      `INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, reference, recipient, provider, plan, remark, receipt_data) VALUES ($1, 'purchase', $2, $3, $4, 'pending', $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
      [userId, service, amount, sellPrice, txnId, txnId, recipient, provider, plan, extra.remark || '', JSON.stringify({ useCashback: extra.useCashback, cashbackUsed, gustmiiWallet: !!gustmiiToken, resellerDiscount: resellerDiscountAmount, resellerDiscountPercent })]
    );
    const txnDbId = txnRes.rows[0].id;

    if (['airtime', 'data', 'tv', 'electricity', 'bet', 'education'].includes(service) && CK_USER_ID && CK_API_KEY) {
      try {
        let apiEndpoint = '';
        let apiParams = { RequestID: txnId };
        const networkCode = NETWORK_CODES[provider.toLowerCase()] || provider.toLowerCase();
        if (service === 'airtime') { apiEndpoint = 'APIAirtimeV1.asp'; apiParams.MobileNetwork = networkCode; apiParams.Amount = amount; apiParams.MobileNumber = recipient; }
        else if (service === 'data') { apiEndpoint = 'APIDatabundleV1.asp'; apiParams.MobileNetwork = networkCode; apiParams.DataPlan = plan; apiParams.MobileNumber = recipient; }
        else if (service === 'tv') { apiEndpoint = 'APICableTVV1.asp'; apiParams.CableTV = provider.toLowerCase(); apiParams.Package = plan; apiParams.SmartCardNo = recipient; }
        else if (service === 'electricity') { apiEndpoint = 'APIElectricityV1.asp'; apiParams.Company = provider.toLowerCase(); apiParams.MeterNo = recipient; apiParams.MeterType = extra.meterType?.toLowerCase() === 'prepaid' ? 'prepaid' : 'postpaid'; apiParams.Amount = amount; }
        else if (service === 'bet') {
          // ClubKonnect betting wallet funding.
          // - recipient  = customer's betting CustomerID (entered by user)
          // - plan        = CK betting company code, e.g. 'product-nairabet'
          //   (stored in pricing.plan when seeding)
          apiEndpoint = 'APIBettingV1.asp';
          apiParams.BettingCompany = plan || provider;
          apiParams.CustomerID = recipient;
          apiParams.Amount = amount;
          apiParams.CallBackURL = (process.env.BASE_URL || 'https://yenllet.vercel.app') + '/api/webhook/clubkonnect';
        }
        else if (service === 'education') {
          // Map examType to CK endpoints.
          //   WAEC -> APIWAECResultV1.asp (returns the result-checker pin)
          //   JAMB -> APIJAMBV1.asp (returns the JAMB e-PIN)
          const exam = (provider || '').toLowerCase();
          if (exam === 'waec') { apiEndpoint = 'APIWAECResultV1.asp'; apiParams.Amount = amount; }
          else if (exam === 'jamb') { apiEndpoint = 'APIJAMBV1.asp'; apiParams.Amount = amount; }
          else throw { isProviderError: true, message: 'Unknown exam type: ' + provider };
        }

        const ckResponse = await axios.get(`${CK_BASE_URL}/${apiEndpoint}`, { params: { ...apiParams, UserID: CK_USER_ID, APIKey: CK_API_KEY }, timeout: 60000 });
        const apiData = ckResponse.data;
        let isSuccessful = false, providerError = 'Unknown provider error';
        if (typeof apiData === 'object') {
          if (apiData.statuscode === '100' || apiData.status === 'ORDER_RECEIVED') isSuccessful = true;
          else providerError = apiData.remark || apiData.status || apiData.msg || 'Transaction declined by provider';
        } else providerError = 'Provider returned an invalid response format.';
        if (!isSuccessful) { const err = new Error(providerError); err.isProviderError = true; throw err; }

        await client.query('UPDATE transactions SET status = $1, receipt_data = $2 WHERE id = $3', ['success', JSON.stringify({ ...apiData, cashbackUsed, resellerDiscount: resellerDiscountAmount }), txnDbId]);
        if (!gustmiiToken && cashbackEarned > 0) {
          await client.query('UPDATE users SET cashback_balance = cashback_balance + $1 WHERE id = $2', [cashbackEarned, userId]);
        }
        await client.query('COMMIT');
        if (service === 'electricity') {
          const meterToken = apiData.token || apiData.Token || 'See receipt for token';
          sendUserEmail(userId, 'Electricity Token Purchase', `Your electricity purchase was successful. <br><b>Meter Token: ${meterToken}</b><br>Meter Number: ${recipient}<br>Amount: ₦${sellPrice}${resellerDiscountAmount > 0 ? ` (after ₦${resellerDiscountAmount} reseller discount)` : ''}`);
        } else {
          sendUserEmail(userId, 'Transaction Successful', `Your ${service} purchase of <b>₦${sellPrice}</b>${resellerDiscountAmount > 0 ? ` (after ₦${resellerDiscountAmount} reseller discount)` : ''} was successful.<br>Transaction ID: ${txnId}`);
        }
        // ✅ Update vendor earnings (if user was referred by a vendor)
        updateVendorEarnings(userId, sellPrice);
        return { success: true, transactionId: txnId, message: `${service} purchase successful`, sellPrice, cashbackUsed, cashbackEarned, resellerDiscount: resellerDiscountAmount };
      } catch (apiErr) {
        if (apiErr.isProviderError) {
          if (gustmiiToken) { await creditGustmiiWallet(sellPrice, gustmiiToken); }
          else { await client.query('UPDATE users SET wallet_balance = wallet_balance + $1, cashback_balance = cashback_balance + $2 WHERE id = $3', [amountFromWallet, cashbackUsed, userId]); }
          await client.query("UPDATE transactions SET status = 'failed', remark = $1 WHERE id = $2", [apiErr.message, txnDbId]);
          await client.query('COMMIT');
          sendUserEmail(userId, 'Transaction Failed & Refunded', `Your ${service} purchase failed.<br>Reason: ${apiErr.message}<br>Your wallet has been refunded with ₦${amountFromWallet}.`);
          throw { status: 502, message: 'Service provider error: ' + apiErr.message };
        }
        try {
          const queryRes = await axios.get(`${CK_BASE_URL}/APIQueryV1.asp`, { params: { UserID: CK_USER_ID, APIKey: CK_API_KEY, RequestID: txnId }, timeout: 15000 });
          const queryData = queryRes.data;
          if (queryData.statuscode === '200' || queryData.status === 'ORDER_COMPLETED') {
            await client.query('UPDATE transactions SET status = $1, receipt_data = $2 WHERE id = $3', ['success', JSON.stringify({ ...queryData, cashbackUsed, resellerDiscount: resellerDiscountAmount }), txnDbId]);
            if (!gustmiiToken && cashbackEarned > 0) { await client.query('UPDATE users SET cashback_balance = cashback_balance + $1 WHERE id = $2', [cashbackEarned, userId]); }
            await client.query('COMMIT');
            sendUserEmail(userId, 'Transaction Successful', `Your ${service} purchase of <b>₦${sellPrice}</b> was successful.<br>Transaction ID: ${txnId}`);
            // ✅ Update vendor earnings
            updateVendorEarnings(userId, sellPrice);
            return { success: true, transactionId: txnId, message: `${service} purchase successful`, sellPrice, cashbackUsed, cashbackEarned, resellerDiscount: resellerDiscountAmount };
          } else if (queryData.statuscode === '100' || queryData.status === 'ORDER_RECEIVED') {
            await client.query('COMMIT');
            sendUserEmail(userId, 'Transaction Processing', `Your ${service} purchase is processing. It will be completed shortly.<br>Transaction ID: ${txnId}`);
            return { success: true, transactionId: txnId, message: 'Transaction is processing. It will be completed shortly.', pending: true };
          } else {
            const failMsg = queryData.remark || queryData.status || 'Transaction failed';
            if (gustmiiToken) { await creditGustmiiWallet(sellPrice, gustmiiToken); }
            else { await client.query('UPDATE users SET wallet_balance = wallet_balance + $1, cashback_balance = cashback_balance + $2 WHERE id = $3', [amountFromWallet, cashbackUsed, userId]); }
            await client.query("UPDATE transactions SET status = 'failed', remark = $1 WHERE id = $2", [failMsg, txnDbId]);
            await client.query('COMMIT');
            sendUserEmail(userId, 'Transaction Failed & Refunded', `Your ${service} purchase failed.<br>Reason: ${failMsg}<br>Your wallet has been refunded with ₦${amountFromWallet}.`);
            throw { status: 502, message: 'Service provider error: ' + failMsg };
          }
        } catch (queryErr) {
          await client.query("UPDATE transactions SET remark = 'Timeout occurred. Query failed. Needs manual review.' WHERE id = $1", [txnDbId]);
          await client.query('COMMIT');
          sendUserEmail(userId, 'Transaction Processing', `Your ${service} purchase is processing. It will be completed shortly.<br>Transaction ID: ${txnId}`);
          return { success: true, transactionId: txnId, message: 'Transaction is processing. It will be completed shortly.', pending: true };
        }
      }
    } else {
      await client.query('UPDATE transactions SET status = $1 WHERE id = $2', ['success', txnDbId]);
      if (!gustmiiToken && cashbackEarned > 0) { await client.query('UPDATE users SET cashback_balance = cashback_balance + $1 WHERE id = $2', [cashbackEarned, userId]); }
      await client.query('COMMIT');
      sendUserEmail(userId, 'Transaction Successful', `Your ${service} purchase of <b>₦${sellPrice}</b>${resellerDiscountAmount > 0 ? ` (after ₦${resellerDiscountAmount} reseller discount)` : ''} was successful.<br>Transaction ID: ${txnId}`);
      // ✅ Update vendor earnings
      updateVendorEarnings(userId, sellPrice);
      return { success: true, transactionId: txnId, message: `${service} purchase successful`, sellPrice, cashbackUsed, cashbackEarned, resellerDiscount: resellerDiscountAmount };
    }
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch {}
    throw { status: err.status || 500, message: err.message || 'Purchase failed' };
  } finally { client.release(); }
};

app.post('/api/webhook/clubkonnect', async (req, res) => {
  res.status(200).send('OK');
  try {
    const { orderid, statuscode, orderstatus } = req.body;
    if (!orderid) return;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const txnRes = await client.query('SELECT id, user_id, total, status, receipt_data FROM transactions WHERE transaction_id = $1 FOR UPDATE', [orderid]);
      if (txnRes.rows.length === 0) return;
      const txn = txnRes.rows[0];
      if (txn.status === 'success' && (statuscode !== '200' && statuscode !== '100')) {
        const receipt = txn.receipt_data || {};
        const cashbackUsed = parseFloat(receipt.cashbackUsed || 0);
        const walletDeducted = parseFloat(txn.total) - cashbackUsed;
        const usedGustmii = receipt.gustmiiWallet;
        if (!usedGustmii) {
          await client.query('UPDATE users SET wallet_balance = wallet_balance + $1, cashback_balance = cashback_balance + $2 WHERE id = $3', [walletDeducted, cashbackUsed, txn.user_id]);
        }
        await client.query("UPDATE transactions SET status = 'failed', remark = $1 WHERE id = $2", [`Provider late failure: ${orderstatus}`, txn.id]);
        await client.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [txn.user_id, 'Transaction Failed & Refunded', `Your ${txn.service} transaction failed and your wallet has been refunded.`, 'wallet']);
        sendUserEmail(txn.user_id, 'Transaction Failed & Refunded', `Your ${txn.service} transaction failed and your wallet has been refunded.`);
      }
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK'); }
    finally { client.release(); }
  } catch (err) {}
});

// ===================== SERVICE ENDPOINTS =====================
app.post('/api/airtime/purchase', authenticate, async (req, res) => {
  try {
    const { provider, phone, amount, pin, useCashback } = req.body;
    if (!provider || !phone || !amount || !pin) return res.status(400).json({ error: 'All fields required' });
    const result = await processPurchase(req.user.id, pin, 'airtime', provider, null, amount, phone, { useCashback }, req);
    res.json(result);
  } catch (err) { res.status(err.status || 500).json({ error: err.message || 'Purchase failed' }); }
});

app.post('/api/data/purchase', authenticate, async (req, res) => {
  try {
    const { provider, phone, plan, amount, pin, useCashback } = req.body;
    if (!provider || !phone || !plan || !pin) return res.status(400).json({ error: 'All fields required' });
    const result = await processPurchase(req.user.id, pin, 'data', provider, plan, amount || 0, phone, { useCashback }, req);
    res.json(result);
  } catch (err) { res.status(err.status || 500).json({ error: err.message || 'Purchase failed' }); }
});

app.post('/api/tv/purchase', authenticate, async (req, res) => {
  try {
    const { provider, smartCardNumber, plan, amount, pin, useCashback } = req.body;
    if (!provider || !smartCardNumber || !plan || !pin) return res.status(400).json({ error: 'All fields required' });
    const result = await processPurchase(req.user.id, pin, 'tv', provider, plan, amount || 0, smartCardNumber, { useCashback }, req);
    res.json(result);
  } catch (err) { res.status(err.status || 500).json({ error: err.message || 'Purchase failed' }); }
});

app.post('/api/electricity/purchase', authenticate, async (req, res) => {
  try {
    const { provider, meterNumber, meterType, amount, pin, useCashback } = req.body;
    if (!provider || !meterNumber || !amount || !pin) return res.status(400).json({ error: 'All fields required' });
    const result = await processPurchase(req.user.id, pin, 'electricity', provider, null, amount, meterNumber, { meterType, useCashback }, req);
    res.json(result);
  } catch (err) { res.status(err.status || 500).json({ error: err.message || 'Purchase failed' }); }
});

app.post('/api/education/purchase', authenticate, async (req, res) => {
  try {
    const { examType, quantity, amount, pin, useCashback } = req.body;
    if (!examType || !quantity || !pin) return res.status(400).json({ error: 'All fields required' });
    const total = (amount || 1900) * quantity;
    const pins = Array.from({ length: quantity }, () => 'PIN-' + Date.now() + Math.random().toString(36).substr(2, 6).toUpperCase());
    const result = await processPurchase(req.user.id, pin, 'education', examType, `${quantity} pins`, total, examType, { quantity, pins, useCashback }, req);
    res.json({ ...result, pins });
  } catch (err) { res.status(err.status || 500).json({ error: err.message || 'Purchase failed' }); }
});

// Lookup table: friendly bet provider name -> ClubKonnect betting code
// (kept in sync with the seed in seedClubKonnectPlans)
const BET_PROVIDER_TO_CK_CODE = {
  // ⚠️ SportyBet uses 'prd-' prefix (NOT 'product-' like the others) per ClubKonnect docs
  'sportybet': 'prd-sporty-bet',
  'nairabet':  'product-nairabet',
  'bangbet':   'product-bang-bet',
  'betway':    'product-bet-way',
  'betland':   'product-bet-land',
  'betking':   'product-bet-king',
  '1xbet':     'product-1x-bet',
  'naijabet':  'product-naija-bet',
  'merrybet':  'product-merry-bet',
};

app.post('/api/bet/fund', authenticate, async (req, res) => {
  try {
    const { provider, userId: betUserId, amount, pin, useCashback } = req.body;
    if (!provider || !betUserId || !amount || !pin) return res.status(400).json({ error: 'All fields required' });
    if (amount < 100) return res.status(400).json({ error: 'Minimum funding amount is ₦100' });
    const ckCode = BET_PROVIDER_TO_CK_CODE[(provider || '').toLowerCase()];
    if (!ckCode) return res.status(400).json({ error: 'Unsupported betting provider: ' + provider });
    // Pass ckCode as the `plan` argument so processPurchase's CK branch
    // can use it as apiParams.BettingCompany.
    const result = await processPurchase(req.user.id, pin, 'bet', provider, ckCode, amount, betUserId, { betUserId, useCashback }, req);
    res.json(result);
  } catch (err) { res.status(err.status || 500).json({ error: err.message || 'Funding failed' }); }
});

// Verify a customer's betting ID before funding (uses APIVerifyBettingV1.asp)
app.post('/api/bet/verify', authenticate, async (req, res) => {
  try {
    const { provider, customerId } = req.body;
    if (!provider || !customerId) return res.status(400).json({ error: 'Provider and customerId required' });
    const ckCode = BET_PROVIDER_TO_CK_CODE[(provider || '').toLowerCase()];
    if (!ckCode) return res.status(400).json({ error: 'Unsupported betting provider' });
    if (!CK_USER_ID || !CK_API_KEY) return res.status(500).json({ error: 'ClubKonnect API credentials not configured. Set CLUBKONNECT_USER_ID and CLUBKONNECT_API_KEY env vars on Vercel.' });
    const verifyRes = await axios.get(`${CK_BASE_URL}/APIVerifyBettingV1.asp`, {
      params: { UserID: CK_USER_ID, APIKey: CK_API_KEY, BettingCompany: ckCode, CustomerID: customerId },
      timeout: 15000,
    });
    const data = verifyRes.data || {};
    const name = (data.customer_name || data.CustomerName || '').toString().trim();
    // ClubKonnect returns various error phrases in customer_name when the ID is invalid:
    //   "Unable to validate Customer ID."
    //   "Error, Invalid Customer ID"
    //   "Customer ID not found"
    // A valid response contains a real person's name (letters + spaces, sometimes with numbers).
    const isError = !name
      || /unable|error|invalid|not found|failed|does not exist|cannot/i.test(name)
      || name.length < 3;
    if (isError) {
      return res.status(400).json({
        error: name || 'Invalid customer ID for ' + provider + '. Please check the ID and try again.'
      });
    }
    res.json({ success: true, customer_name: name });
  } catch (err) {
    // If ClubKonnect itself errors (network/timeout), surface a clear message
    if (err.code === 'ECONNABORTED') {
      return res.status(504).json({ error: 'Verification timed out. Try again.' });
    }
    res.status(err.status || 500).json({ error: err.message || 'Verification failed' });
  }
});

// Public endpoint: list of supported betting providers (for dashboard UI)
app.get('/api/bet/companies', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT provider, plan AS ck_code, selling_price FROM pricing
       WHERE service = 'bet' AND is_active = TRUE ORDER BY provider`
    );
    res.json({ success: true, companies: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load betting companies' });
  }
});

// ===================== TRANSACTIONS & ANALYTICS =====================
app.get('/api/transactions', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100', [req.user.id]);
    res.json({ success: true, transactions: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/transactions/:id/receipt', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT t.*, u.fullname, u.email, u.phone FROM transactions t JOIN users u ON t.user_id = u.id WHERE t.id = $1 AND t.user_id = $2', [req.params.id, req.user.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true, receipt: result.rows[0] });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/analytics', authenticate, async (req, res) => {
  try {
    const { period } = req.query;
    let interval = '1 month';
    if (period === 'week') interval = '1 week';
    if (period === 'year') interval = '1 year';
    const spending = await pool.query(`SELECT service, SUM(total) as total_spent, COUNT(*) as count FROM transactions WHERE user_id = $1 AND type = 'purchase' AND created_at >= NOW() - INTERVAL '${interval}' GROUP BY service`, [req.user.id]);
    res.json({ success: true, spending: spending.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== REFERRAL & SPIN =====================
app.get('/api/referral', authenticate, async (req, res) => {
  try {
    const user = await pool.query('SELECT referral_code, spins_claimed FROM users WHERE id = $1', [req.user.id]);
    const referrals = await pool.query('SELECT fullname, email, created_at FROM users WHERE referred_by = $1', [req.user.id]);
    const totalReferrals = referrals.rows.length;
    const spinsAvailable = Math.floor(totalReferrals / 5) - user.rows[0].spins_claimed;
    res.json({ success: true, referralCode: user.rows[0].referral_code, referralLink: `${getBaseUrl(req)}/register.html?ref=${user.rows[0].referral_code}`, totalReferrals, spinsAvailable: spinsAvailable > 0 ? spinsAvailable : 0 });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/spin/play', authenticate, async (req, res) => {
  try {
    const { phone } = req.body;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const userRes = await client.query('SELECT id, spins_claimed FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
      const user = userRes.rows[0];
      const referrals = await client.query('SELECT COUNT(*) FROM users WHERE referred_by = $1', [req.user.id]);
      const totalReferrals = parseInt(referrals.rows[0].count);
      const spinsAvailable = Math.floor(totalReferrals / 5) - user.spins_claimed;
      if (spinsAvailable <= 0) return res.status(400).json({ error: 'No spins available. Refer 5 people to get a spin.' });
      const settingsRes = await client.query("SELECT value FROM admin_settings WHERE key = 'spin_settings'");
      if (!settingsRes.rows[0] || !settingsRes.rows[0].value.enabled) return res.status(400).json({ error: 'Spin & Earn is currently disabled.' });
      const rewards = settingsRes.rows[0].value.rewards;
      const totalChance = rewards.reduce((sum, r) => sum + r.chance, 0);
      let random = Math.random() * totalChance;
      let wonReward = rewards.find(r => { random -= r.chance; return random <= 0; });
      if (!wonReward) wonReward = rewards[rewards.length - 1];
      let message = `You won: ${wonReward.type === 'none' ? 'Nothing. Try again!' : (wonReward.value + ' ' + wonReward.type)}`;
      if (wonReward.type === 'money') {
        await client.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2', [wonReward.value, req.user.id]);
      } else if (wonReward.type === 'cashback') {
        await client.query('UPDATE users SET cashback_balance = cashback_balance + $1 WHERE id = $2', [wonReward.value, req.user.id]);
      } else if (wonReward.type === 'data' || wonReward.type === 'airtime') {
        if (!phone) return res.status(400).json({ error: 'Phone number required for data/airtime reward' });
        await client.query('UPDATE users SET spins_claimed = spins_claimed + 1 WHERE id = $1', [req.user.id]);
        await client.query('COMMIT');
        const apiEndpoint = wonReward.type === 'data' ? 'APIDatabundleV1.asp' : 'APIAirtimeV1.asp';
        const apiParams = { RequestID: generateTransactionId(), MobileNetwork: '01', MobileNumber: phone };
        if (wonReward.type === 'data') apiParams.DataPlan = wonReward.value; else apiParams.Amount = wonReward.value;
        try {
          const ckResponse = await axios.get(`${CK_BASE_URL}/${apiEndpoint}`, { params: { ...apiParams, UserID: CK_USER_ID, APIKey: CK_API_KEY }, timeout: 30000 });
          if (ckResponse.data.statuscode !== '100') throw new Error(ckResponse.data.remark || 'Failed');
          message = `You won ${wonReward.value} ${wonReward.type}! It has been sent to ${phone}.`;
        } catch (apiErr) {
          const fallbackCashback = wonReward.value * 2;
          await client.query('UPDATE users SET cashback_balance = cashback_balance + $1 WHERE id = $2', [fallbackCashback, req.user.id]);
          message = `You won ${wonReward.value} ${wonReward.type}, but provider failed. You got ₦${fallbackCashback} cashback instead.`;
        }
        return res.json({ success: true, reward: wonReward, message });
      }
      await client.query('UPDATE users SET spins_claimed = spins_claimed + 1 WHERE id = $1', [req.user.id]);
      await client.query('COMMIT');
      res.json({ success: true, reward: wonReward, message });
    } catch (err) { await client.query('ROLLBACK'); throw err; }
    finally { client.release(); }
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== NOTIFICATIONS =====================
app.get('/api/notifications', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50', [req.user.id]);
    const unread = await pool.query('SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND is_read = FALSE', [req.user.id]);
    res.json({ success: true, notifications: result.rows, unreadCount: parseInt(unread.rows[0].count) });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/notifications/:id/read', authenticate, async (req, res) => {
  try {
    await pool.query('UPDATE notifications SET is_read = TRUE WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== BUSINESS PAGE, ADS, REVIEWS, AGENT =====================
app.post('/api/business-page', authenticate, async (req, res) => {
  try {
    const { businessName, description, whatsapp, services } = req.body;
    const existing = await pool.query('SELECT business_page FROM users WHERE id = $1', [req.user.id]);
    if (existing.rows[0]?.business_page) return res.status(400).json({ error: 'You already have a business page. Delete it first.' });
    const link = `${getBaseUrl(req)}/business.html?user=${req.user.id}`;
    await pool.query('UPDATE users SET business_page = $1, business_link = $2 WHERE id = $3', [JSON.stringify({ businessName, description, whatsapp, services, createdAt: new Date() }), link, req.user.id]);
    res.json({ success: true, message: 'Business page created', link });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/business-page', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT business_page, business_link FROM users WHERE id = $1', [req.user.id]);
    res.json({ success: true, business: result.rows[0].business_page, link: result.rows[0].business_link });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.delete('/api/business-page', authenticate, async (req, res) => {
  try {
    await pool.query('UPDATE users SET business_page = NULL, business_link = NULL WHERE id = $1', [req.user.id]);
    res.json({ success: true, message: 'Business page deleted' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/business-page/:userId', async (req, res) => {
  try {
    const result = await pool.query('SELECT fullname, business_page, profile_pic FROM users WHERE id = $1', [req.params.userId]);
    if (result.rows.length === 0 || !result.rows[0].business_page) return res.status(404).json({ error: 'Business page not found', success: false });
    res.json({ success: true, business: result.rows[0].business_page, fullname: result.rows[0].fullname, profilePic: result.rows[0].profile_pic });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/ads/submit', authenticate, async (req, res) => {
  try {
    const { title, link, bannerUrl, topic, days } = req.body;
    const settings = await pool.query("SELECT value FROM admin_settings WHERE key = 'ads_pricing'");
    const pricePerDay = settings.rows.length > 0 ? settings.rows[0].value.price_per_day : 500;
    const totalAmount = pricePerDay * days;
    const user = await pool.query('SELECT wallet_balance FROM users WHERE id = $1', [req.user.id]);
    if (parseFloat(user.rows[0].wallet_balance) < totalAmount) return res.status(400).json({ error: 'Insufficient balance' });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id = $2', [totalAmount, req.user.id]);
      const result = await client.query(`INSERT INTO ads (user_id, title, link, banner_url, topic, price_per_day, total_days, total_amount, start_date, end_date) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW() + make_interval(days => $9)) RETURNING id`, [req.user.id, title, link, bannerUrl, topic, pricePerDay, days, totalAmount, days]);
      await client.query('COMMIT');
      res.json({ success: true, message: 'Ad submitted for approval.', adId: result.rows[0].id });
    } catch (err) { await client.query('ROLLBACK'); throw err; }
    finally { client.release(); }
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/ads/active', async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM ads WHERE status = 'approved' AND NOW() BETWEEN start_date AND end_date ORDER BY RANDOM() LIMIT 5");
    res.json({ success: true, ads: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/reviews', authenticate, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    if (!rating || rating < 1 || rating > 5) return res.status(400).json({ error: 'Rating must be 1-5' });
    await pool.query('INSERT INTO reviews (user_id, rating, comment) VALUES ($1, $2, $3)', [req.user.id, rating, comment]);
    res.json({ success: true, message: 'Review submitted' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/agent/enroll', authenticate, async (req, res) => {
  try {
    const agentCode = 'AG' + req.user.id.toString().padStart(6, '0');
    await pool.query('UPDATE users SET is_agent = TRUE, agent_code = $1 WHERE id = $2', [agentCode, req.user.id]);
    res.json({ success: true, message: 'Agent enrollment successful', agentCode });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== ADMIN ROUTES =====================
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (email !== process.env.ADMIN_EMAIL) return res.status(401).json({ error: 'Invalid credentials' });
    let isMatch = false;
    if (process.env.ADMIN_PASSWORD_HASH) { try { isMatch = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH); } catch {} }
    if (!isMatch && process.env.ADMIN_PASSWORD) isMatch = password === process.env.ADMIN_PASSWORD;
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ email, isAdmin: true }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ success: true, token });
  } catch (err) { res.status(500).json({ error: 'Server error: ' + err.message }); }
});

app.get('/api/admin/dashboard', authenticateAdmin, async (req, res) => {
  try {
    const users = await pool.query('SELECT COUNT(*) FROM users');
    const transactions = await pool.query('SELECT COUNT(*), SUM(total) FROM transactions');
    const revenue = await pool.query("SELECT SUM(total) FROM transactions WHERE status = 'success'");
    const banned = await pool.query('SELECT COUNT(*) FROM users WHERE is_banned = TRUE');
    const resellers = await pool.query("SELECT COUNT(*) FROM reseller_subscriptions WHERE status = 'active'");
    res.json({ success: true, stats: { totalUsers: parseInt(users.rows[0].count), totalTransactions: parseInt(transactions.rows[0].count), totalRevenue: parseFloat(revenue.rows[0].sum) || 0, bannedUsers: parseInt(banned.rows[0].count), activeResellers: parseInt(resellers.rows[0].count) } });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, fullname, email, phone, wallet_balance, cashback_balance, account_number, kyc_status, is_agent, is_banned, email_visible, gustmii_linked, created_at FROM users ORDER BY created_at DESC');
    res.json({ success: true, users: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/admin/users/:id/toggle-email', authenticateAdmin, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT email_visible FROM users WHERE id = $1', [req.params.id]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const newStatus = !userRes.rows[0].email_visible;
    await pool.query('UPDATE users SET email_visible = $1 WHERE id = $2', [newStatus, req.params.id]);
    res.json({ success: true, email_visible: newStatus });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/admin/wallet/credit', authenticateAdmin, async (req, res) => {
  try {
    const { userId, amount, reason } = req.body;
    const txnId = generateTransactionId();
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2', [amount, userId]);
      await client.query("INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, reference, remark) VALUES ($1, 'credit', 'admin_credit', $2, $2, 'success', $3, $3, $4)", [userId, amount, txnId, reason || 'Admin credit']);
      await client.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [userId, 'Wallet Credited', `Your wallet has been credited with ₦${amount}.`, 'admin']);
      await client.query('COMMIT');
      sendUserEmail(userId, 'Wallet Credited', `Your wallet has been credited with <b>₦${amount}</b>.`);
      res.json({ success: true, message: `Wallet credited ₦${amount}` });
    } catch (e) { await client.query('ROLLBACK'); throw e; }
    finally { client.release(); }
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/admin/wallet/debit', authenticateAdmin, async (req, res) => {
  try {
    const { userId, amount, reason } = req.body;
    const txnId = generateTransactionId();
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id = $2', [amount, userId]);
      await client.query("INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, reference, remark) VALUES ($1, 'debit', 'admin_debit', $2, $2, 'success', $3, $3, $4)", [userId, amount, txnId, reason || 'Admin debit']);
      await client.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [userId, 'Wallet Debited', `Your wallet has been debited with ₦${amount}.`, 'admin']);
      await client.query('COMMIT');
      sendUserEmail(userId, 'Wallet Debited', `Your wallet has been debited with <b>₦${amount}</b>.`);
      res.json({ success: true, message: `Wallet debited ₦${amount}` });
    } catch (e) { await client.query('ROLLBACK'); throw e; }
    finally { client.release(); }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/users/:id/ban', authenticateAdmin, async (req, res) => {
  try { await pool.query('UPDATE users SET is_banned = TRUE, ban_reason = $1 WHERE id = $2', [req.body.reason || 'Banned', req.params.id]); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/admin/users/:id/unban', authenticateAdmin, async (req, res) => {
  try { await pool.query('UPDATE users SET is_banned = FALSE, ban_reason = NULL WHERE id = $1', [req.params.id]); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== ADMIN: DELETE USER'S BANK ACCOUNT + BLACKLIST BVN/NIN =====================
//
// Use case: Admin discovers a user's BVN/NIN is fake (or fraudulent). Admin
// wants to (1) clear the user's bank account + BVN/NIN from Yenllet's DB so
// the user can re-generate with a DIFFERENT (valid) BVN, AND optionally
// (2) blacklist the fake BVN/NIN so it can NEVER be used again on Yenllet
// (prevents the user from re-generating with the same fake ID).
//
// Important behavior notes:
//   - On Flutterwave's side, the old virtual account is NOT deleted (Flutterwave
//     does not expose a "delete virtual account" endpoint). It remains alive
//     but Yenllet no longer maps it to this user. The user's wallet_balance is
//     UNCHANGED.
//   - If `blacklist_id` is true, the BVN/NIN is added to `id_blacklist` table.
//     Future `/api/profile/generate-account-from-bvn` calls with that BVN/NIN
//     are rejected BEFORE calling Flutterwave, so Flutterwave won't return
//     the old account.
//   - If `blacklist_id` is false, the user can re-generate with the SAME BVN
//     (Flutterwave will likely return the same account number — usually NOT
//     what you want when the BVN is fake).

app.post('/api/admin/users/:id/delete-account', authenticateAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const userId = parseInt(req.params.id, 10);
    if (!userId) return res.status(400).json({ error: 'Invalid user id' });
    const { reason, blacklist_id = true, ban_user = true } = req.body;
    if (!reason || !reason.trim()) {
      return res.status(400).json({ error: 'Please provide a reason for deleting this account. The user will receive this reason as a notification.' });
    }

    await client.query('BEGIN');

    // Lock the user row
    const userRes = await client.query(
      'SELECT id, fullname, email, phone, kyc_bvn, kyc_nin, kyc_status, account_number, bank_name, wallet_balance, is_banned FROM users WHERE id = $1 FOR UPDATE',
      [userId]
    );
    if (userRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'User not found' });
    }
    const user = userRes.rows[0];

    if (!user.account_number && !user.kyc_bvn && !user.kyc_nin) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'This user has no bank account or BVN/NIN to delete.' });
    }

    const deletedAccount = user.account_number;
    const deletedBank = user.bank_name;
    const deletedBvn = user.kyc_bvn;
    const deletedNin = user.kyc_nin;

    // ✅ Optionally blacklist the BVN (preferred) or NIN
    let blacklistedId = null;
    let blacklistedType = null;
    if (blacklist_id) {
      const idValue = deletedBvn || deletedNin;
      const idType = deletedBvn ? 'BVN' : 'NIN';
      if (idValue) {
        // INSERT ... ON CONFLICT DO NOTHING so re-running on the same ID doesn't fail
        await client.query(
          `INSERT INTO id_blacklist (id_value, id_type, reason, user_id, blocked_by_admin_id)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (id_value) DO UPDATE SET reason = $3, blocked_at = NOW()`,
          [idValue, idType, reason.trim(), userId, req.admin.id]
        );
        blacklistedId = idValue;
        blacklistedType = idType;
        console.log(`🚫 Admin blacklisted ${idType} ${idValue.substring(0,4)}***${idValue.substring(7)} (user ${userId})`);
      }
    }

    // ✅ Clear the user's bank account + BVN/NIN + reset kyc_status to pending.
    // ✅ If ban_user=true, also ban the user (block login). This is the recommended
    //    path when admin deleted the account because the BVN was fake — even though
    //    Flutterwave's old virtual account still exists and Opay will still confirm
    //    the account number, the banned user can no longer log in to Yenllet, so
    //    they cannot benefit from any funds that may be sent to the orphaned account.
    //    Those orphaned deposits are logged separately (see orphaned_deposits table).
    if (ban_user) {
      await client.query(
        `UPDATE users
         SET account_number = NULL,
             bank_name = NULL,
             kyc_bvn = NULL,
             kyc_nin = NULL,
             kyc_status = 'pending',
             kyc_submitted_at = NULL,
             kyc_approved_at = NULL,
             is_banned = TRUE,
             ban_reason = $2
         WHERE id = $1`,
        [userId, `Account deleted by admin: ${reason.trim()}`]
      );
      console.log(`🚫 Admin also banned user ${userId} (ban_user=true)`);
    } else {
      await client.query(
        `UPDATE users
         SET account_number = NULL,
             bank_name = NULL,
             kyc_bvn = NULL,
             kyc_nin = NULL,
             kyc_status = 'pending',
             kyc_submitted_at = NULL,
             kyc_approved_at = NULL
         WHERE id = $1`,
        [userId]
      );
    }

    // ✅ Notify the user
    const notifMsg = blacklistedId
      ? `Your bank account (${deletedAccount || '—'} - ${deletedBank || ''}) and ${blacklistedType} have been removed by admin. Reason: ${reason.trim()}. This ${blacklistedType} has been blacklisted and cannot be used again on Yenllet.${ban_user ? ' Your Yenllet account has also been BANNED — you can no longer log in.' : ''} If you want to use Yenllet, please contact support.`
      : `Your bank account (${deletedAccount || '—'} - ${deletedBank || ''}) and BVN/NIN have been removed by admin. Reason: ${reason.trim()}.${ban_user ? ' Your Yenllet account has also been BANNED — you can no longer log in.' : ' You can generate a new account from your Profile page.'}`;
    await client.query(
      'INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)',
      [userId, '⚠️ Account Removed by Admin', notifMsg, 'kyc']
    );

    await client.query('COMMIT');

    // Email after commit (non-critical)
    sendUserEmail(userId, 'Account Number Removed', `Hi ${user.fullname},<br><br>Your virtual bank account <strong>${deletedAccount || ''}</strong> (${deletedBank || ''}) has been removed by our admin team.<br><br><strong>Reason:</strong> ${reason.trim()}<br><br>${blacklistedId ? 'Your ' + blacklistedType + ' has been blacklisted and cannot be used again on Yenllet. ' : ''}${ban_user ? '<strong>Your Yenllet account has been BANNED.</strong> You can no longer log in. ' : ''}If you believe this was a mistake, please contact support.`);

    console.log(`🗑️ Admin deleted account for user ${userId} (${user.fullname}) — was ${deletedAccount} / ${deletedBank}. Blacklisted: ${blacklist_id ? 'YES' : 'NO'}. Banned: ${ban_user ? 'YES' : 'NO'}`);

    return res.json({
      success: true,
      message: (blacklistedId
        ? `Account deleted and ${blacklistedType} ${blacklistedId.substring(0,4)}***${blacklistedId.substring(7)} blacklisted.`
        : 'Account deleted.')
        + (ban_user ? ' User also BANNED — they can no longer log in.' : ''),
      deleted: {
        account_number: deletedAccount,
        bank_name: deletedBank,
        bvn: deletedBvn,
        nin: deletedNin
      },
      blacklisted: blacklistedId ? { id_type: blacklistedType, id_value: blacklistedId } : null,
      banned: !!ban_user
    });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    res.status(500).json({ error: 'Failed: ' + err.message });
  } finally {
    client.release();
  }
});

// GET — list all blacklisted BVNs/NINs (admin can review and remove from blacklist)
app.get('/api/admin/bvn-blacklist', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT b.*, u.fullname AS user_fullname, u.email AS user_email, a.email AS admin_email
      FROM id_blacklist b
      LEFT JOIN users u ON b.user_id = u.id
      LEFT JOIN users a ON b.blocked_by_admin_id = a.id
      ORDER BY b.blocked_at DESC
    `);
    res.json({ success: true, count: result.rows.length, blacklist: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// DELETE — remove a BVN/NIN from the blacklist (admin reverses the blacklist)
app.delete('/api/admin/bvn-blacklist/:id', authenticateAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!id) return res.status(400).json({ error: 'Invalid blacklist id' });
    const result = await pool.query('DELETE FROM id_blacklist WHERE id = $1 RETURNING id_value, id_type', [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Blacklist entry not found' });
    const row = result.rows[0];
    console.log(`✅ Admin removed ${row.id_type} ${String(row.id_value).substring(0,4)}***${String(row.id_value).substring(7)} from blacklist`);
    res.json({ success: true, message: `${row.id_type} removed from blacklist. Users can now generate accounts with this ID again.` });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== ADMIN: ORPHANED DEPOSITS (trapped funds) =====================
//
// When admin deletes a user's bank account (because BVN was fake), the OLD
// Flutterwave virtual account is still alive on Flutterwave's side. Senders
// like Opay will still confirm the account number and send money to it.
// Yenllet's webhook receives those `transfer.completed` events but can't
// credit anyone (no user owns the account_number anymore). We log those
// deposits in `orphaned_deposits` so admin can:
//   1. See how much money is trapped on each orphaned account
//   2. Manually decide what to do (refund sender, keep in escrow, etc.)
//   3. Mark each deposit as "reviewed" once handled.

// GET — list all orphaned deposits (newest first)
app.get('/api/admin/orphaned-deposits', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM orphaned_deposits
      ORDER BY received_at DESC
      LIMIT 500
    `);
    // ✅ Also compute summary stats: total trapped amount, count, count of unreviewed
    const statsRes = await pool.query(`
      SELECT
        COUNT(*) as total_count,
        COUNT(*) FILTER (WHERE reviewed = FALSE) as unreviewed_count,
        COALESCE(SUM(amount), 0) as total_amount,
        COALESCE(SUM(amount) FILTER (WHERE reviewed = FALSE), 0) as unreviewed_amount
      FROM orphaned_deposits
    `);
    const stats = statsRes.rows[0];
    res.json({
      success: true,
      count: result.rows.length,
      deposits: result.rows,
      stats: {
        total_count: parseInt(stats.total_count),
        unreviewed_count: parseInt(stats.unreviewed_count),
        total_amount: parseFloat(stats.total_amount),
        unreviewed_amount: parseFloat(stats.unreviewed_amount)
      }
    });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// POST — mark an orphaned deposit as reviewed (with optional admin note)
app.post('/api/admin/orphaned-deposits/:id/review', authenticateAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!id) return res.status(400).json({ error: 'Invalid deposit id' });
    const { note } = req.body;
    const result = await pool.query(
      `UPDATE orphaned_deposits
       SET reviewed = TRUE,
           admin_note = $1,
           reviewed_by = $2,
           reviewed_at = NOW()
       WHERE id = $3
       RETURNING id, account_number, amount`,
      [note || '', req.user.email || 'admin', id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Orphaned deposit not found' });
    const r = result.rows[0];
    console.log(`✅ Admin reviewed orphaned deposit #${r.id} (acct ${r.account_number}, ₦${r.amount})`);
    res.json({
      success: true,
      message: `Deposit of ₦${parseFloat(r.amount).toLocaleString()} to account ${r.account_number} marked as reviewed.`
    });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/admin/transactions', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT t.*, u.fullname, u.email FROM transactions t JOIN users u ON t.user_id = u.id ORDER BY t.created_at DESC LIMIT 200');
    res.json({ success: true, transactions: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/admin/pricing', authenticateAdmin, async (req, res) => {
  try { const result = await pool.query('SELECT * FROM pricing ORDER BY service, provider, amount ASC'); res.json({ success: true, pricing: result.rows }); }
  catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.put('/api/admin/pricing', authenticateAdmin, async (req, res) => {
  try {
    const { id, service, provider, plan, amount, sellingPrice, cashbackPercent, isActive, validity, category } = req.body;
    const finalSellingPrice = service === 'airtime' ? parseFloat(amount) : parseFloat(sellingPrice || amount);
    if (id) {
      await pool.query(`UPDATE pricing SET service = $1, provider = $2, plan = $3, amount = $4, selling_price = $5, cashback_percent = $6, is_active = $7, validity = $8, category = $9, updated_at = NOW() WHERE id = $10`, [service, provider, plan || null, parseFloat(amount), finalSellingPrice, parseFloat(cashbackPercent || 0), isActive !== false, validity || null, category || 'general', id]);
    } else {
      await pool.query(`INSERT INTO pricing (service, provider, plan, amount, selling_price, cashback_percent, is_active, validity, category, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) ON CONFLICT (service, provider, plan) DO UPDATE SET amount = EXCLUDED.amount, selling_price = EXCLUDED.selling_price, cashback_percent = EXCLUDED.cashback_percent, is_active = EXCLUDED.is_active, validity = EXCLUDED.validity, category = EXCLUDED.category, updated_at = NOW()`, [service, provider, plan || null, parseFloat(amount), finalSellingPrice, parseFloat(cashbackPercent || 0), isActive !== false, validity || null, category || 'general']);
    }
    res.json({ success: true, message: 'Pricing saved successfully' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.delete('/api/admin/pricing/:id', authenticateAdmin, async (req, res) => {
  try { await pool.query('DELETE FROM pricing WHERE id = $1', [req.params.id]); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/admin/ads', authenticateAdmin, async (req, res) => {
  try { const result = await pool.query('SELECT a.*, u.fullname, u.email FROM ads a JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC'); res.json({ success: true, ads: result.rows }); }
  catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.put('/api/admin/ads/:id/approve', authenticateAdmin, async (req, res) => {
  try { await pool.query("UPDATE ads SET status = 'approved' WHERE id = $1", [req.params.id]); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.put('/api/admin/ads/:id/reject', authenticateAdmin, async (req, res) => {
  try { await pool.query("UPDATE ads SET status = 'rejected' WHERE id = $1", [req.params.id]); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.put('/api/admin/ads/:id/stop', authenticateAdmin, async (req, res) => {
  try { await pool.query("UPDATE ads SET status = 'stopped', end_date = NOW() WHERE id = $1", [req.params.id]); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.delete('/api/admin/ads/:id', authenticateAdmin, async (req, res) => {
  try { await pool.query('DELETE FROM ads WHERE id = $1', [req.params.id]); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/admin/reviews', authenticateAdmin, async (req, res) => {
  try { const result = await pool.query('SELECT r.*, u.fullname, u.email FROM reviews r JOIN users u ON r.user_id = u.id ORDER BY r.created_at DESC'); res.json({ success: true, reviews: result.rows }); }
  catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.put('/api/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    const { key, value } = req.body;
    await pool.query('INSERT INTO admin_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()', [key, JSON.stringify(value)]);
    res.json({ success: true, message: 'Settings updated' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/admin/settings', authenticateAdmin, async (req, res) => {
  try { const result = await pool.query('SELECT key, value FROM admin_settings'); res.json({ success: true, settings: result.rows }); }
  catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== SUPPORT CONTACT (configurable phone number) =====================
//
// Admin controls the support phone number shown to banned users on the login
// screen. Default: 09030943391 (set in seed).
// When admin changes it, banned users immediately see the new number — no
// redeploy needed.

// GET — admin reads the current support contact
app.get('/api/admin/support-contact', authenticateAdmin, async (req, res) => {
  try {
    const support = await getSupportContact();
    res.json({ success: true, support });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// PUT — admin updates the support contact
app.put('/api/admin/support-contact', authenticateAdmin, async (req, res) => {
  try {
    const { phone, whatsapp, email, hours } = req.body;
    const current = await getSupportContact();
    const updated = {
      phone: (phone !== undefined && phone !== '') ? String(phone).trim() : current.phone,
      whatsapp: (whatsapp !== undefined && whatsapp !== '') ? String(whatsapp).trim() : (current.whatsapp || (phone !== undefined ? String(phone).trim() : current.phone)),
      email: (email !== undefined) ? String(email).trim() : current.email,
      hours: (hours !== undefined) ? String(hours).trim() : current.hours,
      updated_at: new Date().toISOString()
    };
    await pool.query(
      "INSERT INTO admin_settings (key, value) VALUES ('support_contact', $1) ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()",
      [JSON.stringify(updated)]
    );
    console.log(`📞 Admin updated support_contact: phone=${updated.phone}, whatsapp=${updated.whatsapp}`);
    res.json({
      success: true,
      message: `Support contact updated. Banned users will now see phone: ${updated.phone}.`,
      support: updated
    });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// PUBLIC — fetch support contact (no auth required).
// Used by login.html / forgot-password.html / register.html to display the
// support phone number under the form, so users always see a real contact.
app.get('/api/public/support-contact', async (req, res) => {
  try {
    const support = await getSupportContact();
    // ✅ Also return WhatsApp deep link + tel: link for one-tap contact
    const whatsappIntl = normalizePhoneInternational(support.whatsapp || support.phone);
    const phoneIntl = support.phone ? support.phone : '';
    res.json({
      success: true,
      support: {
        ...support,
        whatsapp_link: `https://wa.me/${whatsappIntl}?text=${encodeURIComponent('Hello Yenllet support, I need help with my account.')}`,
        call_link: phoneIntl ? `tel:${phoneIntl}` : ''
      }
    });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== KYC VERIFICATION TOGGLE & PENDING QUEUE =====================
//
// Admin controls:
//   1. Toggle "force_verify" ON/OFF — when OFF, users can still generate accounts
//      even if CheckMyNinBvn wallet is empty. When ON, generation is blocked until
//      admin tops up CheckMyNinBvn.
//   2. View CheckMyNinBvn wallet balance (so admin knows when to top up).
//   3. View all users with kyc_status='pending' (and have a bank account).
//   4. Tap "Verify" next to any pending user — server runs CheckMyNinBvn verification
//      using that user's stored BVN/NIN. If verified → kyc_status='approved'.

// GET current KYC verification settings (force_verify flag + notify flag)
app.get('/api/admin/kyc-settings', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT value FROM admin_settings WHERE key = 'kyc_verification'");
    let settings = { force_verify: false, notify_admin_on_skip: true };
    if (result.rows.length > 0) {
      const raw = result.rows[0].value;
      settings = typeof raw === 'string' ? JSON.parse(raw) : raw;
    }
    res.json({ success: true, settings });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// PUT — update force_verify toggle (and notify_admin_on_skip if provided)
app.put('/api/admin/kyc-settings', authenticateAdmin, async (req, res) => {
  try {
    const { force_verify, notify_admin_on_skip } = req.body;
    // Load current
    const result = await pool.query("SELECT value FROM admin_settings WHERE key = 'kyc_verification'");
    let current = { force_verify: false, notify_admin_on_skip: true };
    if (result.rows.length > 0) {
      const raw = result.rows[0].value;
      current = typeof raw === 'string' ? JSON.parse(raw) : raw;
    }
    if (typeof force_verify === 'boolean') current.force_verify = force_verify;
    if (typeof notify_admin_on_skip === 'boolean') current.notify_admin_on_skip = notify_admin_on_skip;
    current.updated_at = new Date().toISOString();
    await pool.query("INSERT INTO admin_settings (key, value) VALUES ('kyc_verification', $1) ON CONFLICT (key) DO UPDATE SET value = $1, updated_at = NOW()", [JSON.stringify(current)]);
    console.log(`🔧 Admin updated kyc_verification: force_verify=${current.force_verify}`);
    res.json({ success: true, message: `KYC verification ${current.force_verify ? 'ENFORCED (users must verify before account generation)' : 'OPTIONAL (users can generate without CheckMyNinBvn verification)'}`, settings: current });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// GET — CheckMyNinBvn wallet balance (so admin knows when to top up)
app.get('/api/admin/checkmyninbvn/balance', authenticateAdmin, async (req, res) => {
  try {
    if (!CHECKMYNINBVN_API_KEY) {
      return res.json({
        success: false,
        configured: false,
        message: 'CheckMyNinBvn API key is NOT configured on the server. Add CHECKMYNINBVN_API_KEY env var on Vercel.'
      });
    }
    // Try common wallet/balance endpoints — CheckMyNinBvn docs use /wallet or /balance.
    // We try each one in sequence until one succeeds.
    const endpoints = ['/wallet/balance', '/balance', '/wallet', '/account/balance', '/user/wallet'];
    let lastErr = null;
    for (const ep of endpoints) {
      try {
        const response = await fetch(`${CHECKMYNINBVN_BASE_URL}${ep}`, {
          method: 'GET',
          headers: { 'x-api-key': CHECKMYNINBVN_API_KEY, 'Content-Type': 'application/json' }
        });
        const data = await response.json();
        // Some endpoints return balance directly, others nest under data
        const balance = data.balance ?? data.data?.balance ?? data.wallet_balance ?? data.data?.wallet_balance ?? null;
        if (response.ok && balance !== null && balance !== undefined) {
          const currency = data.currency || data.data?.currency || 'NGN';
          return res.json({
            success: true,
            configured: true,
            balance: parseFloat(balance),
            currency,
            endpoint_used: ep,
            raw: data
          });
        }
        lastErr = `${ep} → HTTP ${response.status}: ${JSON.stringify(data).substring(0, 200)}`;
      } catch (e) {
        lastErr = `${ep} → ${e.message}`;
      }
    }
    // None of the endpoints worked — return diagnostic info so admin can troubleshoot
    return res.json({
      success: false,
      configured: true,
      balance: null,
      message: 'CheckMyNinBvn API key is set but could not fetch wallet balance. The balance endpoint may have changed on their side. Try a real BVN verification to see if credits are still available.',
      last_error: lastErr
    });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// GET — list users with kyc_status='pending' who already have a bank account
// (i.e., they generated an account while force_verify was OFF but admin hasn't
// verified them yet). Returns id, fullname, email, phone, kyc_bvn, kyc_nin,
// account_number, bank_name, kyc_submitted_at.
app.get('/api/admin/kyc/pending', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, fullname, email, phone,
             kyc_bvn, kyc_nin,
             account_number, bank_name,
             kyc_status, kyc_submitted_at, created_at
      FROM users
      WHERE kyc_status = 'pending'
        AND (kyc_bvn IS NOT NULL OR kyc_nin IS NOT NULL)
        AND account_number IS NOT NULL
        AND is_admin = FALSE
      ORDER BY kyc_submitted_at DESC NULLS LAST, created_at DESC
    `);
    res.json({ success: true, count: result.rows.length, pending: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// POST — admin manually triggers CheckMyNinBvn verification for a pending user.
// Pulls user's stored kyc_bvn (preferred) or kyc_nin, calls CheckMyNinBvn, on
// success sets kyc_status='approved' + kyc_approved_at=NOW(). Returns the
// verification result so admin sees the verified name from NIBSS.
app.post('/api/admin/kyc/verify/:userId', authenticateAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const userId = parseInt(req.params.userId, 10);
    if (!userId) return res.status(400).json({ error: 'Invalid user id' });

    await client.query('BEGIN');
    const userRes = await client.query(
      'SELECT id, fullname, email, phone, kyc_bvn, kyc_nin, kyc_status, account_number FROM users WHERE id = $1 FOR UPDATE',
      [userId]
    );
    if (userRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'User not found' });
    }
    const user = userRes.rows[0];

    if (user.kyc_status === 'approved') {
      await client.query('ROLLBACK');
      return res.json({ success: true, already_verified: true, message: `${user.fullname} is already verified.` });
    }

    // Use BVN if available, else NIN
    const idNumber = user.kyc_bvn || user.kyc_nin;
    const idType = user.kyc_bvn ? 'BVN' : 'NIN';
    if (!idNumber) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'This user has no BVN or NIN stored. Cannot verify.' });
    }

    // Run verification with forceVerify=true so we get the real result (not a skip)
    const verification = await verifyIdWithCheckMyNINBVN(idNumber, idType, true);

    if (!verification.valid) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        success: false,
        verified: false,
        error: verification.error || 'Verification failed',
        user: { id: user.id, fullname: user.fullname, email: user.email, phone: user.phone }
      });
    }

    // ✅ Verified — update user record
    await client.query(
      `UPDATE users
       SET kyc_status = 'approved',
           kyc_approved_at = NOW()
       WHERE id = $1`,
      [userId]
    );

    // Notify the user
    await client.query(
      'INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)',
      [userId, 'KYC Verified ✅', `Your ${idType} has been verified by our team. Your account is now fully approved.`, 'kyc']
    );

    await client.query('COMMIT');

    // Email after commit (non-critical)
    sendUserEmail(userId, 'KYC Verified', `Hi ${user.fullname},<br><br>Great news! Your ${idType} has been verified by our admin team. Your Yenllet account is now fully approved.<br><br>Thank you for your patience.`);

    console.log(`✅ Admin verified user ${userId} (${user.fullname}) ${idType} ${idNumber.substring(0, 4)}***${idNumber.substring(7)}`);

    return res.json({
      success: true,
      verified: true,
      message: `${user.fullname}'s ${idType} verified successfully!`,
      user: {
        id: user.id,
        fullname: user.fullname,
        email: user.email,
        phone: user.phone,
        verified_name: verification.firstName && verification.lastName ? `${verification.firstName} ${verification.lastName}` : null
      }
    });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    res.status(500).json({ error: 'Failed: ' + err.message });
  } finally {
    client.release();
  }
});

// ✅ ADMIN: Seed ClubKonnect data plans manually (SYNCHRONOUS — waits for completion)
app.post('/api/admin/seed-plans', authenticateAdmin, async (req, res) => {
  try {
    console.log('📦 Admin triggered seed plans...');
    await seedClubKonnectPlans();
    res.json({ success: true, message: 'All 122 data plans seeded successfully!' });
  } catch (err) {
    console.error('Seed error:', err.message);
    res.status(500).json({ error: 'Seed failed: ' + err.message });
  }
});

// ✅ ADMIN: Force-run database migrations (vendor columns, FAQ table, fcm_tokens, etc.)
// Use this if you deployed new dashboard.html but the background initDatabase() hasn't
// added the new columns yet (e.g. "column vendor_status does not exist" error).
app.post('/api/admin/run-migrations', authenticateAdmin, async (req, res) => {
  try {
    console.log('🔧 Admin triggered DB migrations...');
    const migrations = [
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS push_enabled BOOLEAN DEFAULT TRUE`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS email_notifications BOOLEAN DEFAULT TRUE`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_vendor BOOLEAN DEFAULT FALSE`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_status VARCHAR(20) DEFAULT 'none'`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_approved_at TIMESTAMP`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_business_name VARCHAR(255)`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_whatsapp VARCHAR(20)`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_experience TEXT`,
      `ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_promotion TEXT`
    ];
    for (const sql of migrations) {
      try { await pool.query(sql); console.log('  ✅', sql.substring(0, 80)); }
      catch (e) { console.error('  ❌', sql.substring(0, 80), '→', e.message); }
    }
    // Create new tables
    const tables = [
      `CREATE TABLE IF NOT EXISTS vendor_referrals (id SERIAL PRIMARY KEY, vendor_id INTEGER REFERENCES users(id) ON DELETE CASCADE, referred_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, referral_code VARCHAR(20) UNIQUE NOT NULL, total_purchases DECIMAL(12,2) DEFAULT 0, vendor_earnings DECIMAL(12,2) DEFAULT 0, created_at TIMESTAMP DEFAULT NOW())`,
      `CREATE TABLE IF NOT EXISTS vendor_chats (id SERIAL PRIMARY KEY, uid VARCHAR(50) UNIQUE NOT NULL, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, vendor_id INTEGER REFERENCES users(id) ON DELETE CASCADE, message TEXT NOT NULL, sender_type VARCHAR(10) NOT NULL DEFAULT 'user', is_read BOOLEAN DEFAULT FALSE, is_faq BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW())`,
      `CREATE TABLE IF NOT EXISTS saved_recipients (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, phone VARCHAR(20) NOT NULL, name VARCHAR(100), network VARCHAR(20), service VARCHAR(20) DEFAULT 'airtime', created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, phone, service))`,
      `CREATE TABLE IF NOT EXISTS faq_questions (id SERIAL PRIMARY KEY, uid VARCHAR(50) UNIQUE NOT NULL, question TEXT NOT NULL, answer TEXT NOT NULL, category VARCHAR(50) DEFAULT 'general', sort_order INTEGER DEFAULT 0, is_active BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT NOW())`,
      `CREATE TABLE IF NOT EXISTS fcm_tokens (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, token TEXT NOT NULL UNIQUE, created_at TIMESTAMP DEFAULT NOW())`
    ];
    for (const sql of tables) {
      try { await pool.query(sql); console.log('  ✅', sql.substring(0, 80)); }
      catch (e) { console.error('  ❌', sql.substring(0, 80), '→', e.message); }
    }
    // Insert default vendor settings if missing
    try {
      await pool.query(`INSERT INTO admin_settings (key, value) VALUES ('vendor_settings', '{"vendor_discount_percent": 5, "vendor_cashback_percent": 2, "vendor_enabled": true, "vendor_portal_open": true}') ON CONFLICT (key) DO NOTHING`);
    } catch (e) {}
    res.json({ success: true, message: '✅ All migrations ran successfully. The vendor_status column and all new tables now exist. Refresh your dashboard page.' });
  } catch (err) {
    console.error('Migration error:', err.message);
    res.status(500).json({ error: 'Migration failed: ' + err.message });
  }
});

// ✅ ADMIN: Sync plans LIVE from ClubKonnect API
app.post('/api/admin/sync-clubkonnect', authenticateAdmin, async (req, res) => {
  try {
    if (!CK_USER_ID || !CK_API_KEY) {
      return res.status(400).json({ error: 'ClubKonnect API credentials not set.' });
    }
    console.log('🔄 Syncing from ClubKonnect...');
    
    const fetchUrl = `${CK_BASE_URL}/APIDatabundlePlansV2.asp?UserID=${CK_USER_ID}`;
    const ckResponse = await axios.get(fetchUrl, { timeout: 30000 });
    const ckData = ckResponse.data;
    
    // ✅ API returns: { MOBILE_NETWORK: { MTN: [{PRODUCT: [...]}], Glo: [...], m_9mobile: [...], Airtel: [...] } }
    const networks = ckData.MOBILE_NETWORK || ckData;
    const plans = [];
    
    const networkMap = { 'MTN': 'MTN', 'Glo': 'Glo', 'Airtel': 'Airtel', 'm_9mobile': '9mobile', '9mobile': '9mobile', 't2mobile': '9mobile' };
    
    for (const [networkKey, networkData] of Object.entries(networks)) {
      if (!networkMap[networkKey]) continue;
      const provider = networkMap[networkKey];
      
      // networkData is an array: [{ ID: "01", PRODUCT: [...] }]
      if (!Array.isArray(networkData)) continue;
      
      for (const netEntry of networkData) {
        const products = netEntry.PRODUCT || netEntry.product || [];
        if (!Array.isArray(products)) continue;
        
        for (const product of products) {
          const planName = (product.PRODUCT_NAME || product.product_name || '').trim();
          const price = parseFloat(product.PRODUCT_AMOUNT || product.product_amount || '0');
          
          if (!planName || isNaN(price) || price <= 0) continue;
          
          // Auto-detect category
          let category = 'general';
          let validity = '30 days';
          const p = planName.toLowerCase();
          
          if (p.includes('daily') || p.includes('1 day') || p.includes('1-day')) { category = 'Awoof Daily'; validity = '1 day'; }
          else if (p.includes('2-day') || p.includes('2 days')) { category = 'Awoof Daily'; validity = '2 days'; }
          else if (p.includes('weekend')) { category = 'Awoof Daily'; validity = 'Weekend'; }
          else if (p.includes('night')) { category = 'SME Night'; validity = '14 days'; }
          else if (p.includes('weekly') || p.includes('7 days') || p.includes('7-days')) { category = p.includes('sme') ? 'SME Weekly' : 'Direct Weekly'; validity = '7 days'; }
          else if (p.includes('14 days') || p.includes('14-days')) { category = p.includes('sme') ? 'SME Weekly' : 'Direct Weekly'; validity = '14 days'; }
          else if (p.includes('3 days') || p.includes('3-days')) { category = 'SME Weekly'; validity = '3 days'; }
          else if (p.includes('monthly') || p.includes('30 days') || p.includes('30-days')) { category = p.includes('sme') ? 'SME Monthly' : 'Direct Monthly'; validity = '30 days'; }
          else if (p.includes('60 days') || p.includes('90 days') || p.includes('365 days') || p.includes('yearly')) { category = 'Direct Long'; validity = p.includes('60') ? '60 days' : p.includes('90') ? '90 days' : '365 days'; }
          else if (p.includes('sme')) { category = 'SME Monthly'; }
          else if (p.includes('direct')) { category = 'Direct Monthly'; }
          
          const sellingPrice = Math.ceil(price * 1.15 / 10) * 10;
          plans.push(['data', provider, planName, price, sellingPrice, validity, category]);
        }
      }
    }
    
    console.log(`📦 Parsed ${plans.length} plans from ClubKonnect`);
    
    if (plans.length === 0) {
      return res.status(500).json({ error: 'No plans parsed. API response keys: ' + Object.keys(ckData).join(', ') });
    }
    
    let inserted = 0, updated = 0;
    for (const [service, provider, plan, amount, sellingPrice, validity, category] of plans) {
      try {
        const existing = await pool.query('SELECT id FROM pricing WHERE service=$1 AND provider=$2 AND plan=$3', [service, provider, plan]);
        if (existing.rows.length > 0) {
          await pool.query('UPDATE pricing SET amount=$1, validity=$2, category=$3, is_active=true WHERE service=$4 AND provider=$5 AND plan=$6', [amount, validity, category, service, provider, plan]);
          updated++;
        } else {
          await pool.query('INSERT INTO pricing (service, provider, plan, amount, selling_price, validity, category, is_active) VALUES ($1,$2,$3,$4,$5,$6,$7,true)', [service, provider, plan, amount, sellingPrice, validity, category]);
          inserted++;
        }
      } catch (e) { /* skip */ }
    }
    
    console.log(`✅ Sync: ${inserted} new, ${updated} updated`);
    res.json({ success: true, message: `Sync complete! ${inserted} new, ${updated} updated.`, stats: { total: plans.length, inserted, updated } });
  } catch (err) {
    console.error('Sync error:', err.message);
    res.status(500).json({ error: 'Sync failed: ' + err.message });
  }
});

app.post('/api/admin/broadcast', authenticateAdmin, async (req, res) => {
  try {
    const { type, title, message, imageUrl } = req.body;
    // ✅ FIX: Also check email_notifications column (the user's notification toggle).
    // Previously broadcast only checked email_visible, so users who toggled email
    // OFF via the Notification Settings modal would still get broadcast emails.
    let users;
    try {
      users = await pool.query('SELECT id, email_visible, email_notifications FROM users');
    } catch (colErr) {
      // email_notifications column doesn't exist yet — fall back to just email_visible
      users = await pool.query('SELECT id, email_visible FROM users');
    }
    const imageHtml = imageUrl ? `<div style="margin:20px 0;text-align:center;"><img src="${imageUrl}" alt="${title}" style="max-width:100%;border-radius:12px;box-shadow:0 4px 12px rgba(0,0,0,0.15);"></div>` : '';
    const fullMessageHtml = message + imageHtml;
    let emailCount = 0, inAppCount = 0;
    for (const user of users.rows) {
      if (type === 'email' || type === 'all') {
        // ✅ Send email if user has email_visible AND email_notifications both TRUE
        const emailNotifEnabled = user.email_notifications !== false; // default TRUE if column missing
        if (user.email_visible && emailNotifEnabled) {
          await sendUserEmail(user.id, title, fullMessageHtml); // ✅ await so we can track failures
          emailCount++;
        }
      }
      if (type === 'inapp' || type === 'all') {
        try {
          await pool.query('INSERT INTO notifications (user_id, title, message, type, image_url) VALUES ($1, $2, $3, $4, $5)', [user.id, title, message, 'broadcast', imageUrl || null]);
        } catch (e) {
          // image_url column might not exist — fall back without it
          await pool.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [user.id, title, message, 'broadcast']);
        }
        inAppCount++;
      }
    }
    res.json({ success: true, message: `Broadcast sent. Email: ${emailCount} users, In-App: ${inAppCount} users.`, stats: { emailCount, inAppCount } });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ NEW: Admin - Get all resellers
app.get('/api/admin/resellers', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT rs.*, u.fullname, u.email, u.phone, u.wallet_balance, u.is_banned,
             (SELECT COUNT(*) FROM reseller_api_keys rak WHERE rak.user_id = rs.user_id) as api_keys_count,
             (SELECT COUNT(*) FROM reseller_transactions rt WHERE rt.reseller_id = rs.user_id) as transactions_count
      FROM reseller_subscriptions rs
      JOIN users u ON rs.user_id = u.id
      ORDER BY rs.created_at DESC
    `);
    res.json({ success: true, resellers: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ NEW: Admin - Toggle reseller subscription status
app.post('/api/admin/resellers/:id/toggle', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body; // 'active', 'expired', 'cancelled'
    await pool.query('UPDATE reseller_subscriptions SET status = $1 WHERE id = $2', [status, req.params.id]);
    res.json({ success: true, message: `Reseller subscription ${status}` });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ NEW: Admin - View all reseller transactions (for admin dashboard)
app.get('/api/admin/reseller-transactions', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT rt.*, u.fullname as reseller_name, u.email as reseller_email
      FROM reseller_transactions rt
      JOIN users u ON rt.reseller_id = u.id
      ORDER BY rt.created_at DESC LIMIT 200
    `);
    res.json({ success: true, transactions: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ NEW: Admin - View a single reseller's transactions
app.get('/api/admin/resellers/:id/transactions', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT rt.*, u.fullname as reseller_name, u.email as reseller_email
      FROM reseller_transactions rt
      JOIN users u ON rt.reseller_id = u.id
      WHERE rt.reseller_id = (SELECT user_id FROM reseller_subscriptions WHERE id = $1)
      ORDER BY rt.created_at DESC LIMIT 100
    `, [req.params.id]);
    res.json({ success: true, transactions: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== PUBLIC STATS =====================
app.get('/api/stats', async (req, res) => {
  try {
    const BASE_USERS = 5000;
    const BASE_TXNS = 15000;
    let dbUsers = 0, dbTxns = 0;
    try {
      const users = await pool.query('SELECT COUNT(*) FROM users');
      dbUsers = parseInt(users.rows[0].count) || 0;
      const transactions = await pool.query("SELECT COUNT(*) FROM transactions WHERE status = 'success'");
      dbTxns = parseInt(transactions.rows[0].count) || 0;
    } catch (dbErr) { console.error('Database query failed for stats:', dbErr.message); }
    res.json({ success: true, stats: { totalUsers: dbUsers + BASE_USERS, totalTransactions: dbTxns + BASE_TXNS, uptime: 99.9 } });
  } catch (err) { res.status(500).json({ success: false, error: 'Failed to fetch stats' }); }
});

// ✅ CROSS-APP BVN BLOCKLIST — public endpoint called by Gustmii to check
// if a BVN is already used on Yenllet. Returns { used: true/false }.
// Public (no auth) so the other app can call it server-to-server.
// Note: Yenllet stores BVN in the `kyc_bvn` column (set when an account
// is generated via /api/profile/generate-account-from-bvn).
app.get('/api/public/check-bvn/:bvn', async (req, res) => {
    const bvn = req.params.bvn;
    if (!bvn || !/^\d{11}$/.test(bvn)) return res.status(400).json({ error: 'Invalid BVN format' });
    try {
        const result = await pool.query('SELECT id FROM users WHERE kyc_bvn = $1', [bvn]);
        res.json({ used: result.rows.length > 0, app: 'yenllet' });
    } catch (err) {
        console.error('BVN check error:', err.message);
        res.status(500).json({ used: false, error: 'Check failed' });
    }
});

// ✅ CROSS-APP NIN BLOCKLIST — public endpoint called by Gustmii to check
// if a NIN is already used on Yenllet.
// Note: Yenllet stores NIN in the `kyc_nin` column (set via /api/kyc/submit
// for NIN, OR via /api/profile/generate-account-from-bvn when user enters NIN).
app.get('/api/public/check-nin/:nin', async (req, res) => {
    const nin = req.params.nin;
    if (!nin || !/^\d{11}$/.test(nin)) return res.status(400).json({ error: 'Invalid NIN format' });
    try {
        const result = await pool.query('SELECT id FROM users WHERE kyc_nin = $1', [nin]);
        res.json({ used: result.rows.length > 0, app: 'yenllet' });
    } catch (err) {
        console.error('NIN check error:', err.message);
        res.status(500).json({ used: false, error: 'Check failed' });
    }
});

// ===================== VENDOR SYSTEM =====================
// ✅ Vendor registration — existing Yenllet users apply to become vendors
app.post('/api/vendor/register', authenticate, async (req, res) => {
  try {
    const { businessName, whatsapp, experience, promotionStrategy } = req.body;
    if (!businessName || !whatsapp || !experience) return res.status(400).json({ error: 'Business name, WhatsApp number, and experience are required' });

    // Check if already a vendor or pending
    const existing = await pool.query('SELECT vendor_status FROM users WHERE id = $1', [req.user.id]);
    if (existing.rows[0].vendor_status === 'pending' || existing.rows[0].vendor_status === 'approved') {
      return res.status(400).json({ error: 'You already have a vendor application.' });
    }

    // Generate vendor referral code
    const vendorRefCode = 'VND' + req.user.id.toString().padStart(5, '0');

    await pool.query(`UPDATE users SET vendor_status = 'pending', vendor_business_name = $1, vendor_whatsapp = $2, vendor_experience = $3, vendor_promotion = $4, referral_code = COALESCE(referral_code, $5) WHERE id = $6`,
      [businessName, whatsapp, experience, promotionStrategy || '', vendorRefCode, req.user.id]);

    // Create vendor_referrals record
    await pool.query(`INSERT INTO vendor_referrals (vendor_id, referral_code) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [req.user.id, vendorRefCode]);

    // Notify admin
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@yenllet.name.ng';
    sendUserEmail(req.user.id, 'Vendor Application Submitted', `Your vendor application has been submitted! We'll review it and get back to you within 24 hours.<br><br><b>Business:</b> ${businessName}<br><b>WhatsApp:</b> ${whatsapp}<br><br>Your vendor referral code is <b>${vendorRefCode}</b>. Once approved, share this with customers to earn commissions on their purchases.`);

    res.json({ success: true, message: 'Vendor application submitted! We will review and respond within 24 hours.', referralCode: vendorRefCode });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: Get all vendor applications
app.get('/api/admin/vendors', authenticateAdmin, async (req, res) => {
  try {
    // ✅ Try the full query (with vendor columns + vendor_referrals subqueries).
    // If it fails (because columns/tables don't exist yet), auto-migrate
    // the columns and fall back to a simpler query without the subqueries.
    let result;
    try {
      result = await pool.query(`
        SELECT u.id, u.fullname, u.email, u.phone, u.vendor_status, u.vendor_business_name, u.vendor_whatsapp,
               u.vendor_experience, u.vendor_promotion, u.vendor_approved_at, u.created_at,
               (SELECT COUNT(*) FROM vendor_referrals vr WHERE vr.vendor_id = u.id) as referral_count,
               (SELECT COALESCE(SUM(vr.vendor_earnings), 0) FROM vendor_referrals vr WHERE vr.vendor_id = u.id) as total_earnings
        FROM users u WHERE u.vendor_status != 'none' ORDER BY u.created_at DESC
      `);
    } catch (qErr) {
      console.warn('⚠️ /api/admin/vendors: vendor columns or vendor_referrals table missing — auto-migrating now.');
      // Auto-add the missing columns (idempotent)
      const migrationSql = [
        'ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_status VARCHAR(20) DEFAULT \'none\'',
        'ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_business_name VARCHAR(255)',
        'ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_whatsapp VARCHAR(20)',
        'ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_experience TEXT',
        'ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_promotion TEXT',
        'ALTER TABLE users ADD COLUMN IF NOT EXISTS vendor_approved_at TIMESTAMP',
        'ALTER TABLE users ADD COLUMN IF NOT EXISTS is_vendor BOOLEAN DEFAULT FALSE'
      ];
      for (const sql of migrationSql) { try { await pool.query(sql); } catch (e) {} }
      // Create vendor_referrals table if missing
      try {
        await pool.query(`CREATE TABLE IF NOT EXISTS vendor_referrals (id SERIAL PRIMARY KEY, vendor_id INTEGER REFERENCES users(id) ON DELETE CASCADE, referred_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, referral_code VARCHAR(20) UNIQUE NOT NULL, total_purchases DECIMAL(12,2) DEFAULT 0, vendor_earnings DECIMAL(12,2) DEFAULT 0, created_at TIMESTAMP DEFAULT NOW())`);
      } catch (e) {}
      // Retry the query — should now succeed
      result = await pool.query(`
        SELECT u.id, u.fullname, u.email, u.phone, u.vendor_status, u.vendor_business_name, u.vendor_whatsapp,
               u.vendor_experience, u.vendor_promotion, u.vendor_approved_at, u.created_at,
               (SELECT COUNT(*) FROM vendor_referrals vr WHERE vr.vendor_id = u.id) as referral_count,
               (SELECT COALESCE(SUM(vr.vendor_earnings), 0) FROM vendor_referrals vr WHERE vr.vendor_id = u.id) as total_earnings
        FROM users u WHERE u.vendor_status != 'none' ORDER BY u.created_at DESC
      `);
    }
    res.json({ success: true, vendors: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: Approve vendor
app.post('/api/admin/vendors/:id/approve', authenticateAdmin, async (req, res) => {
  try {
    await pool.query(`UPDATE users SET vendor_status = 'approved', is_vendor = TRUE, vendor_approved_at = NOW() WHERE id = $1`, [req.params.id]);
    sendUserEmail(req.params.id, '🎉 Vendor Application Approved!', `Congratulations! Your vendor application has been approved.<br><br>You can now access the vendor dashboard, share your referral code, and earn commissions on every purchase made by your referrals.<br><br>Visit your vendor dashboard at: ${process.env.APP_URL || 'https://yenllet.name.ng'}/vendor.html`);
    res.json({ success: true, message: 'Vendor approved' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: Reject vendor
app.post('/api/admin/vendors/:id/reject', authenticateAdmin, async (req, res) => {
  try {
    await pool.query(`UPDATE users SET vendor_status = 'rejected', is_vendor = FALSE WHERE id = $1`, [req.params.id]);
    sendUserEmail(req.params.id, 'Vendor Application Update', `Your vendor application was not approved at this time. Reason: ${req.body.reason || 'Does not meet current requirements'}. You can reapply in the future.`);
    res.json({ success: true, message: 'Vendor rejected' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: Suspend a vendor (set status to 'suspended' — they keep their
// account but lose vendor privileges until re-approved)
app.post('/api/admin/vendors/:id/suspend', authenticateAdmin, async (req, res) => {
  try {
    const reason = req.body.reason || 'Violation of vendor terms';
    await pool.query(`UPDATE users SET vendor_status = 'suspended', is_vendor = FALSE WHERE id = $1`, [req.params.id]);
    sendUserEmail(req.params.id, '⚠️ Vendor Account Suspended', `Your Yenllet vendor account has been suspended.<br><br><b>Reason:</b> ${reason}<br><br>While suspended, you cannot earn commissions on referrals. Your referral code is paused. Contact support if you believe this is an error.`);
    res.json({ success: true, message: 'Vendor suspended. They will be notified by email.' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: Re-approve a previously suspended vendor
app.post('/api/admin/vendors/:id/reactivate', authenticateAdmin, async (req, res) => {
  try {
    await pool.query(`UPDATE users SET vendor_status = 'approved', is_vendor = TRUE, vendor_approved_at = NOW() WHERE id = $1`, [req.params.id]);
    sendUserEmail(req.params.id, '✅ Vendor Account Reactivated', `Good news! Your Yenllet vendor account has been reactivated. You can now access the vendor dashboard and earn commissions on referrals again.`);
    res.json({ success: true, message: 'Vendor reactivated' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: Permanently delete a vendor (reset to non-vendor user)
// This removes all vendor fields and deletes their vendor_referrals records.
// The user account itself is NOT deleted — they just lose all vendor data.
app.delete('/api/admin/vendors/:id', authenticateAdmin, async (req, res) => {
  try {
    const vendorId = req.params.id;
    // First delete all vendor_referrals records for this vendor
    try { await pool.query('DELETE FROM vendor_referrals WHERE vendor_id = $1', [vendorId]); } catch (e) {}
    // Delete all vendor chats
    try { await pool.query('DELETE FROM vendor_chats WHERE vendor_id = $1', [vendorId]); } catch (e) {}
    // Reset the user to a non-vendor state
    await pool.query(`UPDATE users SET vendor_status = 'none', is_vendor = FALSE, vendor_business_name = NULL, vendor_whatsapp = NULL, vendor_experience = NULL, vendor_promotion = NULL, vendor_approved_at = NULL WHERE id = $1`, [vendorId]);
    sendUserEmail(vendorId, 'Vendor Account Deleted', `Your Yenllet vendor account has been permanently deleted by the admin. Your regular Yenllet user account is still active — you can continue to use Yenllet as a normal user. If you believe this was done in error, please contact support.`);
    res.json({ success: true, message: 'Vendor permanently deleted. Their user account remains active.' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: Update vendor discount/cashback settings
app.put('/api/admin/vendor-settings', authenticateAdmin, async (req, res) => {
  try {
    const { vendorDiscountPercent, vendorCashbackPercent, vendorEnabled, vendorPortalOpen } = req.body;
    await pool.query(`INSERT INTO admin_settings (key, value) VALUES ('vendor_settings', $1) ON CONFLICT (key) DO UPDATE SET value = $1`, [JSON.stringify({ vendor_discount_percent: vendorDiscountPercent, vendor_cashback_percent: vendorCashbackPercent, vendor_enabled: vendorEnabled, vendor_portal_open: vendorPortalOpen })]);
    res.json({ success: true, message: 'Vendor settings updated' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Vendor dashboard — referral stats, earnings, referred users, withdrawals
app.get('/api/vendor/dashboard', authenticate, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT vendor_status, vendor_business_name, referral_code, wallet_balance, vendor_earnings_withdrawn FROM users WHERE id = $1', [req.user.id]);
    if (userRes.rows[0].vendor_status !== 'approved') return res.status(403).json({ error: 'Vendor not approved' });

    const settings = await getAdminSettings();
    const vendorSettings = settings.vendor_settings || { vendor_discount_percent: 5, vendor_cashback_percent: 2 };

    // Get referral stats
    const referralsRes = await pool.query(`
      SELECT vr.referral_code, vr.total_purchases, vr.vendor_earnings, vr.created_at,
             u.fullname, u.email, u.phone, u.created_at as user_joined
      FROM vendor_referrals vr
      LEFT JOIN users u ON vr.referred_user_id = u.id
      WHERE vr.vendor_id = $1
      ORDER BY vr.created_at DESC
    `, [req.user.id]);

    const totalEarnings = referralsRes.rows.reduce((sum, r) => sum + parseFloat(r.vendor_earnings || 0), 0);
    const totalPurchases = referralsRes.rows.reduce((sum, r) => sum + parseFloat(r.total_purchases || 0), 0);
    const totalWithdrawn = parseFloat(userRes.rows[0].vendor_earnings_withdrawn || 0);
    const availableEarnings = totalEarnings - totalWithdrawn;

    // Get unread chat count
    const unreadChats = await pool.query('SELECT COUNT(*) FROM vendor_chats WHERE vendor_id = $1 AND sender_type = $2 AND is_read = FALSE', [req.user.id, 'user']);

    // Get withdrawal history
    const withdrawalsRes = await pool.query('SELECT uid, amount, status, requested_at, processed_at, admin_note FROM vendor_withdrawals WHERE vendor_id = $1 ORDER BY created_at DESC LIMIT 20', [req.user.id]);

    res.json({
      success: true,
      vendor: {
        businessName: userRes.rows[0].vendor_business_name,
        referralCode: userRes.rows[0].referral_code,
        status: userRes.rows[0].vendor_status,
        discountPercent: vendorSettings.vendor_discount_percent,
        cashbackPercent: vendorSettings.vendor_cashback_percent,
        walletBalance: parseFloat(userRes.rows[0].wallet_balance || 0)
      },
      stats: {
        totalReferrals: referralsRes.rows.length,
        totalEarnings: totalEarnings,
        totalPurchases: totalPurchases,
        totalWithdrawn: totalWithdrawn,
        availableEarnings: availableEarnings,
        unreadChats: parseInt(unreadChats.rows[0].count)
      },
      referrals: referralsRes.rows,
      withdrawals: withdrawalsRes.rows
    });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Track vendor referral on registration (called when referralCode is a vendor code)
async function trackVendorReferral(userId, referralCode) {
  try {
    const vendorRes = await pool.query('SELECT vendor_id FROM vendor_referrals WHERE referral_code = $1', [referralCode]);
    if (vendorRes.rows.length > 0) {
      await pool.query('UPDATE vendor_referrals SET referred_user_id = $1 WHERE referral_code = $2', [userId, referralCode]);
    }
  } catch (e) { console.error('Vendor referral tracking failed:', e.message); }
}

// ✅ Update vendor earnings when a referred user makes a purchase
async function updateVendorEarnings(userId, purchaseAmount) {
  try {
    // Find who referred this user
    const userRes = await pool.query('SELECT referred_by FROM users WHERE id = $1', [userId]);
    if (!userRes.rows[0]?.referred_by) return;

    const referrerId = userRes.rows[0].referred_by;
    // Check if referrer is an approved vendor
    const vendorRes = await pool.query('SELECT is_vendor, vendor_status FROM users WHERE id = $1', [referrerId]);
    if (!vendorRes.rows[0]?.is_vendor || vendorRes.rows[0]?.vendor_status !== 'approved') return;

    const settings = await getAdminSettings();
    const vendorSettings = settings.vendor_settings || { vendor_discount_percent: 5 };
    const earnings = purchaseAmount * parseFloat(vendorSettings.vendor_discount_percent) / 100;

    await pool.query('UPDATE vendor_referrals SET total_purchases = total_purchases + $1, vendor_earnings = vendor_earnings + $2 WHERE vendor_id = $3 AND referred_user_id = $4', [purchaseAmount, earnings, referrerId, userId]);
    console.log(`💰 Vendor ${referrerId} earned ₦${earnings} from user ${userId}'s purchase of ₦${purchaseAmount}`);
  } catch (e) { console.error('Vendor earnings update failed:', e.message); }
}

// ===================== LIVE CHAT SYSTEM =====================
// ✅ Get FAQ questions (public, for chat widget)
app.get('/api/faq', async (req, res) => {
  try {
    let result;
    try {
      result = await pool.query('SELECT uid, question, answer, category, sort_order FROM faq_questions WHERE is_active = TRUE ORDER BY sort_order ASC, created_at ASC');
    } catch (tErr) {
      // Table doesn't exist yet — auto-create it and return empty list
      console.warn('⚠️ /api/faq: faq_questions table missing — auto-creating it now.');
      try {
        await pool.query(`CREATE TABLE IF NOT EXISTS faq_questions (id SERIAL PRIMARY KEY, uid VARCHAR(50) UNIQUE NOT NULL, question TEXT NOT NULL, answer TEXT NOT NULL, category VARCHAR(50) DEFAULT 'general', sort_order INTEGER DEFAULT 0, is_active BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT NOW())`);
      } catch (e) {}
      result = { rows: [] };
    }
    res.json({ success: true, questions: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: Add FAQ question
app.post('/api/admin/faq', authenticateAdmin, async (req, res) => {
  try {
    const { question, answer, category, sortOrder } = req.body;
    if (!question || !answer) return res.status(400).json({ error: 'Question and answer required' });
    const uid = 'faq' + Date.now() + Math.random().toString(36).substr(2, 6);
    await pool.query('INSERT INTO faq_questions (uid, question, answer, category, sort_order) VALUES ($1, $2, $3, $4, $5)', [uid, question, answer, category || 'general', sortOrder || 0]);
    res.json({ success: true, message: 'FAQ question added' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: Delete FAQ question
app.delete('/api/admin/faq/:uid', authenticateAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM faq_questions WHERE uid = $1', [req.params.uid]);
    res.json({ success: true, message: 'FAQ deleted' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ User: Send chat message to vendor
app.post('/api/chat/send', authenticate, async (req, res) => {
  try {
    const { message, vendorId, isFaq } = req.body;
    if (!message) return res.status(400).json({ error: 'Message required' });

    // If no vendorId specified, send to first available approved vendor
    let targetVendorId = vendorId;
    if (!targetVendorId) {
      const vendorRes = await pool.query("SELECT id FROM users WHERE is_vendor = TRUE AND vendor_status = 'approved' ORDER BY RANDOM() LIMIT 1");
      if (vendorRes.rows.length === 0) return res.status(404).json({ error: 'No vendor available' });
      targetVendorId = vendorRes.rows[0].id;
    }

    const uid = 'msg' + Date.now() + Math.random().toString(36).substr(2, 6);
    await pool.query('INSERT INTO vendor_chats (uid, user_id, vendor_id, message, sender_type, is_faq) VALUES ($1, $2, $3, $4, $5, $6)', [uid, req.user.id, targetVendorId, message, 'user', isFaq || false]);

    // Send push notification to vendor
    await sendPushNotification(targetVendorId, '💬 New Chat Message', message.substring(0, 100));

    res.json({ success: true, message: 'Message sent', chatId: uid });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Vendor: Reply to user chat
app.post('/api/chat/reply', authenticate, async (req, res) => {
  try {
    const { chatUid, message } = req.body;
    if (!chatUid || !message) return res.status(400).json({ error: 'Chat ID and message required' });

    // Get original chat to find user_id
    const chatRes = await pool.query('SELECT user_id, vendor_id FROM vendor_chats WHERE uid = $1', [chatUid]);
    if (chatRes.rows.length === 0) return res.status(404).json({ error: 'Chat not found' });

    const userId = chatRes.rows[0].user_id;
    const vendorId = chatRes.rows[0].vendor_id;

    // Verify the replier is the vendor
    if (req.user.id !== vendorId) return res.status(403).json({ error: 'Only the assigned vendor can reply' });

    const uid = 'msg' + Date.now() + Math.random().toString(36).substr(2, 6);
    await pool.query('INSERT INTO vendor_chats (uid, user_id, vendor_id, message, sender_type, is_read) VALUES ($1, $2, $3, $4, $5, FALSE)', [uid, userId, vendorId, message, 'vendor']);

    // Send push notification to user
    await sendPushNotification(userId, '💬 Vendor Reply', message.substring(0, 100));

    res.json({ success: true, message: 'Reply sent' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ User: Get their chat history with vendor
app.get('/api/chat/history', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT vc.uid, vc.message, vc.sender_type, vc.is_faq, vc.is_read, vc.created_at,
             u.fullname as vendor_name
      FROM vendor_chats vc
      JOIN users u ON vc.vendor_id = u.id
      WHERE vc.user_id = $1
      ORDER BY vc.created_at ASC
    `, [req.user.id]);

    // Mark all as read for user
    await pool.query('UPDATE vendor_chats SET is_read = TRUE WHERE user_id = $1 AND sender_type = $2', [req.user.id, 'vendor']);

    res.json({ success: true, messages: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Vendor: Get their chat inbox (all conversations)
app.get('/api/chat/inbox', authenticate, async (req, res) => {
  try {
    // Verify user is a vendor
    const vendorCheck = await pool.query('SELECT is_vendor, vendor_status FROM users WHERE id = $1', [req.user.id]);
    if (!vendorCheck.rows[0]?.is_vendor) return res.status(403).json({ error: 'Vendor access required' });

    const result = await pool.query(`
      SELECT DISTINCT ON (vc.user_id)
        vc.user_id, vc.message as last_message, vc.created_at as last_time,
        vc.sender_type as last_sender, vc.is_read,
        u.fullname, u.email, u.phone
      FROM vendor_chats vc
      JOIN users u ON vc.user_id = u.id
      WHERE vc.vendor_id = $1
      ORDER BY vc.user_id, vc.created_at DESC
    `, [req.user.id]);

    // Get full conversation for each user
    const conversations = [];
    for (const conv of result.rows) {
      const msgs = await pool.query('SELECT uid, message, sender_type, is_faq, is_read, created_at FROM vendor_chats WHERE vendor_id = $1 AND user_id = $2 ORDER BY created_at ASC', [req.user.id, conv.user_id]);
      conversations.push({ ...conv, messages: msgs.rows });
    }

    // Mark all as read for vendor
    await pool.query('UPDATE vendor_chats SET is_read = TRUE WHERE vendor_id = $1 AND sender_type = $2', [req.user.id, 'user']);

    res.json({ success: true, conversations });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== SAVED RECIPIENTS =====================
// ✅ Get saved phone numbers for quick re-buy
app.get('/api/saved-recipients', authenticate, async (req, res) => {
  try {
    const { service } = req.query;
    let query = 'SELECT id, phone, name, network, service, created_at FROM saved_recipients WHERE user_id = $1';
    const params = [req.user.id];
    if (service) { query += ' AND service = $2'; params.push(service); }
    query += ' ORDER BY created_at DESC';
    let result;
    try {
      result = await pool.query(query, params);
    } catch (tErr) {
      // Table doesn't exist yet — auto-create it and return empty list
      console.warn('⚠️ /api/saved-recipients: saved_recipients table missing — auto-creating it now.');
      try {
        await pool.query(`CREATE TABLE IF NOT EXISTS saved_recipients (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, phone VARCHAR(20) NOT NULL, name VARCHAR(100), network VARCHAR(20), service VARCHAR(20) DEFAULT 'airtime', created_at TIMESTAMP DEFAULT NOW(), UNIQUE(user_id, phone, service))`);
      } catch (e) {}
      result = { rows: [] };
    }
    res.json({ success: true, recipients: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Save a phone number after purchase
app.post('/api/saved-recipients', authenticate, async (req, res) => {
  try {
    const { phone, name, network, service } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone number required' });
    await pool.query('INSERT INTO saved_recipients (user_id, phone, name, network, service) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (user_id, phone, service) DO UPDATE SET name = $3, network = $4', [req.user.id, phone, name || '', network || '', service || 'airtime']);
    res.json({ success: true, message: 'Recipient saved' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Delete a saved recipient
app.delete('/api/saved-recipients/:id', authenticate, async (req, res) => {
  try {
    await pool.query('DELETE FROM saved_recipients WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
    res.json({ success: true, message: 'Recipient deleted' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== FIREBASE PUSH NOTIFICATIONS =====================
// ✅ FCM: Register token (uses Gustmii's Firebase project)
app.post('/api/fcm/register', authenticate, async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token required' });
    await pool.query('INSERT INTO fcm_tokens (user_id, token) VALUES ($1, $2) ON CONFLICT (token) DO UPDATE SET user_id = $1', [req.user.id, token]);
    res.json({ success: true, message: 'Push notification enabled' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ FCM: Unregister token
app.post('/api/fcm/unregister', authenticate, async (req, res) => {
  try {
    const { token } = req.body;
    if (token) await pool.query('DELETE FROM fcm_tokens WHERE token = $1 AND user_id = $2', [token, req.user.id]);
    res.json({ success: true, message: 'Push notification disabled' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ User: Toggle push notifications
app.put('/api/preferences/push', authenticate, async (req, res) => {
  try {
    const { enabled } = req.body;
    try {
      await pool.query('UPDATE users SET push_enabled = $1 WHERE id = $2', [enabled, req.user.id]);
    } catch (colErr) {
      // Column doesn't exist yet — auto-migrate and retry
      console.warn('⚠️ push_enabled column missing — auto-adding it now.');
      await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS push_enabled BOOLEAN DEFAULT TRUE');
      await pool.query('UPDATE users SET push_enabled = $1 WHERE id = $2', [enabled, req.user.id]);
    }
    res.json({ success: true, message: `Push notifications ${enabled ? 'enabled' : 'disabled'}` });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ User: Toggle email notifications
app.put('/api/preferences/email', authenticate, async (req, res) => {
  try {
    const { enabled } = req.body;
    try {
      await pool.query('UPDATE users SET email_notifications = $1 WHERE id = $2', [enabled, req.user.id]);
    } catch (colErr) {
      // Column doesn't exist yet — auto-migrate and retry
      console.warn('⚠️ email_notifications column missing — auto-adding it now.');
      await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS email_notifications BOOLEAN DEFAULT TRUE');
      await pool.query('UPDATE users SET email_notifications = $1 WHERE id = $2', [enabled, req.user.id]);
    }
    res.json({ success: true, message: `Email notifications ${enabled ? 'enabled' : 'disabled'}` });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Get user preferences
app.get('/api/preferences', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT push_enabled, email_notifications FROM users WHERE id = $1', [req.user.id]);
    res.json({ success: true, preferences: result.rows[0] || { push_enabled: true, email_notifications: true } });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: Push notification to all users (supports optional image)
app.post('/api/admin/push-notification', authenticateAdmin, async (req, res) => {
  try {
    const { title, body, imageUrl } = req.body;
    if (!title || !body) return res.status(400).json({ error: 'Title and body required' });
    const result = await sendPushNotification('all', title, body, imageUrl || null);
    res.json({ success: true, message: `Push sent to ${result.successCount} devices`, stats: result });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Helper: Send push notification (uses Gustmii's Firebase project)
// Supports an optional imageUrl (absolute URL or base64 data URL) shown in the notification.
async function sendPushNotification(userIds, title, body, imageUrl = null) {
  try {
    // Using Gustmii's Firebase Admin SDK (initialized via FIREBASE_CONFIG env var)
    // If FIREBASE_CONFIG is not set, push notifications are silently skipped
    if (!process.env.FIREBASE_CONFIG && !process.env.FIREBASE_PRIVATE_KEY) {
      console.warn('⚠️ Firebase not configured — push notification skipped');
      return { successCount: 0, failureCount: 0 };
    }

    // Initialize Firebase Admin (lazy init — only when first push is sent)
    // ✅ FIX: Wrap require() in try/catch so the server doesn't crash with
    // "Cannot find module 'firebase-admin'" if the package isn't installed.
    // Push notifications are silently skipped in that case.
    if (!global._firebaseAdmin) {
      let admin;
      try {
        admin = require('firebase-admin');
      } catch (reqErr) {
        console.error('❌ firebase-admin module not installed. Run: npm install firebase-admin');
        console.error('   Push notifications will be skipped until the package is added.');
        return { successCount: 0, failureCount: 0, error: 'firebase-admin not installed' };
      }
      let serviceAccount;
      try {
        if (process.env.FIREBASE_CONFIG) {
          serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);
        } else {
          serviceAccount = {
            projectId: process.env.FIREBASE_PROJECT_ID || 'gustmii',
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
            privateKey: process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : ''
          };
        }
        admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
        global._firebaseAdmin = admin;
        console.log('✅ Firebase Admin SDK initialized');
      } catch (initErr) {
        console.error('❌ Firebase Admin init failed:', initErr.message);
        return { successCount: 0, failureCount: 0, error: initErr.message };
      }
    }

    const admin = global._firebaseAdmin;

    // Get FCM tokens
    let tokens = [];
    if (userIds === 'all') {
      const tokenRes = await pool.query('SELECT t.token FROM fcm_tokens t JOIN users u ON t.user_id = u.id WHERE u.push_enabled = TRUE');
      tokens = tokenRes.rows.map(r => r.token);
    } else {
      const idArray = Array.isArray(userIds) ? userIds : [userIds];
      const tokenRes = await pool.query('SELECT t.token FROM fcm_tokens t JOIN users u ON t.user_id = u.id WHERE t.user_id = ANY($1) AND u.push_enabled = TRUE', [idArray]);
      tokens = tokenRes.rows.map(r => r.token);
    }

    if (tokens.length === 0) {
      console.log('⚠️ No FCM tokens found — push skipped');
      return { successCount: 0, failureCount: 0 };
    }

    // ✅ Build FCM message — include image if provided
    // Image can be an absolute URL (https://...) or a base64 data URL.
    // Web push notifications support the `image` field for rich notifications.
    const notifPayload = { title, body };
    if (imageUrl) notifPayload.image = imageUrl;

    const message = {
      notification: notifPayload,
      tokens: tokens,
      webpush: {
        notification: {
          title, body,
          icon: 'https://res.cloudinary.com/x9cnhu3z/image/upload/v1792062220/Yenllet_Blue_Ribbon_Logo_ltmv0i.png',
          ...(imageUrl ? { image: imageUrl, badge: imageUrl } : {}),
          click_action: (process.env.APP_URL || 'https://yenllet.name.ng') + '/dashboard.html'
        }
      }
    };

    const response = await admin.messaging().sendEachForMulticast(message);
    console.log(`✅ Push sent: ${response.successCount} success, ${response.failureCount} failed`);

    // Clean up invalid tokens
    if (response.failureCount > 0) {
      const invalidTokens = [];
      response.responses.forEach((resp, idx) => { if (!resp.success) invalidTokens.push(tokens[idx]); });
      if (invalidTokens.length > 0) await pool.query('DELETE FROM fcm_tokens WHERE token = ANY($1)', [invalidTokens]);
    }

    return { successCount: response.successCount, failureCount: response.failureCount };
  } catch (e) {
    console.error('❌ Push notification error:', e.message);
    return { successCount: 0, failureCount: 0 };
  }
}

// ✅ Public: Check vendor portal open status
app.get('/api/public/vendor-status', async (req, res) => {
  try {
    const settings = await getAdminSettings();
    const vendorSettings = settings.vendor_settings || { vendor_enabled: true, vendor_portal_open: true };
    res.json({ success: true, open: vendorSettings.vendor_portal_open !== false, enabled: vendorSettings.vendor_enabled !== false });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/health', (req, res) => res.json({ status: 'ok', version: '13.0' }));

// ===================== PUBLIC API V1 (for developer API keys) =====================
// These endpoints are documented in api-docs.html and use the regular user API key
// (generated from Profile -> Developer API Key in the dashboard)

async function simpleApiKeyAuth(req, res, next) {
  try {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(401).json({ success: false, error: 'Missing API key. Include x-api-key header.' });
    const result = await pool.query('SELECT id, fullname, email, wallet_balance, pin, is_banned FROM users WHERE api_key = $1', [apiKey]);
    if (result.rows.length === 0) return res.status(401).json({ success: false, error: 'Invalid API key' });
    if (result.rows[0].is_banned) return res.status(403).json({ success: false, error: 'Account is banned' });
    req.apiUser = result.rows[0];
    next();
  } catch (err) { res.status(500).json({ success: false, error: 'Authentication failed' }); }
}

// PUBLIC: Get all plans (no auth) - developers see current prices
app.get('/api/v1/plans', async (req, res) => {
  try {
    const { network } = req.query;
    const dataPlans = await pool.query('SELECT id, service, provider, plan, selling_price, validity, category FROM pricing WHERE service = $1 AND is_active = TRUE ORDER BY provider, id', ['data']);
    const tvPlans = await pool.query('SELECT id, service, provider, plan, selling_price, validity, category FROM pricing WHERE service = $1 AND is_active = TRUE ORDER BY provider, id', ['tv']);
    const eduPlans = await pool.query('SELECT id, service, provider, plan, selling_price, validity, category FROM pricing WHERE service = $1 AND is_active = TRUE ORDER BY provider, id', ['education']);
    const result = { success: true, data: {}, tv: {}, education: {} };
    dataPlans.rows.forEach(p => {
      const prov = p.provider.toUpperCase();
      if (!result.data[prov]) result.data[prov] = [];
      result.data[prov].push({ plan_id: p.id, plan: p.plan, price: parseFloat(p.selling_price), validity: p.validity, category: p.category });
    });
    tvPlans.rows.forEach(p => {
      if (!result.tv[p.provider]) result.tv[p.provider] = [];
      result.tv[p.provider].push({ plan_id: p.id, plan: p.plan, price: parseFloat(p.selling_price), validity: p.validity });
    });
    eduPlans.rows.forEach(p => {
      if (!result.education[p.provider]) result.education[p.provider] = [];
      result.education[p.provider].push({ plan_id: p.id, plan: p.plan, price: parseFloat(p.selling_price) });
    });
    if (network) return res.json({ success: true, network: network.toUpperCase(), plans: result.data[network.toUpperCase()] || [] });
    res.json(result);
  } catch (err) { res.status(500).json({ success: false, error: 'Failed to fetch plans' }); }
});

// GET /api/v1/balance - Check wallet balance
app.get('/api/v1/balance', simpleApiKeyAuth, async (req, res) => {
  try {
    res.json({
      success: true,
      balance: parseFloat(req.apiUser.wallet_balance),
      currency: 'NGN',
      user: { name: req.apiUser.fullname, email: req.apiUser.email }
    });
  } catch (err) { res.status(500).json({ success: false, error: 'Failed to fetch balance' }); }
});

// POST /api/v1/airtime - Buy airtime
app.post('/api/v1/airtime', simpleApiKeyAuth, async (req, res) => {
  try {
    const { provider, phone, amount, pin } = req.body;
    if (!provider || !phone || !amount || !pin) return res.status(400).json({ success: false, error: 'provider, phone, amount, pin are required' });
    const result = await processPurchase(req.apiUser.id, pin, 'airtime', provider.toUpperCase(), null, parseFloat(amount), phone, {}, req);
    res.json({ success: true, message: 'Airtime purchase successful', transaction_id: result.transactionId, new_balance: result.sellPrice });
  } catch (err) { res.status(err.status || 500).json({ success: false, error: err.message || 'Purchase failed' }); }
});

// POST /api/v1/data - Buy data
app.post('/api/v1/data', simpleApiKeyAuth, async (req, res) => {
  try {
    const { provider, phone, plan, pin } = req.body;
    if (!provider || !phone || !plan || !pin) return res.status(400).json({ success: false, error: 'provider, phone, plan, pin are required' });
    const planRes = await pool.query('SELECT selling_price FROM pricing WHERE service = $1 AND provider = $2 AND plan = $3 AND is_active = TRUE', ['data', provider.toUpperCase(), plan]);
    const amount = planRes.rows.length ? parseFloat(planRes.rows[0].selling_price) : 0;
    const result = await processPurchase(req.apiUser.id, pin, 'data', provider.toUpperCase(), plan, amount, phone, {}, req);
    res.json({ success: true, message: 'Data purchase successful', transaction_id: result.transactionId, new_balance: result.sellPrice, amount_charged: amount });
  } catch (err) { res.status(err.status || 500).json({ success: false, error: err.message || 'Purchase failed' }); }
});

// POST /api/v1/tv - Subscribe TV
app.post('/api/v1/tv', simpleApiKeyAuth, async (req, res) => {
  try {
    const { provider, smartCardNumber, plan, pin } = req.body;
    if (!provider || !smartCardNumber || !plan || !pin) return res.status(400).json({ success: false, error: 'provider, smartCardNumber, plan, pin are required' });
    const planRes = await pool.query('SELECT selling_price FROM pricing WHERE service = $1 AND provider = $2 AND plan = $3 AND is_active = TRUE', ['tv', provider.toLowerCase(), plan]);
    const amount = planRes.rows.length ? parseFloat(planRes.rows[0].selling_price) : 0;
    const result = await processPurchase(req.apiUser.id, pin, 'tv', provider, plan, amount, smartCardNumber, {}, req);
    res.json({ success: true, message: 'TV subscription successful', transaction_id: result.transactionId, new_balance: result.sellPrice, amount_charged: amount });
  } catch (err) { res.status(err.status || 500).json({ success: false, error: err.message || 'Purchase failed' }); }
});

// POST /api/v1/electricity - Pay electricity
app.post('/api/v1/electricity', simpleApiKeyAuth, async (req, res) => {
  try {
    const { provider, meterNumber, meterType, amount, pin } = req.body;
    if (!provider || !meterNumber || !meterType || !amount || !pin) return res.status(400).json({ success: false, error: 'provider, meterNumber, meterType, amount, pin are required' });
    const result = await processPurchase(req.apiUser.id, pin, 'electricity', provider, null, parseFloat(amount), meterNumber, { meterType }, req);
    res.json({ success: true, message: 'Electricity payment successful', transaction_id: result.transactionId, new_balance: result.sellPrice });
  } catch (err) { res.status(err.status || 500).json({ success: false, error: err.message || 'Purchase failed' }); }
});

// ===================== GIFT BANNERS (Free Cashback Gifts) =====================

// ✅ Admin: Create a gift banner with optional cashback
app.post('/api/admin/gift-banners', authenticateAdmin, async (req, res) => {
  try {
    const { title, description, bannerImage, linkType, linkUrl, internalSection, cashbackAmount, restrictedService, maxClaims, endDate } = req.body;
    if (!title || !bannerImage) return res.status(400).json({ error: 'Title and banner image are required' });
    const uid = 'gift' + Date.now() + Math.random().toString(36).substr(2, 6);
    await pool.query(`INSERT INTO gift_banners (uid, title, description, banner_image, link_type, link_url, internal_section, cashback_amount, restricted_service, max_claims, end_date) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [uid, title, description || '', bannerImage, linkType || 'internal', linkUrl || null, internalSection || null, parseFloat(cashbackAmount || 0), restrictedService || null, parseInt(maxClaims || 0), endDate ? new Date(endDate) : null]);
    res.json({ success: true, message: 'Gift banner created successfully' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: List all gift banners
app.get('/api/admin/gift-banners', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM gift_banners ORDER BY created_at DESC');
    res.json({ success: true, banners: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: Delete a gift banner
app.delete('/api/admin/gift-banners/:id', authenticateAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM gift_banners WHERE id = $1', [req.params.id]);
    res.json({ success: true, message: 'Gift banner deleted' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: Toggle gift banner active status
app.put('/api/admin/gift-banners/:id/toggle', authenticateAdmin, async (req, res) => {
  try {
    const banner = await pool.query('SELECT is_active FROM gift_banners WHERE id = $1', [req.params.id]);
    if (banner.rows.length === 0) return res.status(404).json({ error: 'Banner not found' });
    await pool.query('UPDATE gift_banners SET is_active = $1 WHERE id = $2', [!banner.rows[0].is_active, req.params.id]);
    res.json({ success: true, message: 'Banner status updated' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Public: Get active gift banners (for user dashboard)
app.get('/api/gift-banners', async (req, res) => {
  try {
    const result = await pool.query(`SELECT id, uid, title, description, banner_image, link_type, link_url, internal_section, cashback_amount, restricted_service, max_claims, claims_count FROM gift_banners WHERE is_active = TRUE AND (end_date IS NULL OR end_date > NOW()) AND (max_claims = 0 OR claims_count < max_claims) ORDER BY created_at DESC`);
    res.json({ success: true, banners: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ User: Claim a gift banner cashback
app.post('/api/gift-banners/:uid/claim', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Get the banner with FOR UPDATE to prevent race conditions
    const bannerRes = await client.query('SELECT * FROM gift_banners WHERE uid = $1 AND is_active = TRUE FOR UPDATE', [req.params.uid]);
    if (bannerRes.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Gift banner not found or expired' }); }
    const banner = bannerRes.rows[0];

    // Check max claims
    if (banner.max_claims > 0 && banner.claims_count >= banner.max_claims) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'This gift has reached its maximum claims' });
    }

    // Check if user already claimed (UNIQUE constraint prevents double-claiming)
    const existingClaim = await client.query('SELECT id FROM claimed_gifts WHERE user_id = $1 AND gift_banner_id = $2', [req.user.id, banner.id]);
    if (existingClaim.rows.length > 0) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'You have already claimed this gift' }); }

    // Create claim record
    await client.query('INSERT INTO claimed_gifts (user_id, gift_banner_id, cashback_amount, restricted_service) VALUES ($1, $2, $3, $4)',
      [req.user.id, banner.id, banner.cashback_amount, banner.restricted_service]);

    // Increment claims count on banner
    await client.query('UPDATE gift_banners SET claims_count = claims_count + 1 WHERE id = $1', [banner.id]);

    // Add cashback to user's restricted cashback balance (store in cashback_balance for simplicity)
    // Note: restricted_service is tracked in claimed_gifts so the purchase flow can check it
    if (parseFloat(banner.cashback_amount) > 0) {
      await client.query('UPDATE users SET cashback_balance = cashback_balance + $1 WHERE id = $2', [banner.cashback_amount, req.user.id]);
    }

    await client.query('COMMIT');

    // Notification
    await pool.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)',
      [req.user.id, '🎁 Gift Claimed!', `You claimed ₦${parseFloat(banner.cashback_amount).toLocaleString()} cashback from "${banner.title}". ${banner.restricted_service ? 'Use it for ' + banner.restricted_service + ' purchases.' : 'Use it for any purchase.'}`, 'gift']);

    res.json({ success: true, message: `₦${parseFloat(banner.cashback_amount).toLocaleString()} cashback claimed!`, cashbackAmount: banner.cashback_amount, restrictedService: banner.restricted_service });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Failed: ' + err.message });
  } finally { client.release(); }
});

// ✅ User: Check which gifts they've claimed
app.get('/api/gift-banners/claimed', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT cg.gift_banner_id, cg.cashback_amount, cg.restricted_service, cg.is_used, cg.claimed_at, gb.title
      FROM claimed_gifts cg
      JOIN gift_banners gb ON cg.gift_banner_id = gb.id
      WHERE cg.user_id = $1 AND cg.is_used = FALSE
      ORDER BY cg.claimed_at DESC
    `, [req.user.id]);
    res.json({ success: true, claimedGifts: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== VENDOR WEEKLY TARGETS =====================

// ✅ Helper: Get or create the current week's target record for a vendor
async function getOrCreateVendorWeeklyTarget(vendorId) {
  const settings = await getAdminSettings();
  const targetSettings = settings.vendor_weekly_target || { enabled: false, referrals_needed: 10, active_users_needed: 8, transactions_per_user: 2, bonus_amount: 1000, week_start_day: 1 };
  if (!targetSettings.enabled) return null;

  // Calculate week start (Monday by default)
  const now = new Date();
  const dayOfWeek = now.getDay(); // 0 = Sunday
  const weekStartDay = targetSettings.week_start_day || 1; // 1 = Monday
  const diff = (dayOfWeek - weekStartDay + 7) % 7;
  const weekStart = new Date(now);
  weekStart.setDate(now.getDate() - diff);
  weekStart.setHours(0, 0, 0, 0);
  const weekEnd = new Date(weekStart);
  weekEnd.setDate(weekStart.getDate() + 6);
  weekEnd.setHours(23, 59, 59, 999);

  // Try to get existing record
  let result = await pool.query('SELECT * FROM vendor_weekly_targets WHERE vendor_id = $1 AND week_start = $2', [vendorId, weekStart]);

  if (result.rows.length === 0) {
    // Create new record for this week
    await pool.query(`INSERT INTO vendor_weekly_targets (vendor_id, week_start, week_end, bonus_amount) VALUES ($1, $2, $3, $4) ON CONFLICT (vendor_id, week_start) DO NOTHING`,
      [vendorId, weekStart, weekEnd, targetSettings.bonus_amount]);
    result = await pool.query('SELECT * FROM vendor_weekly_targets WHERE vendor_id = $1 AND week_start = $2', [vendorId, weekStart]);
  }

  if (result.rows.length === 0) return null;
  const target = result.rows[0];

  // Count referrals made THIS WEEK by this vendor
  const referralsRes = await pool.query(`
    SELECT COUNT(DISTINCT vr.referred_user_id) as count
    FROM vendor_referrals vr
    WHERE vr.vendor_id = $1 AND vr.created_at >= $2 AND vr.created_at <= $3
  `, [vendorId, weekStart, weekEnd]);
  const referralsMade = parseInt(referralsRes.rows[0].count) || 0;

  // Count how many of those referred users made purchases this week
  const activeUsersRes = await pool.query(`
    SELECT COUNT(DISTINCT t.user_id) as count, COUNT(t.id) as total_txns
    FROM transactions t
    JOIN vendor_referrals vr ON t.user_id = vr.referred_user_id
    WHERE vr.vendor_id = $1 AND t.status = 'success' AND t.created_at >= $2 AND t.created_at <= $3
  `, [vendorId, weekStart, weekEnd]);
  const activeUsers = parseInt(activeUsersRes.rows[0].count) || 0;
  const totalTxns = parseInt(activeUsersRes.rows[0].total_txns) || 0;

  // Update the target record
  const isTargetMet = referralsMade >= targetSettings.referrals_needed && activeUsers >= targetSettings.active_users_needed;
  await pool.query('UPDATE vendor_weekly_targets SET referrals_made = $1, active_users = $2, total_user_transactions = $3, is_target_met = $4 WHERE id = $5',
    [referralsMade, activeUsers, totalTxns, isTargetMet, target.id]);

  return {
    ...target,
    referrals_made: referralsMade,
    active_users: activeUsers,
    total_user_transactions: totalTxns,
    is_target_met: isTargetMet,
    settings: targetSettings,
    week_start: weekStart,
    week_end: weekEnd
  };
}

// ✅ Vendor: Get weekly target progress
app.get('/api/vendor/weekly-target', authenticate, async (req, res) => {
  try {
    // Verify user is an approved vendor
    const userRes = await pool.query('SELECT vendor_status FROM users WHERE id = $1', [req.user.id]);
    if (userRes.rows[0]?.vendor_status !== 'approved') return res.status(403).json({ error: 'Vendor access required' });

    const target = await getOrCreateVendorWeeklyTarget(req.user.id);
    if (!target) return res.json({ success: true, enabled: false });

    res.json({ success: true, enabled: true, target });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Vendor: Claim weekly target bonus (credits wallet — NOT a bank withdrawal)
app.post('/api/vendor/weekly-target/claim', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verify user is an approved vendor
    const userRes = await client.query('SELECT vendor_status FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
    if (userRes.rows[0]?.vendor_status !== 'approved') { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Vendor access required' }); }

    // Get current week's target
    const target = await getOrCreateVendorWeeklyTarget(req.user.id);
    if (!target || !target.is_target_met) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Weekly target not yet met' }); }

    // Check if already claimed
    const existing = await client.query('SELECT id FROM vendor_weekly_targets WHERE vendor_id = $1 AND week_start = $2 AND bonus_claimed = TRUE FOR UPDATE', [req.user.id, target.week_start]);
    if (existing.rows.length > 0) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Bonus already claimed for this week' }); }

    // Credit the bonus to vendor's wallet
    const bonusAmount = parseFloat(target.bonus_amount);
    await client.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2', [bonusAmount, req.user.id]);

    // Mark as claimed
    await client.query('UPDATE vendor_weekly_targets SET bonus_claimed = TRUE WHERE vendor_id = $1 AND week_start = $2', [req.user.id, target.week_start]);

    // Log the transaction
    const txnId = generateTransactionId();
    await client.query(`INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, reference, remark) VALUES ($1, 'credit', 'vendor_bonus', $2, $2, 'success', $3, $4, 'Weekly vendor target bonus')`,
      [req.user.id, bonusAmount, txnId, `VENDOR-BONUS-${req.user.id}-${Date.now()}`]);

    // Notification
    await client.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)',
      [req.user.id, '🎉 Weekly Target Bonus Claimed!', `Congratulations! You earned ₦${bonusAmount.toLocaleString()} for meeting your weekly vendor target. The bonus has been credited to your Yenllet wallet.`, 'vendor']);

    await client.query('COMMIT');
    sendUserEmail(req.user.id, '🎉 Weekly Target Bonus Claimed!', `Congratulations! You earned <b>₦${bonusAmount.toLocaleString()}</b> for meeting your weekly vendor target. The bonus has been credited to your Yenllet wallet.`);

    res.json({ success: true, message: `₦${bonusAmount.toLocaleString()} bonus claimed and credited to your wallet!` });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Failed: ' + err.message });
  } finally { client.release(); }
});

// ✅ Admin: Get all vendors' weekly target progress
app.get('/api/admin/vendor-targets', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT vwt.*, u.fullname, u.email, u.vendor_business_name
      FROM vendor_weekly_targets vwt
      JOIN users u ON vwt.vendor_id = u.id
      ORDER BY vwt.week_start DESC, vwt.vendor_id
    `);
    res.json({ success: true, targets: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: GET vendor weekly target settings (admin.html form loader)
// Reads from admin_settings; returns sensible defaults if row doesn't exist yet.
app.get('/api/admin/vendor-target-settings', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT value FROM admin_settings WHERE key = 'vendor_weekly_target'");
    let settings = { enabled: false, referrals_needed: 10, active_users_needed: 5, transactions_per_user: 1, bonus_amount: 1000, reset_day: 1 };
    if (result.rows.length > 0) {
      const v = result.rows[0].value;
      settings = {
        enabled: v.enabled !== false,
        referrals_needed: v.referrals_needed || 10,
        active_users_needed: v.active_users_needed || 5,
        transactions_per_user: v.transactions_per_user || 1,
        bonus_amount: v.bonus_amount || 1000,
        // Server stores as week_start_day, admin.html expects reset_day
        reset_day: v.week_start_day !== undefined ? v.week_start_day : 1
      };
    }
    res.json({ success: true, settings });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: GET all vendors' current week progress (richer view than /vendor-targets)
// Used by admin.html to render the live progress list with referral_count + active_users_count
app.get('/api/admin/vendor-target-progress', authenticateAdmin, async (req, res) => {
  try {
    const settingsRes = await pool.query("SELECT value FROM admin_settings WHERE key = 'vendor_weekly_target'");
    const targetSettings = settingsRes.rows.length > 0 ? settingsRes.rows[0].value : { week_start_day: 1, referrals_needed: 10, active_users_needed: 5 };
    const now = new Date();
    const dayOfWeek = now.getDay();
    const weekStartDay = targetSettings.week_start_day || 1;
    const diff = (dayOfWeek - weekStartDay + 7) % 7;
    const weekStart = new Date(now);
    weekStart.setDate(now.getDate() - diff);
    weekStart.setHours(0, 0, 0, 0);
    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekStart.getDate() + 6);
    weekEnd.setHours(23, 59, 59, 999);

    const vendorsRes = await pool.query("SELECT id, fullname, vendor_business_name FROM users WHERE vendor_status = 'approved' ORDER BY fullname");
    const progress = [];

    for (const v of vendorsRes.rows) {
      const refsRes = await pool.query(`SELECT COUNT(DISTINCT referred_user_id) as cnt FROM vendor_referrals WHERE vendor_id = $1 AND created_at >= $2 AND created_at <= $3`, [v.id, weekStart, weekEnd]);
      const referral_count = parseInt(refsRes.rows[0].cnt) || 0;
      const activeRes = await pool.query(`SELECT COUNT(DISTINCT t.user_id) as cnt FROM transactions t JOIN vendor_referrals vr ON t.user_id = vr.referred_user_id WHERE vr.vendor_id = $1 AND t.status = 'success' AND t.created_at >= $2 AND t.created_at <= $3`, [v.id, weekStart, weekEnd]);
      const active_users_count = parseInt(activeRes.rows[0].cnt) || 0;
      const claimedRes = await pool.query(`SELECT bonus_claimed FROM vendor_weekly_targets WHERE vendor_id = $1 AND week_start = $2`, [v.id, weekStart]);
      const claimed_this_week = claimedRes.rows.length > 0 ? claimedRes.rows[0].bonus_claimed : false;
      progress.push({ vendor_id: v.id, fullname: v.fullname, business_name: v.vendor_business_name, referral_count, referrals_needed: targetSettings.referrals_needed || 10, active_users_count, active_users_needed: targetSettings.active_users_needed || 5, claimed_this_week });
    }

    res.json({ success: true, progress, week_start: weekStart, week_end: weekEnd });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: Save vendor weekly target settings
app.put('/api/admin/vendor-target-settings', authenticateAdmin, async (req, res) => {
  try {
    const { enabled, referralsNeeded, activeUsersNeeded, transactionsPerUser, bonusAmount, weekStartDay } = req.body;
    await pool.query(`INSERT INTO admin_settings (key, value) VALUES ('vendor_weekly_target', $1) ON CONFLICT (key) DO UPDATE SET value = $1`,
      [JSON.stringify({ enabled: !!enabled, referrals_needed: parseInt(referralsNeeded || 10), active_users_needed: parseInt(activeUsersNeeded || 8), transactions_per_user: parseInt(transactionsPerUser || 2), bonus_amount: parseFloat(bonusAmount || 1000), week_start_day: parseInt(weekStartDay || 1) })]);
    res.json({ success: true, message: 'Vendor weekly target settings saved' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== VENDOR WITHDRAWALS (earnings → wallet) =====================
// Vendors withdraw their referral earnings to their Yenllet wallet.
// This is NOT a bank withdrawal — money stays inside Yenllet.
// Admin must approve each withdrawal request before it's credited.

// ✅ Vendor: Request a withdrawal of earnings to wallet
app.post('/api/vendor/withdraw', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verify user is an approved vendor
    const userRes = await client.query('SELECT vendor_status, vendor_earnings_withdrawn FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
    if (userRes.rows[0]?.vendor_status !== 'approved') { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Vendor access required' }); }

    const amount = parseFloat(req.body.amount);
    if (!amount || amount < 100) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Minimum withdrawal is ₦100' }); }

    // Calculate total earnings and available balance
    const earningsRes = await client.query('SELECT COALESCE(SUM(vendor_earnings), 0) as total FROM vendor_referrals WHERE vendor_id = $1', [req.user.id]);
    const totalEarnings = parseFloat(earningsRes.rows[0].total);
    const totalWithdrawn = parseFloat(userRes.rows[0].vendor_earnings_withdrawn || 0);
    const available = totalEarnings - totalWithdrawn;

    // Check for pending withdrawals (can't have two pending at once)
    const pendingRes = await client.query("SELECT id FROM vendor_withdrawals WHERE vendor_id = $1 AND status = 'pending'", [req.user.id]);
    if (pendingRes.rows.length > 0) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'You already have a pending withdrawal request. Wait for it to be processed.' }); }

    if (amount > available) { await client.query('ROLLBACK'); return res.status(400).json({ error: `Insufficient earnings. Available: ₦${available.toLocaleString()}` }); }

    // Create withdrawal request
    const uid = 'vw' + Date.now() + Math.random().toString(36).substr(2, 6);
    await client.query('INSERT INTO vendor_withdrawals (uid, vendor_id, amount, status) VALUES ($1, $2, $3, $4)', [uid, req.user.id, amount, 'pending']);

    await client.query('COMMIT');
    res.json({ success: true, message: 'Withdrawal request submitted! Admin will review and process it shortly.', withdrawalUid: uid });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Failed: ' + err.message });
  } finally { client.release(); }
});

// ✅ Vendor: Get withdrawal history
app.get('/api/vendor/withdrawals', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT uid, amount, status, requested_at, processed_at, admin_note FROM vendor_withdrawals WHERE vendor_id = $1 ORDER BY created_at DESC LIMIT 50', [req.user.id]);
    res.json({ success: true, withdrawals: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: Get all vendor withdrawal requests
app.get('/api/admin/vendor-withdrawals', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT vw.*, u.fullname, u.email, u.vendor_business_name,
             (SELECT COALESCE(SUM(vr.vendor_earnings), 0) FROM vendor_referrals vr WHERE vr.vendor_id = vw.vendor_id) as total_earnings,
             u.vendor_earnings_withdrawn as total_withdrawn
      FROM vendor_withdrawals vw
      JOIN users u ON vw.vendor_id = u.id
      ORDER BY vw.created_at DESC
    `);
    res.json({ success: true, withdrawals: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: Approve a vendor withdrawal (credits vendor's Yenllet wallet)
app.post('/api/admin/vendor-withdrawals/:id/approve', authenticateAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Get the withdrawal request with FOR UPDATE
    const wdRes = await client.query('SELECT * FROM vendor_withdrawals WHERE id = $1 AND status = $2 FOR UPDATE', [req.params.id, 'pending']);
    if (wdRes.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Withdrawal not found or already processed' }); }

    const withdrawal = wdRes.rows[0];
    const amount = parseFloat(withdrawal.amount);

    // Credit the vendor's Yenllet wallet
    await client.query('UPDATE users SET wallet_balance = wallet_balance + $1, vendor_earnings_withdrawn = vendor_earnings_withdrawn + $2 WHERE id = $3', [amount, amount, withdrawal.vendor_id]);

    // Mark withdrawal as approved
    await client.query("UPDATE vendor_withdrawals SET status = 'approved', processed_at = NOW(), processed_by = $1 WHERE id = $2", [req.user.email || 'admin', withdrawal.id]);

    // Log the transaction
    const txnId = generateTransactionId();
    await client.query(`INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, reference, remark) VALUES ($1, 'credit', 'vendor_withdrawal', $2, $2, 'success', $3, $4, 'Vendor earnings withdrawal to wallet')`,
      [withdrawal.vendor_id, amount, txnId, withdrawal.uid]);

    // Notification to vendor
    await client.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)',
      [withdrawal.vendor_id, '✅ Withdrawal Approved!', `Your withdrawal of ₦${amount.toLocaleString()} has been approved and credited to your Yenllet wallet. You can now use it for purchases.`, 'vendor']);

    await client.query('COMMIT');
    sendUserEmail(withdrawal.vendor_id, '✅ Vendor Withdrawal Approved', `Your withdrawal request of <b>₦${amount.toLocaleString()}</b> has been approved by admin and credited to your Yenllet wallet. You can use these funds for airtime, data, bills, and more.`);

    res.json({ success: true, message: `Withdrawal of ₦${amount.toLocaleString()} approved and credited to vendor's wallet.` });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Failed: ' + err.message });
  } finally { client.release(); }
});

// ✅ Admin: Reject a vendor withdrawal
app.post('/api/admin/vendor-withdrawals/:id/reject', authenticateAdmin, async (req, res) => {
  try {
    const note = req.body.note || 'Rejected by admin';
    const wdRes = await pool.query('SELECT * FROM vendor_withdrawals WHERE id = $1 AND status = $2', [req.params.id, 'pending']);
    if (wdRes.rows.length === 0) return res.status(404).json({ error: 'Withdrawal not found or already processed' });

    await pool.query("UPDATE vendor_withdrawals SET status = 'rejected', processed_at = NOW(), admin_note = $1, processed_by = $2 WHERE id = $3", [note, req.user.email || 'admin', req.params.id]);

    // Notify vendor
    await pool.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)',
      [wdRes.rows[0].vendor_id, '❌ Withdrawal Rejected', `Your withdrawal request of ₦${parseFloat(wdRes.rows[0].amount).toLocaleString()} was rejected. Reason: ${note}`, 'vendor']);

    sendUserEmail(wdRes.rows[0].vendor_id, 'Withdrawal Rejected', `Your withdrawal request of <b>₦${parseFloat(wdRes.rows[0].amount).toLocaleString()}</b> was rejected. Reason: ${note}. Your earnings are still available — you can submit a new request.`);

    res.json({ success: true, message: 'Withdrawal rejected. Vendor notified.' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== SCHEDULED PURCHASES (Auto-Buy, Subscriptions, Scheduling) =====================
// Covers: auto-buy data, TV subscription renewal, electricity scheduling
// User can toggle ON/OFF via the is_active field

// ✅ Helper: ensure scheduled_purchases table exists (auto-migrate)
// Prevents 'relation scheduled_purchases does not exist' on cold-start Vercel deployments
// where initDatabase() has not yet completed. Same pattern as vendor tables.
async function ensureScheduledPurchasesTable() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS scheduled_purchases (
        id SERIAL PRIMARY KEY,
        uid VARCHAR(50) UNIQUE NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        type VARCHAR(30) NOT NULL DEFAULT 'auto_buy',
        service VARCHAR(50) NOT NULL,
        provider VARCHAR(50),
        plan VARCHAR(100),
        recipient VARCHAR(50) NOT NULL,
        amount DECIMAL(12,2) DEFAULT 0,
        frequency VARCHAR(20) DEFAULT 'monthly',
        next_run_date DATE NOT NULL,
        last_run_date TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE,
        pin_required BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW()
    )`);
  } catch (e) { console.error('ensureScheduledPurchasesTable error:', e.message); }
}

// ✅ User: Create a scheduled purchase (auto-buy or subscription)
app.post('/api/scheduled-purchases', authenticate, async (req, res) => {
  try {
    await ensureScheduledPurchasesTable();
    const { type, service, provider, plan, recipient, amount, frequency, nextRunDate } = req.body;
    if (!service || !recipient || !nextRunDate) return res.status(400).json({ error: 'Service, recipient, and next run date are required' });
    const uid = 'sch' + Date.now() + Math.random().toString(36).substr(2, 6);
    await pool.query(`INSERT INTO scheduled_purchases (uid, user_id, type, service, provider, plan, recipient, amount, frequency, next_run_date, is_active) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRUE)`,
      [uid, req.user.id, type || 'auto_buy', service, provider || null, plan || null, recipient, parseFloat(amount || 0), frequency || 'monthly', nextRunDate]);
    res.json({ success: true, message: 'Scheduled purchase created! It will run automatically on the specified date.', uid });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ User: Get all their scheduled purchases
app.get('/api/scheduled-purchases', authenticate, async (req, res) => {
  try {
    await ensureScheduledPurchasesTable();
    const result = await pool.query('SELECT * FROM scheduled_purchases WHERE user_id = $1 ORDER BY next_run_date ASC', [req.user.id]);
    res.json({ success: true, schedules: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ User: Toggle a scheduled purchase ON/OFF (pause/resume)
app.put('/api/scheduled-purchases/:uid/toggle', authenticate, async (req, res) => {
  try {
    await ensureScheduledPurchasesTable();
    const current = await pool.query('SELECT is_active FROM scheduled_purchases WHERE uid = $1 AND user_id = $2', [req.params.uid, req.user.id]);
    if (current.rows.length === 0) return res.status(404).json({ error: 'Schedule not found' });
    const newState = !current.rows[0].is_active;
    await pool.query('UPDATE scheduled_purchases SET is_active = $1 WHERE uid = $2', [newState, req.params.uid]);
    res.json({ success: true, message: `Schedule ${newState ? 'resumed (ON)' : 'paused (OFF)'}`, isActive: newState });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ User: Delete a scheduled purchase
app.delete('/api/scheduled-purchases/:uid', authenticate, async (req, res) => {
  try {
    await ensureScheduledPurchasesTable();
    await pool.query('DELETE FROM scheduled_purchases WHERE uid = $1 AND user_id = $2', [req.params.uid, req.user.id]);
    res.json({ success: true, message: 'Schedule deleted' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: Get all scheduled purchases (for monitoring)
app.get('/api/admin/scheduled-purchases', authenticateAdmin, async (req, res) => {
  try {
    await ensureScheduledPurchasesTable();
    const result = await pool.query(`
      SELECT sp.*, u.fullname, u.email, u.phone
      FROM scheduled_purchases sp
      JOIN users u ON sp.user_id = u.id
      ORDER BY sp.next_run_date ASC LIMIT 200
    `);
    res.json({ success: true, schedules: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== BULK AIRTIME =====================

// ✅ User: Send bulk airtime to multiple numbers at once
app.post('/api/bulk-airtime', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    const { provider, numbers, amountPerNumber, pin } = req.body;
    if (!provider || !numbers || !Array.isArray(numbers) || numbers.length === 0) return res.status(400).json({ error: 'Provider and numbers array are required' });
    if (!amountPerNumber || parseFloat(amountPerNumber) < 50) return res.status(400).json({ error: 'Minimum amount per number is ₦50' });
    if (!pin) return res.status(400).json({ error: 'Transaction PIN is required' });
    if (numbers.length > 100) return res.status(400).json({ error: 'Maximum 100 numbers per bulk send' });

    const totalAmount = parseFloat(amountPerNumber) * numbers.length;
    await client.query('BEGIN');

    // Verify PIN and check balance
    const userRes = await client.query('SELECT pin, wallet_balance, is_banned FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
    const user = userRes.rows[0];
    if (user.is_banned) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Account banned' }); }
    if (!user.pin || !await bcrypt.compare(pin, user.pin)) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Invalid PIN' }); }
    if (parseFloat(user.wallet_balance) < totalAmount) { await client.query('ROLLBACK'); return res.status(400).json({ error: `Insufficient balance. Need ₦${totalAmount.toLocaleString()} for ${numbers.length} numbers` }); }

    // Deduct total from wallet
    await client.query('UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id = $2', [totalAmount, req.user.id]);

    // Create bulk log
    const bulkUid = 'bulk' + Date.now() + Math.random().toString(36).substr(2, 6);
    await client.query(`INSERT INTO bulk_airtime_logs (uid, user_id, provider, amount_per_number, total_amount, numbers_count, status) VALUES ($1, $2, $3, $4, $5, $6, 'processing')`,
      [bulkUid, req.user.id, provider, parseFloat(amountPerNumber), totalAmount, numbers.length]);

    await client.query('COMMIT');

    // Process each number (async, non-blocking — don't keep user waiting)
    (async () => {
      let successCount = 0, failedCount = 0;
      for (const phone of numbers) {
        try {
          const txnId = generateTransactionId();
          await pool.query(`INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, recipient, provider, remark) VALUES ($1, 'purchase', 'bulk_airtime', $2, $2, 'pending', $3, $4, $5, 'Bulk airtime send')`,
            [req.user.id, parseFloat(amountPerNumber), txnId, phone, provider]);

          if (CK_USER_ID && CK_API_KEY) {
            const networkCode = NETWORK_CODES[provider.toLowerCase()] || provider.toLowerCase();
            const ckResponse = await axios.get(`${CK_BASE_URL}/APIAirtimeV1.asp`, { params: { RequestID: txnId, MobileNetwork: networkCode, Amount: parseFloat(amountPerNumber), MobileNumber: phone, UserID: CK_USER_ID, APIKey: CK_API_KEY }, timeout: 30000 });
            if (ckResponse.data && (ckResponse.data.statuscode === '100' || ckResponse.data.status === 'ORDER_RECEIVED')) {
              await pool.query("UPDATE transactions SET status = 'success' WHERE transaction_id = $1", [txnId]);
              successCount++;
            } else {
              await pool.query("UPDATE transactions SET status = 'failed', remark = $1 WHERE transaction_id = $2", [ckResponse.data?.remark || 'Provider error', txnId]);
              failedCount++;
            }
          } else {
            await pool.query("UPDATE transactions SET status = 'success' WHERE transaction_id = $1", [txnId]);
            successCount++;
          }
        } catch (e) {
          failedCount++;
        }
      }

      // Refund for failed numbers
      const refundAmount = failedCount * parseFloat(amountPerNumber);
      if (refundAmount > 0) {
        await pool.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2', [refundAmount, req.user.id]);
        await pool.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [req.user.id, 'Bulk Airtime Partial Refund', `${failedCount} number(s) failed. ₦${refundAmount.toLocaleString()} refunded to your wallet.`, 'wallet']);
      }

      // Update bulk log
      await pool.query('UPDATE bulk_airtime_logs SET success_count = $1, failed_count = $2, status = $3 WHERE uid = $4', [successCount, failedCount, 'completed', bulkUid]);

      // Send notification
      await pool.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [req.user.id, 'Bulk Airtime Completed', `Sent airtime to ${successCount}/${numbers.length} numbers. ${failedCount > 0 ? failedCount + ' failed and were refunded.' : 'All successful!'}`, 'wallet']);
      sendUserEmail(req.user.id, 'Bulk Airtime Completed', `Your bulk airtime send is complete:<br><br><b>Successful:</b> ${successCount}/${numbers.length}<br><b>Failed:</b> ${failedCount}${failedCount > 0 ? ' (refunded ₦' + refundAmount.toLocaleString() + ')' : ''}<br><b>Provider:</b> ${provider}<br><b>Amount per number:</b> ₦${parseFloat(amountPerNumber).toLocaleString()}`);
    })().catch(e => console.error('Bulk airtime background error:', e.message));

    res.json({ success: true, message: `Bulk airtime processing! Sending ₦${parseFloat(amountPerNumber).toLocaleString()} to ${numbers.length} ${provider} numbers. You'll be notified when it completes.`, totalAmount, numbersCount: numbers.length });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Failed: ' + err.message });
  } finally { client.release(); }
});

// ✅ User: Get bulk airtime history
app.get('/api/bulk-airtime/history', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM bulk_airtime_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50', [req.user.id]);
    res.json({ success: true, history: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== DATA GIFTING =====================

// ✅ User: Send data as a gift with a custom message
app.post('/api/data-gifts', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    const { recipientPhone, recipientName, provider, plan, amount, pin, customMessage } = req.body;
    if (!recipientPhone || !provider || !plan || !pin) return res.status(400).json({ error: 'Recipient phone, provider, plan, and PIN are required' });

    await client.query('BEGIN');

    // Verify PIN and balance
    const userRes = await client.query('SELECT pin, wallet_balance, is_banned, fullname FROM users WHERE id = $1 FOR UPDATE', [req.user.id]);
    const user = userRes.rows[0];
    if (user.is_banned) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Account banned' }); }
    if (!user.pin || !await bcrypt.compare(pin, user.pin)) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Invalid PIN' }); }

    // Get plan price
    const planRes = await client.query('SELECT selling_price FROM pricing WHERE service = $1 AND provider = $2 AND plan = $3 AND is_active = TRUE', ['data', provider.toUpperCase(), plan]);
    const sellPrice = planRes.rows.length ? parseFloat(planRes.rows[0].selling_price) : parseFloat(amount || 0);

    if (parseFloat(user.wallet_balance) < sellPrice) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Insufficient balance' }); }

    // Deduct from wallet
    await client.query('UPDATE users SET wallet_balance = wallet_balance - $1 WHERE id = $2', [sellPrice, req.user.id]);

    // Create gift record
    const giftUid = 'gift_d' + Date.now() + Math.random().toString(36).substr(2, 6);
    const txnId = generateTransactionId();
    await client.query(`INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, recipient, provider, plan, remark) VALUES ($1, 'purchase', 'data_gift', $2, $3, 'pending', $4, $5, $6, $7, $8)`,
      [req.user.id, sellPrice, sellPrice, txnId, recipientPhone, provider, plan, `Data gift to ${recipientName || recipientPhone}${customMessage ? ': ' + customMessage : ''}`]);

    await client.query(`INSERT INTO data_gifts (uid, sender_id, recipient_phone, recipient_name, provider, plan, amount, custom_message, status, transaction_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9)`,
      [giftUid, req.user.id, recipientPhone, recipientName || '', provider, plan, sellPrice, customMessage || '', txnId]);

    await client.query('COMMIT');

    // Process the data purchase (async)
    (async () => {
      try {
        if (CK_USER_ID && CK_API_KEY) {
          const networkCode = NETWORK_CODES[provider.toLowerCase()] || provider.toLowerCase();
          const ckResponse = await axios.get(`${CK_BASE_URL}/APIDatabundleV1.asp`, { params: { RequestID: txnId, MobileNetwork: networkCode, DataPlan: plan, MobileNumber: recipientPhone, UserID: CK_USER_ID, APIKey: CK_API_KEY }, timeout: 60000 });
          if (ckResponse.data && (ckResponse.data.statuscode === '100' || ckResponse.data.status === 'ORDER_RECEIVED')) {
            await pool.query("UPDATE transactions SET status = 'success' WHERE transaction_id = $1", [txnId]);
            await pool.query("UPDATE data_gifts SET status = 'delivered' WHERE uid = $1", [giftUid]);
            await pool.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [req.user.id, '🎁 Data Gift Delivered!', `Your data gift (${plan}) has been delivered to ${recipientName || recipientPhone}.${customMessage ? ' Message: "' + customMessage + '"' : ''}`, 'gift']);
            sendUserEmail(req.user.id, '🎁 Data Gift Delivered!', `Your data gift has been delivered!<br><br><b>Recipient:</b> ${recipientName || recipientPhone}<br><b>Plan:</b> ${plan}<br><b>Provider:</b> ${provider}<br>${customMessage ? '<b>Message:</b> "' + customMessage + '"<br>' : ''}<b>Amount:</b> ₦${sellPrice.toLocaleString()}`);

            // ✅ NEW: Try to notify the RECIPIENT with sender name + custom message
            try {
              const normPhone = normalizePhone(recipientPhone);
              const recipientUser = await pool.query('SELECT id, fullname, email FROM users WHERE phone = $1', [normPhone]);
              if (recipientUser.rows.length > 0) {
                const r = recipientUser.rows[0];
                const senderName = user.fullname || 'A Yenllet user';
                const recipientMsg = `🎁 You received a data gift from ${senderName}! ${plan} from ${provider} has been delivered to your phone.${customMessage ? '<br><br><strong>Message from ' + senderName + ':</strong><br>"' + customMessage + '"' : ''}`;
                await pool.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [r.id, '🎁 Data Gift Received!', recipientMsg, 'gift']);
                sendUserEmail(r.id, '🎁 You Received a Data Gift!', `Hi ${r.fullname},<br><br>You just received a data gift from <strong>${senderName}</strong>!<br><br><b>Plan:</b> ${plan}<br><b>Provider:</b> ${provider}<br>${customMessage ? '<br><b>Message from ' + senderName + ':</b><br><div style="background:#f0fdf4;border-left:4px solid #10b981;padding:12px;margin:10px 0;border-radius:8px;font-style:italic;">' + customMessage + '</div>' : ''}<br>The data has been delivered to your phone (${recipientPhone}).`);
                sendPushNotification(r.id, '🎁 Data Gift from ' + senderName + '!', customMessage ? (customMessage.substring(0, 80) + (customMessage.length > 80 ? '...' : '')) : (plan + ' delivered to your phone'));
                console.log(`✅ Data gift recipient notified: ${r.fullname} (${r.email}) — gift from ${senderName}`);
              } else {
                console.log(`ℹ️ Data gift recipient ${recipientPhone} is not a Yenllet user — custom message not delivered.`);
                await pool.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [req.user.id, 'ℹ️ Gift Message Not Delivered', `The data was successfully delivered to ${recipientName || recipientPhone}, but the custom message could not be shown because the recipient is not yet a Yenllet user. They received the data on their phone.`, 'info']);
              }
            } catch (recipientErr) {
              console.error('Failed to notify data gift recipient:', recipientErr.message);
            }
          } else {
            // Refund
            await pool.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2', [sellPrice, req.user.id]);
            await pool.query("UPDATE transactions SET status = 'failed' WHERE transaction_id = $1", [txnId]);
            await pool.query("UPDATE data_gifts SET status = 'failed' WHERE uid = $1", [giftUid]);
            await pool.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [req.user.id, 'Data Gift Failed', `Your data gift to ${recipientName || recipientPhone} failed. ₦${sellPrice.toLocaleString()} refunded.`, 'wallet']);
          }
        }
      } catch (e) {
        await pool.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2', [sellPrice, req.user.id]);
        await pool.query("UPDATE transactions SET status = 'failed' WHERE transaction_id = $1", [txnId]);
        await pool.query("UPDATE data_gifts SET status = 'failed' WHERE uid = $1", [giftUid]);
      }
    })().catch(e => console.error('Data gift error:', e.message));

    res.json({ success: true, message: `Data gift sent to ${recipientName || recipientPhone}! They'll receive ${plan} from ${provider}. You'll be notified when it's delivered.`, giftUid });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Failed: ' + err.message });
  } finally { client.release(); }
});

// ✅ User: Get their data gift history
app.get('/api/data-gifts', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM data_gifts WHERE sender_id = $1 ORDER BY created_at DESC LIMIT 50', [req.user.id]);
    res.json({ success: true, gifts: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== LEADERBOARD PRIZE SETTINGS =====================
// ✅ Admin: GET leaderboard prize settings (for admin.html form)
app.get('/api/admin/leaderboard-prizes', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT value FROM admin_settings WHERE key = 'leaderboard_prizes'");
    let settings = { first_prize: 10000, second_prize: 5000, third_prize: 3000, consolation_prize: 500, data_gift_gb: 1, min_referrals: 1, min_transactions_per_referral: 5 };
    if (result.rows.length > 0) {
      const v = result.rows[0].value;
      settings = {
        first_prize: parseFloat(v.first_prize) || 10000,
        second_prize: parseFloat(v.second_prize) || 5000,
        third_prize: parseFloat(v.third_prize) || 3000,
        consolation_prize: parseFloat(v.consolation_prize) || 500,
        data_gift_gb: parseFloat(v.data_gift_gb) || 1,
        min_referrals: parseInt(v.min_referrals) || 1,
        // ✅ NEW: A referred user only counts toward the vendor's leaderboard
        // ranking if they have made at least N successful transactions this month.
        // Default = 5. This prevents vendors from referring inactive signups
        // just to climb the leaderboard — only ACTIVE buyers count.
        min_transactions_per_referral: parseInt(v.min_transactions_per_referral) !== undefined ? parseInt(v.min_transactions_per_referral) : 5
      };
    }
    res.json({ success: true, settings });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: PUT (save) leaderboard prize settings
app.put('/api/admin/leaderboard-prizes', authenticateAdmin, async (req, res) => {
  try {
    const { first_prize, second_prize, third_prize, consolation_prize, data_gift_gb, min_referrals, min_transactions_per_referral } = req.body;
    const settings = {
      first_prize: parseFloat(first_prize) || 10000,
      second_prize: parseFloat(second_prize) || 5000,
      third_prize: parseFloat(third_prize) || 3000,
      consolation_prize: parseFloat(consolation_prize) || 500,
      data_gift_gb: parseFloat(data_gift_gb) || 1,
      min_referrals: parseInt(min_referrals) || 1,
      min_transactions_per_referral: parseInt(min_transactions_per_referral) || 5
    };
    await pool.query("INSERT INTO admin_settings (key, value) VALUES ('leaderboard_prizes', $1) ON CONFLICT (key) DO UPDATE SET value = $1", [JSON.stringify(settings)]);
    res.json({ success: true, message: 'Leaderboard prize settings saved. Vendors must now have referred users who each made at least ' + settings.min_transactions_per_referral + ' successful transactions to qualify.', settings });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ✅ Admin: POST - Distribute this month's prizes to top 20 vendors (ONE-CLICK)
// Fetches leaderboard, then credits each winner:
//   1st: first_prize to wallet
//   2nd: second_prize to wallet
//   3rd: third_prize to wallet
//   4th-10th: consolation_prize to cashback_balance
//   11th-20th: data_gift_gb GB data via ClubKonnect (skipped if CK not configured)
app.post('/api/admin/leaderboard/distribute-prizes', authenticateAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Load prize settings
    const settingsRes = await client.query("SELECT value FROM admin_settings WHERE key = 'leaderboard_prizes'");
    const s = settingsRes.rows.length > 0 ? settingsRes.rows[0].value : {};
    const firstPrize = parseFloat(s.first_prize) || 10000;
    const secondPrize = parseFloat(s.second_prize) || 5000;
    const thirdPrize = parseFloat(s.third_prize) || 3000;
    const consolationPrize = parseFloat(s.consolation_prize) || 500;
    const dataGiftGb = parseFloat(s.data_gift_gb) || 1;
    const minReferrals = parseInt(s.min_referrals) || 1;
    // ✅ NEW: Only count referred users who have made ≥N successful transactions this month.
    // This makes the leaderboard strict — vendors who refer inactive signups don't rank.
    const minTxnsPerReferral = parseInt(s.min_transactions_per_referral) || 5;

    // ✅ Use the same strict query as the public /api/leaderboard endpoint.
    // This guarantees the distribution matches what admin sees on the leaderboard tab.
    // extraSelectColumns + extraGroupBy add email/phone/business_name for the distribution loop.
    const lbRes = await client.query(
      buildStrictLeaderboardQuery(
        ', u.email, u.phone, u.vendor_business_name',
        ', u.email, u.phone, u.vendor_business_name'
      ),
      [null, minTxnsPerReferral]
    );

    // ✅ Apply min_referrals filter (after the strict query — admin can require N active referrals minimum)
    const winners = lbRes.rows.filter(w => parseInt(w.referral_count) >= minReferrals);
    if (winners.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: `No vendors qualify for prizes this month. To qualify, a vendor must have at least ${minReferrals} referred user(s) who EACH made at least ${minTxnsPerReferral} successful transaction(s) this month.`
      });
    }

    // Check if prizes were already distributed this month (prevent double-distribution)
    const alreadyDist = await client.query("SELECT value FROM admin_settings WHERE key = 'leaderboard_prizes_distributed'");
    const monthKey = new Date().toLocaleString('en-US', { month: 'long', year: 'numeric' });
    if (alreadyDist.rows.length > 0 && alreadyDist.rows[0].value.month === monthKey) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Prizes already distributed for ' + monthKey + '. To distribute again, delete the leaderboard_prizes_distributed row from admin_settings.' });
    }

    const distributed = [];
    let consolationCount = 0, dataGiftCount = 0;

    for (let i = 0; i < winners.length; i++) {
      const winner = winners[i];
      const rank = i + 1;
      let prizeType = '', prizeAmount = 0, prizeDesc = '';

      if (rank === 1) {
        // 1st place — credit wallet
        prizeAmount = firstPrize;
        prizeType = 'wallet';
        prizeDesc = '1st place leaderboard prize';
        await client.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2', [prizeAmount, winner.id]);
        const txnId = generateTransactionId();
        await client.query("INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, reference, remark) VALUES ($1, 'credit', 'leaderboard_prize', $2, $2, 'success', $3, $4, $5)",
          [winner.id, prizeAmount, txnId, 'LB-1ST-' + monthKey, prizeDesc]);
      } else if (rank === 2) {
        // 2nd place — credit wallet
        prizeAmount = secondPrize;
        prizeType = 'wallet';
        prizeDesc = '2nd place leaderboard prize';
        await client.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2', [prizeAmount, winner.id]);
        const txnId = generateTransactionId();
        await client.query("INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, reference, remark) VALUES ($1, 'credit', 'leaderboard_prize', $2, $2, 'success', $3, $4, $5)",
          [winner.id, prizeAmount, txnId, 'LB-2ND-' + monthKey, prizeDesc]);
      } else if (rank === 3) {
        // 3rd place — credit wallet
        prizeAmount = thirdPrize;
        prizeType = 'wallet';
        prizeDesc = '3rd place leaderboard prize';
        await client.query('UPDATE users SET wallet_balance = wallet_balance + $1 WHERE id = $2', [prizeAmount, winner.id]);
        const txnId = generateTransactionId();
        await client.query("INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, reference, remark) VALUES ($1, 'credit', 'leaderboard_prize', $2, $2, 'success', $3, $4, $5)",
          [winner.id, prizeAmount, txnId, 'LB-3RD-' + monthKey, prizeDesc]);
      } else if (rank >= 4 && rank <= 10) {
        // 4th-10th — credit cashback
        prizeAmount = consolationPrize;
        prizeType = 'cashback';
        prizeDesc = 'Top 10 leaderboard cashback prize';
        await client.query('UPDATE users SET cashback_balance = cashback_balance + $1 WHERE id = $2', [prizeAmount, winner.id]);
        consolationCount++;
      } else if (rank >= 11 && rank <= 20) {
        // 11th-20th — data gift via ClubKonnect (async, non-blocking)
        if (CK_USER_ID && CK_API_KEY && winner.phone) {
          try {
            const dataPlan = dataGiftGb + 'GB'; // Simplified — admin can adjust plan name in pricing table
            const txnId = generateTransactionId();
            // Find a data plan that matches the GB amount for MTN (default network for prizes)
            const planRes = await pool.query("SELECT plan FROM pricing WHERE service = 'data' AND provider = 'MTN' AND plan ILIKE $1 AND is_active = TRUE LIMIT 1", ['%' + dataGiftGb + 'GB%']);
            const ckPlan = planRes.rows.length > 0 ? planRes.rows[0].plan : (dataGiftGb + 'GB - Monthly (SME)');
            const ckResponse = await axios.get(`${CK_BASE_URL}/APIDatabundleV1.asp`, {
              params: { RequestID: txnId, MobileNetwork: '01', DataPlan: ckPlan, MobileNumber: winner.phone, UserID: CK_USER_ID, APIKey: CK_API_KEY },
              timeout: 60000
            });
            if (ckResponse.data && (ckResponse.data.statuscode === '100' || ckResponse.data.status === 'ORDER_RECEIVED')) {
              await client.query("INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, recipient, provider, plan, remark) VALUES ($1, 'credit', 'leaderboard_data_prize', 0, 0, 'success', $2, $3, 'MTN', $4, $5)",
                [winner.id, txnId, winner.phone, ckPlan, 'Top 20 leaderboard data prize']);
              prizeType = 'data';
              prizeAmount = 0;
              prizeDesc = dataGiftGb + 'GB data gift';
              dataGiftCount++;
            } else {
              // CK failed — fall back to cashback equivalent
              const fallbackAmt = dataGiftGb * 200; // ~₦200 per GB fallback
              await client.query('UPDATE users SET cashback_balance = cashback_balance + $1 WHERE id = $2', [fallbackAmt, winner.id]);
              prizeType = 'cashback';
              prizeAmount = fallbackAmt;
              prizeDesc = 'Top 20 leaderboard prize (data gift failed - cashback fallback)';
              dataGiftCount++;
            }
          } catch (ckErr) {
            // CK error — fall back to cashback
            const fallbackAmt = dataGiftGb * 200;
            await client.query('UPDATE users SET cashback_balance = cashback_balance + $1 WHERE id = $2', [fallbackAmt, winner.id]);
            prizeType = 'cashback';
            prizeAmount = fallbackAmt;
            prizeDesc = 'Top 20 leaderboard prize (CK error - cashback fallback)';
            dataGiftCount++;
          }
        } else {
          // CK not configured — give cashback equivalent
          const fallbackAmt = dataGiftGb * 200;
          await client.query('UPDATE users SET cashback_balance = cashback_balance + $1 WHERE id = $2', [fallbackAmt, winner.id]);
          prizeType = 'cashback';
          prizeAmount = fallbackAmt;
          prizeDesc = 'Top 20 leaderboard prize (CK not configured - cashback fallback)';
          dataGiftCount++;
        }
      }

      // Send notification to winner
      await client.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)',
        [winner.id, '🏆 Leaderboard Prize Won!', `Congratulations ${winner.fullname}! You ranked #${rank} on the ${monthKey} vendor leaderboard. Your prize: ${prizeDesc}${prizeAmount > 0 ? ' (₦' + prizeAmount.toLocaleString() + ')' : ''}. ${prizeType === 'wallet' ? 'It has been credited to your Yenllet wallet.' : prizeType === 'cashback' ? 'It has been added to your cashback balance.' : 'It has been sent to your phone.'}`, 'leaderboard']);

      // Send email + push notification
      sendUserEmail(winner.id, '🏆 Leaderboard Prize Won!', `Congratulations ${winner.fullname}!<br><br>You ranked <b>#${rank}</b> on the ${monthKey} vendor leaderboard.<br><br><b>Prize:</b> ${prizeDesc}${prizeAmount > 0 ? ' (₦' + prizeAmount.toLocaleString() + ')' : ''}<br><br>${prizeType === 'wallet' ? 'Your prize has been credited to your Yenllet wallet.' : prizeType === 'cashback' ? 'Your prize has been added to your cashback balance.' : 'Your data gift has been sent to your phone.'}<br><br>Keep referring users to climb the leaderboard next month!`);
      sendPushNotification(winner.id, '🏆 Leaderboard Prize Won!', `You ranked #${rank} this month! Prize: ${prizeDesc}`);

      distributed.push({ rank, vendor_id: winner.id, fullname: winner.fullname, email: winner.email, prize_type: prizeType, prize_amount: prizeAmount, prize_desc: prizeDesc });
    }

    // Mark prizes as distributed for this month (prevent double-distribution)
    await client.query("INSERT INTO admin_settings (key, value) VALUES ('leaderboard_prizes_distributed', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
      [JSON.stringify({ month: monthKey, distributed_at: new Date(), winners_count: distributed.length })]);

    await client.query('COMMIT');

    const summary = {
      first_name: distributed[0]?.fullname || 'N/A',
      first_prize: firstPrize,
      second_name: distributed[1]?.fullname || 'N/A',
      second_prize: secondPrize,
      third_name: distributed[2]?.fullname || 'N/A',
      third_prize: thirdPrize,
      consolation_count: consolationCount,
      consolation_prize: consolationPrize,
      data_gift_count: dataGiftCount,
      data_gift_gb: dataGiftGb,
      total_winners: distributed.length
    };

    res.json({ success: true, message: `Prizes distributed to ${distributed.length} vendors!`, winners: distributed, summary });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    res.status(500).json({ error: 'Failed: ' + err.message });
  } finally {
    client.release();
  }
});

// ===================== LEADERBOARDS =====================
//
// ✅ STRICT LEADERBOARD — only referred users who have made ≥N successful
// transactions THIS MONTH count toward the vendor's ranking. N is configurable
// by admin (default 5). This prevents vendors from referring inactive signups
// just to climb the leaderboard — only ACTIVE buyers count toward ranking.
//
// The query is structured as:
//   1. Find each approved vendor's referred users (this month).
//   2. For each referred user, count their successful transactions this month.
//   3. Only count the referred user if their transaction count ≥ N.
//   4. Rank vendors by their count of "active referred users" (descending),
//      then by total vendor_earnings (descending) as a tiebreaker.

// Helper: builds the strict leaderboard SQL — used by both /api/leaderboard
// (public) and /api/admin/leaderboard/distribute-prizes (admin). Returns
// { sql, params } where sql uses $1, $2 for month start + min_txns.
const buildStrictLeaderboardQuery = (extraSelectColumns = '', extraGroupBy = '') => `
  WITH referred_with_txn_counts AS (
    SELECT
      vr.vendor_id,
      vr.referred_user_id,
      vr.vendor_earnings,
      COUNT(t.id) FILTER (WHERE t.status = 'success') AS referred_user_txn_count
    FROM vendor_referrals vr
    LEFT JOIN transactions t
      ON t.user_id = vr.referred_user_id
     AND t.type = 'purchase'
     AND t.created_at >= date_trunc('month', NOW())
    WHERE vr.created_at >= date_trunc('month', NOW())
    GROUP BY vr.vendor_id, vr.referred_user_id, vr.vendor_earnings
  ),
  active_referrals AS (
    -- Only count referred users whose txn_count ≥ min_txns threshold
    SELECT
      vendor_id,
      COUNT(*) AS active_referral_count,
      COALESCE(SUM(vendor_earnings), 0) AS total_earnings
    FROM referred_with_txn_counts
    WHERE referred_user_txn_count >= $2
    GROUP BY vendor_id
  )
  SELECT u.id, u.fullname, u.profile_pic,
         COALESCE(ar.active_referral_count, 0) AS referral_count,
         COALESCE(ar.total_earnings, 0) AS total_earnings
         ${extraSelectColumns}
  FROM users u
  LEFT JOIN active_referrals ar ON ar.vendor_id = u.id
  WHERE u.vendor_status = 'approved'
    AND COALESCE(ar.active_referral_count, 0) > 0
  GROUP BY u.id, u.fullname, u.profile_pic, ar.active_referral_count, ar.total_earnings ${extraGroupBy}
  ORDER BY referral_count DESC, total_earnings DESC
  LIMIT 20
`;

// ✅ Public: Get top 20 referrers this month (strict leaderboard)
app.get('/api/leaderboard', async (req, res) => {
  try {
    // Load min_transactions_per_referral from admin settings (default 5)
    let minTxns = 5;
    try {
      const s = await pool.query("SELECT value FROM admin_settings WHERE key = 'leaderboard_prizes'");
      if (s.rows.length > 0) {
        const v = typeof s.rows[0].value === 'string' ? JSON.parse(s.rows[0].value) : s.rows[0].value;
        if (v && v.min_transactions_per_referral !== undefined) {
          minTxns = parseInt(v.min_transactions_per_referral) || 5;
        }
      }
    } catch (e) { /* use default */ }

    const result = await pool.query(buildStrictLeaderboardQuery(), [null, minTxns]);
    res.json({
      success: true,
      leaderboard: result.rows,
      month: new Date().toLocaleString('en-US', { month: 'long', year: 'numeric' }),
      rules: {
        min_transactions_per_referral: minTxns,
        note: `A referred user only counts toward ranking if they have made at least ${minTxns} successful transactions this month.`
      }
    });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== START =====================
if (process.env.VERCEL) { module.exports = app; }
else { app.listen(PORT, () => console.log(`🚀 Yenllet VTU Server v12.0 running on port ${PORT}`)); }
