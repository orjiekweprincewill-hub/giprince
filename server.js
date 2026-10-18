/**
 * Yenllet VTU Platform - Server (REBUILT v8.2 - Yenllet Branding & Resend API)
 */
require('dotenv').config();
console.log("CK Credentials Loaded:", process.env.CLUBKONNECT_USER_ID ? "YES" : "NO");
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ===================== DATABASE =====================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 8000 
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
try {
  if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
} catch (e) { /* Ignore on Vercel read-only fs */ }

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'yenllet_secret_key');
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
};

const authenticateAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'yenllet_secret_key');
    if (!decoded.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    req.user = decoded;
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
};

// ===================== HELPERS =====================
// ✅ FIXED: 10-Digit Account Number Generator
const generateAccountNumber = () => Math.floor(Math.random() * 9000000000 + 1000000000).toString();
const generateReferralCode = (userId) => 'YL' + userId.toString().padStart(6, '0');
const normalizePhone = (phone) => {
  if (!phone) return '';
  let p = phone.replace(/\D/g, '');
  if (p.startsWith('234')) p = p.slice(3);
  if (p.startsWith('0')) p = p.slice(1);
  return p;
};
const generateTransactionId = () => 'TXN' + Date.now() + Math.random().toString(36).substr(2, 6).toUpperCase();
const hashPassword = async (pwd) => bcrypt.hash(pwd, 10);
const isValidPin = (pin) => /^\d{4}$/.test(pin);

// DYNAMIC URL HELPER
const getBaseUrl = (req) => {
  if (req.headers.origin) return req.headers.origin.replace(/\/$/, '');
  if (req.headers.referer) return req.headers.referer.replace(/\/$/, '').split('/').slice(0, 3).join('/');
  return process.env.APP_URL || 'http://localhost:3000';
};

const CK_BASE_URL = 'https://www.nellobytesystems.com';
const CK_USER_ID = process.env.CLUBKONNECT_USER_ID || '';
const CK_API_KEY = process.env.CLUBKONNECT_API_KEY || '';

const NETWORK_CODES = { 'mtn': '01', 'glo': '02', '9mobile': '03', 'etisalat': '03', 'airtel': '04' };

const flwRequest = async (method, endpoint, data = null) => {
  let baseUrl = process.env.FLW_BASE_URL || 'https://api.flutterwave.com';
  baseUrl = baseUrl.replace(/\/v3\/?$/, '');
  const config = { method, url: `${baseUrl}${endpoint}`, headers: { 'Authorization': `Bearer ${process.env.FLW_SECRET_KEY}`, 'Content-Type': 'application/json' } };
  if (data) config.data = data;
  return axios(config);
};

// ✅ RESEND EMAIL API WITH LOGO TEMPLATE & USER OPT-OUT
const sendUserEmail = async (userId, subject, textContent, actionUrl = null, actionText = null) => {
  try {
    if (!process.env.RESEND_API_KEY) return;
    const userRes = await pool.query('SELECT email, fullname, email_visible FROM users WHERE id = $1', [userId]);
    if (!userRes.rows.length || !userRes.rows[0].email_visible) return; // Respect Opt-out
    
    const email = userRes.rows[0].email;
    const fullname = userRes.rows[0].fullname;
    
    const buttonHtml = actionUrl ? `<a href="${actionUrl}" style="display:inline-block;background:#2563eb;color:white;padding:12px 24px;text-decoration:none;border-radius:5px;margin:20px 0;font-weight:bold;">${actionText || 'Click Here'}</a>` : '';
    
    const html = `
      <!DOCTYPE html>
      <html>
      <head><meta charset="UTF-8"></head>
      <body style="font-family: 'Segoe UI', sans-serif; background-color: #f8f9fa; margin: 0; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
          <div style="background-color: #1e293b; padding: 20px; text-align: center;">
            <img src="https://res.cloudinary.com/x9cnhu3z/image/upload/v1792062220/Yenllet_Blue_Ribbon_Logo_ltmv0i.png" alt="Yenllet Logo" style="height: 50px;">
          </div>
          <div style="padding: 30px;">
            <h2 style="color: #1f2937; margin-bottom: 10px;">${subject}</h2>
            <p style="color: #4b5563; line-height: 1.6;">Hi ${fullname},</p>
            <div style="color: #4b5563; line-height: 1.6;">${textContent}</div>
            ${buttonHtml}
          </div>
          <div style="background-color: #f1f5f9; padding: 20px; text-align: center; font-size: 12px; color: #64748b;">
            <p>&copy; ${new Date().getFullYear()} Yenllet. All rights reserved.</p>
            <p>You are receiving this because you have email notifications enabled. <br>If you do not want to receive these emails, you can turn them off in your Yenllet Profile settings.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    await axios.post('https://api.resend.com/emails', {
      from: 'Yenllet <no-reply@yenllet.name.ng>',
      to: [email],
      subject: subject,
      html: html
    }, {
      headers: { 'Authorization': `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' }
    });
  } catch (e) { console.error('Resend Email Error:', e.response?.data || e.message); }
};

// ===================== DATABASE INIT =====================
async function initDatabase() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY, fullname VARCHAR(255) NOT NULL, email VARCHAR(255) UNIQUE NOT NULL,
        phone VARCHAR(20) UNIQUE NOT NULL, password_hash TEXT NOT NULL, profile_pic TEXT, business_link TEXT, business_page JSONB,
        is_admin BOOLEAN DEFAULT FALSE, kyc_status VARCHAR(20) DEFAULT 'pending', kyc_bvn VARCHAR(11), kyc_nin VARCHAR(11),
        kyc_submitted_at TIMESTAMP, kyc_approved_at TIMESTAMP, wallet_balance DECIMAL(12,2) DEFAULT 0,
        cashback_balance DECIMAL(12,2) DEFAULT 0, account_number VARCHAR(12) UNIQUE, bank_name VARCHAR(100) DEFAULT 'Yenllet Bank',
        pin TEXT, referral_code VARCHAR(20) UNIQUE, referred_by INTEGER REFERENCES users(id), is_banned BOOLEAN DEFAULT FALSE,
        ban_reason TEXT, email_visible BOOLEAN DEFAULT TRUE, is_agent BOOLEAN DEFAULT FALSE, agent_code VARCHAR(20),
        spins_claimed INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, type VARCHAR(50) NOT NULL,
        service VARCHAR(50), amount DECIMAL(12,2) NOT NULL, total DECIMAL(12,2) NOT NULL, status VARCHAR(20) DEFAULT 'pending',
        transaction_id VARCHAR(100) UNIQUE, reference VARCHAR(100), recipient VARCHAR(50), provider VARCHAR(50), plan VARCHAR(100),
        remark TEXT, cashback DECIMAL(12,2) DEFAULT 0, receipt_data JSONB, created_at TIMESTAMP DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, title VARCHAR(255) NOT NULL,
        message TEXT, type VARCHAR(50) DEFAULT 'info', is_read BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS admin_settings (
        id SERIAL PRIMARY KEY, key VARCHAR(100) UNIQUE NOT NULL, value JSONB NOT NULL, updated_at TIMESTAMP DEFAULT NOW()
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS pricing (
        id SERIAL PRIMARY KEY, service VARCHAR(50) NOT NULL, provider VARCHAR(50) NOT NULL, plan VARCHAR(100),
        amount DECIMAL(12,2) NOT NULL, selling_price DECIMAL(12,2) NOT NULL, discount_percent DECIMAL(5,2) DEFAULT 0,
        cashback_percent DECIMAL(5,2) DEFAULT 0, validity VARCHAR(50), is_active BOOLEAN DEFAULT TRUE, updated_at TIMESTAMP DEFAULT NOW(),
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

    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS cashback_balance DECIMAL(12,2) DEFAULT 0`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS spins_claimed INTEGER DEFAULT 0`);
    await pool.query(`ALTER TABLE pricing ADD COLUMN IF NOT EXISTS validity VARCHAR(50)`);

    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token TEXT`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_expires TIMESTAMP`);

    await pool.query(`INSERT INTO admin_settings (key, value) VALUES 
        ('ads_pricing', '{"price_per_day": 500, "max_days": 30}'),
        ('withdrawal_settings', '{"min": 500, "max": 500000, "fee": 50}'),
        ('welcome_bonus', '{"enabled": false, "amount": 0}'),
        ('referral_reward', '{"enabled": false, "amount": 0}'),
        ('spin_settings', '{"enabled": false, "rewards": [{"type":"money", "value":100, "chance":30}, {"type":"cashback", "value":50, "chance":30}, {"type":"none", "value":0, "chance":40}]}')
      ON CONFLICT (key) DO NOTHING`);
    console.log('✅ Yenllet Database initialized successfully');
  } catch (err) {
    console.error('❌ Database init error:', err.message);
  }
}

initDatabase().catch(err => console.error('DB Init Error:', err));

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

      const result = await client.query(
        'INSERT INTO users (fullname, email, phone, password_hash) VALUES ($1, $2, $3, $4) RETURNING id',
        [fullname, email, normalizedPhone, passwordHash]
      );
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
      }

      await client.query('COMMIT');
      const token = jwt.sign({ id: userId, email, isAdmin: false }, process.env.JWT_SECRET || 'yenllet_secret_key', { expiresIn: '7d' });
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
    if (user.is_banned) return res.status(403).json({ error: 'Account banned. Contact support.' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, process.env.JWT_SECRET || 'yenllet_secret_key', { expiresIn: '7d' });
    res.json({
      success: true, token,
      user: { id: user.id, fullname: user.fullname, email: user.email, wallet: user.wallet_balance, cashback: user.cashback_balance, accountNumber: user.account_number, kycStatus: user.kyc_status, hasPin: !!user.pin, profilePic: user.profile_pic }
    });
  } catch (err) { res.status(500).json({ error: 'Login failed: ' + err.message }); }
});

// ===================== PASSWORD RESET =====================
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const userResult = await pool.query('SELECT id, fullname FROM users WHERE email = $1', [email]);
    
    // Security: Always return success to prevent email enumeration
    if (userResult.rows.length === 0) {
      return res.json({ success: true, message: 'If that email exists, a reset link has been sent.' });
    }

    const user = userResult.rows[0];
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 hour from now

    await pool.query(
      'UPDATE users SET reset_token = $1, reset_expires = $2 WHERE id = $3',
      [token, expires, user.id]
    );

    const resetLink = `${getBaseUrl(req)}/forgot-password.html?token=${token}`;
    sendUserEmail(user.id, 'Yenllet Password Reset', `You requested a password reset. Click the link below to reset your password:<br><a href="${resetLink}" style="background-color:#2563eb;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;display:inline-block;">Reset Password</a><br><br>This link will expire in 1 hour.<br>If you didn't request this, please ignore this email.`);

    res.json({ success: true, message: 'If that email exists, a reset link has been sent.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to process request' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword || newPassword.length < 6) {
      return res.status(400).json({ error: 'Invalid request or password too short (min 6 characters)' });
    }

    const userResult = await pool.query(
      'SELECT id FROM users WHERE reset_token = $1 AND reset_expires > NOW()',
      [token]
    );

    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    const userId = userResult.rows[0].id;
    const passwordHash = await hashPassword(newPassword);

    await pool.query(
      'UPDATE users SET password_hash = $1, reset_token = NULL, reset_expires = NULL WHERE id = $2',
      [passwordHash, userId]
    );

    res.json({ success: true, message: 'Password reset successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ===================== PROFILE =====================
app.get('/api/profile', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, fullname, email, phone, wallet_balance, cashback_balance, account_number, bank_name,
              referral_code, kyc_status, is_agent, email_visible, is_banned, spins_claimed,
              profile_pic, business_page, business_link, pin IS NOT NULL as has_pin, created_at
       FROM users WHERE id = $1`, [req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, profile: result.rows[0] });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.put('/api/profile', authenticate, async (req, res) => {
  try {
    const { fullname, emailVisible } = req.body;
    await pool.query('UPDATE users SET fullname = $1, email_visible = $2, updated_at = NOW() WHERE id = $3', [fullname, emailVisible, req.user.id]);
    res.json({ success: true, message: 'Profile updated' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.post('/api/profile/generate-account', authenticate, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT kyc_status, account_number FROM users WHERE id = $1', [req.user.id]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    if (userRes.rows[0].kyc_status !== 'approved') return res.status(400).json({ error: 'Please complete KYC first' });
    if (userRes.rows[0].account_number) return res.json({ success: true, message: 'Account already generated', accountNumber: userRes.rows[0].account_number });

    let accountNumber;
    let isUnique = false;
    let attempts = 0;
    while (!isUnique && attempts < 10) {
      accountNumber = generateAccountNumber();
      const check = await pool.query('SELECT id FROM users WHERE account_number = $1 AND id != $2', [accountNumber, req.user.id]);
      if (check.rows.length === 0) isUnique = true;
      attempts++;
    }

    await pool.query("UPDATE users SET account_number = $1, bank_name = 'Yenllet Bank' WHERE id = $2", [accountNumber, req.user.id]);
    res.json({ success: true, message: 'Account number generated', accountNumber });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
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

// ===================== KYC =====================
app.post('/api/kyc/submit', authenticate, async (req, res) => {
  try {
    const { bvn, nin } = req.body;
    const userId = req.user.id;
    if (!bvn || bvn.length !== 11) return res.status(400).json({ error: 'Valid 11-digit BVN is required' });

    const userResult = await pool.query('SELECT account_number FROM users WHERE id = $1', [userId]);
    if (userResult.rows[0].account_number) return res.json({ success: true, message: 'KYC already approved' });

    // ✅ STRICT FLUTTERWAVE BVN VERIFICATION
    try {
      const bvnResponse = await flwRequest('POST', '/v3/kyc/bvns', { bvn });
      if (bvnResponse.data && bvnResponse.data.status === 'success') {
        await pool.query(`UPDATE users SET kyc_status = 'approved', kyc_bvn = $1, kyc_submitted_at = NOW(), kyc_approved_at = NOW() WHERE id = $2`, [bvn, userId]);
        await pool.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [userId, 'KYC Approved!', 'You can now generate your account number.', 'kyc']);
        sendUserEmail(userId, 'KYC Approved', 'Your KYC has been approved. You can now generate your account number.');
        return res.json({ success: true, message: 'KYC approved! You can now generate your account number.', kycStatus: 'approved' });
      } else {
        return res.status(400).json({ error: 'Flutterwave could not verify this BVN.' });
      }
    } catch (flwErr) {
      return res.status(400).json({ error: 'BVN verification failed. Please check your BVN and try again.' });
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

    // ✅ YENLLET PREFIX FOR ROUTER
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

// WEBHOOK RECEIVER (Accepts both direct FLW and forwarded from Gustmii)
app.post('/api/wallet/webhook', async (req, res) => {
  res.status(200).end();
  try {
    const routerSecret = req.headers['x-site-router-secret'];
    const flwSignature = req.headers['verif-hash'];
    const payload = req.body;

    const isFromRouter = routerSecret && routerSecret === process.env.ROUTER_SECRET;
    const isFromFlutterwave = flwSignature && flwSignature === process.env.FLW_SECRET_HASH;

    if (!isFromRouter && !isFromFlutterwave) {
      console.warn('⚠️ Unauthorized webhook attempt.');
      return;
    }

    if (payload.event === 'charge.completed' && payload.data?.status === 'successful') {
      const txRef = payload.data.tx_ref;
      const amountPaid = parseFloat(payload.data.amount);
      const flwTxId = payload.data.id;
      if (payload.data.currency !== 'NGN') return;

      // ✅ YENLLET TX_REF CHECK
      if (txRef && txRef.startsWith('YENLLET-')) {
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
  } catch (err) {}
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
    const result = await pool.query('SELECT * FROM pricing WHERE is_active = TRUE ORDER BY service, provider, selling_price ASC');
    res.json({ success: true, pricing: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed to fetch pricing' }); }
});

// ===================== PROCESS PURCHASE =====================
const processPurchase = async (userId, pin, service, provider, plan, amount, recipient, extra = {}) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const userRes = await client.query('SELECT pin, wallet_balance, cashback_balance, is_banned FROM users WHERE id = $1 FOR UPDATE', [userId]);
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

    let cashbackUsed = 0;
    let amountFromWallet = sellPrice;

    if (extra.useCashback && parseFloat(user.cashback_balance) > 0) {
      cashbackUsed = Math.min(parseFloat(user.cashback_balance), sellPrice);
      amountFromWallet = sellPrice - cashbackUsed;
    }

    if (parseFloat(user.wallet_balance) < amountFromWallet) throw { status: 400, message: 'Insufficient balance' };

    const txnId = generateTransactionId();
    
    await client.query('UPDATE users SET wallet_balance = wallet_balance - $1, cashback_balance = cashback_balance - $2 WHERE id = $3', [amountFromWallet, cashbackUsed, userId]);
    
    const txnRes = await client.query(
      `INSERT INTO transactions (user_id, type, service, amount, total, status, transaction_id, reference, recipient, provider, plan, remark, receipt_data)
       VALUES ($1, 'purchase', $2, $3, $4, 'pending', $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
      [userId, service, amount, sellPrice, txnId, txnId, recipient, provider, plan, extra.remark || '', JSON.stringify({ useCashback: extra.useCashback, cashbackUsed })]
    );
    const txnDbId = txnRes.rows[0].id;

    if (['airtime', 'data', 'tv', 'electricity'].includes(service) && CK_USER_ID && CK_API_KEY) {
      try {
        let apiEndpoint = '';
        let apiParams = { RequestID: txnId };
        const networkCode = NETWORK_CODES[provider.toLowerCase()] || provider.toLowerCase();

        if (service === 'airtime') {
          apiEndpoint = 'APIAirtimeV1.asp';
          apiParams.MobileNetwork = networkCode; apiParams.Amount = amount; apiParams.MobileNumber = recipient;
        } else if (service === 'data') {
          apiEndpoint = 'APIDatabundleV1.asp';
          apiParams.MobileNetwork = networkCode; apiParams.DataPlan = plan; apiParams.MobileNumber = recipient;
        } else if (service === 'tv') {
          apiEndpoint = 'APICableTVV1.asp';
          apiParams.CableTV = provider.toLowerCase(); apiParams.Package = plan; apiParams.SmartCardNo = recipient;
        } else if (service === 'electricity') {
          apiEndpoint = 'APIElectricityV1.asp';
          apiParams.Company = provider.toLowerCase(); apiParams.MeterNo = recipient;
          apiParams.MeterType = extra.meterType?.toLowerCase() === 'prepaid' ? 'prepaid' : 'postpaid'; apiParams.Amount = amount;
        }

        const ckResponse = await axios.get(`${CK_BASE_URL}/${apiEndpoint}`, { params: { ...apiParams, UserID: CK_USER_ID, APIKey: CK_API_KEY }, timeout: 60000 });
        const apiData = ckResponse.data;

        let isSuccessful = false;
        let providerError = 'Unknown provider error';
        
        if (typeof apiData === 'object') {
          if (apiData.statuscode === '100' || apiData.status === 'ORDER_RECEIVED') {
            isSuccessful = true;
          } else {
            providerError = apiData.remark || apiData.status || apiData.msg || 'Transaction declined by provider';
          }
        } else {
          providerError = 'Provider returned an invalid response format.';
        }

        if (!isSuccessful) {
          const err = new Error(providerError);
          err.isProviderError = true;
          throw err;
        }
        
        await client.query('UPDATE transactions SET status = $1, receipt_data = $2 WHERE id = $3', ['success', JSON.stringify({ ...apiData, cashbackUsed }), txnDbId]);
        
        if (cashbackEarned > 0) {
          await client.query('UPDATE users SET cashback_balance = cashback_balance + $1 WHERE id = $2', [cashbackEarned, userId]);
        }
        
        await client.query('COMMIT');
        
        // ✅ EXTRACT ELECTRICITY TOKEN AND EMAIL IT
        if (service === 'electricity') {
          const meterToken = apiData.token || apiData.Token || 'See receipt for token';
          sendUserEmail(userId, 'Electricity Token Purchase', `Your electricity purchase was successful. <br><b>Meter Token: ${meterToken}</b><br>Meter Number: ${recipient}<br>Amount: ₦${sellPrice}`);
        } else {
          sendUserEmail(userId, 'Transaction Successful', `Your ${service} purchase of <b>₦${sellPrice}</b> was successful.<br>Transaction ID: ${txnId}`);
        }
        return { success: true, transactionId: txnId, message: `${service} purchase successful`, sellPrice, cashbackUsed, cashbackEarned };
      } catch (apiErr) {
        if (apiErr.isProviderError) {
          await client.query('UPDATE users SET wallet_balance = wallet_balance + $1, cashback_balance = cashback_balance + $2 WHERE id = $3', [amountFromWallet, cashbackUsed, userId]);
          await client.query("UPDATE transactions SET status = 'failed', remark = $1 WHERE id = $2", [apiErr.message, txnDbId]);
          await client.query('COMMIT');
          sendUserEmail(userId, 'Transaction Failed & Refunded', `Your ${service} purchase failed.<br>Reason: ${apiErr.message}<br>Your wallet has been refunded with ₦${amountFromWallet}.`);
          throw { status: 502, message: 'Service provider error: ' + apiErr.message };
        }

        try {
          const queryRes = await axios.get(`${CK_BASE_URL}/APIQueryV1.asp`, { params: { UserID: CK_USER_ID, APIKey: CK_API_KEY, RequestID: txnId }, timeout: 15000 });
          const queryData = queryRes.data;
          
          if (queryData.statuscode === '200' || queryData.status === 'ORDER_COMPLETED') {
            await client.query('UPDATE transactions SET status = $1, receipt_data = $2 WHERE id = $3', ['success', JSON.stringify({ ...queryData, cashbackUsed }), txnDbId]);
            if (cashbackEarned > 0) {
              await client.query('UPDATE users SET cashback_balance = cashback_balance + $1 WHERE id = $2', [cashbackEarned, userId]);
            }
            await client.query('COMMIT');
            sendUserEmail(userId, 'Transaction Successful', `Your ${service} purchase of <b>₦${sellPrice}</b> was successful.<br>Transaction ID: ${txnId}`);
            return { success: true, transactionId: txnId, message: `${service} purchase successful`, sellPrice, cashbackUsed, cashbackEarned };
          } else if (queryData.statuscode === '100' || queryData.status === 'ORDER_RECEIVED') {
            await client.query('COMMIT');
            sendUserEmail(userId, 'Transaction Processing', `Your ${service} purchase is processing. It will be completed shortly.<br>Transaction ID: ${txnId}`);
            return { success: true, transactionId: txnId, message: 'Transaction is processing. It will be completed shortly.', pending: true };
          } else {
            const failMsg = queryData.remark || queryData.status || 'Transaction failed';
            await client.query('UPDATE users SET wallet_balance = wallet_balance + $1, cashback_balance = cashback_balance + $2 WHERE id = $3', [amountFromWallet, cashbackUsed, userId]);
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
      if (cashbackEarned > 0) {
        await client.query('UPDATE users SET cashback_balance = cashback_balance + $1 WHERE id = $2', [cashbackEarned, userId]);
      }
      await client.query('COMMIT');
      sendUserEmail(userId, 'Transaction Successful', `Your ${service} purchase of <b>₦${sellPrice}</b> was successful.<br>Transaction ID: ${txnId}`);
      return { success: true, transactionId: txnId, message: `${service} purchase successful`, sellPrice, cashbackUsed, cashbackEarned };
    }
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch {}
    throw { status: err.status || 500, message: err.message || 'Purchase failed' };
  } finally {
    client.release();
  }
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

        await client.query('UPDATE users SET wallet_balance = wallet_balance + $1, cashback_balance = cashback_balance + $2 WHERE id = $3', [walletDeducted, cashbackUsed, txn.user_id]);
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
    const result = await processPurchase(req.user.id, pin, 'airtime', provider, null, amount, phone, { useCashback });
    res.json(result);
  } catch (err) { res.status(err.status || 500).json({ error: err.message || 'Purchase failed' }); }
});

app.post('/api/data/purchase', authenticate, async (req, res) => {
  try {
    const { provider, phone, plan, amount, pin, useCashback } = req.body;
    if (!provider || !phone || !plan || !pin) return res.status(400).json({ error: 'All fields required' });
    const result = await processPurchase(req.user.id, pin, 'data', provider, plan, amount || 0, phone, { useCashback });
    res.json(result);
  } catch (err) { res.status(err.status || 500).json({ error: err.message || 'Purchase failed' }); }
});

app.post('/api/tv/purchase', authenticate, async (req, res) => {
  try {
    const { provider, smartCardNumber, plan, amount, pin, useCashback } = req.body;
    if (!provider || !smartCardNumber || !plan || !pin) return res.status(400).json({ error: 'All fields required' });
    const result = await processPurchase(req.user.id, pin, 'tv', provider, plan, amount || 0, smartCardNumber, { useCashback });
    res.json(result);
  } catch (err) { res.status(err.status || 500).json({ error: err.message || 'Purchase failed' }); }
});

app.post('/api/electricity/purchase', authenticate, async (req, res) => {
  try {
    const { provider, meterNumber, meterType, amount, pin, useCashback } = req.body;
    if (!provider || !meterNumber || !amount || !pin) return res.status(400).json({ error: 'All fields required' });
    const result = await processPurchase(req.user.id, pin, 'electricity', provider, null, amount, meterNumber, { meterType, useCashback });
    res.json(result);
  } catch (err) { res.status(err.status || 500).json({ error: err.message || 'Purchase failed' }); }
});

app.post('/api/education/purchase', authenticate, async (req, res) => {
  try {
    const { examType, quantity, amount, pin, useCashback } = req.body;
    if (!examType || !quantity || !pin) return res.status(400).json({ error: 'All fields required' });
    const total = (amount || 3500) * quantity;
    const pins = Array.from({ length: quantity }, () => 'PIN-' + Date.now() + Math.random().toString(36).substr(2, 6).toUpperCase());
    const result = await processPurchase(req.user.id, pin, 'education', examType, `${quantity} pins`, total, examType, { quantity, pins, useCashback });
    res.json({ ...result, pins });
  } catch (err) { res.status(err.status || 500).json({ error: err.message || 'Purchase failed' }); }
});

app.post('/api/bet/fund', authenticate, async (req, res) => {
  try {
    const { provider, userId: betUserId, amount, pin, useCashback } = req.body;
    if (!provider || !betUserId || !amount || !pin) return res.status(400).json({ error: 'All fields required' });
    const result = await processPurchase(req.user.id, pin, 'bet', provider, null, amount, betUserId, { betUserId, useCashback });
    res.json(result);
  } catch (err) { res.status(err.status || 500).json({ error: err.message || 'Funding failed' }); }
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

    res.json({
      success: true,
      referralCode: user.rows[0].referral_code,
      referralLink: `${getBaseUrl(req)}/register.html?ref=${user.rows[0].referral_code}`,
      totalReferrals,
      spinsAvailable: spinsAvailable > 0 ? spinsAvailable : 0
    });
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

// ===================== BUSINESS PAGE =====================
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

// ===================== ADS =====================
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

// ===================== ADMIN ROUTES =====================
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (email !== process.env.ADMIN_EMAIL) return res.status(401).json({ error: 'Invalid credentials' });
    let isMatch = false;
    if (process.env.ADMIN_PASSWORD_HASH) { try { isMatch = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH); } catch {} }
    if (!isMatch && process.env.ADMIN_PASSWORD) isMatch = password === process.env.ADMIN_PASSWORD;
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ email, isAdmin: true }, process.env.JWT_SECRET || 'yenllet_secret_key', { expiresIn: '1d' });
    res.json({ success: true, token });
  } catch (err) { res.status(500).json({ error: 'Server error: ' + err.message }); }
});

app.get('/api/admin/dashboard', authenticateAdmin, async (req, res) => {
  try {
    const users = await pool.query('SELECT COUNT(*) FROM users');
    const transactions = await pool.query('SELECT COUNT(*), SUM(total) FROM transactions');
    const revenue = await pool.query("SELECT SUM(total) FROM transactions WHERE status = 'success'");
    const banned = await pool.query('SELECT COUNT(*) FROM users WHERE is_banned = TRUE');
    res.json({ success: true, stats: { totalUsers: parseInt(users.rows[0].count), totalTransactions: parseInt(transactions.rows[0].count), totalRevenue: parseFloat(revenue.rows[0].sum) || 0, bannedUsers: parseInt(banned.rows[0].count) } });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, fullname, email, phone, wallet_balance, cashback_balance, account_number, kyc_status, is_agent, is_banned, email_visible, created_at FROM users ORDER BY created_at DESC');
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
    const { id, service, provider, plan, amount, sellingPrice, cashbackPercent, isActive, validity } = req.body;
    const finalSellingPrice = service === 'airtime' ? parseFloat(amount) : parseFloat(sellingPrice || amount);
    if (id) {
      await pool.query(`UPDATE pricing SET service = $1, provider = $2, plan = $3, amount = $4, selling_price = $5, cashback_percent = $6, is_active = $7, validity = $8, updated_at = NOW() WHERE id = $9`, [service, provider, plan || null, parseFloat(amount), finalSellingPrice, parseFloat(cashbackPercent || 0), isActive !== false, validity || null, id]);
    } else {
      await pool.query(`INSERT INTO pricing (service, provider, plan, amount, selling_price, cashback_percent, is_active, validity, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW()) ON CONFLICT (service, provider, plan) DO UPDATE SET amount = EXCLUDED.amount, selling_price = EXCLUDED.selling_price, cashback_percent = EXCLUDED.cashback_percent, is_active = EXCLUDED.is_active, validity = EXCLUDED.validity, updated_at = NOW()`, [service, provider, plan || null, parseFloat(amount), finalSellingPrice, parseFloat(cashbackPercent || 0), isActive !== false, validity || null]);
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

// ✅ ADMIN BROADCAST ROUTE (Updated to use Resend API)
app.post('/api/admin/broadcast', authenticateAdmin, async (req, res) => {
  try {
    const { type, title, message } = req.body;
    const users = await pool.query('SELECT id, email_visible FROM users');
    for (const user of users.rows) {
      if (type === 'email' || type === 'all') {
        if (user.email_visible) {
          sendUserEmail(user.id, title, message);
        }
      }
      if (type === 'inapp' || type === 'all') { await pool.query('INSERT INTO notifications (user_id, title, message, type) VALUES ($1, $2, $3, $4)', [user.id, title, message, 'broadcast']); }
    }
    res.json({ success: true, message: 'Broadcast sent' });
  } catch (err) { res.status(500).json({ error: 'Failed: ' + err.message }); }
});

// ===================== PUBLIC STATS =====================
app.get('/api/stats', async (req, res) => {
  try {
    const BASE_USERS = 5000; 
    const BASE_TXNS = 15000;
    let dbUsers = 0;
    let dbTxns = 0;
    
    try {
      const users = await pool.query('SELECT COUNT(*) FROM users');
      dbUsers = parseInt(users.rows[0].count) || 0;
      const transactions = await pool.query("SELECT COUNT(*) FROM transactions WHERE status = 'success'");
      dbTxns = parseInt(transactions.rows[0].count) || 0;
    } catch (dbErr) {
      console.error('Database query failed for stats, using base numbers only:', dbErr.message);
    }
    
    res.json({
      success: true,
      stats: {
        totalUsers: dbUsers + BASE_USERS,
        totalTransactions: dbTxns + BASE_TXNS,
        uptime: 99.9
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to fetch stats' });
  }
});

// ===================== START =====================
if (process.env.VERCEL) {
  module.exports = app;
} else {
  app.listen(PORT, () => console.log(`🚀 Yenllet VTU Server running on port ${PORT}`));
}