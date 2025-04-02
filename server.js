const express = require('express');
const path = require('path');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const http = require('http');
const socketIo = require('socket.io');
const fs = require('fs');

require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: [
      'http://localhost:5500',
      'http://127.0.0.1:5500',
      'http://localhost:3000',
      'http://127.0.0.1:3000',
      'http://localhost:8000',
      'http://127.0.0.1:8000',
      'http://localhost:8080',
      'http://127.0.0.1:8080'
    ],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
  },
  transports: ['websocket', 'polling']
});

const port = process.env.PORT || 3000;
const publicPath = path.join(__dirname, 'public');
const uploadsDir = path.join(publicPath, 'uploads');

// Ensure uploads directory exists
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer Configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// Middleware
app.use(helmet());
app.use(bodyParser.json({ limit: '10kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10kb' }));
app.use(cors({
  origin: [
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    'http://localhost:3000',
    'http://127.0.0.1:3000'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Static Files
app.use(express.static(publicPath));
app.use('/uploads', express.static(uploadsDir));

// Database Connection
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'registration_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  timezone: '+00:00'
});

// Email Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Storage for OTPs and reset tokens
const otpStorage = {};
const resetTokens = {};

// Cleanup expired OTPs and tokens every hour
setInterval(() => {
  const now = Date.now();
  Object.keys(otpStorage).forEach(email => {
    if (otpStorage[email].expiry < now) delete otpStorage[email];
  });
  Object.keys(resetTokens).forEach(email => {
    if (resetTokens[email].expires < now) delete resetTokens[email];
  });
}, 3600000);

// Initialize Database Schema
async function initializeDatabase() {
  const connection = await pool.getConnection();
  try {
    // Create tables
    await connection.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id INT AUTO_INCREMENT PRIMARY KEY,
        fullname VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        fullname VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        phone VARCHAR(20) NOT NULL,
        password VARCHAR(255) NOT NULL,
        gender VARCHAR(10) NOT NULL,
        dob DATE NOT NULL,
        message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        transaction_id VARCHAR(50) UNIQUE NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        status ENUM('pending', 'completed', 'rejected') DEFAULT 'pending',
        user_id INT,
        method VARCHAR(50),
        screenshot VARCHAR(255),
        notes TEXT,
        admin_notes TEXT,
        verified_by INT,
        verified_at DATETIME,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // Add admin foreign key constraint
    await connection.query(`
      ALTER TABLE payments 
      MODIFY COLUMN verified_by INT NULL,
      ADD CONSTRAINT fk_payments_admin 
      FOREIGN KEY (verified_by) REFERENCES admins(id)
      ON DELETE SET NULL
    `).catch(() => {});

    // Create initial admin
    console.log('Checking for admin account:', process.env.ADMIN_EMAIL);
    const [admin] = await connection.query('SELECT * FROM admins WHERE email = ?', [process.env.ADMIN_EMAIL]);
    
    if (admin.length === 0 && process.env.ADMIN_PASSWORD) {
      console.log('Creating admin account...');
      const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
      await connection.query(
        'INSERT INTO admins (fullname, email, password) VALUES (?, ?, ?)',
        ['Admin User', process.env.ADMIN_EMAIL, hashedPassword]
      );
      console.log('✅ Admin user created successfully');
    } else if (admin.length > 0) {
      console.log('ℹ️ Admin user already exists');
    }

  } catch (error) {
    console.error('Database initialization error:', error);
    throw error;
  } finally {
    connection.release();
  }
}

// Socket.IO
io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);
  
  socket.on('payment:update', (payment) => {
    io.emit('payment:updated', payment);
  });
  
  socket.on('payment:new', (payment) => {
    io.emit('payment:created', payment);
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// ====================== MIDDLEWARE ====================== //
const authenticate = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

const adminOnly = async (req, res, next) => {
  try {
    const [admin] = await pool.query('SELECT * FROM admins WHERE id = ?', [req.user.id]);
    if (!admin.length) return res.status(403).json({ error: 'Admin access required' });
    next();
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
};

// ====================== ADMIN ENDPOINTS ====================== //
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const [admin] = await pool.query('SELECT * FROM admins WHERE email = ?', [email]);
    
    if (!admin.length) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, admin[0].password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { 
        id: admin[0].id,
        email: admin[0].email,
        role: 'admin'
      },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ 
      success: true,
      token,
      admin: { 
        id: admin[0].id,
        email: admin[0].email,
        name: admin[0].fullname
      }
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Login service unavailable' });
  }
});

app.get('/api/admin/payments', authenticate, adminOnly, async (req, res) => {
  try {
    const [payments] = await pool.query(`
      SELECT 
        p.*,
        u.email as user_email,
        a.email as verified_by_email
      FROM payments p
      LEFT JOIN users u ON p.user_id = u.id
      LEFT JOIN admins a ON p.verified_by = a.id
      ORDER BY p.created_at DESC
    `);

    res.json(payments.map(payment => ({
      ...payment,
      screenshot: payment.screenshot ? `/uploads/${payment.screenshot}` : null
    })));
  } catch (error) {
    console.error('Admin payment fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch payments' });
  }
});

app.post('/api/admin/verify-payment/:transactionId', authenticate, adminOnly, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    
    const { transactionId } = req.params;
    const { status, notes = "No notes provided" } = req.body;
    const adminId = req.user.id;

    if (!['completed', 'rejected', 'pending'].includes(status)) {
      await connection.rollback();
      return res.status(400).json({ error: 'Invalid status' });
    }

    const [result] = await connection.query(
      `UPDATE payments 
       SET status = ?, 
           admin_notes = ?, 
           verified_by = ?, 
           verified_at = NOW() 
       WHERE transaction_id = ?`,
      [status, notes, adminId, transactionId]
    );

    if (result.affectedRows === 0) {
      await connection.rollback();
      return res.status(404).json({ error: 'Payment not found' });
    }

    const [updatedPayment] = await connection.query(`
      SELECT p.*, u.email as user_email 
      FROM payments p
      LEFT JOIN users u ON p.user_id = u.id
      WHERE p.transaction_id = ?
    `, [transactionId]);

    await connection.commit();
    io.emit('payment:update', updatedPayment[0]);
    res.json({ success: true, payment: updatedPayment[0] });

  } catch (error) {
    await connection.rollback();
    console.error('Payment verification error:', error);
    res.status(500).json({ error: 'Verification failed' });
  } finally {
    connection.release();
  }
});

app.get('/api/admin/payment-stats', authenticate, adminOnly, async (req, res) => {
  try {
    const [stats] = await pool.query(`
      SELECT 
        SUM(CASE WHEN status = 'completed' THEN amount ELSE 0 END) as total_revenue,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as verified_count,
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_count,
        SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected_count
      FROM payments
    `);

    res.json({
      totalRevenue: stats[0].total_revenue || 0,
      verifiedCount: stats[0].verified_count || 0,
      pendingCount: stats[0].pending_count || 0,
      rejectedCount: stats[0].rejected_count || 0
    });
  } catch (error) {
    console.error('Stats fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ====================== USER ENDPOINTS ====================== //
app.post('/api/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }

    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (users.length > 0) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = Date.now() + 5 * 60 * 1000;
    otpStorage[email] = { otp, expiry };

    await transporter.sendMail({
      from: `"NetDark" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your OTP Code',
      html: `
        <h2>NetDark Registration OTP</h2>
        <p>Your verification code is: <strong>${otp}</strong></p>
        <p>This code will expire in 5 minutes.</p>
      `
    });

    res.status(200).json({ success: true, message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(500).json({ error: 'Failed to send OTP. Please try again later.' });
  }
});

app.post('/api/verify-otp', (req, res) => {
  try {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ error: 'Email and OTP are required' });
    }

    const storedOtp = otpStorage[email];
    
    if (!storedOtp) {
      return res.status(401).json({ error: 'OTP not found. Please request a new one.' });
    }

    if (Date.now() > storedOtp.expiry) {
      delete otpStorage[email];
      return res.status(401).json({ error: 'OTP expired. Please request a new one.' });
    }

    if (storedOtp.otp !== otp) {
      return res.status(401).json({ error: 'Invalid OTP. Please try again.' });
    }

    otpStorage[email].verified = true;
    res.status(200).json({ success: true, message: 'OTP verified successfully' });
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ error: 'OTP verification failed' });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const { fullname, email, phone, password, gender, dob, message, otp } = req.body;
    
    if (!fullname || !email || !phone || !password || !gender || !dob || !otp) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const storedOtp = otpStorage[email];
    if (!storedOtp || storedOtp.otp !== otp || !storedOtp.verified) {
      return res.status(401).json({ error: 'OTP verification failed' });
    }

    const [existing] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existing.length > 0) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    
    await pool.query(
      `INSERT INTO users (fullname, email, phone, password, gender, dob, message) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [fullname, email, phone, hashedPassword, gender, dob, message]
    );

    delete otpStorage[email];
    res.status(201).json({ success: true, message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed. Please try again.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    
    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { 
        id: user.id,
        email: user.email,
        role: 'user'
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ 
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.fullname
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed. Please try again.' });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const [user] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    
    if (user.length === 0) {
      return res.status(404).json({ error: 'Email not found' });
    }

    const token = crypto.randomBytes(20).toString('hex');
    const expires = Date.now() + 3600000;
    resetTokens[email] = { token, expires };

    const resetUrl = `http://localhost:${port}/reset-password.html?token=${token}&email=${encodeURIComponent(email)}`;
    
    await transporter.sendMail({
      from: `"NetDark Support" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Password Reset Request',
      html: `
        <h2>Password Reset</h2>
        <p>You requested a password reset for your NetDark account.</p>
        <p>Click this link to reset your password:</p>
        <a href="${resetUrl}">Reset Password</a>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request this, please ignore this email.</p>
      `
    });

    res.json({ success: true, message: 'Reset link sent to email' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Error processing request' });
  }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;
    
    if (!email || !token || !newPassword) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const record = resetTokens[email];
    
    if (!record || record.token !== token) {
      return res.status(400).json({ error: 'Invalid token' });
    }

    if (record.expires < Date.now()) {
      delete resetTokens[email];
      return res.status(400).json({ error: 'Token expired' });
    }

    if (newPassword.length < 8 || !/[A-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
      return res.status(400).json({ 
        error: 'Password must be at least 8 characters with at least one uppercase letter and one number'
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
    delete resetTokens[email];

    res.json({ success: true, message: 'Password updated successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Error resetting password' });
  }
});

app.post('/api/payments', upload.single('screenshot'), async (req, res) => {
  try {
    const { transaction_id, amount, notes, user_id } = req.body;
    const screenshot = req.file ? req.file.filename : null;

    if (!/^[A-Za-z0-9]{8,20}$/.test(transaction_id)) {
      return res.status(400).json({ error: 'Invalid transaction ID format' });
    }

    const [existing] = await pool.query(
      'SELECT * FROM payments WHERE transaction_id = ?',
      [transaction_id]
    );
    if (existing.length > 0) {
      return res.status(400).json({ error: 'This transaction was already submitted' });
    }

    const [result] = await pool.query(
      `INSERT INTO payments 
       (transaction_id, amount, status, user_id, screenshot, notes)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [transaction_id, amount, 'pending', user_id, screenshot, notes || '']
    );

    const [payment] = await pool.query(`
      SELECT p.*, u.email as user_email 
      FROM payments p
      JOIN users u ON p.user_id = u.id
      WHERE p.id = ?
    `, [result.insertId]);

    io.emit('payment:new', payment[0]);
    res.json({ 
      success: true,
      message: 'Payment submitted for review',
      payment: payment[0]
    });
  } catch (error) {
    console.error('Payment submission error:', error);
    
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File size too large. Maximum 5MB allowed.' });
    }
    
    if (error.message === 'Only image files are allowed!') {
      return res.status(400).json({ error: 'Only image files are allowed!' });
    }
    
    res.status(500).json({ error: 'Payment submission failed' });
  }
});

// Health Check
app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy',
    timestamp: new Date(),
    uptime: process.uptime(),
    database: 'connected',
    socket: io.engine.clientsCount > 0 ? 'connected' : 'disconnected'
  });
});

// Serve HTML files
app.get('*', (req, res) => {
  res.sendFile(path.join(publicPath, 'index.html'));
});

// Error handling
app.use((err, req, res, next) => {
  console.error('❌ Error:', err.stack);
  res.status(500).json({ 
    error: 'Something went wrong!',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Start Server
async function startServer() {
  try {
    // Verify database connection
    const conn = await pool.getConnection();
    console.log('✅ Database connected successfully');
    conn.release();

    // Verify email configuration
    await transporter.verify();
    console.log('✅ Email server is ready');

    // Initialize database schema
    await initializeDatabase();

    // Start listening
    server.listen(port, () => {
      console.log(`🚀 Server running on http://localhost:${port}`);
      console.log(`📁 Serving static files from: ${publicPath}`);
      console.log(`🔒 JWT Secret: ${process.env.JWT_SECRET ? 'Set' : 'Missing!'}`);
      console.log(`📧 Email Service: ${process.env.EMAIL_USER ? 'Configured' : 'Not configured'}`);
      console.log(`👑 Admin Email: ${process.env.ADMIN_EMAIL ? process.env.ADMIN_EMAIL : 'Not configured'}`);
      console.log(`🔌 WebSocket Server: Running on port ${port}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();