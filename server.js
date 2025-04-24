import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { initDB, getDB } from './db.js';
import cors from 'cors';

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.FULL_PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// In production, use Redis instead of in-memory Set
const activeTokens = new Set();

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health check endpoint
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    message: 'JLearn API with persistent sessions',
    timestamp: new Date().toISOString()
  });
});

// Initialize database
(async () => {
  try {
    await initDB();
    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database initialization failed:', err);
    process.exit(1);
  }
})();

// Enhanced Authentication Middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization || req.query.token;
  
  if (!authHeader) {
    return res.status(401).json({ error: 'Authorization header missing' });
  }

  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;

  // Check if token was invalidated
  if (!activeTokens.has(token)) {
    return res.status(403).json({ error: 'Session terminated. Please login again.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({ error: 'Invalid or malformed token' });
    }
    req.user = user;
    next();
  });
};

// User Registration
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (!email || !username || !password) {
    return res.status(400).json({ 
      error: 'All fields are required',
      fields: { email: !email, username: !username, password: !password }
    });
  }

  try {
    const db = getDB();
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await db.execute({
      sql: 'INSERT INTO user_profiles (username, email, password_hash) VALUES (?, ?, ?)',
      args: [username, email, hashedPassword],
    });

    const userId = Number(result.lastInsertRowid);

    await db.execute({
      sql: 'INSERT INTO user_achievements (user_id, xp_points) VALUES (?, ?)',
      args: [userId, 0],
    });

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: { userId, username, email }
    });
  } catch (err) {
    console.error('Signup error:', err);
    if (err.message?.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Email already exists' });
    }
    return res.status(500).json({ error: 'Registration failed' });
  }
});

// Login with persistent token
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT user_id, username, email, password_hash FROM user_profiles WHERE email = ?',
      args: [email],
    });

    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    await db.execute({
      sql: 'UPDATE user_profiles SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?',
      args: [user.user_id],
    });

    // Generate token with NO expiration
    const token = jwt.sign(
      {
        id: user.user_id,
        email: user.email,
        username: user.username
      },
      JWT_SECRET
      // No expiresIn parameter
    );

    // Add to active tokens
    activeTokens.add(token);

    return res.json({
      success: true,
      message: 'Login successful - persistent session',
      token,
      user: {
        id: user.user_id,
        username: user.username,
        email: user.email
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Login failed' });
  }
});

// Explicit logout endpoint
app.post('/logout', authenticateJWT, (req, res) => {
  const token = req.headers.authorization.slice(7);
  
  // Remove token from active set
  activeTokens.delete(token);
  
  res.json({ 
    success: true,
    message: 'Logged out successfully. Token invalidated.' 
  });
});

// Emergency token invalidation (for app uninstall/data clear)
app.post('/invalidate-all', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT user_id FROM user_profiles WHERE email = ?',
      args: [email],
    });

    const user = result.rows[0];
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify password
    const pwResult = await db.execute({
      sql: 'SELECT password_hash FROM user_profiles WHERE user_id = ?',
      args: [user.user_id],
    });

    const isMatch = await bcrypt.compare(password, pwResult.rows[0].password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // In production: Query all tokens for this user from Redis/db and remove
    // Here we simply clear all tokens (simplified for example)
    activeTokens.clear();

    res.json({ 
      success: true,
      message: 'All sessions invalidated successfully' 
    });
  } catch (err) {
    console.error('Invalidation error:', err);
    res.status(500).json({ error: 'Session invalidation failed' });
  }
});

// Protected progress update endpoint
app.post('/progress', authenticateJWT, async (req, res) => {
  const { language, level, module_id, lesson_id, is_completed, current_question_index } = req.body;

  if (!language || level === undefined || module_id === undefined || lesson_id === undefined) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const db = getDB();
    const bitPosition = 1 << (lesson_id - 1);
    const maskUpdate = is_completed ? bitPosition : 0;

    await db.execute({
      sql: `
        INSERT INTO user_module_progress 
          (user_id, language, level, module_id, completion_mask, 
           current_lesson_id, current_question_index)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id, language, level, module_id) 
        DO UPDATE SET
          completion_mask = CASE 
            WHEN ? = 0 THEN completion_mask & ~?
            ELSE completion_mask | ?
          END,
          current_lesson_id = excluded.current_lesson_id,
          current_question_index = excluded.current_question_index,
          last_updated = CURRENT_TIMESTAMP
      `,
      args: [
        req.user.id,
        language,
        level,
        module_id,
        maskUpdate,
        lesson_id,
        current_question_index || 0,
        maskUpdate,
        bitPosition,
        bitPosition
      ],
    });

    res.json({ 
      success: true,
      message: 'Progress updated successfully' 
    });
  } catch (err) {
    console.error('Progress update error:', err);
    res.status(500).json({ error: 'Failed to update progress' });
  }
});

// Get user profile
app.get('/profile', authenticateJWT, async (req, res) => {
  try {
    const db = getDB();
    const result = await db.execute({
      sql: 'SELECT user_id, username, email, created_at, last_login FROM user_profiles WHERE user_id = ?',
      args: [req.user.id],
    });

    res.json({
      success: true,
      profile: result.rows[0]
    });
  } catch (err) {
    console.error('Profile fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
