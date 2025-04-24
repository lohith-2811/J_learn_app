import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { createClient } from '@libsql/client';
import cors from 'cors';

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.FULL_PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection
const db = createClient({
  url: process.env.DATABASE_URL,
  authToken: process.env.DATABASE_AUTH_TOKEN,
});

// Initialize database
async function initDB() {
  try {
    await db.batch([
      {
        sql: `
          CREATE TABLE IF NOT EXISTS user_profiles (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          )
        `,
      },
      {
        sql: `
          CREATE TABLE IF NOT EXISTS user_module_progress (
            user_id INTEGER,
            language VARCHAR(50),
            level INTEGER,
            module_id INTEGER,
            completion_mask BIGINT DEFAULT 0,
            current_lesson_id INTEGER DEFAULT 1,
            current_question_index INTEGER DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, language, level, module_id),
            FOREIGN KEY (user_id) REFERENCES user_profiles(user_id) ON DELETE CASCADE
          )
        `,
      },
      {
        sql: `
          CREATE TABLE IF NOT EXISTS user_achievements (
            user_id INTEGER PRIMARY KEY,
            xp_points INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES user_profiles(user_id) ON DELETE CASCADE
          )
        `,
      },
      {
        sql: `
          CREATE TABLE IF NOT EXISTS lesson_details (
            language VARCHAR(50),
            level INTEGER,
            module_id INTEGER,
            total_lessons INTEGER,
            PRIMARY KEY (language, level, module_id)
          )
        `,
      }
    ]);
    console.log('Database tables created successfully');
  } catch (err) {
    console.error('Failed to create database tables:', err);
    throw err;
  }
}

// Health check endpoint
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    message: 'JLearn Full API is running',
    timestamp: new Date().toISOString()
  });
});

// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization || req.query.token;
  if (authHeader) {
    let token = authHeader;
    if (token.startsWith('Bearer ')) token = token.slice(7);
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        console.error('JWT verification error:', err);
        return res.status(403).json({ error: 'Invalid or expired token' });
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ error: 'Authorization header missing' });
  }
};

// User Registration
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (!email) return res.status(400).json({ error: 'Email is required', field: 'email' });
  if (!username) return res.status(400).json({ error: 'Username is required', field: 'username' });
  if (!password) return res.status(400).json({ error: 'Password is required', field: 'password' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.execute({
      sql: 'INSERT INTO user_profiles (username, email, password_hash) VALUES (?, ?, ?)',
      args: [username, email, hashedPassword],
    });

    const user_id = Number(result.lastInsertRowid);
    await db.execute({
      sql: 'INSERT INTO user_achievements (user_id, xp_points) VALUES (?, ?)',
      args: [user_id, 0],
    });

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: { user_id, username, email }
    });
  } catch (err) {
    console.error('Signup error:', err);
    if (err.message && err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Email already exists', field: 'email' });
    }
    return res.status(500).json({ error: 'Registration failed' });
  }
});

// User Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const result = await db.execute({
      sql: 'SELECT * FROM user_profiles WHERE email = ?',
      args: [email],
    });

    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

    await db.execute({
      sql: 'UPDATE user_profiles SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?',
      args: [user.user_id],
    });

    const token = jwt.sign(
      { id: user.user_id, email: user.email, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    return res.json({
      success: true,
      token,
      user: { id: user.user_id, username: user.username, email: user.email }
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Login failed' });
  }
});

// Progress Tracking Endpoints (Optimized)
app.get('/progress', authenticateJWT, async (req, res) => {
  try {
    const result = await db.execute({
      sql: 'SELECT * FROM user_module_progress WHERE user_id = ?',
      args: [req.user.id],
    });

    res.json({
      success: true,
      progress: result.rows
    });
  } catch (err) {
    console.error('Progress fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch progress' });
  }
});

app.post('/progress', authenticateJWT, async (req, res) => {
  const { language, level, module_id, lesson_id, is_completed, current_question_index } = req.body;

  if (!language || level === undefined || module_id === undefined || lesson_id === undefined) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    // Calculate bitmask update
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
            WHEN excluded.completion_mask = 0 THEN completion_mask & ~?
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
        bitPosition,
        bitPosition
      ],
    });

    res.json({ success: true, message: 'Progress updated successfully' });
  } catch (err) {
    console.error('Progress update error:', err);
    res.status(500).json({ error: 'Failed to update progress' });
  }
});

// Achievements Endpoints
app.get('/achievements', authenticateJWT, async (req, res) => {
  try {
    const result = await db.execute({
      sql: 'SELECT xp_points FROM user_achievements WHERE user_id = ?',
      args: [req.user.id],
    });

    res.json({
      success: true,
      xp_points: result.rows[0]?.xp_points || 0
    });
  } catch (err) {
    console.error('Achievements fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch achievements' });
  }
});

app.post('/achievements/add-xp', authenticateJWT, async (req, res) => {
  const { xp } = req.body;

  if (!xp || isNaN(xp)) {
    return res.status(400).json({ error: 'Valid XP amount required' });
  }

  try {
    await db.execute({
      sql: 'UPDATE user_achievements SET xp_points = xp_points + ? WHERE user_id = ?',
      args: [parseInt(xp), req.user.id],
    });

    res.json({ success: true, message: 'XP added successfully' });
  } catch (err) {
    console.error('XP update error:', err);
    res.status(500).json({ error: 'Failed to add XP' });
  }
});

// Initialize and start server
(async () => {
  try {
    await initDB();
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (err) {
    console.error('Server startup failed:', err);
    process.exit(1);
  }
})();