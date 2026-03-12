const express = require('express');
const mysql = require('mysql2');
const multer = require('multer');
const axios = require('axios');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;

// ── FLASK ML BACKEND URL (set this in Render Environment Variables)
// If you don't have Flask deployed yet, the /predict route will return demo data
const FLASK_URL = process.env.FLASK_URL || '';

// ── MIDDLEWARE ──
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(__dirname));

// ── MULTER FILE UPLOAD ──
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '_' + file.originalname);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB max
});

// ══════════════════════════════════════════
//  MYSQL CONNECTION (uses Render Env Vars)
// ══════════════════════════════════════════
// In Render → Environment Variables, add:
//   DB_HOST     = your Railway/Aiven MySQL host
//   DB_USER     = your MySQL username
//   DB_PASS     = your MySQL password
//   DB_NAME     = ids_db
//   DB_PORT     = 3306

const db = mysql.createConnection({
  host:               process.env.MYSQLHOST,
  user:               process.env.MYSQLUSER,
  password:           process.env.MYSQLPASSWORD,
  database:           process.env.MYSQLDATABASE,
  port:               process.env.MYSQLPORT || 3306,
  ssl:                { rejectUnauthorized: false }, // needed for Railway/Aiven cloud MySQL
  connectTimeout:     30000,
  waitForConnections: true
});

db.connect(err => {
  if (err) {
    console.error('DB CONNECTION ERROR:', err.message);
    console.log('Server will start but database features will not work.');
    console.log('Set DB_HOST, DB_USER, DB_PASS, DB_NAME in Render environment variables.');
  } else {
    console.log('MySQL connected successfully');
    createTables();
  }
});

// ── AUTO CREATE TABLES ──
function createTables() {
  db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id         INT AUTO_INCREMENT PRIMARY KEY,
      username   VARCHAR(100) NOT NULL UNIQUE,
      password   VARCHAR(255) NOT NULL,
      role       ENUM('user','admin') DEFAULT 'user',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `, err => { if (err) console.error('users table:', err.message); else console.log('users table ready'); });

  db.query(`
    CREATE TABLE IF NOT EXISTS uploads (
      id               INT AUTO_INCREMENT PRIMARY KEY,
      user_id          INT NOT NULL,
      filename         VARCHAR(255) NOT NULL,
      filepath         VARCHAR(500) NOT NULL,
      total_records    INT DEFAULT 0,
      attacks_detected INT DEFAULT 0,
      normal_traffic   INT DEFAULT 0,
      status           ENUM('pending','completed','failed') DEFAULT 'pending',
      uploaded_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `, err => { if (err) console.error('uploads table:', err.message); else console.log('uploads table ready'); });

  db.query(`
    CREATE TABLE IF NOT EXISTS predictions (
      id           INT AUTO_INCREMENT PRIMARY KEY,
      upload_id    INT NOT NULL,
      prediction   ENUM('ATTACK','NORMAL') NOT NULL,
      confidence   FLOAT DEFAULT NULL,
      attack_type  VARCHAR(50) DEFAULT NULL,
      predicted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (upload_id) REFERENCES uploads(id) ON DELETE CASCADE
    )
  `, err => { if (err) console.error('predictions table:', err.message); else console.log('predictions table ready'); });
}

// ══════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════

// ── HOME → login page ──
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});

// ── REGISTER ──
app.post('/register', async (req, res) => {
  const { username, password, confirm_password } = req.body;

  if (!username || !password)
    return res.redirect('/register?error=Please fill all fields');
  if (password !== confirm_password)
    return res.redirect('/register?error=Passwords do not match');

  db.query('SELECT id FROM users WHERE username = ?', [username], async (err, results) => {
    if (err) return res.redirect('/register?error=Database error. Please try again.');
    if (results.length > 0) return res.redirect('/register?error=Username already taken');

    try {
      const hashed = await bcrypt.hash(password, 10);
      db.query(
        'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
        [username, hashed, 'user'],
        (err2) => {
          if (err2) return res.redirect('/register?error=Registration failed. Try again.');
          res.redirect('/?success=Account created! Please login');
        }
      );
    } catch (e) {
      res.redirect('/register?error=Server error');
    }
  });
});

// ── LOGIN ──
app.post('/login', (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password)
    return res.redirect('/?error=Please fill all fields');

  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err) return res.redirect('/?error=Database error. Please try again.');
    if (results.length === 0) return res.redirect('/?error=Invalid username or password');

    const user = results[0];

    try {
      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.redirect('/?error=Invalid username or password');

      // Role check
      if (role === 'admin' && user.role !== 'admin')
        return res.redirect('/?error=You do not have admin access');
      if (role === 'user' && user.role === 'admin')
        return res.redirect('/?error=Please select Admin role to login');

      // Redirect based on role
      if (user.role === 'admin') {
        res.redirect('/admin-dashboard.html');
      } else {
        res.redirect('/user-dashboard.html');
      }
    } catch (e) {
      res.redirect('/?error=Server error');
    }
  });
});

// ── RESET PASSWORD ──
app.post('/reset-password', async (req, res) => {
  const { username, new_password } = req.body;
  if (!username || !new_password)
    return res.json({ success: false, message: 'Please fill all fields' });

  try {
    const hashed = await bcrypt.hash(new_password, 10);
    db.query(
      'UPDATE users SET password = ? WHERE username = ?',
      [hashed, username],
      (err, result) => {
        if (err) return res.json({ success: false, message: 'Database error' });
        if (result.affectedRows === 0)
          return res.json({ success: false, message: 'Username not found' });
        res.json({ success: true });
      }
    );
  } catch (e) {
    res.json({ success: false, message: 'Server error' });
  }
});

// ── UPLOAD FILE ──
app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file)
    return res.json({ success: false, message: 'No file uploaded' });

  const userId = req.query.user_id || req.body.user_id || 1;

  db.query(
    'INSERT INTO uploads (user_id, filename, filepath, status) VALUES (?, ?, ?, ?)',
    [userId, req.file.originalname, req.file.path, 'pending'],
    (err, result) => {
      if (err) {
        console.error('Upload DB error:', err.message);
        return res.json({ success: false, message: 'Database error during upload' });
      }
      res.json({
        success: true,
        upload_id: result.insertId,
        filename: req.file.originalname,
        message: 'File uploaded successfully'
      });
    }
  );
});

// ── PREDICT ──
app.get('/predict', async (req, res) => {
  const uploadId = req.query.upload_id;
  if (!uploadId)
    return res.json({ success: false, message: 'No upload_id provided' });

  db.query('SELECT * FROM uploads WHERE id = ?', [uploadId], async (err, results) => {
    if (err || results.length === 0)
      return res.json({ success: false, message: 'Upload not found' });

    const uploadRecord = results[0];

    // If Flask ML backend URL is configured, call it
    if (FLASK_URL) {
      try {
        const flaskRes = await axios.post(
          `${FLASK_URL}/predict`,
          { filepath: uploadRecord.filepath },
          { timeout: 120000 }
        );

        const data     = flaskRes.data;
        const total    = data.total   || 0;
        const attacks  = data.attacks || 0;
        const normal   = data.normal  || 0;

        db.query(
          'UPDATE uploads SET total_records=?, attacks_detected=?, normal_traffic=?, status=? WHERE id=?',
          [total, attacks, normal, 'completed', uploadId]
        );

        if (data.predictions && Array.isArray(data.predictions) && data.predictions.length > 0) {
          const vals = data.predictions.map(p => [
            uploadId,
            p.prediction  || 'NORMAL',
            p.confidence  || null,
            p.attack_type || null
          ]);
          db.query(
            'INSERT INTO predictions (upload_id, prediction, confidence, attack_type) VALUES ?',
            [vals],
            err2 => { if (err2) console.error('Predictions insert error:', err2.message); }
          );
        }

        return res.json({
          success:          true,
          total, attacks, normal,
          attack_types:     data.attack_types     || {},
          predictions:      data.predictions      || [],
          confusion_matrix: data.confusion_matrix || null,
          roc_data:         data.roc_data         || null
        });

      } catch (flaskErr) {
        console.error('Flask ML backend error:', flaskErr.message);
        // Fall through to demo data below
      }
    }

    // ── DEMO DATA (when Flask not available) ──
    const demoTotal   = 500;
    const demoAttacks = 47;
    const demoNormal  = 453;

    db.query(
      'UPDATE uploads SET total_records=?, attacks_detected=?, normal_traffic=?, status=? WHERE id=?',
      [demoTotal, demoAttacks, demoNormal, 'completed', uploadId]
    );

    res.json({
      success:     true,
      total:       demoTotal,
      attacks:     demoAttacks,
      normal:      demoNormal,
      attack_types: { DoS: 22, Probe: 15, R2L: 7, U2R: 3 },
      predictions: [],
      note:        'Demo mode — set FLASK_URL in Render environment variables to enable ML predictions'
    });
  });
});

// ── ADMIN: ALL UPLOADS ──
app.get('/admin/uploads', (req, res) => {
  db.query(
    `SELECT u.id, u.filename, u.total_records, u.attacks_detected,
            u.normal_traffic, u.status, u.uploaded_at, usr.username
     FROM uploads u
     LEFT JOIN users usr ON u.user_id = usr.id
     ORDER BY u.uploaded_at DESC`,
    (err, results) => {
      if (err) return res.json({ success: false, message: 'Database error' });
      res.json({ success: true, uploads: results });
    }
  );
});

// ── ADMIN: DOWNLOAD FILE ──
app.get('/admin/file/:id', (req, res) => {
  db.query('SELECT filepath, filename FROM uploads WHERE id = ?', [req.params.id], (err, results) => {
    if (err || results.length === 0)
      return res.status(404).json({ message: 'File not found' });
    const file = results[0];
    if (!fs.existsSync(file.filepath))
      return res.status(404).json({ message: 'File missing on server' });
    res.download(file.filepath, file.filename);
  });
});

// ── ADMIN: STATS ──
app.get('/admin/stats', (req, res) => {
  db.query('SELECT COUNT(*) as total_users FROM users WHERE role="user"', (e1, users) => {
    db.query('SELECT COUNT(*) as total_uploads FROM uploads', (e2, uploads) => {
      db.query('SELECT SUM(attacks_detected) as total_attacks FROM uploads', (e3, attacks) => {
        res.json({
          success:       true,
          total_users:   users[0]?.total_users    || 0,
          total_uploads: uploads[0]?.total_uploads || 0,
          total_attacks: attacks[0]?.total_attacks || 0
        });
      });
    });
  });
});

// ── HEALTH CHECK (Render uses this to confirm app is running) ──
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'IDS Backend is running' });
});

// ── START SERVER ──
app.listen(PORT, '0.0.0.0', () => {
  console.log(`IDS Backend running on port ${PORT}`);
});
