const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const multer = require("multer");
const fs = require("fs");
const axios = require("axios");
const nodemailer = require("nodemailer");
const FormData = require("form-data");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("frontend"));

/* ================= DATABASE ================= */
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "Aditya@8",   // 🔴 change if needed
  database: "ids_db"
});

db.connect(err => {
  if (err) {
    console.error("❌ DB ERROR:", err);
    process.exit(1);
  }
  console.log("✅ MySQL Connected");
});

/* ================= EMAIL (GMAIL SMTP) ================= */
/*
IMPORTANT:
1. Enable 2-Step Verification in Gmail
2. Generate App Password
3. Use App Password here (NOT Gmail password)
*/
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "cutebabu248@gmail.com",   // 🔴 sender gmail
    pass: "Babbu@123#"               // 🔴 gmail app password
  }
});

/* ================= UPLOAD (MULTER) ================= */
if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");

const storage = multer.diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) =>
    cb(null, Date.now() + "_" + file.originalname)
});

const upload = multer({ storage });

/* ================= ROUTES ================= */

/* 🔐 LOGIN */
app.post("/login", (req, res) => {
  const users = [
    { username: "admin", password: "admin123", role: "admin" },
    { username: "user", password: "user123", role: "user" }
  ];

  const user = users.find(
    u => u.username === req.body.username && u.password === req.body.password
  );

  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  res.json(user);
});

/* 📤 USER UPLOAD */
app.post("/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const username = req.body.username || "user";

    /* 1️⃣ Save upload in DB */
    db.query(
      "INSERT INTO uploads (username, filename, status, uploaded_at) VALUES (?, ?, 'Pending', NOW())",
      [username, req.file.filename]
    );

    /* 2️⃣ EMAIL NOTIFICATION */
    // await transporter.sendMail({
    //   from: `"IDS Alert" <cutebabu248@gmail.com>`,
    //   to: "asuribabu789l@gmail.com",   // 🔴 admin email
    //   subject: "🚨 IDS Alert – New File Uploaded",
    //   html: `
    //     <h3>New Dataset Uploaded</h3>
    //     <p><b>User:</b> ${username}</p>
    //     <p><b>File:</b> ${req.file.filename}</p>
    //     <p>Status: <b>Pending Analysis</b></p>
    //   `
    // });

    /* 3️⃣ SEND FILE TO FLASK */
    const formData = new FormData();
    formData.append("file", fs.createReadStream(req.file.path));

    await axios.post("http://localhost:5001/upload", formData, {
      headers: formData.getHeaders(),
      timeout: 20000
    });

    res.json({ message: "File uploaded & notification sent" });

  } catch (err) {
    console.error("UPLOAD ERROR:", err.message);
    res.status(500).json({ error: "Upload failed" });
  }
});

/* 📁 ADMIN – FETCH ALL UPLOADS */
app.get("/admin/uploads", (req, res) => {
  db.query(
    `SELECT id, username, filename, prediction, confidence, status, uploaded_at
     FROM uploads
     ORDER BY uploaded_at DESC`,
    (err, rows) => {
      if (err) {
        console.error("ADMIN UPLOADS ERROR:", err);
        return res.json([]);
      }
      res.json(rows);
    }
  );
});

/* 👁️ ADMIN – VIEW FILE + RUN PREDICTION */
app.get("/admin/file/:id", async (req, res) => {
  try {
    const flaskRes = await axios.get("http://localhost:5001/predict", {
      timeout: 20000
    });

    const data = flaskRes.data;

    const prediction =
      data.attacks_detected > data.normal_detected ? "Attack" : "Normal";

    const confidence = data.attacks_detected / data.total_records;

    db.query(
      "UPDATE uploads SET prediction=?, confidence=?, status='Analyzed' WHERE id=?",
      [prediction, confidence, req.params.id]
    );

    res.json({ prediction, confidence });

  } catch (err) {
    console.error("ADMIN VIEW ERROR:", err.message);
    res.status(500).json({ error: "Prediction unavailable" });
  }
});

/* 🔍 USER DASHBOARD – RUN DETECTION */
app.get("/predict", async (req, res) => {
  try {
    const response = await axios.get("http://localhost:5001/predict", {
      timeout: 20000
    });
    res.json(response.data);
  } catch (err) {
    console.error("PREDICT ERROR:", err.message);
    res.status(500).json({ error: "Prediction failed" });
  }
});

/* ================= START ================= */
app.listen(5000, () => {
  console.log("🚀 IDS Backend running on http://localhost:5000");
});
