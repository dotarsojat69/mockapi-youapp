const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt"); // Tambahkan bcrypt
const multer = require("multer");
const upload = multer({ dest: "uploads/" });

const app = express();
const PORT = 8000;
const SECRET_KEY = "your_secret_key_here";
const SALT_ROUNDS = 10; // Jumlah round untuk hashing

app.use(
  cors({
    origin: ["http://localhost:3000", "http://127.0.0.1:3000"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "Access-Control-Allow-Methods",
      "Access-Control-Allow-Origin",
      "Access-Control-Allow-Headers",
    ],
    credentials: true,
  })
);

// Contoh handler OPTIONS untuk Express
app.options("*", (req, res) => {
  res.header("Access-Control-Allow-Origin", "http://localhost:3000");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.sendStatus(200);
});

// Middleware
app.use(bodyParser.json());

// Dummy user database
const users = [];

// Middleware untuk verifikasi token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Validasi input
const validateInput = (username, password, email) => {
  const errors = [];

  // Validasi username
  if (!username || username.length < 6) {
    errors.push("Username must be at least 6 characters long");
  }

  // Validasi password
  if (!password || password.length < 8) {
    errors.push("Password must be at least 8 characters long");
  }

  // Validasi email sederhana
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email)) {
    errors.push("Invalid email format");
  }

  return errors;
};

// Login Endpoint
app.post("/api/login", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    // Cari user berdasarkan username atau email
    const user = users.find(
      (u) =>
        (username && u.username === username) || (email && u.email === email)
    );

    if (user) {
      // Bandingkan password yang di-hash
      const isMatch = await bcrypt.compare(password, user.password);

      if (isMatch) {
        // Generate token
        const token = jwt.sign({ username: user.username }, SECRET_KEY, {
          expiresIn: "1h",
        });

        res.json({
          message: "Login successful",
          token: token,
        });
      } else {
        res.status(401).json({ message: "Invalid credentials" });
      }
    } else {
      res.status(401).json({ message: "User not found" });
    }
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Register Endpoint
app.post("/api/register", async (req, res) => {
  const { username, password, email } = req.body;

  // Validasi input
  const validationErrors = validateInput(username, password, email);
  if (validationErrors.length > 0) {
    return res.status(400).json({
      message: "Validation failed",
      errors: validationErrors,
    });
  }

  try {
    // Cek apakah username sudah ada
    if (users.some((u) => u.username === username)) {
      return res.status(400).json({ message: "Username already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Tambah user baru
    const newUser = {
      username,
      password: hashedPassword,
      email,
      profile: {},
      createdAt: new Date(),
    };
    users.push(newUser);

    res.status(201).json({
      message: "Registration successful",
      user: { username, email },
    });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Registration failed", error: error.message });
  }
});

// Get Profile Endpoint
app.get("/api/profile", authenticateToken, (req, res) => {
  const user = users.find((u) => u.username === req.user.username);

  if (user) {
    // Exclude sensitive information
    const { password, ...safeUserData } = user;

    res.json({
      username: safeUserData.username,
      email: safeUserData.email,
      profile: safeUserData.profile || {},
      createdAt: safeUserData.createdAt,
    });
  } else {
    res.status(404).json({ message: "User not found" });
  }
});

app.put(
  "/api/profile",
  authenticateToken,
  upload.single("profilePicture"),
  (req, res) => {
    const { username } = req.user;
    const updateData = req.body;

    const userIndex = users.findIndex((u) => u.username === username);

    if (userIndex !== -1) {
      // Proses birthday untuk menghitung horoscope dan zodiak
      if (updateData.birthday) {
        const birthday = new Date(updateData.birthday);
        updateData.horoscope = calculateHoroscope(birthday);
        updateData.zodiac = calculateZodiac(birthday);
      }

      // Update profil
      users[userIndex].profile = {
        ...users[userIndex].profile,
        ...updateData,
      };

      // Jika ada gambar yang di-upload, simpan path-nya
      if (req.file) {
        users[userIndex].profile.profilePicture = req.file.path; // Simpan path gambar
      }

      res.json({
        message: "Profile updated successfully",
        profile: users[userIndex].profile,
      });
    } else {
      res.status(404).json({ message: "User  not found" });
    }
  }
);

app.post("/api/logout", authenticateToken, (req, res) => {
  res.json({
    message: "Logout successful",
  });
});

// Jalankan server
app.listen(PORT, () => {
  console.log(`Mock API berjalan di http://localhost:${PORT}`);
});
