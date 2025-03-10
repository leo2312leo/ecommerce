const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors()); // Allow frontend requests
app.use(express.json()); // Parse JSON body

const SECRET_KEY = "your_secret_key"; // Change this to a strong secret

// Create MySQL Connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'new_password', // Use the new password
  database: 'mydatabase'
});

db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err);
  } else {
    console.log("Connected to MySQL database");
  }
});

// User Signup
app.post("/signup", async (req, res) => {
    const { username, email, password } = req.body;

    // Check if email already exists
    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
        if (err) return res.status(500).send(err);

        if (results.length > 0) {
            return res.status(400).json({ message: "Email already exists" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [username, email, hashedPassword],
            (err, result) => {
                if (err) return res.status(500).send(err);
                res.json({ message: "User registered successfully", userId: result.insertId });
            }
        );
    });
});

// User Login
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
        if (err) return res.status(500).send(err);

        if (results.length === 0) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        const user = results[0];

        // Compare passwords
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: "Invalid email or password" });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });

        res.json({ message: "Login successful", token });
    });
});

// Get User Profile (Protected Route)
app.get("/profile", (req, res) => {
    const { userId } = req.query;
    
    db.query("SELECT id, name, email FROM users WHERE id = ?", [userId], (err, results) => {
        if (err) return res.status(500).send(err);
        if (results.length === 0) return res.status(404).json({ message: "User not found" });
        
        res.json(results[0]);
    });
});
const PORT = process.env.PORT || 6000; // Change 5000 to 6000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});



