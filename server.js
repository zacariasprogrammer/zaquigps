const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

const app = express();
app.use(express.json());

// Enable CORS for your ZaquiGPS frontend
app.use(cors({
  origin: '*', // Replace '*' with your actual GitHub Pages / frontend domain in production
  methods: ['GET', 'POST']
}));

const JWT_SECRET = process.env.JWT_SECRET || "zaquigps_super_secret_key";
const PORT = process.env.PORT || 10000; // Render automatically sets process.env.PORT

// Mock User Database (In production, connect to a free MongoDB Atlas or Supabase PostgreSQL instance)
const usersDB = {};

// Anti-Hack / Anti-Brute Force Rate Limiter
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Max 5 requests per IP per 15 minutes on auth routes
  message: { message: "Too many login/signup attempts. Rate limit triggered for security. Try again in 15 minutes." }
});

app.use('/api/auth/', authLimiter);

// Healthcheck route
app.get('/', (req, res) => {
  res.send('ZaquiGPS Auth Server is Running!');
});

// Signup Route
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 8) {
    return res.status(400).json({ message: "Password must be at least 8 characters long." });
  }

  if (usersDB[email]) {
    return res.status(400).json({ message: "Account already exists." });
  }

  const hashedPassword = await bcrypt.hash(password, 12);
  usersDB[email] = { email, password: hashedPassword, twoFactorSecret: null, twoFactorEnabled: false };

  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1h' });
  res.status(201).json({ token, user: { email, twoFactorEnabled: false } });
});

// Signin Route (with 2FA Verification)
app.post('/api/auth/signin', async (req, res) => {
  const { email, password, twoFactorCode } = req.body;
  const user = usersDB[email];

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Invalid email or password." });
  }

  if (user.twoFactorEnabled) {
    if (!twoFactorCode) {
      return res.status(401).json({ requires2FA: true, message: "2FA code required." });
    }
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: twoFactorCode
    });
    if (!verified) {
      return res.status(401).json({ message: "Invalid 2FA authentication code." });
    }
  }

  const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, user: { email: user.email, twoFactorEnabled: user.twoFactorEnabled } });
});

// Setup 2FA
app.post('/api/auth/setup-2fa', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = usersDB[decoded.email];

    const secret = speakeasy.generateSecret({ name: `ZaquiGPS (${user.email})` });
    user.twoFactorSecret = secret.base32;
    user.twoFactorEnabled = true;

    res.json({ secret: secret.base32, otpauth_url: secret.otpauth_url });
  } catch (err) {
    res.status(401).json({ message: "Invalid or expired token." });
  }
});

app.listen(PORT, () => console.log(`ZaquiGPS Auth Server running on port ${PORT}`));
