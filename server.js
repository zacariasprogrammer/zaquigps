const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const nodemailer = require('nodemailer');
const axios = require('axios');
const crypto = require('crypto');

const app = express();

// Trust reverse proxy for Render environment (fixes rate-limiter & IP lookup issues)
app.set('trust proxy', 1);

app.use(express.json());

// Enable CORS for your ZaquiGPS frontend
app.use(cors({
  origin: '*', // Replace '*' with your actual GitHub Pages / frontend domain in production
  methods: ['GET', 'POST']
}));

const JWT_SECRET = process.env.JWT_SECRET || "zaquigps_super_secret_key";
const PORT = process.env.PORT || 10000; // Render automatically sets process.env.PORT

// Mock User Database
const usersDB = {};

// Nodemailer Transporter Configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER, // Your Gmail address
    pass: process.env.EMAIL_PASS  // Your Gmail App Password
  }
});

// Helper function to resolve location and dispatch security alert email
async function sendSecurityAlertEmail(userEmail, clientIp) {
  let locationStr = "Unknown Location";
  try {
    // Resolve IP geolocation using ip-api.com
    const geoRes = await axios.get(`http://ip-api.com/json/${clientIp}`);
    if (geoRes.data && geoRes.data.status === 'success') {
      locationStr = `${geoRes.data.city}, ${geoRes.data.regionName}, ${geoRes.data.country}`;
    }
  } catch (err) {
    console.error("IP Geolocation lookup failed:", err.message);
  }

  const alertEmailOptions = {
    from: '"ZaquiGPS Security" <no-reply@zaquigps.com>',
    to: userEmail,
    subject: '⚠️ Security Alert: New Login to Your ZaquiGPS Account',
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0a0a0c; color: #ffffff; padding: 24px; border-radius: 16px;">
        <h2 style="color: #00d2ff; margin-bottom: 16px;">ZaquiGPS Security Alert</h2>
        <p style="font-size: 15px; color: #e5e5ea;">A new sign-in attempt was detected on your account.</p>
        
        <div style="background-color: #1c1c1e; padding: 16px; border-radius: 12px; margin: 20px 0; border: 1px solid rgba(255,255,255,0.1);">
          <p style="margin: 6px 0; font-size: 14px;"><strong>IP Address:</strong> <span style="color: #30d158;">${clientIp}</span></p>
          <p style="margin: 6px 0; font-size: 14px;"><strong>Location:</strong> <span style="color: #ff9f0a;">${locationStr}</span></p>
          <p style="margin: 6px 0; font-size: 14px;"><strong>Time:</strong> ${new Date().toUTCString()}</p>
        </div>

        <p style="font-size: 13px; color: #8e8e93;">If this was you, no action is needed. If you did not log in, someone may have compromised your password!</p>
      </div>
    `
  };

  try {
    await transporter.sendMail(alertEmailOptions);
  } catch (err) {
    console.error("Failed to send security alert email:", err.message);
  }
}

// Send an email-verification link to a new user (Gmail SMTP)
async function sendVerificationEmail(userEmail, token) {
  const verifyUrl = `${process.env.BACKEND_URL || 'https://zaquigps.onrender.com'}/api/auth/verify-email?token=${token}`;
  const mailOptions = {
    from: `"ZaquiGPS" <${process.env.EMAIL_USER}>`,
    to: userEmail,
    subject: 'Verify your ZaquiGPS account',
    text: `Welcome to ZaquiGPS! Tap this link to verify your email and activate your account:\n${verifyUrl}\n\nThis link expires in 24 hours.`,
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0a0a0c; color: #ffffff; padding: 24px; border-radius: 16px;">
        <h2 style="color: #00d2ff; margin-bottom: 16px;">\u{1F9ED} Verify your email</h2>
        <p style="font-size: 15px; color: #e5e5ea;">Welcome to ZaquiGPS! Tap the button below to verify your email and activate your account.</p>
        <a href="${verifyUrl}" style="display: inline-block; margin: 20px 0; padding: 14px 28px; background-color: #00d2ff; color: #0a0a0c; font-weight: bold; font-size: 16px; text-decoration: none; border-radius: 12px;">Verify Email</a>
        <p style="font-size: 13px; color: #8e8e93;">This link expires in 24 hours. If you didn't create this account, you can ignore this email.</p>
      </div>
    `
  };
  await transporter.sendMail(mailOptions);
}

// Styled HTML page shown when the verification link is opened
function verifyPage(ok) {
  const title = ok ? 'Email verified!' : 'Link invalid or expired';
  const msg = ok
    ? 'Your ZaquiGPS account is now active. You can sign in on the app.'
    : 'This verification link is invalid or has expired. Try creating your account again to get a fresh link.';
  const color = ok ? '#30d158' : '#ff453a';
  const emoji = ok ? '\u{2705}' : '\u{26A0}\uFE0F';
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title} — ZaquiGPS</title></head>
<body style="margin:0;background:#0a0a0c;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;">
<div style="text-align:center;padding:32px;max-width:420px;">
<div style="font-size:56px;">${emoji}</div>
<h1 style="color:${color};">${title}</h1>
<p style="color:#e5e5ea;font-size:16px;">${msg}</p>
</div></body></html>`;
}

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

// Signup Route (with email verification)
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 8) {
    return res.status(400).json({ message: "Password must be at least 8 characters long." });
  }

  if (usersDB[email]) {
    const existing = usersDB[email];
    if (existing.verified) {
      return res.status(400).json({ message: "Account already exists." });
    }
    // Unverified account: refresh the token and resend the email instead of erroring
    existing.verifyToken = crypto.randomBytes(32).toString('hex');
    existing.verifyExpires = Date.now() + 24 * 60 * 60 * 1000;
    try {
      await sendVerificationEmail(email, existing.verifyToken);
    } catch (err) {
      console.error("Verification email failed:", err.message);
    }
    return res.status(200).json({ message: "Verification email resent. Check your inbox.", user: { email, verified: false } });
  }

  const hashedPassword = await bcrypt.hash(password, 12);
  const verifyToken = crypto.randomBytes(32).toString('hex');
  usersDB[email] = {
    email, password: hashedPassword,
    twoFactorSecret: null, twoFactorEnabled: false,
    verified: false, verifyToken,
    verifyExpires: Date.now() + 24 * 60 * 60 * 1000 // 24 hours
  };

  try {
    await sendVerificationEmail(email, verifyToken);
  } catch (err) {
    console.error("Verification email failed:", err.message);
    // Don't fail signup if the email fails — the user can trigger a resend
  }

  // No JWT yet — signin stays locked until the email is verified
  res.status(201).json({ message: "Account created! Check your email for a verification link.", user: { email, verified: false } });
});

// Email verification — the link in the signup email lands here
app.get('/api/auth/verify-email', (req, res) => {
  const { token } = req.query;
  const user = token ? Object.values(usersDB).find(u => u.verifyToken === token) : null;
  if (!user || Date.now() > user.verifyExpires) {
    return res.status(400).send(verifyPage(false));
  }
  user.verified = true;
  user.verifyToken = null;
  user.verifyExpires = null;
  res.send(verifyPage(true));
});

// Signin Route (with 2FA Verification & IP Security Alert Email)
app.post('/api/auth/signin', async (req, res) => {
  const { email, password, twoFactorCode } = req.body;
  const user = usersDB[email];

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Invalid email or password." });
  }

  if (!user.verified) {
    return res.status(403).json({ message: "Please verify your email first. Check your inbox for the link." });
  }

  // Extract client IP address (handles Render reverse proxies)
  const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();

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

  // Dispatch background security alert email with IP & Location info
  sendSecurityAlertEmail(user.email, clientIp);

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

// Rate limiter for the public route-alert email endpoint (prevents abuse)
const emailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Max 10 route-alert emails per IP per hour
  message: { message: "Too many email requests. Try again later." }
});

// Route-saved email alert (Gmail SMTP).
// The recipient is fixed server-side via ALERT_EMAIL_TO (falls back to EMAIL_USER)
// and is NEVER taken from the client, so this endpoint can't be abused as an open relay.
app.post('/api/send-email', emailLimiter, async (req, res) => {
  const clean = (v) => (typeof v === 'string' ? v.slice(0, 200) : '');
  const title = clean(req.body && req.body.routeTitle);
  const dist = clean(req.body && req.body.routeDist);
  const time = clean(req.body && req.body.routeTime);
  if (!title) return res.status(400).json({ message: "routeTitle is required." });

  const mailOptions = {
    from: `"ZaquiGPS" <${process.env.EMAIL_USER}>`,
    to: process.env.ALERT_EMAIL_TO || process.env.EMAIL_USER,
    subject: 'ZaquiGPS Alert: Route saved to vault!',
    text: `ZaquiGPS Alert: Route saved to vault!\nDestination: ${title}\nDistance: ${dist}\nTime: ${time}`,
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0a0a0c; color: #ffffff; padding: 24px; border-radius: 16px;">
        <h2 style="color: #00d2ff; margin-bottom: 16px;">\u{1F9ED} Route saved to vault!</h2>
        <div style="background-color: #1c1c1e; padding: 16px; border-radius: 12px; margin: 20px 0; border: 1px solid rgba(255,255,255,0.1);">
          <p style="margin: 6px 0; font-size: 14px;"><strong>Destination:</strong> <span style="color: #30d158;">${title}</span></p>
          <p style="margin: 6px 0; font-size: 14px;"><strong>Distance:</strong> <span style="color: #ff9f0a;">${dist}</span></p>
          <p style="margin: 6px 0; font-size: 14px;"><strong>Time:</strong> <span style="color: #ff9f0a;">${time}</span></p>
        </div>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ ok: true });
  } catch (err) {
    console.error("Route alert email failed:", err.message);
    res.status(500).json({ message: "Email failed to send." });
  }
});

// Resend the verification email (rate-limited like the route alerts)
app.post('/api/auth/resend-verification', emailLimiter, async (req, res) => {
  const { email } = req.body || {};
  const user = usersDB[email];
  if (!user) return res.status(404).json({ message: "Account not found." });
  if (user.verified) return res.status(400).json({ message: "Email already verified." });

  user.verifyToken = crypto.randomBytes(32).toString('hex');
  user.verifyExpires = Date.now() + 24 * 60 * 60 * 1000;
  try {
    await sendVerificationEmail(user.email, user.verifyToken);
    res.json({ message: "Verification email resent. Check your inbox." });
  } catch (err) {
    console.error("Resend verification failed:", err.message);
    res.status(500).json({ message: "Failed to send verification email." });
  }
});

// Bind to host 0.0.0.0 for Render host routing
app.listen(PORT, '0.0.0.0', () => console.log(`ZaquiGPS Auth Server running on port ${PORT}`));
