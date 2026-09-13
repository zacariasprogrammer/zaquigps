.com, // Your Gmail address
    pass: process.env.ubpnsbrkhvdlwart // Your Gmail App Password
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

// Signin Route (with 2FA Verification & IP Security Alert Email)
app.post('/api/auth/signin', async (req, res) => {
  const { email, password, twoFactorCode } = req.body;
  const user = usersDB[email];

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Invalid email or password." });
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
    user.twoFactorSecret = secret.base32; running on port ${PORT}`));
