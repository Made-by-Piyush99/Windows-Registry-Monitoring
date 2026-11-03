// Vercel Serverless Function: Admin Authentication
export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const cleanPassword = password.trim();

    // Configurable credentials or defaults
    const validEmails = [
      (process.env.ADMIN_EMAIL || 'admin@registrymonitor.com').toLowerCase(),
      'piyush@admin.com',
      'admin@gmail.com',
      'piyush@gmail.com'
    ];
    const validPasswords = [
      process.env.ADMIN_PASSWORD || 'admin123',
      'Piyush@2026',
      'admin'
    ];

    const isEmailValid = validEmails.includes(cleanEmail);
    const isPasswordValid = validPasswords.includes(cleanPassword);

    if (isEmailValid && isPasswordValid) {
      // Create session token
      const token = Buffer.from(`${cleanEmail}:${Date.now()}:regmonitor_admin_secret`).toString('base64');
      return res.status(200).json({
        success: true,
        message: 'Authentication successful',
        token,
        user: {
          email: cleanEmail,
          role: 'Administrator',
          name: 'Piyush (Admin)'
        }
      });
    }

    return res.status(401).json({
      success: false,
      error: 'Invalid email or password. Default is admin@registrymonitor.com / admin123'
    });
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error: ' + err.message });
  }
}
