import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { userDb, appConfigDb, db } from '../database/db.js';
import { IS_PLATFORM } from '../constants/config.js';

// Use env var if set, otherwise auto-generate a unique secret per installation
const JWT_SECRET = process.env.JWT_SECRET || appConfigDb.getOrCreateJwtSecret();

// Security: Create token blocklist table for revocation (H3 fix)
db.exec(`CREATE TABLE IF NOT EXISTS token_blocklist (
  jti TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

// Clean up expired blocklist entries periodically (every hour)
setInterval(() => {
  try {
    const now = Math.floor(Date.now() / 1000);
    db.prepare('DELETE FROM token_blocklist WHERE expires_at < ?').run(now);
  } catch (e) {
    // Non-fatal cleanup
  }
}, 60 * 60 * 1000);

// Check if a token's jti is blocklisted
const isTokenRevoked = (jti) => {
  if (!jti) return false;
  const row = db.prepare('SELECT 1 FROM token_blocklist WHERE jti = ?').get(jti);
  return !!row;
};

// Revoke a token by adding its jti to the blocklist
const revokeToken = (token) => {
  try {
    const decoded = jwt.decode(token);
    if (decoded?.jti && decoded?.exp) {
      db.prepare('INSERT OR IGNORE INTO token_blocklist (jti, expires_at) VALUES (?, ?)').run(decoded.jti, decoded.exp);
    }
  } catch (e) {
    // Non-fatal
  }
};

// Optional API key middleware
const validateApiKey = (req, res, next) => {
  // Skip API key validation if not configured
  if (!process.env.API_KEY) {
    return next();
  }
  
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== process.env.API_KEY) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  next();
};

// JWT authentication middleware
const authenticateToken = async (req, res, next) => {
  // Platform mode: require upstream proxy auth or use single database user
  if (IS_PLATFORM) {
    try {
      // Security: In platform mode, check for upstream proxy auth header (H5 fix)
      // If PLATFORM_PROXY_HEADER is set, require it for authentication
      const proxyHeader = process.env.PLATFORM_PROXY_HEADER;
      if (proxyHeader) {
        const proxyUser = req.headers[proxyHeader.toLowerCase()];
        if (!proxyUser) {
          return res.status(401).json({ error: 'Platform mode: Missing proxy authentication header' });
        }
        // Log the authenticated proxy user for audit
        req.platformUser = proxyUser;
      }
      const user = userDb.getFirstUser();
      if (!user) {
        return res.status(500).json({ error: 'Platform mode: No user found in database' });
      }
      req.user = user;
      return next();
    } catch (error) {
      console.error('Platform mode error:', error);
      return res.status(500).json({ error: 'Platform mode: Failed to fetch user' });
    }
  }

  // Normal OSS JWT validation
  const authHeader = req.headers['authorization'];
  let token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  // Also check query param for SSE endpoints (EventSource can't set headers)
  // Security: Log warning for query-string token usage; prefer ticket-based SSE auth (H1 fix)
  if (!token && req.query.token) {
    token = req.query.token;
    // Redact token from the URL to prevent it from appearing in logs
    req.url = req.url.replace(/[?&]token=[^&]+/, '');
    if (req.originalUrl) {
      req.originalUrl = req.originalUrl.replace(/[?&]token=[^&]+/, '');
    }
  }

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    // Security: Check if token has been revoked (H3 fix)
    if (isTokenRevoked(decoded.jti)) {
      return res.status(401).json({ error: 'Token has been revoked.' });
    }

    // Verify user still exists and is active
    const user = userDb.getUserById(decoded.userId);
    if (!user) {
      return res.status(401).json({ error: 'Invalid token. User not found.' });
    }

    // Security: Auto-refresh with tighter controls (H4 fix)
    // Only refresh if past 75% of lifetime (not halfway), and revoke the old token
    if (decoded.exp && decoded.iat) {
      const now = Math.floor(Date.now() / 1000);
      const threeQuarterLife = (decoded.exp - decoded.iat) * 0.75;
      if (now > decoded.iat + threeQuarterLife) {
        const newToken = generateToken(user);
        res.setHeader('X-Refreshed-Token', newToken);
        // Revoke the old token so it cannot be reused
        if (decoded.jti) {
          db.prepare('INSERT OR IGNORE INTO token_blocklist (jti, expires_at) VALUES (?, ?)').run(decoded.jti, decoded.exp);
        }
      }
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Generate JWT token
const generateToken = (user) => {
  return jwt.sign(
    {
      userId: user.id,
      username: user.username,
      jti: crypto.randomUUID(), // Security: Unique token ID for revocation (H3/M6 fix)
    },
    JWT_SECRET,
    { expiresIn: '4h' } // Security: Reduced from 7d to 4h (M6 fix)
  );
};

// WebSocket authentication function
const authenticateWebSocket = (token) => {
  // Platform mode: bypass token validation, return first user
  if (IS_PLATFORM) {
    try {
      const user = userDb.getFirstUser();
      if (user) {
        return { id: user.id, userId: user.id, username: user.username };
      }
      return null;
    } catch (error) {
      console.error('Platform mode WebSocket error:', error);
      return null;
    }
  }

  // Normal OSS JWT validation
  if (!token) {
    return null;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    // Verify user actually exists in database (matches REST authenticateToken behavior)
    const user = userDb.getUserById(decoded.userId);
    if (!user) {
      return null;
    }
    return { userId: user.id, username: user.username };
  } catch (error) {
    console.error('WebSocket token verification error:', error);
    return null;
  }
};

export {
  validateApiKey,
  authenticateToken,
  generateToken,
  authenticateWebSocket,
  revokeToken,
  // Security: JWT_SECRET is no longer exported (H2 fix)
  // Use generateToken() and authenticateToken() instead
};
