/**
 * Security regression tests for authentication & authorization
 * 
 * These tests verify that security fixes remain in place and
 * prevent regressions when new features are added.
 */
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const serverDir = path.join(__dirname, '../../server');

// ─────────────────────────────────────────────────────────────
// C1: CORS must NOT be wildcard
// ─────────────────────────────────────────────────────────────
describe('C1: CORS Configuration', () => {
  it('should not use wildcard CORS', () => {
    const indexJs = fs.readFileSync(path.join(serverDir, 'index.js'), 'utf8');
    // Ensure we're not using cors() with no origin config
    expect(indexJs).not.toMatch(/cors\(\s*\{\s*exposedHeaders/);
    expect(indexJs).not.toMatch(/cors\(\s*\)/);
    // Ensure origin restriction is present
    expect(indexJs).toContain('origin:');
  });

  it('should have an explicit origin allowlist or function', () => {
    const indexJs = fs.readFileSync(path.join(serverDir, 'index.js'), 'utf8');
    expect(indexJs).toMatch(/ALLOWED_ORIGINS|allowedOrigins|origin:\s*\(/);
  });
});

// ─────────────────────────────────────────────────────────────
// C2: Rate limiting must exist on auth endpoints
// ─────────────────────────────────────────────────────────────
describe('C2: Rate Limiting', () => {
  it('should import rate limiting library in auth routes', () => {
    const authRoutes = fs.readFileSync(path.join(serverDir, 'routes/auth.js'), 'utf8');
    expect(authRoutes).toContain('express-rate-limit');
  });

  it('should apply rate limiter to login route', () => {
    const authRoutes = fs.readFileSync(path.join(serverDir, 'routes/auth.js'), 'utf8');
    expect(authRoutes).toMatch(/router\.post\(['"]\/login['"]\s*,\s*\w*[Ll]imit/);
  });

  it('should apply rate limiter to register route', () => {
    const authRoutes = fs.readFileSync(path.join(serverDir, 'routes/auth.js'), 'utf8');
    expect(authRoutes).toMatch(/router\.post\(['"]\/register['"]\s*,\s*\w*[Ll]imit/);
  });
});

// ─────────────────────────────────────────────────────────────
// C3: Credentials must be encrypted at rest
// ─────────────────────────────────────────────────────────────
describe('C3: Credential Encryption', () => {
  it('should encrypt credentials before storing in database', () => {
    const dbJs = fs.readFileSync(path.join(serverDir, 'database/db.js'), 'utf8');
    expect(dbJs).toContain('encryptValue');
    expect(dbJs).toContain('aes-256-gcm');
  });

  it('should decrypt credentials when reading from database', () => {
    const dbJs = fs.readFileSync(path.join(serverDir, 'database/db.js'), 'utf8');
    expect(dbJs).toContain('decryptValue');
  });

  it('should handle legacy unencrypted values gracefully', () => {
    const dbJs = fs.readFileSync(path.join(serverDir, 'database/db.js'), 'utf8');
    // The decrypt function should check for the 'enc:' prefix
    expect(dbJs).toMatch(/!stored\.startsWith\(['"]enc:/);
  });
});

// ─────────────────────────────────────────────────────────────
// H1: JWT token must not leak in logs
// ─────────────────────────────────────────────────────────────
describe('H1: JWT Token Leakage Prevention', () => {
  it('should redact token from request URL', () => {
    const authMiddleware = fs.readFileSync(path.join(serverDir, 'middleware/auth.js'), 'utf8');
    expect(authMiddleware).toMatch(/req\.url.*replace.*token/);
  });
});

// ─────────────────────────────────────────────────────────────
// H2: JWT_SECRET must not be exported
// ─────────────────────────────────────────────────────────────
describe('H2: JWT Secret Export Prevention', () => {
  it('should NOT export JWT_SECRET as a usable export', () => {
    const authMiddleware = fs.readFileSync(path.join(serverDir, 'middleware/auth.js'), 'utf8');
    // Match export block and ensure JWT_SECRET is not an actual export (comments are OK)
    const exportMatch = authMiddleware.match(/export\s*\{([^}]+)\}/);
    expect(exportMatch).toBeTruthy();
    // Filter out comment lines and check remaining exports
    const actualExports = exportMatch[1]
      .split('\n')
      .filter(line => !line.trim().startsWith('//'))
      .join('');
    expect(actualExports).not.toContain('JWT_SECRET');
  });
});

// ─────────────────────────────────────────────────────────────
// H3: Token revocation must exist
// ─────────────────────────────────────────────────────────────
describe('H3: Token Revocation', () => {
  it('should have a token blocklist table', () => {
    const authMiddleware = fs.readFileSync(path.join(serverDir, 'middleware/auth.js'), 'utf8');
    expect(authMiddleware).toContain('token_blocklist');
  });

  it('should check blocklist during authentication', () => {
    const authMiddleware = fs.readFileSync(path.join(serverDir, 'middleware/auth.js'), 'utf8');
    expect(authMiddleware).toContain('isTokenRevoked');
  });

  it('should revoke token on logout', () => {
    const authRoutes = fs.readFileSync(path.join(serverDir, 'routes/auth.js'), 'utf8');
    expect(authRoutes).toContain('revokeToken');
  });
});

// ─────────────────────────────────────────────────────────────
// H5: Platform mode must validate proxy auth
// ─────────────────────────────────────────────────────────────
describe('H5: Platform Mode Security', () => {
  it('should check for proxy authentication header in platform mode', () => {
    const authMiddleware = fs.readFileSync(path.join(serverDir, 'middleware/auth.js'), 'utf8');
    expect(authMiddleware).toContain('PLATFORM_PROXY_HEADER');
  });
});

// ─────────────────────────────────────────────────────────────
// H6: No shell injection in system update
// ─────────────────────────────────────────────────────────────
describe('H6: Shell Injection Prevention', () => {
  it('should NOT use sh -c for system update', () => {
    const indexJs = fs.readFileSync(path.join(serverDir, 'index.js'), 'utf8');
    // Find the update endpoint section
    const updateSection = indexJs.substring(
      indexJs.indexOf('/api/system/update'),
      indexJs.indexOf('/api/system/update') + 2000
    );
    expect(updateSection).not.toMatch(/spawn\(['"]sh['"]\s*,\s*\[['"]?-c/);
  });

  it('should use shell: false in spawn calls', () => {
    const indexJs = fs.readFileSync(path.join(serverDir, 'index.js'), 'utf8');
    const updateSection = indexJs.substring(
      indexJs.indexOf('/api/system/update'),
      indexJs.indexOf('/api/system/update') + 2000
    );
    expect(updateSection).toContain('shell: false');
  });
});

// ─────────────────────────────────────────────────────────────
// M1: Password policy must be strong
// ─────────────────────────────────────────────────────────────
describe('M1: Password Policy', () => {
  it('should require passwords of at least 12 characters', () => {
    const authRoutes = fs.readFileSync(path.join(serverDir, 'routes/auth.js'), 'utf8');
    // Check for minimum length >= 12
    const minLengthMatch = authRoutes.match(/password\.length\s*<\s*(\d+)/);
    expect(minLengthMatch).toBeTruthy();
    expect(parseInt(minLengthMatch[1])).toBeGreaterThanOrEqual(12);
  });
});

// ─────────────────────────────────────────────────────────────
// M2: Security headers must be configured
// ─────────────────────────────────────────────────────────────
describe('M2: Security Headers', () => {
  it('should use helmet middleware', () => {
    const indexJs = fs.readFileSync(path.join(serverDir, 'index.js'), 'utf8');
    expect(indexJs).toContain("import helmet from 'helmet'");
    expect(indexJs).toContain('app.use(helmet(');
  });
});

// ─────────────────────────────────────────────────────────────
// M4: Session files must have restrictive permissions
// ─────────────────────────────────────────────────────────────
describe('M4: Session File Permissions', () => {
  it('should write session files with mode 0600', () => {
    const sessionManager = fs.readFileSync(path.join(serverDir, 'sessionManager.js'), 'utf8');
    expect(sessionManager).toMatch(/mode:\s*0o600/);
  });
});

// ─────────────────────────────────────────────────────────────
// M6: JWT lifetime must be short
// ─────────────────────────────────────────────────────────────
describe('M6: JWT Lifetime', () => {
  it('should have JWT expiry of 24 hours or less', () => {
    const authMiddleware = fs.readFileSync(path.join(serverDir, 'middleware/auth.js'), 'utf8');
    const expiryMatch = authMiddleware.match(/expiresIn:\s*['"](\d+)([hdms])['"]/);
    expect(expiryMatch).toBeTruthy();
    
    const value = parseInt(expiryMatch[1]);
    const unit = expiryMatch[2];
    
    let hours;
    switch (unit) {
      case 'h': hours = value; break;
      case 'd': hours = value * 24; break;
      case 'm': hours = value / 60; break;
      case 's': hours = value / 3600; break;
    }
    
    expect(hours).toBeLessThanOrEqual(24);
  });

  it('should include jti (JWT ID) for revocation support', () => {
    const authMiddleware = fs.readFileSync(path.join(serverDir, 'middleware/auth.js'), 'utf8');
    expect(authMiddleware).toContain('jti:');
  });
});

// ─────────────────────────────────────────────────────────────
// L2: Error handler must sanitize production errors
// ─────────────────────────────────────────────────────────────
describe('L2: Error Handler', () => {
  it('should have a global error handler', () => {
    const indexJs = fs.readFileSync(path.join(serverDir, 'index.js'), 'utf8');
    // Express error handlers have 4 params: (err, req, res, next)
    expect(indexJs).toMatch(/app\.use\(\s*\(\s*err\s*,\s*req\s*,\s*res/);
  });

  it('should check NODE_ENV before exposing error details', () => {
    const indexJs = fs.readFileSync(path.join(serverDir, 'index.js'), 'utf8');
    expect(indexJs).toContain("process.env.NODE_ENV === 'development'");
  });
});
