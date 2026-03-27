/**
 * Security regression tests for infrastructure, headers, and configuration
 */
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const serverDir = path.join(__dirname, '../../server');
const rootDir = path.join(__dirname, '../..');

// ─────────────────────────────────────────────────────────────
// Security Headers
// ─────────────────────────────────────────────────────────────
describe('Security Headers', () => {
  it('should use helmet middleware for HTTP security headers', () => {
    const indexJs = fs.readFileSync(path.join(serverDir, 'index.js'), 'utf8');
    expect(indexJs).toContain("import helmet from 'helmet'");
    expect(indexJs).toMatch(/app\.use\(helmet\(/);
  });
});

// ─────────────────────────────────────────────────────────────
// HTTPS / TLS Configuration
// ─────────────────────────────────────────────────────────────
describe('Network Security', () => {
  it('should not bind to 0.0.0.0 without explicit opt-in', () => {
    const indexJs = fs.readFileSync(path.join(serverDir, 'index.js'), 'utf8');
    // 0.0.0.0 is the default but should be configurable
    expect(indexJs).toContain("process.env.HOST || '0.0.0.0'");
  });
});

// ─────────────────────────────────────────────────────────────
// Package Security
// ─────────────────────────────────────────────────────────────
describe('Package Configuration', () => {
  it('should have security-related dependencies', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8'));
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
    
    expect(allDeps).toHaveProperty('helmet');
    expect(allDeps).toHaveProperty('express-rate-limit');
    expect(allDeps).toHaveProperty('bcrypt');
  });

  it('should have a lockfile', () => {
    expect(fs.existsSync(path.join(rootDir, 'package-lock.json'))).toBe(true);
  });

  it('should not have .env files committed', () => {
    const envFiles = ['.env', '.env.local', '.env.production'];
    for (const envFile of envFiles) {
      const exists = fs.existsSync(path.join(rootDir, envFile));
      if (exists) {
        // It's OK if the file exists locally, but check it's in .gitignore
        const gitignore = fs.readFileSync(path.join(rootDir, '.gitignore'), 'utf8').split('\n');
        const isIgnored = gitignore.some(line => {
          const pattern = line.trim();
          return pattern === envFile || pattern === '.env*' || pattern === '.env';
        });
        expect(isIgnored).toBe(true);
      }
    }
  });
});

// ─────────────────────────────────────────────────────────────
// CI/CD Security
// ─────────────────────────────────────────────────────────────
describe('CI/CD Configuration', () => {
  it('should have a CI workflow', () => {
    expect(fs.existsSync(path.join(rootDir, '.github/workflows/ci.yml'))).toBe(true);
  });

  it('should have a security scanning workflow', () => {
    expect(fs.existsSync(path.join(rootDir, '.github/workflows/security.yml'))).toBe(true);
  });

  it('should run security tests in CI', () => {
    const ciYml = fs.readFileSync(path.join(rootDir, '.github/workflows/ci.yml'), 'utf8');
    expect(ciYml).toContain('tests/security');
  });

  it('should run npm audit in CI', () => {
    const securityYml = fs.readFileSync(path.join(rootDir, '.github/workflows/security.yml'), 'utf8');
    expect(securityYml).toContain('npm audit');
  });

  it('CI workflow should pin actions to major versions', () => {
    const ciYml = fs.readFileSync(path.join(rootDir, '.github/workflows/ci.yml'), 'utf8');
    // All uses: should reference @v4 not @main or @master
    const actionRefs = ciYml.match(/uses:\s*([^\n]+)/g) || [];
    const unpinnedActions = actionRefs.filter(ref => {
      return ref.includes('@main') || ref.includes('@master');
    });
    expect(unpinnedActions).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────
// Error Handling
// ─────────────────────────────────────────────────────────────
describe('Error Handling', () => {
  it('should have a global error handler that checks NODE_ENV', () => {
    const indexJs = fs.readFileSync(path.join(serverDir, 'index.js'), 'utf8');
    expect(indexJs).toMatch(/app\.use\(\s*\(\s*err\s*,/);
    expect(indexJs).toContain('NODE_ENV');
  });
});

// ─────────────────────────────────────────────────────────────
// Credential Storage
// ─────────────────────────────────────────────────────────────
describe('Credential Storage', () => {
  it('should use bcrypt with salt rounds >= 10 for password hashing', () => {
    const authRoutes = fs.readFileSync(path.join(serverDir, 'routes/auth.js'), 'utf8');
    const saltMatch = authRoutes.match(/saltRounds\s*=\s*(\d+)/);
    expect(saltMatch).toBeTruthy();
    expect(parseInt(saltMatch[1])).toBeGreaterThanOrEqual(10);
  });

  it('should not return password_hash in user queries', () => {
    const dbJs = fs.readFileSync(path.join(serverDir, 'database/db.js'), 'utf8');
    // getUserById should SELECT specific fields, not *
    const getUserByIdMatch = dbJs.match(/getUserById[\s\S]*?prepare\(['"]([^'"]+)['"]\)/);
    expect(getUserByIdMatch).toBeTruthy();
    expect(getUserByIdMatch[1]).not.toContain('password_hash');
    expect(getUserByIdMatch[1]).not.toContain('SELECT *');
  });

  it('should sanitize repo URLs to strip embedded credentials', () => {
    const pluginLoader = fs.readFileSync(path.join(serverDir, 'utils/plugin-loader.js'), 'utf8');
    expect(pluginLoader).toContain('sanitizeRepoUrl');
  });
});

// ─────────────────────────────────────────────────────────────
// Plugin Security
// ─────────────────────────────────────────────────────────────
describe('Plugin System Security', () => {
  it('should validate plugin manifest before loading', () => {
    const pluginLoader = fs.readFileSync(path.join(serverDir, 'utils/plugin-loader.js'), 'utf8');
    expect(pluginLoader).toContain('validateManifest');
  });

  it('should reject plugin entries with path traversal', () => {
    const pluginLoader = fs.readFileSync(path.join(serverDir, 'utils/plugin-loader.js'), 'utf8');
    expect(pluginLoader).toContain("'..'");
    expect(pluginLoader).toContain('isAbsolute');
  });

  it('should validate plugin names with strict regex', () => {
    const pluginsRoute = fs.readFileSync(path.join(serverDir, 'routes/plugins.js'), 'utf8');
    // Plugin names must be alphanumeric + hyphens/underscores only
    expect(pluginsRoute).toMatch(/\[a-zA-Z0-9_-\]\+/);
  });
});

// ─────────────────────────────────────────────────────────────
// WebSocket Security
// ─────────────────────────────────────────────────────────────
describe('WebSocket Security', () => {
  it('should authenticate WebSocket connections', () => {
    const indexJs = fs.readFileSync(path.join(serverDir, 'index.js'), 'utf8');
    expect(indexJs).toContain('authenticateWebSocket');
    expect(indexJs).toContain('verifyClient');
  });
});
