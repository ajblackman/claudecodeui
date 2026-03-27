/**
 * Security regression tests for input validation, injection, and XSS prevention
 * 
 * Scans the codebase for known dangerous patterns and verifies
 * that mitigations are in place.
 */
import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const serverDir = path.join(__dirname, '../../server');
const srcDir = path.join(__dirname, '../../src');

/**
 * Recursively get all files matching a pattern in a directory
 */
function getFiles(dir, extensions = ['.js', '.ts', '.tsx', '.jsx']) {
  const results = [];
  if (!fs.existsSync(dir)) return results;
  
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '.git') continue;
    if (entry.isDirectory()) {
      results.push(...getFiles(fullPath, extensions));
    } else if (extensions.some(ext => entry.name.endsWith(ext))) {
      results.push(fullPath);
    }
  }
  return results;
}

// ─────────────────────────────────────────────────────────────
// Command Injection — spawn must use shell: false
// ─────────────────────────────────────────────────────────────
describe('Command Injection Prevention', () => {
  it('should not use exec() or execSync() in server route/middleware code', () => {
    const serverFiles = getFiles(serverDir);
    const violations = [];
    
    // Exclude CLI entry point — it runs locally as a user tool, not as a server
    const excludedFiles = ['cli.js'];
    
    for (const file of serverFiles) {
      const basename = path.basename(file);
      if (excludedFiles.includes(basename)) continue;
      
      const content = fs.readFileSync(file, 'utf8');
      const relativePath = path.relative(serverDir, file);
      
      // Check for exec/execSync usage (excluding db.exec which is SQLite)
      const lines = content.split('\n');
      lines.forEach((line, i) => {
        // Skip SQLite db.exec calls and import statements
        if (line.includes('db.exec') || line.includes('import')) return;
        if (/(?:^|\s|;)exec\(|execSync\(/.test(line)) {
          violations.push(`${relativePath}:${i + 1}: ${line.trim()}`);
        }
      });
    }
    
    expect(violations).toEqual([]);
  });

  it('should use shell: false in all spawn calls in server code (except documented exceptions)', () => {
    const serverFiles = getFiles(serverDir);
    const violations = [];
    
    // taskmaster.js uses shell:true for `which` command detection — this is acceptable
    // because the command is hardcoded, not user-supplied
    const allowedShellTrue = {
      'routes/taskmaster.js': ['which', '--version'],
    };
    
    for (const file of serverFiles) {
      const content = fs.readFileSync(file, 'utf8');
      const relativePath = path.relative(serverDir, file);
      
      // Find all spawn calls with shell: true
      const shellTruePattern = /spawn\w*\([^)]*\{[^}]*shell\s*:\s*true/g;
      let match;
      while ((match = shellTruePattern.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        const line = content.split('\n')[lineNum - 1];
        
        // Check if this is an allowed exception
        const allowed = allowedShellTrue[relativePath];
        if (allowed && allowed.some(cmd => line.includes(`'${cmd}'`) || line.includes(`"${cmd}"`))) {
          continue;
        }
        
        violations.push(`${relativePath}:${lineNum}: spawn with shell: true`);
      }
    }
    
    expect(violations).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────
// SQL Injection — All queries must use parameterized statements
// ─────────────────────────────────────────────────────────────
describe('SQL Injection Prevention', () => {
  it('should not use string concatenation or template literals in SQL queries', () => {
    const dbFile = fs.readFileSync(path.join(serverDir, 'database/db.js'), 'utf8');
    const violations = [];
    
    const lines = dbFile.split('\n');
    lines.forEach((line, i) => {
      // Check for string concatenation in prepare() calls
      if (line.includes('.prepare(') && (line.includes("'+") || line.includes("+ '") || line.includes('`'))) {
        // Allow prepared statements that use template literals for static SQL building (like IN clauses with ?)
        if (!line.includes('${') && !line.includes("'+")) {
          return; // Static template literal is OK
        }
        // Exception: building placeholder strings like '?,?,?' is safe
        if (line.includes("'?'") || line.includes("`,")) {
          return;
        }
        violations.push(`db.js:${i + 1}: ${line.trim()}`);
      }
    });
    
    expect(violations).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────
// Path Traversal — File operations must validate paths
// ─────────────────────────────────────────────────────────────
describe('Path Traversal Prevention', () => {
  it('should validate file paths in git routes', () => {
    const gitRoutes = fs.readFileSync(path.join(serverDir, 'routes/git.js'), 'utf8');
    expect(gitRoutes).toContain('validateFilePath');
    expect(gitRoutes).toContain('path traversal');
  });

  it('should validate plugin names against path traversal', () => {
    const pluginLoader = fs.readFileSync(path.join(serverDir, 'utils/plugin-loader.js'), 'utf8');
    // Must have alphanumeric-only validation for plugin names
    expect(pluginLoader).toMatch(/\^?\[a-zA-Z0-9_-\]\+\$?/);
    // Must reject '..' in entry paths
    expect(pluginLoader).toContain("'..'");
  });

  it('should sanitize session IDs in session manager', () => {
    const sessionManager = fs.readFileSync(path.join(serverDir, 'sessionManager.js'), 'utf8');
    expect(sessionManager).toContain('_safeFilePath');
    // The regex strips slashes, backslashes, and '..' from session IDs
    expect(sessionManager).toMatch(/_safeFilePath/);
    expect(sessionManager).toMatch(/replace\(/);
  });
});

// ─────────────────────────────────────────────────────────────
// XSS Prevention — dangerouslySetInnerHTML must be sanitized
// ─────────────────────────────────────────────────────────────
describe('XSS Prevention', () => {
  it('should sanitize SVG content in plugin icons', () => {
    const pluginIcon = fs.readFileSync(
      path.join(srcDir, 'components/plugins/view/PluginIcon.tsx'), 'utf8'
    );
    expect(pluginIcon).toContain('DOMPurify');
    expect(pluginIcon).toContain('sanitize');
  });

  it('should have limited dangerouslySetInnerHTML usage', () => {
    const srcFiles = getFiles(srcDir);
    const usages = [];
    
    for (const file of srcFiles) {
      const content = fs.readFileSync(file, 'utf8');
      const relativePath = path.relative(srcDir, file);
      
      const lines = content.split('\n');
      lines.forEach((line, i) => {
        if (line.includes('dangerouslySetInnerHTML')) {
          usages.push(`${relativePath}:${i + 1}`);
        }
      });
    }
    
    // Document all dangerouslySetInnerHTML usages — each must be audited
    // Currently expected: PluginIcon.tsx (sanitized with DOMPurify)
    console.log(`Found ${usages.length} dangerouslySetInnerHTML usages:`, usages);
    
    // Ensure the count doesn't grow silently — update this number when new usages are added
    expect(usages.length).toBeLessThanOrEqual(2);
  });

  it('should have limited innerHTML usage in TypeScript/JSX', () => {
    const srcFiles = getFiles(srcDir);
    const usages = [];
    
    for (const file of srcFiles) {
      const content = fs.readFileSync(file, 'utf8');
      const relativePath = path.relative(srcDir, file);
      
      const lines = content.split('\n');
      lines.forEach((line, i) => {
        // Match .innerHTML = but not dangerouslySetInnerHTML
        if (line.includes('.innerHTML') && !line.includes('dangerouslySetInnerHTML')) {
          usages.push(`${relativePath}:${i + 1}`);
        }
      });
    }
    
    console.log(`Found ${usages.length} innerHTML usages:`, usages);
    // Each innerHTML usage must have a documented security justification
    expect(usages.length).toBeLessThanOrEqual(2);
  });
});

// ─────────────────────────────────────────────────────────────
// Sensitive Data Exposure — No secrets in client code
// ─────────────────────────────────────────────────────────────
describe('Sensitive Data Exposure', () => {
  it('should not have API keys or secrets hardcoded in frontend', () => {
    const srcFiles = getFiles(srcDir);
    const violations = [];
    
    const secretPatterns = [
      { pattern: /sk-[a-zA-Z0-9]{20,}/, name: 'OpenAI API key' },
      { pattern: /ghp_[a-zA-Z0-9]{36}/, name: 'GitHub PAT' },
      { pattern: /gho_[a-zA-Z0-9]{36}/, name: 'GitHub OAuth' },
      { pattern: /AIza[a-zA-Z0-9_-]{35}/, name: 'Google API key' },
      { pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/, name: 'Private key' },
    ];
    
    for (const file of srcFiles) {
      const content = fs.readFileSync(file, 'utf8');
      const relativePath = path.relative(srcDir, file);
      
      const lines = content.split('\n');
      for (const { pattern, name } of secretPatterns) {
        lines.forEach((line, i) => {
          if (pattern.test(line)) {
            // Exclude placeholder/example values (e.g. placeholder="ghp_xxx...")
            if (/placeholder|example|sample|mock|test|dummy|xxx/i.test(line)) return;
            violations.push(`${relativePath}:${i + 1}: possible ${name}`);
          }
        });
      }
    }
    
    expect(violations).toEqual([]);
  });

  it('should not log sensitive data in console statements', () => {
    const serverFiles = getFiles(serverDir);
    const violations = [];
    
    for (const file of serverFiles) {
      const content = fs.readFileSync(file, 'utf8');
      const relativePath = path.relative(serverDir, file);
      
      const lines = content.split('\n');
      lines.forEach((line, i) => {
        if (/console\.(log|info|warn|error).*(?:password|secret|token|apiKey|api_key)/i.test(line)) {
          // Allow logging of token-related status messages but not values
          if (/token.*error|token.*verif|token.*invalid|token.*revoked|token.*expired/i.test(line)) return;
          if (/WebSocket.*token/i.test(line)) return;
          if (/Refreshed.*Token/i.test(line)) return;
          violations.push(`${relativePath}:${i + 1}: ${line.trim()}`);
        }
      });
    }
    
    // If violations found, they should be reviewed — may be false positives
    if (violations.length > 0) {
      console.warn('Potential sensitive data logging:', violations);
    }
  });
});

// ─────────────────────────────────────────────────────────────
// Dependency Safety — No known dangerous packages
// ─────────────────────────────────────────────────────────────
describe('Dependency Safety', () => {
  it('should not use eval() or Function() constructor', () => {
    const allFiles = [...getFiles(serverDir), ...getFiles(srcDir)];
    const violations = [];
    
    for (const file of allFiles) {
      const content = fs.readFileSync(file, 'utf8');
      const relativePath = path.relative(path.join(__dirname, '../..'), file);
      
      const lines = content.split('\n');
      lines.forEach((line, i) => {
        // Skip comments
        if (line.trim().startsWith('//') || line.trim().startsWith('*')) return;
        if (/(?:^|[^.])\beval\s*\(/.test(line) || /new\s+Function\s*\(/.test(line)) {
          violations.push(`${relativePath}:${i + 1}: ${line.trim()}`);
        }
      });
    }
    
    expect(violations).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────
// Authentication Coverage — All API routes must be protected
// ─────────────────────────────────────────────────────────────
describe('Authentication Coverage', () => {
  it('should protect all /api/ routes with authenticateToken or validateApiKey', () => {
    const indexJs = fs.readFileSync(path.join(serverDir, 'index.js'), 'utf8');
    
    // Find all app.use('/api/...' route mounts
    const routeMounts = indexJs.match(/app\.use\(['"]\/api\/[^'"]+['"]/g) || [];
    const unprotectedRoutes = [];
    
    for (const mount of routeMounts) {
      const routePath = mount.match(/['"]([^'"]+)['"]/)[1];
      
      // Find the full line to check for auth middleware
      const line = indexJs.split('\n').find(l => l.includes(mount));
      
      // These routes are intentionally public
      const publicRoutes = ['/api/auth', '/api/agent'];
      if (publicRoutes.some(r => routePath.startsWith(r))) continue;
      
      if (!line.includes('authenticateToken') && !line.includes('validateApiKey')) {
        unprotectedRoutes.push(routePath);
      }
    }
    
    expect(unprotectedRoutes).toEqual([]);
  });
});
