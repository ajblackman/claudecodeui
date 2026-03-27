import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.{js,ts}'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'text-summary', 'lcov', 'html'],
      include: ['server/**/*.js'],
      exclude: [
        'server/cli.js',
        'server/load-env.js',
        'node_modules/**',
        'dist/**',
      ],
      thresholds: {
        // Start with achievable thresholds; raise as coverage improves
        lines: 20,
        functions: 15,
        branches: 15,
        statements: 20,
      },
    },
    // Separate test pools for security vs unit tests
    testTimeout: 15000,
  },
  resolve: {
    alias: {
      '@server': path.resolve(__dirname, 'server'),
      '@shared': path.resolve(__dirname, 'shared'),
    },
  },
});
