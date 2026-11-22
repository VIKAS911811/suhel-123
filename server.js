import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';
import { createRequire } from 'module';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);

process.env.NODE_ENV = process.env.NODE_ENV || 'production';

const distDir = path.join(__dirname, 'dist');
const distServer = path.join(distDir, 'server.cjs');
const distIndex = path.join(distDir, 'index.html');

if (!fs.existsSync(distServer) || !fs.existsSync(distIndex)) {
  console.log('Production build not found. Running npm run build...');
  execSync('npm run build', { cwd: __dirname, stdio: 'inherit' });
}

require(distServer);
