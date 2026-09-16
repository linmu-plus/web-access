// scripts/paths.mjs
// web-access 运行时路径 —— 所有运行时状态收拢在一处（git 外、skill 外）
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const RUNTIME_DIR = path.join(os.homedir(), '.web-access');
export const BROWSER_DIR = path.join(RUNTIME_DIR, 'browser');
export const TOKEN_FILE = path.join(RUNTIME_DIR, 'token');
export const PID_FILE = path.join(RUNTIME_DIR, 'pid');
export const AUDIT_FILE = path.join(RUNTIME_DIR, 'audit.log');
export const CONFIRM_FILE = path.join(RUNTIME_DIR, 'confirm.token');

export function ensureRuntimeDir() {
  fs.mkdirSync(RUNTIME_DIR, { recursive: true });
}
