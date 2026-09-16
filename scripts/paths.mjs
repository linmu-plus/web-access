// scripts/paths.mjs
// web-access 运行时路径 —— 所有运行时状态收拢在一处（git 外、skill 外）
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const RUNTIME_DIR = path.join(os.homedir(), '.web-access');
export const BROWSER_DIR = path.join(RUNTIME_DIR, 'browser');
export const TOKEN_FILE = path.join(RUNTIME_DIR, 'token');
export const PID_FILE = path.join(RUNTIME_DIR, 'pid');
export const AUDIT_FILE = path.join(RUNTIME_DIR, 'audit.log');
export const CONFIRM_FILE = path.join(RUNTIME_DIR, 'confirm.token');

export function ensureRuntimeDir() {
  fs.mkdirSync(RUNTIME_DIR, { recursive: true });
}

// CLI 入口判定（junction/symlink 安全）：argv[1] 经 realpath 后与 import.meta.url 比较
// 根因：node 会把 ESM 主模块的 import.meta.url 解析为真实路径（realpath），
// 而 pathToFileURL(process.argv[1]) 保留调用侧的 junction/symlink 路径，
// 两者字符串不等 → 旧守卫永假 → 经 junction 调用时脚本静默无操作、exit 0。
// 修复语义：argv[1] 的 realpath 等于 importMetaUrl 指向的真实文件 → 视为直接执行。
// 直接跑脚本 → true；被 import（argv[1] 为测试运行器路径或 undefined）→ false
export function isMainEntry(importMetaUrl, argvPath = process.argv[1]) {
  if (!argvPath) return false;
  try { return pathToFileURL(fs.realpathSync(argvPath)).href === importMetaUrl; }
  catch { return false; }
}
