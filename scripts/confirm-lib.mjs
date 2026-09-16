// scripts/confirm-lib.mjs
// 确认门共享逻辑：confirm.mjs（生成）与 cdp-proxy.mjs（校验消费）共用
import fs from 'node:fs';
import crypto from 'node:crypto';
import { CONFIRM_FILE, ensureRuntimeDir } from './paths.mjs';

export function writeConfirm(purpose, ttlSeconds, filePath = CONFIRM_FILE) {
  ensureRuntimeDir();
  const now = Date.now();
  const rec = {
    code: crypto.randomBytes(8).toString('hex'),
    purpose: String(purpose),
    createdAt: now,
    expiresAt: now + ttlSeconds * 1000,
  };
  fs.writeFileSync(filePath, JSON.stringify(rec, null, 2));
  return rec;
}

// 校验并消费：放行即删除文件（单次有效）；code 不匹配时保留文件（防攻击者探测销毁）
export function checkConfirm(headerCode, { filePath = CONFIRM_FILE, now = Date.now() } = {}) {
  let rec = null;
  try { rec = JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch { rec = null; }
  if (!rec || typeof rec.code !== 'string') {
    return { status: 403, error: '确认门：当前没有待确认的操作。请用户运行 node <base>/scripts/confirm.mjs "<操作说明>" 生成 code 并转交。' };
  }
  if (rec.expiresAt <= now) {
    try { fs.unlinkSync(filePath); } catch {}
    return { status: 403, error: `确认 code 已过期（用途：${rec.purpose}）。请用户重新运行 confirm.mjs。` };
  }
  if (String(headerCode || '').trim() !== rec.code) {
    return { status: 403, error: '确认 code 不匹配。请核对用户提供的 code。' };
  }
  try { fs.unlinkSync(filePath); } catch {}
  return null;
}
