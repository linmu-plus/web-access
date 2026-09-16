#!/usr/bin/env node
// scripts/confirm.mjs —— 生成一次性确认 token（硬确认门）
// 用法：node confirm.mjs "<操作说明>"
// 输出的 code 在 TTL 内单次有效；用户把 code 转告 Agent，Agent 以 X-Web-Access-Confirm 头携带
import { writeConfirm } from './confirm-lib.mjs';
import { loadPermissions } from './permissions.mjs';

const purpose = process.argv[2];
if (!purpose) {
  console.error('用法：node confirm.mjs "<操作说明>"');
  console.error('示例：node confirm.mjs "在小红书创作者平台上传 3 张图片并发布"');
  process.exit(1);
}
let cfg;
try {
  cfg = loadPermissions().cfg;
} catch (e) {
  // fail-closed：permissions.json 非法时输出单行可行动错误，不裸抛堆栈
  console.error(`❌ ${e.message}`);
  process.exit(1);
}
const ttl = cfg.confirm.ttlSeconds;
// 第二道防线（loadPermissions 已校验，防 CLI 直接运行时配置被绕过）
if (!Number.isInteger(ttl) || ttl < 1 || ttl > 3600) {
  console.error('❌ confirm.ttlSeconds 需为 1-3600 的整数（字段说明见 docs/superpowers/specs/2026-09-15-web-access-hardening-design.md §6），请修复 permissions.json 中的 confirm.ttlSeconds 后重试。');
  process.exit(1);
}
const rec = writeConfirm(purpose, ttl);
console.log(`确认 token 已生成（${ttl}s 内有效，单次使用）`);
console.log(`  用途：${rec.purpose}`);
console.log(`  code：${rec.code}`);
console.log('  将此 code 转告 Agent；Agent 调用高危端点时以 X-Web-Access-Confirm 头携带。');
