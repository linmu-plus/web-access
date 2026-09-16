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
const { cfg } = loadPermissions();
const rec = writeConfirm(purpose, cfg.confirm.ttlSeconds);
console.log(`确认 token 已生成（${cfg.confirm.ttlSeconds}s 内有效，单次使用）`);
console.log(`  用途：${rec.purpose}`);
console.log(`  code：${rec.code}`);
console.log('  将此 code 转告 Agent；Agent 调用高危端点时以 X-Web-Access-Confirm 头携带。');
