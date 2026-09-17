#!/usr/bin/env node
// deploy.mjs —— 将开发副本（本仓库）的 skill 内容同步到安装目录
//
// 用法：node deploy.mjs [--target <安装目录>]
//   默认安装目录：%USERPROFILE%\.agents\skills\web-access
//
// 复制内容：SKILL.md / README.md / permissions.json / scripts\ / references\
// 不复制：.git、.superpowers、docs\、test\、deploy.mjs —— 均为开发副本专属
//
// 说明：开发副本（本仓库）与安装副本是两份独立文件；改完代码跑一次本脚本，
// 然后在受影响的会话里重跑 check-deps（必要时 stop-proxy 后重启）生效。
// 运行时状态（token/pid/audit.log/专用实例）在 %USERPROFILE%\.web-access\，
// 与副本位置无关，两份副本共享。
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SKILL_ROOT = path.dirname(fileURLToPath(import.meta.url));
const FILES = ['SKILL.md', 'README.md', 'permissions.json'];
const DIRS = ['scripts', 'references'];
const EXCLUDE_IN_ROOT = ['deploy.mjs'];

const args = process.argv.slice(2);
const ti = args.indexOf('--target');
if (ti !== -1 && (ti + 1 >= args.length || args[ti + 1].startsWith('--'))) {
  console.error('❌ --target 需要一个目录参数');
  process.exit(1);
}
const TARGET = path.resolve(ti !== -1 ? args[ti + 1] : path.join(os.homedir(), '.agents', 'skills', 'web-access'));

if (fs.existsSync(TARGET) && !fs.statSync(TARGET).isDirectory()) {
  console.error(`❌ 目标已存在且不是目录：${TARGET}`);
  process.exit(1);
}
if (path.resolve(TARGET) === path.resolve(SKILL_ROOT)) {
  console.error('❌ 目标不能是开发副本自身');
  process.exit(1);
}
if (path.resolve(TARGET).startsWith(path.resolve(SKILL_ROOT) + path.sep)) {
  console.error('❌ 目标不能位于开发副本内部');
  process.exit(1);
}

fs.mkdirSync(TARGET, { recursive: true });
for (const f of FILES) {
  const src = path.join(SKILL_ROOT, f);
  const dst = path.join(TARGET, f);
  // permissions.json 是「用户偏好」而非代码：安装副本已存在时保留其现值，
  // 否则会把你在安装副本里选的 browser 偏好冲回出厂默认。需要强制覆盖用 --force-config。
  if (f === 'permissions.json' && fs.existsSync(dst) && !args.includes('--force-config')) {
    const cur = fs.readFileSync(dst, 'utf8');
    const next = fs.readFileSync(src, 'utf8');
    if (cur !== next) console.log('ℹ️  permissions.json 已存在，保留安装副本现值（如需覆盖：--force-config）');
    continue;
  }
  fs.copyFileSync(src, dst);
}
for (const d of DIRS) {
  fs.rmSync(path.join(TARGET, d), { recursive: true, force: true });
  fs.cpSync(path.join(SKILL_ROOT, d), path.join(TARGET, d), { recursive: true });
}
console.log(`✅ 已同步到 ${TARGET}`);
console.log('   提示：若 proxy 正在运行，修改过的脚本需 stop-proxy 后重跑 check-deps 才生效。');
