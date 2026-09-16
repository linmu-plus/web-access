#!/usr/bin/env node
// check-deps —— 权限校验 + 专用实例/Proxy 编排（web-access v3 前置检查）
//
// 用法：
//   node check-deps.mjs                  按 permissions.json 执行
//   node check-deps.mjs --browser edge   本次临时指定浏览器（isolation=off 时生效）
//
// 退出码：0 就绪 | 1 失败 | 2 需用户决策（isolation=off 且多浏览器未设偏好）

import fs from 'node:fs';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensureRuntimeDir, TOKEN_FILE } from './paths.mjs';
import { selectBrowser, knownBrowsers } from './browser-discovery.mjs';
import { launchBrowser } from './launch-browser.mjs';
import { loadPermissions, migrateLegacyConfig, profileLine, LEGACY_CONFIG_PATH } from './permissions.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PROXY_SCRIPT = path.join(ROOT, 'scripts', 'cdp-proxy.mjs');
const PROXY_PORT = Number(process.env.CDP_PROXY_PORT || 3456);

function parseArgs(argv) {
  const opts = { browser: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--browser' && argv[i + 1]) { opts.browser = argv[i + 1]; i++; }
    else if (argv[i].startsWith('--browser=')) opts.browser = argv[i].slice('--browser='.length);
  }
  return opts;
}

function checkNode() {
  const major = Number(process.versions.node.split('.')[0]);
  if (major >= 22) console.log(`node: ok (v${process.versions.node})`);
  else console.log(`node: warn (v${process.versions.node}, 建议升级到 22+)`);
}

// --- 迁移旧 config.env ---
function migrateLegacy() {
  const legacy = migrateLegacyConfig();
  if (!legacy) return;
  try {
    const raw = JSON.parse(fs.readFileSync(path.join(ROOT, 'permissions.json'), 'utf8'));
    if (!raw.browser) { raw.browser = legacy.value; fs.writeFileSync(path.join(ROOT, 'permissions.json'), JSON.stringify(raw, null, 2) + '\n'); }
    console.log(`migrate: 已将 config.env 的 WEB_ACCESS_BROWSER=${legacy.value} 迁入 permissions.json`);
    fs.unlinkSync(path.join(ROOT, 'config.env'));
    console.log('migrate: 已删除旧 config.env');
  } catch (e) {
    console.log(`⚠️  config.env 迁移失败（${e.message}），忽略旧配置继续`);
  }
}

// --- proxy 启动与健康轮询（带 token） ---
async function waitForToken(ms = 8000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    try { const t = fs.readFileSync(TOKEN_FILE, 'utf8').trim(); if (t) return t; } catch {}
    await new Promise(r => setTimeout(r, 300));
  }
  return null;
}

function httpGetJson(url, token, timeoutMs = 3000) {
  return fetch(url, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    signal: AbortSignal.timeout(timeoutMs),
  }).then(async (res) => { try { return JSON.parse(await res.text()); } catch { return null; } }).catch(() => null);
}

function startProxyDetached(browserOverride) {
  const logFile = path.join(os.tmpdir(), 'cdp-proxy.log');
  const logFd = fs.openSync(logFile, 'a');
  const args = [path.join(ROOT, 'scripts', 'cdp-proxy.mjs')];
  if (browserOverride) args.push('--browser', browserOverride);
  const child = spawn(process.execPath, args, {
    detached: true, stdio: ['ignore', logFd, logFd],
    ...(os.platform() === 'win32' ? { windowsHide: true } : {}),
  });
  child.unref();
  fs.closeSync(logFd);
}

async function ensureProxy(expectedBrowserId, browserOverride) {
  let token = await waitForToken(0);
  const healthUrl = `http://127.0.0.1:${PROXY_PORT}/health`;
  const targetsUrl = `http://127.0.0.1:${PROXY_PORT}/targets`;

  if (token) {
    const health = await httpGetJson(healthUrl, token);
    if (health?.status === 'ok' && health.connected) {
      const runningId = health.browser?.id;
      if (expectedBrowserId === 'dedicated' && runningId !== 'dedicated') {
        console.log(`proxy: 当前连接非专用实例，需重启 —— 运行 node scripts/stop-proxy.mjs 后重跑本命令`);
        return false;
      }
      console.log(`proxy: ready (${health.browser?.label || 'unknown'})`);
      return true;
    }
  }

  console.log('proxy: starting...');
  startProxyDetached(browserOverride);
  token = await waitForToken(8000);
  if (!token) { console.error('❌ proxy 未写出 token（查看 %TEMP%\\cdp-proxy.log）'); return false; }

  for (let i = 1; i <= 15; i++) {
    const result = await httpGetJson(targetsUrl, token, 8000);
    if (Array.isArray(result)) {
      const h = await httpGetJson(healthUrl, token);
      console.log(`proxy: ready (${h?.browser?.label || 'unknown'})`);
      return true;
    }
    if (i === 1) console.log('⚠️  等待浏览器连接中（专用实例若未启动会被自动拉起）...');
    await new Promise(r => setTimeout(r, 1000));
  }
  console.error('❌ 连接超时。日志：' + path.join(os.tmpdir(), 'cdp-proxy.log'));
  return false;
}

// --- 浏览器决策（含 strict 自动拉起） ---
async function resolveBrowser(override, cfg) {
  const result = await selectBrowser(override, cfg.browser, { isolation: cfg.isolation });
  switch (result.kind) {
    case 'ok': {
      const tag = { override: '[--browser 指定]', preference: '[permissions.json 偏好]', dedicated: '[专用隔离实例]' }[result.source] || '';
      console.log(`browser: ok (${result.browser.label}, port ${result.browser.port}) ${tag}`);
      return { proceed: true, browserId: result.browser.id };
    }
    case 'no-dedicated': {
      console.log('browser: 专用隔离实例未运行，正在启动...');
      const inst = await launchBrowser(override);
      if (!inst) return { proceed: false, exitCode: 1 };
      console.log(`browser: ok (专用隔离实例, 端口 ${inst.port})`);
      return { proceed: true, browserId: 'dedicated' };
    }
    case 'ambiguous': {
      const detectedIds = new Set(result.detected.map(b => b.id));
      console.log(`browser: needs decision — 未设偏好。已开调试：${result.detected.map(b => `${b.label}(${b.port})`).join('、') || '无'}`);
      console.log('  其他可配置：' + knownBrowsers().filter(b => !detectedIds.has(b.id)).map(b => b.label).join('、'));
      console.log('  请询问用户在 permissions.json 设 "browser" 字段');
      return { proceed: false, exitCode: 2 };
    }
    case 'mismatch': case 'empty': {
      console.log(`browser: error — isolation=off 模式下 ${result.kind}`);
      console.log('  建议回到默认 strict 隔离模式（专用实例由 launch-browser.mjs 管理）');
      return { proceed: false, exitCode: 1 };
    }
  }
}

async function main() {
  ensureRuntimeDir();
  migrateLegacy();

  let perms;
  try { perms = loadPermissions(); }
  catch (e) { console.error('❌ ' + e.message); process.exit(1); }
  if (perms.fileMissing) console.log('⚠️  permissions.json 缺失——正在使用内置默认策略');
  console.log(profileLine(perms.cfg));

  checkNode();

  const opts = parseArgs(process.argv.slice(2));
  const { proceed, exitCode, browserId } = await resolveBrowser(opts.browser, perms.cfg);
  if (!proceed) process.exit(exitCode);

  const proxyOk = await ensureProxy(browserId, opts.browser);
  if (!proxyOk) process.exit(1);

  const patternsDir = path.join(ROOT, 'references', 'site-patterns');
  try {
    const sites = fs.readdirSync(patternsDir).filter(f => f.endsWith('.md')).map(f => f.replace(/\.md$/, ''));
    if (sites.length) console.log(`\nsite-patterns: ${sites.join(', ')}`);
  } catch {}
}

await main();
