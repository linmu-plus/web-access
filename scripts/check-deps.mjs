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
import { loadPermissions, migrateLegacyConfig, profileLine } from './permissions.mjs';

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

// 真读一次 token 文件（替代恒返回 null 的 waitForToken(0)）
function readTokenFile() {
  try { const t = fs.readFileSync(TOKEN_FILE, 'utf8').trim(); return t || null; } catch { return null; }
}

function httpGetJson(url, token, timeoutMs = 3000) {
  return fetch(url, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    signal: AbortSignal.timeout(timeoutMs),
  }).then(async (res) => { try { return JSON.parse(await res.text()); } catch { return null; } }).catch(() => null);
}

// 无鉴权探测：只要端口上返回了任何 HTTP 响应（如 403）即说明有活的 HTTP 服务；
// 连接被拒/超时（fetch throw）才视为无活 proxy。
function probeAlive(url) {
  return fetch(url, { signal: AbortSignal.timeout(2000) })
    .then(async (res) => { try { await res.text(); } catch {} return true; })
    .catch(() => false);
}

function startProxyDetached(browserOverride) {
  const logFile = path.join(os.tmpdir(), 'cdp-proxy.log');
  const logFd = fs.openSync(logFile, 'a');
  const args = [PROXY_SCRIPT];
  if (browserOverride) args.push('--browser', browserOverride);
  const child = spawn(process.execPath, args, {
    detached: true, stdio: ['ignore', logFd, logFd],
    ...(os.platform() === 'win32' ? { windowsHide: true } : {}),
  });
  child.unref();
  fs.closeSync(logFd);
}

// 轮询 /targets 直到就绪或失败；带 .error 字段的 JSON（auth.mjs 的可行动中文自救信息）原文透出
async function pollTargets(targetsUrl, healthUrl, token, expectedBrowserId = null) {
  for (let i = 1; i <= 15; i++) {
    const result = await httpGetJson(targetsUrl, token, 8000);
    if (Array.isArray(result)) {
      const h = await httpGetJson(healthUrl, token);
      console.log(`proxy: ready (${h?.browser?.label || 'unknown'})`);
      return true;
    }
    if (result && typeof result === 'object' && result.error) {
      console.error('❌ proxy 拒绝请求：' + result.error);
      return false;
    }
    if (i === 1) console.log('⚠️  等待浏览器连接中（专用实例若未启动会被自动拉起）...');
    await new Promise(r => setTimeout(r, 1000));
  }
  console.error('❌ 连接超时。日志：' + path.join(os.tmpdir(), 'cdp-proxy.log'));
  if (expectedBrowserId === 'dedicated') {
    console.error('❌ 专用隔离实例可能已退出（记录陈旧）。处理：重跑 node scripts/launch-browser.mjs 重建');
  }
  return false;
}

async function ensureProxy(expectedBrowserId, browserOverride) {
  const healthUrl = `http://127.0.0.1:${PROXY_PORT}/health`;
  const targetsUrl = `http://127.0.0.1:${PROXY_PORT}/targets`;

  const token = readTokenFile();
  if (token) {
    const health = await httpGetJson(healthUrl, token);
    if (health?.status === 'ok' && health.connected) {
      // 复用分支（复用守卫对称化）：期望浏览器与运行中浏览器双向比对；
      // runningId 为 'unknown'（isolation=off 手动 fallback 端口）时无法可靠比对，豁免
      const runningId = health.browser?.id;
      if (expectedBrowserId && runningId && runningId !== 'unknown' && runningId !== expectedBrowserId) {
        console.log(`proxy: 当前连接浏览器(${runningId})与期望(${expectedBrowserId})不一致，需重启 —— 运行 node scripts/stop-proxy.mjs 后重跑本命令`);
        return false;
      }
      console.log(`proxy: ready (${health.browser?.label || 'unknown'})`);
      return true;
    }
    if (health?.status === 'ok') {
      // proxy 活着但未连浏览器 → 不 spawn（避免端口被占导致子进程退出），直接用该 token 轮询
      console.log('proxy: 已在运行（未连接浏览器），等待连接...');
      return pollTargets(targetsUrl, healthUrl, token, expectedBrowserId);
    }
    if (health && health.error) {
      // 403 JSON（token 不匹配等）→ 把 auth.mjs 的自救信息原文透出
      console.error('❌ proxy /health 鉴权失败：' + health.error);
      return false;
    }
    if (health === null) {
      // fetch 失败：区分「proxy 活着但我们没有有效 token」与「无活 proxy」
      if (await probeAlive(healthUrl)) {
        console.error('❌ token 文件与运行中的 proxy 不匹配。处理：运行 node scripts/stop-proxy.mjs 后重跑 check-deps.mjs');
        return false;
      }
      // 连接拒绝 → 无活 proxy → 继续启动
    }
  } else {
    // token 文件缺失/为空：同样先探测是否有活 proxy（活 proxy 只在 fresh listen 时写 token，
    // 此场景下直接 spawn 的新子进程会探测到健康实例后静默退出 → 误报「未写出 token」；
    // 且 unlink 会交错删掉新 proxy 刚写的 token，造成「活 proxy + 无 token」砖状态）
    if (await probeAlive(healthUrl)) {
      console.error('❌ proxy 在运行但 token 文件缺失/为空。处理：运行 node scripts/stop-proxy.mjs 后重跑 check-deps.mjs');
      return false;
    }
    // 连接拒绝 → 无活 proxy → 继续启动
  }

  console.log('proxy: starting...');
  try { fs.unlinkSync(TOKEN_FILE); } catch {}  // 走到这里说明两条路径（token 有效探测失败 / token 缺失/为空探测失败）都已确认无活 proxy，清掉陈旧 token，避免误读为旧值（此前两处清理都只删 pid 的遗留竞态）
  startProxyDetached(browserOverride);
  const newToken = await waitForToken(8000);
  if (!newToken) { console.error('❌ proxy 未写出 token（查看 %TEMP%\\cdp-proxy.log）'); return false; }
  return pollTargets(targetsUrl, healthUrl, newToken, expectedBrowserId);
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
