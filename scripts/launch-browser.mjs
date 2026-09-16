#!/usr/bin/env node
// scripts/launch-browser.mjs —— 启动专用隔离浏览器实例（isolation=strict 下的唯一合法连接对象）
// 用法：node launch-browser.mjs [--browser chrome|edge]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { BROWSER_DIR, ensureRuntimeDir } from './paths.mjs';
import { knownBrowsers, checkPort, findDedicatedInstance } from './browser-discovery.mjs';
import { loadPermissions } from './permissions.mjs';

function die(msg) { console.error('❌ ' + msg); process.exit(1); }

function parseBrowserArg() {
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--browser' && argv[i + 1]) return argv[i + 1];
    if (argv[i].startsWith('--browser=')) return argv[i].slice('--browser='.length);
  }
  return null;
}

export async function launchBrowser(override = null) {
  ensureRuntimeDir();
  const { cfg } = loadPermissions();
  const id = override || cfg.browser;
  const b = knownBrowsers().find(x => x.id === id);
  if (!b) {
    die(`未指定浏览器：在 permissions.json 设 "browser": "chrome|edge"，或运行 node launch-browser.mjs --browser chrome|edge`);
  }
  const exe = (b.exePaths || []).find(p => fs.existsSync(p) || !p.includes(path.sep));
  if (!exe) die(`找不到 ${b.label} 可执行文件。已尝试：${(b.exePaths || []).join('；')}`);

  const existing = await findDedicatedInstance();
  if (existing) {
    console.log(`专用实例已在运行（端口 ${existing.port}），无需重复启动`);
    return existing;
  }
  if (await checkPort(9222)) {
    die(`端口 9222 已被其他进程占用（可能是日常浏览器手动开过调试端口）。关闭占用者后重试。`);
  }

  console.log(`启动 ${b.label} 专用实例（数据目录 ${BROWSER_DIR}）`);
  const child = spawn(exe, [
    `--user-data-dir=${BROWSER_DIR}`,
    '--remote-debugging-port=9222',
    '--no-first-run',
    '--no-default-browser-check',
  ], { detached: true, stdio: 'ignore', ...(os.platform() === 'win32' ? { windowsHide: false } : {}) });
  child.unref();

  // 就绪判定双通道（任一满足即就绪）：
  // 1) 旧路径：DevToolsActivePort 文件存在且首行端口 >0（兼容旧内核浏览器）
  // 2) 新路径：HTTP 探测 /json/version —— Chromium 153 内核不再写 DevToolsActivePort，
  //    改由这里确认后写入 dedicated.json（自建记录，供 findDedicatedInstance 发现）
  const portFile = path.join(BROWSER_DIR, 'DevToolsActivePort');
  for (let i = 0; i < 120; i++) {
    await new Promise(r => setTimeout(r, 500));
    try {
      const port = parseInt(fs.readFileSync(portFile, 'utf8').trim().split(/\r?\n/)[0], 10);
      if (port > 0) { console.log(`✅ 专用实例就绪（端口 ${port}）`); return await findDedicatedInstance(); }
    } catch { /* 尚未就绪 */ }
    try {
      const res = await fetch('http://127.0.0.1:9222/json/version', { signal: AbortSignal.timeout(5000) });
      if (res.ok) {
        const info = await res.json();
        const wsUrl = info?.webSocketDebuggerUrl;
        if (typeof wsUrl === 'string' && wsUrl.startsWith('ws://')) {
          const wsPath = new URL(wsUrl).pathname;
          fs.writeFileSync(path.join(BROWSER_DIR, 'dedicated.json'),
            JSON.stringify({ port: 9222, wsPath, confirmedAt: new Date().toISOString() }, null, 2) + '\n');
          console.log('✅ 专用实例就绪（端口 9222，HTTP 探测确认）');
          return await findDedicatedInstance();
        }
      }
    } catch { /* HTTP 探测失败，继续轮询 */ }
  }
  die('60 秒内专用实例未就绪（DevToolsActivePort 未生成且调试端口 HTTP 探测无响应）。若浏览器已弹出窗口，稍后重跑本命令。');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const inst = await launchBrowser(parseBrowserArg());
  process.exit(inst ? 0 : 1);
}
