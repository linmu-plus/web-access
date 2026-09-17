#!/usr/bin/env node
// close-browser.mjs — 关闭专用隔离实例。
//
// 为什么单独一个脚本：专用实例是"登录态载体"，日常任务里应该长驻（冷启动慢、反复拉起要重新登录、
// 每次都触发权限确认）；但**验证/排查/临时**用途拉起的实例用完必须关掉，否则会残留后台浏览器进程、
// 占着 9222 端口、并在用户下次使用时表现出"莫名其妙的窗口"。
//
// 只关专用实例，绝不触碰用户日常浏览器：只认 dedicated.json 记录，或本 skill 固定约定的 9222 调试端口。
// 关闭顺序：CDP Browser.close（优雅，浏览器走正常退出流程，能落盘 profile）→ 失败则按 pid 终止 → 仍失败报错。
//
// 用法：node "<skill-base-dir>/scripts/close-browser.mjs"
// 幂等：实例没在运行时正常退出（exit 0），不报错。

import fs from 'node:fs';
import path from 'node:path';
import { BROWSER_DIR } from './paths.mjs';
import { checkPort } from './browser-discovery.mjs';
import { isMainEntry } from './paths.mjs';

const RECORD_PATH = path.join(BROWSER_DIR, 'dedicated.json');
const DEFAULT_PORT = 9222;
const CLOSE_TIMEOUT_MS = 8000;
const RELEASE_TIMEOUT_MS = 15000;

function log(msg) {
  process.stdout.write(msg + '\n');
}

// 清理失败要说清楚：残留记录会让下次启动误判"实例仍在"，属于必须让用户知道的状态。
function reportClear(result) {
  if (result.ok) return;
  log(`注意：实例记录未能清理（${result.error?.code || result.error?.message}）：${RECORD_PATH}`);
  log('该记录会让下次启动误判"实例仍在"，请手动删除。');
}

function readRecord() {
  try {
    const raw = fs.readFileSync(RECORD_PATH, 'utf8').replace(/^\uFEFF/, '');
    const rec = JSON.parse(raw);
    return rec && typeof rec === 'object' ? rec : null;
  } catch {
    return null;
  }
}

// 返回 {ok, error}：清理失败必须让调用方知道。记录若残留，下次启动会拿它当"实例仍在"，进而误判。
function clearRecord() {
  try {
    fs.unlinkSync(RECORD_PATH);
    return { ok: true, error: null };
  } catch (err) {
    if (err && err.code === 'ENOENT') return { ok: true, error: null };
    return { ok: false, error: err };
  }
}

// 记录里没有 wsPath 时（例如实例是人工手起的），从 HTTP 端点补取。
async function fetchWsPath(port) {
  try {
    const res = await fetch(`http://127.0.0.1:${port}/json/version`, {
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) return null;
    const info = await res.json();
    if (!info || typeof info.webSocketDebuggerUrl !== 'string') return null;
    return new URL(info.webSocketDebuggerUrl).pathname;
  } catch {
    return null;
  }
}

// 发 Browser.close 后浏览器会自行退出，socket 随之关闭——不等响应，以 close 事件为成功信号。
function cdpClose(port, wsPath) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (ok) => {
      if (settled) return;
      settled = true;
      resolve(ok);
    };
    let ws;
    try {
      ws = new WebSocket(`ws://127.0.0.1:${port}${wsPath}`);
    } catch {
      return done(false);
    }
    const timer = setTimeout(() => {
      try { ws.close(); } catch {}
      done(false);
    }, CLOSE_TIMEOUT_MS);
    ws.addEventListener('open', () => {
      try {
        ws.send(JSON.stringify({ id: 1, method: 'Browser.close' }));
      } catch {
        clearTimeout(timer);
        done(false);
      }
    });
    ws.addEventListener('close', () => {
      clearTimeout(timer);
      done(true);
    });
    ws.addEventListener('error', () => {
      clearTimeout(timer);
      done(false);
    });
  });
}

async function waitForRelease(port, timeoutMs = RELEASE_TIMEOUT_MS) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (!(await checkPort(port))) return true;
    if (Date.now() >= deadline) return false;
    await new Promise((r) => setTimeout(r, 400));
  }
}

// 回退路径：pid 必须是正整数，避免误杀（记录损坏时不能拿垃圾值去 kill）。
function killPid(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid);
    return true;
  } catch {
    return false;
  }
}

async function main() {
  const record = readRecord();
  const port = Number.isInteger(record?.port) && record.port > 0 ? record.port : DEFAULT_PORT;

  if (!(await checkPort(port))) {
    log(`专用实例未在运行（端口 ${port} 无监听）。`);
    reportClear(clearRecord());
    return 0;
  }

  log(`发现专用实例（端口 ${port}），正在关闭…`);

  // 1) 优雅路径
  const wsPath = typeof record?.wsPath === 'string' && record.wsPath
    ? record.wsPath
    : await fetchWsPath(port);
  if (wsPath) {
    const ok = await cdpClose(port, wsPath);
    if (ok && (await waitForRelease(port))) {
      log('已通过 CDP Browser.close 优雅关闭专用实例。');
      reportClear(clearRecord());
      return 0;
    }
  }

  // 2) 回退：按记录中的 pid 终止
  const pid = record?.pid;
  if (killPid(pid)) {
    log(`CDP 关闭未生效，已按 pid ${pid} 终止进程。`);
    if (await waitForRelease(port)) {
      log('已关闭专用实例。');
      reportClear(clearRecord());
      return 0;
    }
  }

  // 3) 兜底：不动用户日常浏览器，交由人工处理
  log(`关闭失败：端口 ${port} 仍在监听。请手动关闭该调试实例后重试（不要直接关闭用户日常浏览器）。`);
  return 1;
}

if (isMainEntry(import.meta.url)) {
  process.exitCode = await main();
}

export { readRecord, clearRecord, killPid, waitForRelease };
