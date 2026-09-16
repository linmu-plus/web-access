// 浏览器 CDP 端口发现 + 选择 - 单一职责模块
// 被 cdp-proxy.mjs / check-deps.mjs / launch-browser.mjs 共享
// isolation=strict（默认策略）：只认 %USERPROFILE%\.web-access\browser 下的专用隔离实例
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { BROWSER_DIR } from './paths.mjs';

// 已知支持 remote debugging 的浏览器：devToolsPath（日常安装的调试端口文件）+ exePaths（启动专用实例用）
// 加新浏览器：只改这里
export function knownBrowsers() {
  const home = os.homedir();
  const localAppData = process.env.LOCALAPPDATA || '';
  const pf = process.env.ProgramFiles || 'C:\\Program Files';
  const pf86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
  switch (os.platform()) {
    case 'darwin':
      return [
        { id: 'chrome',   label: 'Chrome',         devToolsPath: path.join(home, 'Library/Application Support/Google/Chrome/DevToolsActivePort'), exePaths: ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'] },
        { id: 'chrome-canary', label: 'Chrome Canary', devToolsPath: path.join(home, 'Library/Application Support/Google/Chrome Canary/DevToolsActivePort'), exePaths: ['/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary'] },
        { id: 'chromium', label: 'Chromium',       devToolsPath: path.join(home, 'Library/Application Support/Chromium/DevToolsActivePort'), exePaths: ['/Applications/Chromium.app/Contents/MacOS/Chromium'] },
        { id: 'edge',     label: 'Microsoft Edge', devToolsPath: path.join(home, 'Library/Application Support/Microsoft Edge/DevToolsActivePort'), exePaths: ['/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge'] },
      ];
    case 'linux':
      return [
        { id: 'chrome',   label: 'Chrome',         devToolsPath: path.join(home, '.config/google-chrome/DevToolsActivePort'), exePaths: ['google-chrome', 'google-chrome-stable'] },
        { id: 'chromium', label: 'Chromium',       devToolsPath: path.join(home, '.config/chromium/DevToolsActivePort'), exePaths: ['chromium', 'chromium-browser'] },
        { id: 'edge',     label: 'Microsoft Edge', devToolsPath: path.join(home, '.config/microsoft-edge/DevToolsActivePort'), exePaths: ['microsoft-edge'] },
      ];
    case 'win32':
      return [
        { id: 'chrome',   label: 'Chrome',         devToolsPath: path.join(localAppData, 'Google/Chrome/User Data/DevToolsActivePort'), exePaths: [path.join(localAppData, 'Google/Chrome/Application/chrome.exe'), path.join(pf, 'Google/Chrome/Application/chrome.exe'), path.join(pf86, 'Google/Chrome/Application/chrome.exe')] },
        { id: 'chromium', label: 'Chromium',       devToolsPath: path.join(localAppData, 'Chromium/User Data/DevToolsActivePort'), exePaths: [path.join(localAppData, 'Chromium/Application/chrome.exe'), path.join(pf, 'Chromium/Application/chrome.exe')] },
        { id: 'edge',     label: 'Microsoft Edge', devToolsPath: path.join(localAppData, 'Microsoft/Edge/User Data/DevToolsActivePort'), exePaths: [path.join(localAppData, 'Microsoft/Edge/Application/msedge.exe'), path.join(pf86, 'Microsoft/Edge/Application/msedge.exe'), path.join(pf, 'Microsoft/Edge/Application/msedge.exe')] },
      ];
    default:
      return [];
  }
}

// TCP 端口监听检测（不触发浏览器调试授权弹窗）
export function checkPort(port, host = '127.0.0.1', timeoutMs = 2000) {
  return new Promise((resolve) => {
    const socket = net.createConnection(port, host);
    const timer = setTimeout(() => { socket.destroy(); resolve(false); }, timeoutMs);
    socket.once('connect', () => { clearTimeout(timer); socket.destroy(); resolve(true); });
    socket.once('error', () => { clearTimeout(timer); resolve(false); });
  });
}

// 专用隔离实例：两级发现
// 1) 旧通道：读 <dir>\DevToolsActivePort（旧内核浏览器，逻辑不变）
// 2) 新通道：Chromium 153+ 不再写 DevToolsActivePort，改读 launch-browser 写入的
//    <dir>\dedicated.json（{ port, wsPath, confirmedAt }）——解析失败/字段缺失或非法一律 fail-closed 返回 null
export async function findDedicatedInstance(dir = BROWSER_DIR) {
  // 旧通道：DevToolsActivePort 端口文件
  let content;
  try { content = fs.readFileSync(path.join(dir, 'DevToolsActivePort'), 'utf8'); } catch { content = null; }
  if (content !== null) {
    const lines = content.trim().split(/\r?\n/).filter(Boolean);
    const port = parseInt(lines[0], 10);
    if (!(port > 0 && port < 65536)) return null;
    if (!(await checkPort(port))) return null;
    return { id: 'dedicated', label: '专用隔离实例', devToolsPath: path.join(dir, 'DevToolsActivePort'), port, wsPath: lines[1] || null, dedicatedDir: dir };
  }
  // 新通道：dedicated.json 自建记录
  let rec;
  try { rec = JSON.parse(fs.readFileSync(path.join(dir, 'dedicated.json'), 'utf8')); } catch { return null; }
  const port = rec?.port;
  const wsPath = rec?.wsPath;
  if (!Number.isInteger(port) || !(port > 0 && port < 65536)) return null;
  if (typeof wsPath !== 'string' || !wsPath || !rec.confirmedAt) return null;
  if (!(await checkPort(port))) return null;
  // 陈旧记录防护：记录含 pid 时，TCP 活端口之外还要求进程本体存活（process.kill(pid,0)）——
  // 专用浏览器死亡后记录持久残留，若端口被其它进程占用，无此校验会把冒名者当专用实例接受
  if (rec.pid !== undefined && rec.pid !== null) {
    try { process.kill(rec.pid, 0); } catch { return null; }
  }
  return { id: 'dedicated', label: '专用隔离实例', devToolsPath: path.join(dir, 'dedicated.json'), port, wsPath, dedicatedDir: dir };
}

// 兜底（仅 isolation=off 时使用）：扫描常用固定端口
export async function findFallbackPort() {
  for (const port of [9222, 9229, 9333]) if (await checkPort(port)) return port;
  return null;
}

// 决策入口
// override  — 命令行 --browser（最高优先，仅 isolation=off 时生效）
// configured— permissions.json 的 browser 值（仅 isolation=off 时生效）
// strict 模式：只认专用隔离实例，默认路径扫描与 fallback 端口全部不走
export async function selectBrowser(override = null, configured = null, opts = {}) {
  const isolation = opts.isolation ?? 'off';
  const dedicatedDir = opts.dedicatedDir ?? BROWSER_DIR;

  if (isolation === 'strict') {
    const dedicated = await findDedicatedInstance(dedicatedDir);
    if (dedicated) return { kind: 'ok', browser: dedicated, source: 'dedicated', detected: [], configured, isolation };
    return { kind: 'no-dedicated', detected: [], configured, isolation };
  }

  const detected = (await detectAll());
  if (override) {
    const match = detected.find(b => b.id === override);
    if (match) return { kind: 'ok', browser: match, source: 'override', detected, configured, override, isolation };
    return { kind: 'mismatch', source: 'override', detected, configured, override, isolation };
  }
  if (configured) {
    const match = detected.find(b => b.id === configured);
    if (match) return { kind: 'ok', browser: match, source: 'preference', detected, configured, isolation };
    return { kind: 'mismatch', source: 'preference', detected, configured, isolation };
  }
  if (detected.length === 0) return { kind: 'empty', detected, configured, isolation };
  return { kind: 'ambiguous', detected, configured, isolation };
}

// 返回所有开了 toggle 且端口活的日常浏览器（isolation=off 模式专用）
async function detectAll() {
  const result = [];
  for (const browser of knownBrowsers()) {
    let content;
    try { content = fs.readFileSync(browser.devToolsPath, 'utf8'); } catch { continue; }
    const lines = content.trim().split(/\r?\n/).filter(Boolean);
    const port = parseInt(lines[0], 10);
    if (!(port > 0 && port < 65536)) continue;
    if (!(await checkPort(port))) continue;
    result.push({ ...browser, port, wsPath: lines[1] || null });
  }
  return result;
}
