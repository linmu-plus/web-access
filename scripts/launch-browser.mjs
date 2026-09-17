#!/usr/bin/env node
// scripts/launch-browser.mjs —— 启动专用隔离浏览器实例（isolation=strict 下的唯一合法连接对象）
// 用法：node launch-browser.mjs [--browser chrome|edge]
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { BROWSER_DIR, ensureRuntimeDir, isMainEntry } from './paths.mjs';
import { knownBrowsers, checkPort, findDedicatedInstance } from './browser-discovery.mjs';
import { loadPermissions } from './permissions.mjs';

function die(msg) { console.error('❌ ' + msg); process.exit(1); }

// F) 身份状态检查（纯函数，可测）：解析 Local State 的 profile.info_cache，
// 任一 entry 的 user_name 非空 → 视为已登录，返回账号名；否则 null（干净）。
// 解析失败抛错由调用方兜底（浏览器可能尚未异步写入 Local State → 报「身份状态未知」）。
export function detectSignedInAccount(localStateJson) {
  const data = JSON.parse(localStateJson);
  const cache = data?.profile?.info_cache;
  if (!cache || typeof cache !== 'object') return null;
  for (const entry of Object.values(cache)) {
    const name = entry?.user_name;
    if (typeof name === 'string' && name.trim()) return name;
  }
  return null;
}

// H) 首启导入污染检测（纯函数，可测）：仅对全新数据目录在就绪后调用。
// 背景（实测事故）：Edge 首启会自动导入用户日常 Chrome 的数据——书签（Default\Bookmarks）、
// 自动填充（Web Data）、密码（Login Data）、扩展与 Chrome 账号元数据
// （signin.accounts_metadata_dict）一并带入，且该导入通道与隐式登录相互独立：
// --no-first-run / First Run 哨兵 / --disable-sync / msImplicitSignin 特性禁用一条都拦不住。
// 多信号冗余判据（任一命中即污染）：
//   硬信号：Default\Bookmarks 文件存在——全新 profile 首启不会生成书签文件
//   软信号（同步通道）：Default\Preferences 的 signin.accounts_metadata_dict 非空
//     （Chrome 账号元数据被带入）或 sync.has_been_enabled === true（同步已启用过）
// 不查 profile 显示名：中文环境默认名（人员 1）跨环境易误判，软信号已并入上述实现。
// 命中返回描述列表（空数组=干净）；Preferences 读取/解析失败按该项未命中处理（防误杀）。
export function detectImportArtifacts(browserDir) {
  const hits = [];
  if (fs.existsSync(path.join(browserDir, 'Default', 'Bookmarks'))) {
    hits.push('Bookmarks 文件已存在（首启导入的书签副本，全新 profile 不会有此文件）');
  }
  // 注意：Default\Extensions 目录**不算**导入污染——机器上装有 IDM/迅雷等下载管理器时，
  // 其扩展会经机器级注册表/external_extensions.json 被注入任何新 profile，即使加了
  // --disable-extensions 文件仍会落盘（但不会注册加载：Preferences 无 settings 条目）。
  // 这是系统级已知行为，按已知噪音忽略，不再作为 kill+purge 依据。
  let prefs = null;
  try { prefs = JSON.parse(fs.readFileSync(path.join(browserDir, 'Default', 'Preferences'), 'utf8')); } catch { prefs = null; }
  const accounts = prefs?.signin?.accounts_metadata_dict;
  if (accounts && typeof accounts === 'object' && Object.keys(accounts).length > 0) {
    hits.push('检测到同步信号：Chrome 账号元数据已被带入（signin.accounts_metadata_dict 非空）');
  }
  if (prefs?.sync?.has_been_enabled === true) {
    hits.push('检测到同步已启用（Preferences sync.has_been_enabled=true）');
  }
  return hits;
}

// H) 首启导入污染检测的门控（纯函数，可测）：
// fresh 判据放宽（I2 事故形态）：目录存在但只有脚手架（早前浏览器尝试留下的
// First Run/空组件目录，无 Default）时，旧判据 `!fs.existsSync(BROWSER_DIR)` 会判为
// 非 fresh → 整个跳过导入检测，而浏览器仍可能按首启自动导入。
// 用户手动数据全在 Default\ 下——无 Default 即无用户数据可误杀，
// 因此「目录不存在」或「无 Default」都视为 fresh 并跑导入检测。
export function shouldRunImportCheck({ dirExists, defaultExists }) {
  return !dirExists || !defaultExists;
}

// M4）kill/purge 处的 pid 收集（纯函数，可测）：recordedPid 与 childPid 去重，
// 同一 pid 只 kill 一次；空值过滤，recordedPid 优先在前。
export function collectPids(recordedPid, childPid) {
  return [...new Set([recordedPid, childPid].filter(pid => pid != null))];
}

// 首启导入是异步过程，可能晚于就绪快照落盘（I1）：首次检测通过后延迟 5 秒复检一次。
export const IMPORT_RECHECK_DELAY_MS = 5000;

// I3）启动前占用检测（纯函数，可测）。
// 事故形态（2026-09-17 实测）：profile 被一个**未开调试端口**的 Chrome 占用时，Chrome 启动会
// 把参数交给既有实例后自身退出（singleton 机制）→ 9222 永不监听、DevToolsActivePort 永不生成
// → check-deps 干等 60 秒后报「专用实例未就绪」，把排查方向误导成「Chrome 起不来/不支持调试端口」。
// 实测反证：同机同版本 Chrome 153 用干净 profile 能正常开调试端口，失败时间窗内 profile 零写入
//（Chrome 在动 profile 之前就退出了）。故启动前必须先判占用，避免 60 秒空等 + 误导性报错。
// 三态：
//   free     无占用，可直接启动
//   stale    有残留锁标记（上次异常退出留下的 SingletonLock）但无进程占用 → 清掉锁再启动
//   occupied 确有进程占用 profile（或锁被持有）→ 必须人工处理，不能盲目启动
// 注意判据优先级：**有进程占用即 occupied**，此时残留锁标记是无意义的副产物，不能降级为 stale。
export function classifyProfileOccupancy({ lockHeld, hasSingletonLock, strayBrowserCount }) {
  if (Number(strayBrowserCount) > 0) return 'occupied';
  if (lockHeld) return 'occupied';
  if (hasSingletonLock) return 'stale';
  return 'free';
}

// 占用提示文案（纯函数，可测）：occupied 必须给出可操作出口，且不得复用「60 秒超时」措辞，
// 否则又会被误读为「浏览器起不来」。stale 说明会自动清理，无需用户动作。
export function occupancyMessage(state, port) {
  if (state === 'occupied') {
    return `专用实例的 profile 已被占用（数据目录 ${BROWSER_DIR}），但没有开放调试端口 ${port}。`
      + `这通常意味着上一次拉起的实例没有正常关闭——它会把新的启动参数接管后自行退出，`
      + `导致本脚本永远等不到调试端口。请先运行：node "<skill-base-dir>/scripts/close-browser.mjs" 关闭它，然后重试。`;
  }
  if (state === 'stale') {
    return `检测到上次异常退出残留的 profile 锁（SingletonLock），无进程占用，将自动清理后继续。`;
  }
  return null;
}

// I3）占用探测（IO 部分，配合上面的纯函数）。
// 探两个信号，任一命中即视为被占用：
//   1) SingletonLock 存在（Chromium singleton 单例锁）
//   2) 存在命令行含本 profile 路径的浏览器进程
// 第 2 项是 Windows 上更可靠的信号：Chromium 在 Windows 用命名互斥体而非仅靠 SingletonLock 文件，
// 锁文件可能不落盘或被上次异常退出的残留物覆盖，而「有没有进程拿着这个目录」才是真判据。
// WMI/CIM 在受限环境下可能被拒（实测 DSH 沙箱拒绝 Get-CimInstance）→ 探测失败按「未占用」放行，
// 不能因为探测不到就把正常启动全堵死（fail-open 仅限探测本身；真正的占用仍由后续 60 秒兜底）。
function probeProfileOccupancy() {
  const lockPath = path.join(BROWSER_DIR, 'SingletonLock');
  let hasSingletonLock = false;
  try { hasSingletonLock = fs.existsSync(lockPath); } catch { hasSingletonLock = false; }

  // 锁文件能否被独占打开：被持有则打不开。注意权限错误（EPERM/EACCES）与「被占用」在
  // Node 层不好区分，故此信号仅作辅助，主判据是进程枚举。
  let lockHeld = false;
  if (hasSingletonLock) {
    try {
      const fd = fs.openSync(lockPath, 'r+');
      fs.closeSync(fd);
    } catch {
      lockHeld = true;
    }
  }

  let strayBrowserCount = 0;
  try {
    const out = execFileSync('powershell', [
      '-NoProfile', '-Command',
      `@(Get-CimInstance Win32_Process -Filter "Name='chrome.exe' or Name='msedge.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*${BROWSER_DIR.replace(/'/g, "''")}*' }).Count`,
    ], { encoding: 'utf8', timeout: 8000, stdio: ['ignore', 'pipe', 'ignore'] });
    strayBrowserCount = parseInt(String(out).trim(), 10) || 0;
  } catch {
    strayBrowserCount = 0; // 探测不可用 → 放行（不阻断正常启动）
  }

  return { lockHeld, hasSingletonLock, strayBrowserCount };
}

// 身份状态检查（尽力而为的软报告，非拦截）：不硬失败、不杀浏览器——
// 硬杀会把用户手动登录的小号会话一起杀掉，与「专用实例允许手动登录选定站点」的语义冲突；
// 隐式登录的数据同步已由 --disable-sync 切断，这里只做状态披露。
function checkIdentityState() {
  try {
    const raw = fs.readFileSync(path.join(BROWSER_DIR, 'Local State'), 'utf8');
    const account = detectSignedInAccount(raw);
    if (account) {
      console.error(`⚠️ 专用实例检测到已登录账号：${account}——若非你手动登录，请在该实例的 edge://settings/profiles 断开，并考虑删除数据目录重建`);
    } else {
      console.error('✅ 专用实例身份状态：未登录（干净）');
    }
  } catch {
    console.error('⚠️ 专用实例身份状态未知（Local State 尚未写入或不可读，已跳过检查）');
  }
}

// H) 全新目录的收尾（升级版就绪验证）：就绪判定通过后做首启导入检测。
// I1）就绪快照可能早于首启导入落盘：首次检测通过后延迟 5 秒复检一次——
// 复检命中 → 同一 kill+purge+die 路径（die 文案注明「延迟复检发现」）；
// 复检干净 → 静默通过（复检在 die 之外不产生任何行为副作用）。
// 命中 → 杀掉刚 spawn 的实例（dedicated.json 记录 pid 优先 / child.pid 兜底，去重）→
// 1s 退避 → 删除整个 BROWSER_DIR（含导入副本）→ fail-closed die。
// 不自动重拉：全新目录重拉会再次触发首启导入形成死循环，处置权交给调用方。
// 目录已存在且含 Default（用户手动数据，重启场景）不做导入检测——用户手动往专用实例加书签属设计允许，避免误杀。
async function finalizeFreshInstance(freshDir, childPid) {
  const inst = await findDedicatedInstance();
  if (freshDir) {
    let hits = detectImportArtifacts(BROWSER_DIR);
    let detectedByRecheck = false;
    if (hits.length === 0) {
      await new Promise(r => setTimeout(r, IMPORT_RECHECK_DELAY_MS));
      hits = detectImportArtifacts(BROWSER_DIR);
      detectedByRecheck = hits.length > 0;
    }
    if (hits.length > 0) {
      let recordedPid = null;
      try { recordedPid = JSON.parse(fs.readFileSync(path.join(BROWSER_DIR, 'dedicated.json'), 'utf8'))?.pid ?? null; } catch { /* 无记录则用 child.pid */ }
      for (const pid of collectPids(recordedPid, childPid)) {
        try { process.kill(pid); } catch { /* 进程已退出，忽略 */ }
      }
      await new Promise(r => setTimeout(r, 1000));
      let rmError = null;
      try { fs.rmSync(BROWSER_DIR, { recursive: true, force: true }); } catch (e) { rmError = e; }
      die([
        rmError
          ? `检测到全新数据目录被浏览器首启自动导入污染（fail-closed：宁可拒绝工作，也不在污染实例上干活），已终止专用实例，但数据目录删除未完成（${rmError.message}）——需手动删除：${BROWSER_DIR}`
          : `检测到全新数据目录被浏览器首启自动导入污染（fail-closed：宁可拒绝工作，也不在污染实例上干活），已终止专用实例并删除数据目录 ${BROWSER_DIR}`,
        ...(detectedByRecheck ? ['说明：首次就绪检测未命中，延迟 5 秒复检才发现导入落盘（首启导入是异步过程，可能晚于就绪快照）'] : []),
        `命中项：${hits.join('；')}`,
        `机制：浏览器首启会自动导入你日常 Chrome 的书签/自动填充/密码/扩展与账号元数据——该导入通道与隐式登录相互独立，--no-first-run/--disable-sync 均拦不住，此为独立防线`,
        `出路：① 改用 --browser chrome 启动专用实例（需日常 Chrome 未运行时启动）② 设置 Edge 策略 AutoImportAtFirstRun=0 关闭首启自动导入（会影响日常 Edge 的首启导入行为，需你确认后自行设置）`,
      ].join('\n'));
    }
  }
  checkIdentityState();
  return inst;
}

function parseBrowserArg() {
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--browser' && argv[i + 1]) return argv[i + 1];
    if (argv[i].startsWith('--browser=')) return argv[i].slice('--browser='.length);
  }
  return null;
}

export async function launchBrowser(override = null) {
  // freshDir 判定必须在任何建目录动作之前。I2 门控放宽：目录存在但无 Default（只有
  // 脚手架，如早前浏览器尝试留下的 First Run/空组件目录）也视为 fresh 并跑导入检测——
  // 用户手动数据全在 Default\ 下，无 Default 即无用户数据可误杀。
  const dirExists = fs.existsSync(BROWSER_DIR);
  const freshDir = shouldRunImportCheck({
    dirExists,
    defaultExists: dirExists && fs.existsSync(path.join(BROWSER_DIR, 'Default')),
  });
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
    checkIdentityState();
    return existing;
  }
  if (await checkPort(9222)) {
    die(`端口 9222 已被其他进程占用（可能是日常浏览器手动开过调试端口）。关闭占用者后重试。`);
  }

  // I3）启动前占用检测：profile 被未开调试端口的实例占用时，Chrome 会把参数交给既有实例后
  // 自行退出 → 必然等满 60 秒并报出误导性的「未就绪」。这里提前判掉，1 秒内给出可操作提示。
  const occupancy = classifyProfileOccupancy(probeProfileOccupancy());
  if (occupancy === 'occupied') {
    die(occupancyMessage('occupied', 9222));
  }
  if (occupancy === 'stale') {
    console.log(occupancyMessage('stale', 9222));
    for (const f of ['SingletonLock', 'SingletonCookie', 'SingletonSocket']) {
      try { fs.rmSync(path.join(BROWSER_DIR, f), { force: true }); } catch { /* 尽力而为 */ }
    }
  }

  console.log(`启动 ${b.label} 专用实例（数据目录 ${BROWSER_DIR}）`);
  const child = spawn(exe, [
    `--user-data-dir=${BROWSER_DIR}`,
    '--remote-debugging-port=9222',
    '--no-first-run',
    '--no-default-browser-check',
    // 防隐式登录/同步邀请（OS 级账号注入邀请不被空 user-data-dir 挡住）
    '--disable-sync',
    '--disable-features=msImplicitSignin,ImplicitSignin',
    // 已知系统级行为：IDM/迅雷等下载管理器经 Chrome 安装目录 external_extensions.json 与
    // 注册表（HKLM\Software\[WOW6432Node\]Google\Chrome\Extensions）被机器级注入任何新
    // profile——实测 --disable-extensions 不能阻止其扩展文件落盘（Chromium 外部扩展
    // provider 照常解包），但会阻止注册加载：Preferences 无 settings 条目，chrome://extensions
    // 不可见，即「文件在磁盘、不运行」。按已知噪音接受；如需在专用实例手动装扩展，需去掉
    // 本参数重启（副作用：chrome://extensions 将不可用）。
    '--disable-extensions',
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
      if (port > 0) { console.log(`✅ 专用实例就绪（端口 ${port}）`); return await finalizeFreshInstance(freshDir, child.pid); }
    } catch { /* 尚未就绪 */ }
    try {
      const res = await fetch('http://127.0.0.1:9222/json/version', { signal: AbortSignal.timeout(5000) });
      if (res.ok) {
        const info = await res.json();
        const wsUrl = info?.webSocketDebuggerUrl;
        if (typeof wsUrl === 'string' && wsUrl.startsWith('ws://')) {
          const wsPath = new URL(wsUrl).pathname;
          // pid 记录进 dedicated.json：专用实例死后记录成为陈旧信任的判断依据（findDedicatedInstance 会用 process.kill(pid,0) 复核）
          fs.writeFileSync(path.join(BROWSER_DIR, 'dedicated.json'),
            JSON.stringify({ port: 9222, wsPath, pid: child.pid, confirmedAt: new Date().toISOString() }, null, 2) + '\n');
          console.log('✅ 专用实例就绪（端口 9222，HTTP 探测确认）');
          return await finalizeFreshInstance(freshDir, child.pid);
        }
      }
    } catch { /* HTTP 探测失败，继续轮询 */ }
  }
  die('60 秒内专用实例未就绪（DevToolsActivePort 未生成且调试端口 HTTP 探测无响应）。若浏览器已弹出窗口，稍后重跑本命令。');
}

if (isMainEntry(import.meta.url)) {
  const inst = await launchBrowser(parseBrowserArg());
  process.exit(inst ? 0 : 1);
}
