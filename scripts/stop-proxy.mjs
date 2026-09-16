#!/usr/bin/env node
// scripts/stop-proxy.mjs —— 停止 cdp-proxy（替代 6 处 pkill -f cdp-proxy.mjs，跨平台）
import fs from 'node:fs';
import { PID_FILE } from './paths.mjs';

let pid = NaN;
try { pid = parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10); } catch {}
if (!Number.isInteger(pid) || pid <= 0) {
  console.log('没有找到运行中的 proxy（无 pid 记录）。若进程仍存活，可手动结束 node cdp-proxy.mjs。');
  process.exit(0);
}
try {
  process.kill(pid);
  console.log(`已停止 proxy（pid ${pid}）`);
} catch (e) {
  if (e.code === 'ESRCH') console.log(`pid ${pid} 已不存在（proxy 可能已退出）`);
  else { console.error(`停止失败：${e.message}`); process.exit(1); }
}
try { fs.unlinkSync(PID_FILE); } catch {}
