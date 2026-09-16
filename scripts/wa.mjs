#!/usr/bin/env node
// scripts/wa.mjs —— web-access 统一调用封装：读 token → 带鉴权调 proxy → 错误透传
// 用法：node wa.mjs <endpoint> [args...]   （endpoint 列表见 SKILL.md「Proxy API」节）
// 确认门：confirm.mode=hard 时先由用户运行 confirm.mjs，再以 WA_CONFIRM=<code> 环境变量调用
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
import { TOKEN_FILE } from './paths.mjs';

const PORT = process.env.CDP_PROXY_PORT || 3456;
const POST_ENDPOINTS = new Set(['new', 'navigate', 'eval', 'click', 'clickAt', 'setFiles']);

function die(msg) { console.error('❌ ' + msg); process.exit(1); }

export function buildRequest(argv) {
  const [endpoint, ...args] = argv;
  if (!endpoint || endpoint === 'help') {
    throw new Error('用法：node wa.mjs <new|navigate|eval|click|clickAt|setFiles|screenshot|scroll|back|info|close|targets|health> [args...]');
  }
  const need = (n) => { if (args.length < n) throw new Error(`参数不足：${endpoint} 需要至少 ${n} 个参数`); };
  if (!POST_ENDPOINTS.has(endpoint) && !['health', 'targets', 'info', 'back', 'close', 'scroll', 'screenshot'].includes(endpoint)) {
    throw new Error(`未知 endpoint: ${endpoint}`);
  }
  const q = (pairs) => '?' + pairs.filter(Boolean).join('&');
  switch (endpoint) {
    case 'new': need(1); return { method: 'POST', endpoint: '/new', body: args.join(' ') };
    case 'navigate': need(2); return { method: 'POST', endpoint: `/navigate?target=${encodeURIComponent(args[0])}`, body: args[1] };
    case 'eval': need(1); return { method: 'POST', endpoint: `/eval?target=${encodeURIComponent(args[0])}`, body: args.slice(1).join(' ') || 'document.title' };
    case 'click': case 'clickAt': need(2); return { method: 'POST', endpoint: `/${endpoint}?target=${encodeURIComponent(args[0])}`, body: args[1] };
    case 'setFiles': {
      need(3);
      return { method: 'POST', endpoint: `/setFiles?target=${encodeURIComponent(args[0])}`, body: JSON.stringify({ selector: args[1], files: args.slice(2) }) };
    }
    case 'screenshot': need(1); return { method: 'GET', endpoint: `/screenshot${q([`target=${encodeURIComponent(args[0])}`, args[1] && `file=${encodeURIComponent(args[1])}`])}`, body: undefined };
    case 'scroll': need(1); return { method: 'GET', endpoint: `/scroll${q([`target=${encodeURIComponent(args[0])}`, args[1] && `y=${encodeURIComponent(args[1])}`, args[2] && `direction=${encodeURIComponent(args[2])}`])}`, body: undefined };
    case 'back': case 'info': case 'close': need(1); return { method: 'GET', endpoint: `/${endpoint}?target=${encodeURIComponent(args[0])}`, body: undefined };
    case 'targets': case 'health': return { method: 'GET', endpoint: `/${endpoint}`, body: undefined };
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let req;
  try { req = buildRequest(process.argv.slice(2)); } catch (e) { die(e.message); }
  const { method, endpoint, body } = req;
  let token;
  try { token = fs.readFileSync(TOKEN_FILE, 'utf8').trim(); }
  catch { die(`读不到 token（${TOKEN_FILE}）。处理：运行 node <base>/scripts/check-deps.mjs 重新拉起 proxy。`); }
  const headers = { Authorization: `Bearer ${token}` };
  const confirm = process.env.WA_CONFIRM;
  if (confirm) headers['X-Web-Access-Confirm'] = confirm;
  const res = await fetch(`http://127.0.0.1:${PORT}${endpoint}`, { method, headers, ...(body !== undefined ? { body } : {}) });
  const text = await res.text();
  if (res.status >= 400) die(`HTTP ${res.status} ${endpoint}\n${text}`);
  console.log(text);
}
