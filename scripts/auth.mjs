// scripts/auth.mjs
// HTTP 入口鉴权：token（主）+ Host/Origin/Sec-Fetch-Site（保险）
// 三层机制与攻击场景的对应关系见规格 §4 / §4b
import crypto from 'node:crypto';

export function newToken() {
  return crypto.randomBytes(32).toString('hex');
}

export function checkAuth(req, token, port) {
  const portStr = String(port);
  const host = String(req.headers.host || '').toLowerCase();
  const okHosts = [`127.0.0.1:${portStr}`, `localhost:${portStr}`];
  if (!okHosts.includes(host)) {
    return { status: 403, error: `Host 非法（"${host}"）。本服务只接受本机直连；若这是网页内的请求，此拒绝是预期防护（DNS rebinding 防线）。` };
  }
  const origin = req.headers.origin;
  if (origin) {
    let o;
    try { o = new URL(String(origin)); } catch { return { status: 403, error: `Origin 非法: ${origin}` }; }
    if (!['127.0.0.1', 'localhost'].includes(o.hostname) || o.port !== portStr) {
      return { status: 403, error: `Origin 非法（跨站来源被拒绝）: ${origin}` };
    }
  }
  const sfs = req.headers['sec-fetch-site'];
  if (sfs && sfs !== 'none' && sfs !== 'same-origin' && sfs !== 'same-site') {
    return { status: 403, error: `Sec-Fetch-Site 表明跨站来源（${sfs}），已拒绝` };
  }
  const header = String(req.headers.authorization || '');
  const given = header.startsWith('Bearer ') ? header.slice(7) : String(req.headers['x-web-access-token'] || '');
  if (!given) return { status: 403, error: '缺少鉴权头 Authorization: Bearer <token>（token 在 %USERPROFILE%\\.web-access\\token）' };
  if (typeof token !== 'string' || given.length !== token.length ||
      !crypto.timingSafeEqual(Buffer.from(given), Buffer.from(token))) {
    return { status: 403, error: 'token 不匹配。若 proxy 刚重启过，请重新读取 token 文件；必要时运行 scripts/stop-proxy.mjs 后重跑 check-deps.mjs' };
  }
  return null;
}
