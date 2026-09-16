// test/wa.test.mjs
import { test } from 'node:test';
import assert from 'node:assert';
import { buildRequest } from '../scripts/wa.mjs';

test('POST 端点映射', () => {
  assert.deepEqual(buildRequest(['new', 'https://example.com?a=1&b=2']), { method: 'POST', endpoint: '/new', body: 'https://example.com?a=1&b=2' });
  assert.deepEqual(buildRequest(['navigate', 'T1', 'https://x.com']), { method: 'POST', endpoint: '/navigate?target=T1', body: 'https://x.com' });
  assert.deepEqual(buildRequest(['eval', 'T1']), { method: 'POST', endpoint: '/eval?target=T1', body: 'document.title' });
  assert.deepEqual(buildRequest(['click', 'T1', 'button.ok']), { method: 'POST', endpoint: '/click?target=T1', body: 'button.ok' });
  assert.deepEqual(buildRequest(['setFiles', 'T1', 'input[type=file]', 'a.png', 'b.png']),
    { method: 'POST', endpoint: '/setFiles?target=T1', body: JSON.stringify({ selector: 'input[type=file]', files: ['a.png', 'b.png'] }) });
});

test('GET 端点映射', () => {
  assert.deepEqual(buildRequest(['health']), { method: 'GET', endpoint: '/health', body: undefined });
  assert.deepEqual(buildRequest(['screenshot', 'T1', 'C:/tmp/s.png']), { method: 'GET', endpoint: '/screenshot?target=T1&file=C%3A%2Ftmp%2Fs.png', body: undefined });
  assert.deepEqual(buildRequest(['scroll', 'T1', '3000', 'bottom']), { method: 'GET', endpoint: '/scroll?target=T1&y=3000&direction=bottom', body: undefined });
  assert.deepEqual(buildRequest(['close', 'T1']), { method: 'GET', endpoint: '/close?target=T1', body: undefined });
});

test('未知端点 / 缺参 → 抛错', () => {
  assert.throws(() => buildRequest(['nope']), /未知 endpoint/);
  assert.throws(() => buildRequest(['new']), /参数不足/);
});
