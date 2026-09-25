import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');

test('cloud API defaults use same-origin state endpoints', () => {
  const apiUrl = html.match(/apiUrl:\s*'([^']+)'/)?.[1];
  assert.equal(apiUrl, '/api/state');
  assert.equal(new URL(apiUrl, 'https://preview.example').origin, 'https://preview.example');
  assert.equal(new URL(apiUrl, 'https://production.example').origin, 'https://production.example');
  assert.match(html, /const dailyUploadUrl = '\/api\/state-daily-upload';/);
});

test('index.html contains no hardcoded absolute API URL', () => {
  assert.doesNotMatch(html, /https?:\/\/[^\s'"<>]+\/api\//i);
});
