// Vercel Serverless API for the shared dashboard state.
// Requires a Vercel Blob store connected to this project, which provides
// BLOB_READ_WRITE_TOKEN automatically as an environment variable.
import { put, list } from '@vercel/blob';

const STATE_PATH = 'sales-training-dashboard/state.json';

async function findStateBlob() {
  const result = await list({ prefix: STATE_PATH, limit: 20 });
  return result.blobs.find(b => b.pathname === STATE_PATH) || null;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();

  try {
    if (req.method === 'GET') {
      const blob = await findStateBlob();
      if (!blob) return res.status(200).json({});
      const response = await fetch(blob.url, { cache: 'no-store' });
      if (!response.ok) throw new Error(`Blob read failed: HTTP ${response.status}`);
      const text = await response.text();
      let data = {};
      try { data = JSON.parse(text || '{}'); }
      catch (_) { return res.status(500).json({ error: 'invalid stored data', message: 'State cloud bukan JSON valid.' }); }
      return res.status(200).json(data);
    }

    if (req.method === 'POST') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      const payload = body && body.payload;
      if (!payload || typeof payload !== 'object') {
        return res.status(400).json({ error: 'missing payload', message: 'POST harus memiliki payload object.' });
      }
      if (!payload.staffMaster || !payload.database) {
        return res.status(400).json({ error: 'invalid payload', message: 'Format dashboard tidak lengkap.' });
      }

      const text = JSON.stringify(payload);
      if (text.length > 20 * 1024 * 1024) {
        return res.status(413).json({ error: 'payload_too_large', message: 'Data dashboard melebihi 20 MB.' });
      }

      const blob = await put(STATE_PATH, text, {
        access: 'public',
        addRandomSuffix: false,
        contentType: 'application/json',
        cacheControlMaxAge: 0,
      });
      return res.status(200).json({ ok: true, savedAt: new Date().toISOString(), pathname: blob.pathname });
    }

    return res.status(405).json({ error: 'method_not_allowed' });
  } catch (error) {
    console.error('dashboard state API error', error);
    return res.status(500).json({ error: 'server_error', message: error?.message || 'Unknown server error' });
  }
}
