import { get, put, list } from '@vercel/blob';

const STATE_PATH = 'sales-training-dashboard/state.json';

function blobAuth() {
  const token = process.env.BLOB_READ_WRITE_TOKEN;
  const oidcToken = process.env.VERCEL_OIDC_TOKEN;
  const storeId = process.env.BLOB_STORE_ID;

  if (!storeId) {
    throw new Error('BLOB_STORE_ID is not available in this Vercel deployment.');
  }

  if (token) {
    return { token, storeId };
  }

  if (oidcToken) {
    return { oidcToken, storeId };
  }

  throw new Error('No Vercel Blob credentials are available in this deployment.');
}

async function findStateBlob() {
  const result = await list({
    prefix: STATE_PATH,
    limit: 20,
    ...blobAuth()
  });

  return result.blobs.find((blob) => blob.pathname === STATE_PATH) || null;
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  try {
    if (req.method === 'GET') {
      const blob = await findStateBlob();

      if (!blob) {
        return res.status(200).json({});
      }

      const result = await get(blob.pathname, {
        access: 'private',
        ...blobAuth()
      });

      if (!result) {
        return res.status(404).json({});
      }

      const text = await new Response(result.stream).text();

      try {
        return res.status(200).json(JSON.parse(text || '{}'));
      } catch {
        return res.status(500).json({
          error: 'invalid_stored_data',
          message: 'State cloud bukan JSON valid.'
        });
      }
    }

    if (req.method === 'POST') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      const payload = body?.payload;

      if (!payload || typeof payload !== 'object') {
        return res.status(400).json({
          error: 'missing_payload',
          message: 'POST harus memiliki payload object.'
        });
      }

      if (!payload.staffMaster || !payload.database) {
        return res.status(400).json({
          error: 'invalid_payload',
          message: 'Format dashboard tidak lengkap.'
        });
      }

      const text = JSON.stringify(payload);

      if (text.length > 20 * 1024 * 1024) {
        return res.status(413).json({
          error: 'payload_too_large',
          message: 'Data dashboard melebihi 20 MB.'
        });
      }

      const blob = await put(STATE_PATH, text, {
        access: 'private',
        addRandomSuffix: false,
        allowOverwrite: true,
        contentType: 'application/json',
        cacheControlMaxAge: 0,
        ...blobAuth()
      });

      return res.status(200).json({
        ok: true,
        savedAt: new Date().toISOString(),
        pathname: blob.pathname
      });
    }

    return res.status(405).json({
      error: 'method_not_allowed'
    });
  } catch (error) {
    console.error('dashboard state API error', error);

    return res.status(500).json({
      error: 'server_error',
      message: error?.message || 'Unknown server error'
    });
  }
}
