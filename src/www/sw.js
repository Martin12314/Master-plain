// ============================================================================
// File: www/sw.js
// ============================================================================

// sw.js — Service Worker for apex origin
// Response verification + protected-flow bootstrap + request signing

let SIG_VERIFY_KEY = null;

let REQ_SIGN_KEYPAIR = null;
let REQ_SIGN_KID = null;
let REQ_SIGN_THUMBPRINT = null;
let REQ_SIGN_READY = false;

let HOST_JWE_JWK = null;
let HOST_JWE_KID = null;
let PROTECTED_FLOW_BOOTSTRAP_PROMISE = null;

const APP_ORIGIN = 'https://app.masteroppgave2026.no';

const BOOTSTRAP_PATHS = new Set([
  '/sw.js',
  '/Installer.js',
  '/installer.js',
]);

function log(...args) {
  const msg = args.join(' ');
  console.log('[SW]', msg);

  self.clients.matchAll({ includeUncontrolled: true }).then(clients => {
    for (const client of clients) {
      client.postMessage({
        type: 'SW_LOG',
        message: msg,
        ts: new Date().toISOString()
      });
    }
  });
}

function shouldBypassSecurity(url) {
  return url.pathname.startsWith('/unsigned/');
}

function shouldSignRequest(url, method) {
  method = String(method || 'GET').toUpperCase();
  if (method === 'GET' || method === 'HEAD') return false;

  return (
    url.pathname === '/api/login' ||
    url.pathname === '/api/echo'
  );
}

self.addEventListener('install', () => {
  log('install → skipWaiting');
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  log('activate → clients.claim');
  event.waitUntil(self.clients.claim());
});

function b64ToBytes(b64) {
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

function bytesToB64(bytes) {
  let bin = '';
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const chunkSize = 0x8000;
  for (let i = 0; i < arr.length; i += chunkSize) {
    bin += String.fromCharCode(...arr.subarray(i, i + chunkSize));
  }
  return btoa(bin);
}

function bytesToB64Url(bytes) {
  return bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function parseDigestHeader(cd) {
  const m = cd?.match(/sha-256=:(.+):/i);
  return m ? m[1] : null;
}

function parseSigHeader(sig) {
  const m = sig?.match(/sig1=:(.+):/i);
  return m ? m[1] : null;
}

function isProtectedContentType(ct) {
  ct = (ct || '').toLowerCase();
  return (
    ct.includes('text/html') ||
    ct.includes('application/json') ||
    ct.includes('application/javascript') ||
    ct.includes('text/javascript') ||
    ct.includes('text/css') ||
    ct.includes('image/png') ||
    ct.includes('image/jpeg') ||
    ct.includes('image/webp') ||
    ct.includes('image/svg+xml')
  );
}

async function verifyResponse(response, bodyBytes, method, targetUri) {
  if (!SIG_VERIFY_KEY) {
    throw new Error('verification key not installed');
  }

  const cd = response.headers.get('Content-Digest');
  const sig = response.headers.get('Signature');
  const sigInput = response.headers.get('Signature-Input');

  if (!cd || !sig || !sigInput) {
    throw new Error('missing security headers (need Content-Digest + Signature + Signature-Input)');
  }

  const expectedB64 = parseDigestHeader(cd);
  if (!expectedB64) {
    throw new Error('bad Content-Digest format');
  }

  const actualHash = await crypto.subtle.digest('SHA-256', bodyBytes);
  const actualB64 = bytesToB64(actualHash);

  if (actualB64 !== expectedB64) {
    throw new Error('digest mismatch');
  }

  const params = sigInput.replace(/^sig1=/, '');
  const base =
    `"@method": "${String(method).toLowerCase()}"\n` +
    `"@target-uri": "${targetUri}"\n` +
    `"@status": ${response.status}\n` +
    `content-digest: ${cd}\n` +
    `"@signature-params": ${params}`;

  const sigB64 = parseSigHeader(sig);
  if (!sigB64) {
    throw new Error('bad Signature format');
  }

  const ok = await crypto.subtle.verify(
    { name: 'RSA-PSS', saltLength: 32 },
    SIG_VERIFY_KEY,
    b64ToBytes(sigB64),
    new TextEncoder().encode(base)
  );

  if (!ok) {
    throw new Error('signature verification failed');
  }
}

async function fetchVerifiedJson(method, targetUri, init = {}) {
  if (!SIG_VERIFY_KEY) {
    throw new Error('verification key not installed yet');
  }

  const r = await fetch(APP_ORIGIN + targetUri, {
    method,
    mode: 'cors',
    cache: 'no-store',
    redirect: 'follow',
    credentials: 'omit',
    ...init
  });

  const bodyBytes = await r.clone().arrayBuffer();
  await verifyResponse(r, bodyBytes, method, targetUri);

  if (!r.ok) {
    throw new Error(`${targetUri} failed HTTP ${r.status}`);
  }

  return JSON.parse(new TextDecoder().decode(bodyBytes));
}

function canonicalizeReqSignPublicJwk(jwk) {
  if (!jwk || jwk.kty !== 'RSA' || !jwk.n || !jwk.e) {
    throw new Error('invalid request-sign public JWK');
  }

  return JSON.stringify({
    e: jwk.e,
    kty: 'RSA',
    n: jwk.n
  });
}

async function computeReqSignJwkThumbprint(jwk) {
  const canonical = canonicalizeReqSignPublicJwk(jwk);
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return bytesToB64Url(hash);
}

function buildReqKeyRegistrationProofBase(kid, thumbprint) {
  return (
    `"kid": "${kid}"\n` +
    `"thumbprint": "${thumbprint}"`
  );
}

async function generateReqSigningKeypair() {
  if (REQ_SIGN_KEYPAIR) {
    const jwk = await crypto.subtle.exportKey('jwk', REQ_SIGN_KEYPAIR.publicKey);
    jwk.alg = 'PS256';
    jwk.use = 'sig';
    jwk.kid = REQ_SIGN_KID;

    return {
      kid: REQ_SIGN_KID,
      jwk,
      reused: true
    };
  }

  REQ_SIGN_KID = 'sw-req-' + Date.now() + '-' + Math.random().toString(36).slice(2, 10);

  REQ_SIGN_KEYPAIR = await crypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  );

  const jwk = await crypto.subtle.exportKey('jwk', REQ_SIGN_KEYPAIR.publicKey);
  jwk.alg = 'PS256';
  jwk.use = 'sig';
  jwk.kid = REQ_SIGN_KID;

  return {
    kid: REQ_SIGN_KID,
    jwk,
    reused: false
  };
}

async function fetchVerifiedHostJweJwk() {
  if (!SIG_VERIFY_KEY) {
    throw new Error('verification key not installed yet');
  }

  const targetUri = '/key-exchange';
  const upstreamUrl = APP_ORIGIN + targetUri;

  const r = await fetch(upstreamUrl, {
    method: 'GET',
    mode: 'cors',
    cache: 'no-store',
    redirect: 'follow',
    credentials: 'omit'
  });

  if (!r.ok) {
    throw new Error('key-exchange failed HTTP ' + r.status);
  }

  const bodyBytes = await r.clone().arrayBuffer();
  await verifyResponse(r, bodyBytes, 'GET', targetUri);

  const jwk = JSON.parse(new TextDecoder().decode(bodyBytes));
  if (!jwk || jwk.kty !== 'RSA' || !jwk.n || !jwk.e) {
    throw new Error('invalid host JWE key');
  }

  HOST_JWE_JWK = jwk;
  HOST_JWE_KID = jwk.kid || '(no-kid)';

  log('verified host JWE key fetched (kid=' + HOST_JWE_KID + ')');

  return jwk;
}

async function registerReqSigningKeyWithServer() {
  const hostJwk = HOST_JWE_JWK || await fetchVerifiedHostJweJwk();
  const result = await generateReqSigningKeypair();

  const thumbprint = await computeReqSignJwkThumbprint(result.jwk);
  const proofBase = buildReqKeyRegistrationProofBase(result.kid, thumbprint);

  const proofBuf = await crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    REQ_SIGN_KEYPAIR.privateKey,
    new TextEncoder().encode(proofBase)
  );

  log('registering request-sign public key with server (kid=' + result.kid + ', thumb=' + thumbprint + ')');

  const j = await fetchVerifiedJson('POST', '/req-key/register', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      kid: result.kid,
      jwk: result.jwk,
      jwkThumbprint: thumbprint,
      proof: bytesToB64(proofBuf)
    })
  });

  if (!j?.ok) {
    throw new Error('request-sign registration not accepted');
  }

  if (j.acceptedKid !== result.kid) {
    throw new Error('request-sign registration kid mismatch');
  }

  if (j.acceptedThumbprint !== thumbprint) {
    throw new Error('request-sign registration thumbprint mismatch');
  }

  REQ_SIGN_THUMBPRINT = thumbprint;
  REQ_SIGN_READY = true;

  return {
    ok: true,
    reqSignKid: result.kid,
    reqSignThumbprint: thumbprint,
    hostJweKid: hostJwk.kid || '(no-kid)',
    hostJweJwk: hostJwk,
    reused: result.reused
  };
}

async function ensureProtectedFlowReady() {
  if (HOST_JWE_JWK && REQ_SIGN_READY && REQ_SIGN_KID && REQ_SIGN_THUMBPRINT) {
    return {
      ok: true,
      reqSignReady: true,
      reqSignKid: REQ_SIGN_KID,
      reqSignThumbprint: REQ_SIGN_THUMBPRINT,
      hostJweKid: HOST_JWE_KID,
      hostJweJwk: HOST_JWE_JWK,
      reused: true
    };
  }

  if (PROTECTED_FLOW_BOOTSTRAP_PROMISE) {
    return await PROTECTED_FLOW_BOOTSTRAP_PROMISE;
  }

  PROTECTED_FLOW_BOOTSTRAP_PROMISE = (async () => {
    REQ_SIGN_READY = false;
    REQ_SIGN_THUMBPRINT = null;

    if (!HOST_JWE_JWK) {
      await fetchVerifiedHostJweJwk();
    }

    const reg = await registerReqSigningKeyWithServer();

    const out = {
      ok: true,
      reqSignReady: true,
      reqSignKid: reg.reqSignKid,
      reqSignThumbprint: reg.reqSignThumbprint,
      hostJweKid: reg.hostJweKid,
      hostJweJwk: reg.hostJweJwk,
      reused: reg.reused
    };

    log(
      'protected-flow ready',
      'hostKid=' + out.hostJweKid,
      'reqSignKid=' + out.reqSignKid,
      'thumb=' + out.reqSignThumbprint
    );

    return out;
  })();

  try {
    return await PROTECTED_FLOW_BOOTSTRAP_PROMISE;
  } finally {
    PROTECTED_FLOW_BOOTSTRAP_PROMISE = null;
  }
}

self.addEventListener('message', async event => {
  const type = event.data?.type;

  if (type === 'SET_SIG_KEY') {
    try {
      SIG_VERIFY_KEY = await crypto.subtle.importKey(
        'jwk',
        event.data.jwk,
        { name: 'RSA-PSS', hash: 'SHA-256' },
        false,
        ['verify']
      );

      const kid = event.data.jwk?.kid || '?';
      log('signature verification key installed (kid=' + kid + ')');

      if (event.source?.postMessage) {
        event.source.postMessage({ type: 'SIG_KEY_INSTALLED', kid });
      }
    } catch (e) {
      SIG_VERIFY_KEY = null;
      const msg = e?.message || String(e);
      log('ERROR installing signature key:', msg);

      if (event.source?.postMessage) {
        event.source.postMessage({ type: 'SIG_KEY_ERROR', message: msg });
      }
    }
    return;
  }

  if (type === 'GET_REQ_SIGN_STATUS') {
    try {
      const state = await ensureProtectedFlowReady();

      if (event.source?.postMessage) {
        event.source.postMessage({
          type: 'REQ_SIGN_STATUS',
          ready: !!state.reqSignReady,
          ok: !!state.ok,
          kid: state.reqSignKid || null,
          thumbprint: state.reqSignThumbprint || null,
          hostJweKid: state.hostJweKid || null
        });
      }
    } catch (e) {
      const msg = e?.message || String(e);
      log('ERROR request-sign bootstrap:', msg);

      if (event.source?.postMessage) {
        event.source.postMessage({
          type: 'REQ_SIGN_STATUS',
          ready: false,
          ok: false,
          message: msg
        });
      }
    }
    return;
  }

  if (type === 'GET_PROTECTED_FLOW_STATE') {
    try {
      const state = await ensureProtectedFlowReady();

      if (event.source?.postMessage) {
        event.source.postMessage({
          type: 'PROTECTED_FLOW_STATE',
          ...state
        });
      }
    } catch (e) {
      const msg = e?.message || String(e);
      log('ERROR protected-flow bootstrap:', msg);

      if (event.source?.postMessage) {
        event.source.postMessage({
          type: 'PROTECTED_FLOW_STATE',
          ok: false,
          message: msg
        });
      }
    }
    return;
  }
});

async function addRequestSignature(headers, method, targetUri, bodyBytes) {
  if (!REQ_SIGN_KEYPAIR || !REQ_SIGN_KID || !REQ_SIGN_READY) {
    throw new Error('request-signing key not ready');
  }

  const digestHash = await crypto.subtle.digest('SHA-256', bodyBytes);
  const digestB64 = bytesToB64(digestHash);
  const created = Math.floor(Date.now() / 1000);

  const base =
    `"@method": "${String(method).toLowerCase()}"\n` +
    `"@target-uri": "${targetUri}"\n` +
    `"x-req-created": ${created}\n` +
    `"x-req-content-digest": sha-256=:${digestB64}:\n` +
    `"x-client-key-id": ${REQ_SIGN_KID}`;

  const sigBuf = await crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    REQ_SIGN_KEYPAIR.privateKey,
    new TextEncoder().encode(base)
  );

  headers.set('X-Client-Key-Id', REQ_SIGN_KID);
  headers.set('X-Req-Created', String(created));
  headers.set('X-Req-Content-Digest', 'sha-256=:' + digestB64 + ':');
  headers.set('X-Req-Signature', bytesToB64(sigBuf));
}

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  if (!url.protocol.startsWith('http')) return;
  if (url.origin !== self.location.origin) return;
  if (BOOTSTRAP_PATHS.has(url.pathname)) return;

  event.respondWith((async () => {
    if (shouldBypassSecurity(url)) {
      const upstreamUrl = APP_ORIGIN + url.pathname + url.search;

      const init = {
        method: event.request.method,
        redirect: 'follow',
        credentials: 'omit',
        headers: new Headers()
      };

      const contentType = event.request.headers.get('Content-Type');
      if (contentType) {
        init.headers.set('Content-Type', contentType);
      }

      if (event.request.method !== 'GET' && event.request.method !== 'HEAD') {
        init.body = await event.request.clone().arrayBuffer();
        if (!init.headers.has('Content-Type')) {
          init.headers.set('Content-Type', 'application/octet-stream');
        }
      }

      const res = await fetch(upstreamUrl, init);
      log('BYPASS', url.pathname, '→', res.status);
      return res;
    }

    if (!SIG_VERIFY_KEY) {
      const res = await fetch(event.request);
      log('PASS (no key yet)', url.pathname, '→', res.status);
      return res;
    }

    const upstreamUrl = APP_ORIGIN + url.pathname + url.search;

    const init = {
      method: event.request.method,
      redirect: 'follow',
      credentials: 'omit',
      headers: new Headers()
    };

    const contentType = event.request.headers.get('Content-Type');
    if (contentType) {
      init.headers.set('Content-Type', contentType);
    }

    let requestBodyBytes = new ArrayBuffer(0);
    if (event.request.method !== 'GET' && event.request.method !== 'HEAD') {
      requestBodyBytes = await event.request.clone().arrayBuffer();
      init.body = requestBodyBytes;
      if (!init.headers.has('Content-Type')) {
        init.headers.set('Content-Type', 'application/octet-stream');
      }
    }

    if (shouldSignRequest(url, event.request.method)) {
      await ensureProtectedFlowReady();
      const targetUri = url.pathname + url.search;
      await addRequestSignature(init.headers, event.request.method, targetUri, requestBodyBytes);
    }

    let res;
    try {
      res = await fetch(upstreamUrl, init);
    } catch (e) {
      log('NETWORK ERROR', url.pathname, e?.message || String(e));
      throw e;
    }

    const ct = res.headers.get('Content-Type') || '';
    if (!isProtectedContentType(ct)) {
      log('PASS (unverified type)', url.pathname, 'ct=', ct, '→', res.status);
      return res;
    }

    const bodyBytes = await res.clone().arrayBuffer();

    try {
      const method = event.request.method;
      const targetUri = url.pathname + url.search;
      await verifyResponse(res, bodyBytes, method, targetUri);

      log('OK', url.pathname, 'ct=', ct, 'status=', res.status);

      const outHeaders = new Headers(res.headers);
      outHeaders.delete('content-length');

      return new Response(bodyBytes, {
        status: res.status,
        statusText: res.statusText,
        headers: outHeaders
      });
    } catch (e) {
      log('BLOCK', url.pathname, 'reason=', e.message || String(e), 'ct=', ct, 'status=', res.status);

      return new Response(
        'Blocked by Service Worker (integrity violation): ' + (e.message || 'unknown'),
        { status: 498, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
      );
    }
  })());
});