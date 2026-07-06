let sigVerifyKey = null;
let sigVerifyKid = null;

let reqSignKeypair = null;
let reqSignKid = null;
let reqSignThumbprint = null;
let reqSignReady = false;

let hostJweJwk = null;
let hostJweKid = null;
let protectedFlowBootstrapPromise = null;

const APP_ORIGIN = 'https://app.masteroppgave2026.no';

const TRUSTED_SIG_PUB_JWK = {
  kty: 'RSA',
  kid: 'sig-key-1',
  alg: 'PS256',
  n: 'wSOfiQdpVMMEeqJv-Nz_yifuyOJb6TglNPD7wrkexmlRpe4u7QyUscTfBQbt6rNxKjIv9W9LGhy4hk7WqwHVBLFBE_uvF0-SIjxDdL2EecV7Xd4-iRnjj2aQV0NVRguE01O1ZKl-vJDxbzFBuUhjwmgxSxFvudjN-owZYdTk-qaqn0kFaGsSqfS70hUgL8WV_gkMNhWAhlOQcVgfcC4xesafCMolEO1bZ-XO1l_gcGW4k8Dr6U7vozaZTvjQUjeF_fXlHbXOWsRgOxU61qe8RSmFFXAuYTkcP_KXpSgQxC8XojR04DLQfJTobf1O0LzeS0IPNuqxgOCH-zuyLdSYsQ',
  e: 'AQAB'
};

const BOOTSTRAP_PATHS = new Set(['/sw.js']);

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

function logJson(title, obj) {
  log(`${title}\n${JSON.stringify(obj, null, 2)}`);
}

function normalizeDemo(mode) {
  return String(mode || '').trim().toLowerCase();
}

function getDemoForApi(url) {
  if (url.pathname !== '/api/login' && url.pathname !== '/api/echo') {
    return '';
  }
  return normalizeDemo(url.searchParams.get('demo'));
}

function shouldBypassSecurity(url) {
  return url.pathname.startsWith('/unsigned/');
}

function shouldSignRequest(url, method) {
  const m = String(method || 'GET').toUpperCase();
  if (m === 'GET' || m === 'HEAD') return false;
  return url.pathname === '/api/login' || url.pathname === '/api/echo';
}

async function ensureSigVerifyKeyReady() {
  if (sigVerifyKey) {
    return;
  }

  sigVerifyKey = await crypto.subtle.importKey(
    'jwk',
    TRUSTED_SIG_PUB_JWK,
    { name: 'RSA-PSS', hash: 'SHA-256' },
    false,
    ['verify']
  );

  sigVerifyKid = TRUSTED_SIG_PUB_JWK.kid || '?';
  log('signature verification key loaded from local SW keystore (kid=' + sigVerifyKid + ')');
}

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    await ensureSigVerifyKeyReady();
    log('install → skipWaiting');
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    await ensureSigVerifyKeyReady();
    log('activate → clients.claim');
    await self.clients.claim();
  })());
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
  const value = (ct || '').toLowerCase();
  return (
    value.includes('text/html') ||
    value.includes('application/json') ||
    value.includes('application/javascript') ||
    value.includes('text/javascript') ||
    value.includes('text/css') ||
    value.includes('image/png') ||
    value.includes('image/jpeg') ||
    value.includes('image/webp') ||
    value.includes('image/svg+xml')
  );
}

async function computeDigestHeader(bodyBytes) {
  const actualHash = await crypto.subtle.digest('SHA-256', bodyBytes);
  return 'sha-256=:' + bytesToB64(actualHash) + ':';
}

function buildResponseSignatureBase(response, method, targetUri) {
  const cd = response.headers.get('Content-Digest');
  const sigInput = response.headers.get('Signature-Input');
  if (!cd || !sigInput) {
    return null;
  }
  const params = sigInput.replace(/^sig1=/, '');
  return (
    `"@method": "${String(method).toLowerCase()}"\n` +
    `"@target-uri": "${targetUri}"\n` +
    `"@status": ${response.status}\n` +
    `content-digest: ${cd}\n` +
    `"@signature-params": ${params}`
  );
}

async function buildResponseVerifyLog(response, bodyBytes, method, targetUri) {
  const contentDigest = response.headers.get('Content-Digest');
  const signature = response.headers.get('Signature');
  const signatureInput = response.headers.get('Signature-Input');
  const computedDigest = await computeDigestHeader(bodyBytes);
  const signatureBase = buildResponseSignatureBase(response, method, targetUri);

  const info = {
    method,
    targetUri,
    status: response.status,
    receivedDigest: contentDigest,
    computedDigest,
    digestMatches: contentDigest === computedDigest,
    verificationKeyId: sigVerifyKid,
    signatureInput,
    signature,
    signatureBase,
    signatureValid: null
  };

  if (!contentDigest || !signature || !signatureInput) {
    info.error = 'missing security headers';
    return info;
  }

  if (!parseDigestHeader(contentDigest)) {
    info.error = 'bad Content-Digest format';
    return info;
  }

  if (contentDigest !== computedDigest) {
    info.error = 'digest mismatch';
    return info;
  }

  const sigB64 = parseSigHeader(signature);
  if (!sigB64) {
    info.error = 'bad Signature format';
    return info;
  }

  const ok = await crypto.subtle.verify(
    { name: 'RSA-PSS', saltLength: 32 },
    sigVerifyKey,
    b64ToBytes(sigB64),
    new TextEncoder().encode(signatureBase)
  );

  info.signatureValid = ok;
  if (!ok) {
    info.error = 'signature verification failed';
  }

  return info;
}

async function verifyResponse(response, bodyBytes, method, targetUri) {
  await ensureSigVerifyKeyReady();
  const info = await buildResponseVerifyLog(response, bodyBytes, method, targetUri);
  logJson(info.error ? 'Response verification FAILED' : 'Response verification OK', info);
  if (info.error) {
    throw new Error(info.error);
  }
}

async function fetchVerifiedJson(method, targetUri, init = {}) {
  await ensureSigVerifyKeyReady();

  const response = await fetch(APP_ORIGIN + targetUri, {
    method,
    mode: 'cors',
    cache: 'no-store',
    redirect: 'follow',
    credentials: 'omit',
    ...init
  });

  const bodyBytes = await response.clone().arrayBuffer();
  await verifyResponse(response, bodyBytes, method, targetUri);

  if (!response.ok) {
    throw new Error(`${targetUri} failed HTTP ${response.status}`);
  }

  return JSON.parse(new TextDecoder().decode(bodyBytes));
}

function canonicalizeReqSignPublicJwk(jwk) {
  if (!jwk || jwk.kty !== 'RSA' || !jwk.n || !jwk.e) {
    throw new Error('invalid request-sign public JWK');
  }
  return JSON.stringify({ e: jwk.e, kty: 'RSA', n: jwk.n });
}

async function computeReqSignJwkThumbprint(jwk) {
  const canonical = canonicalizeReqSignPublicJwk(jwk);
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return bytesToB64Url(hash);
}

function buildReqKeyRegistrationProofBase(kid, thumbprint) {
  return `"kid": "${kid}"\n"thumbprint": "${thumbprint}"`;
}

async function generateReqSigningKeypair() {
  if (reqSignKeypair) {
    const jwk = await crypto.subtle.exportKey('jwk', reqSignKeypair.publicKey);
    jwk.alg = 'PS256';
    jwk.use = 'sig';
    jwk.kid = reqSignKid;
    return {
      kid: reqSignKid,
      jwk,
      privateKey: reqSignKeypair.privateKey,
      reused: true
    };
  }

  reqSignKid = 'sw-req-' + Date.now() + '-' + Math.random().toString(36).slice(2, 10);
  reqSignKeypair = await crypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  );

  const jwk = await crypto.subtle.exportKey('jwk', reqSignKeypair.publicKey);
  jwk.alg = 'PS256';
  jwk.use = 'sig';
  jwk.kid = reqSignKid;

  return {
    kid: reqSignKid,
    jwk,
    privateKey: reqSignKeypair.privateKey,
    reused: false
  };
}

async function generateEphemeralReqSigningKeypair() {
  const kid = 'sw-demo-' + Date.now() + '-' + Math.random().toString(36).slice(2, 10);
  const keypair = await crypto.subtle.generateKey(
    {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  );

  const jwk = await crypto.subtle.exportKey('jwk', keypair.publicKey);
  jwk.alg = 'PS256';
  jwk.use = 'sig';
  jwk.kid = kid;

  return {
    kid,
    jwk,
    privateKey: keypair.privateKey,
    reused: false
  };
}

async function fetchVerifiedHostJweJwk() {
  await ensureSigVerifyKeyReady();

  const targetUri = '/key-exchange';
  const response = await fetch(APP_ORIGIN + targetUri, {
    method: 'GET',
    mode: 'cors',
    cache: 'no-store',
    redirect: 'follow',
    credentials: 'omit'
  });

  if (!response.ok) {
    throw new Error('key-exchange failed HTTP ' + response.status);
  }

  const bodyBytes = await response.clone().arrayBuffer();
  await verifyResponse(response, bodyBytes, 'GET', targetUri);

  const jwk = JSON.parse(new TextDecoder().decode(bodyBytes));
  if (!jwk || !jwk.n || !jwk.e) {
    throw new Error('invalid host JWE key');
  }

  hostJweJwk = jwk;
  hostJweKid = jwk.kid || '(no-kid)';
  log('verified host JWE key fetched (kid=' + hostJweKid + ')');
  return jwk;
}

async function registerReqSigningKeyWithServer(demo = '', ephemeral = false) {
  const currentHostJwk = hostJweJwk || await fetchVerifiedHostJweJwk();
  const material = ephemeral ? await generateEphemeralReqSigningKeypair() : await generateReqSigningKeypair();

  const thumbprint = await computeReqSignJwkThumbprint(material.jwk);
  const proofBase = buildReqKeyRegistrationProofBase(material.kid, thumbprint);

  const proofBuf = await crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    material.privateKey,
    new TextEncoder().encode(proofBase)
  );

  const targetUri = demo ? '/req-key/register?demo=' + encodeURIComponent(demo) : '/req-key/register';

  log('registering request-sign public key with server (kid=' + material.kid + ', thumb=' + thumbprint + ')');

  const response = await fetchVerifiedJson('POST', targetUri, {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      kid: material.kid,
      jwk: material.jwk,
      jwkThumbprint: thumbprint,
      proof: bytesToB64(proofBuf)
    })
  });

  log('[REQ-KEY-REGISTER] client thumbprint = ' + thumbprint);
  log('[REQ-KEY-REGISTER] host   thumbprint = ' + (response?.acceptedThumbprint || '(missing)'));

  if (!response?.ok) {
    throw new Error('request-sign registration not accepted');
  }
  if (response.acceptedKid !== material.kid) {
    throw new Error('request-sign registration kid mismatch');
  }
  if (response.acceptedThumbprint !== thumbprint) {
    throw new Error('request-sign registration thumbprint mismatch');
  }

  if (!ephemeral) {
    reqSignThumbprint = thumbprint;
    reqSignReady = true;
  }

  return {
    ok: true,
    reqSignKid: material.kid,
    reqSignThumbprint: thumbprint,
    hostJweKid: currentHostJwk.kid || '(no-kid)',
    hostJweJwk: currentHostJwk,
    reused: material.reused
  };
}

async function ensureProtectedFlowReady() {
  await ensureSigVerifyKeyReady();

  if (hostJweJwk && reqSignReady && reqSignKid && reqSignThumbprint) {
    return {
      ok: true,
      reqSignReady: true,
      reqSignKid,
      reqSignThumbprint,
      hostJweKid,
      hostJweJwk,
      reused: true
    };
  }

  if (protectedFlowBootstrapPromise) {
    return await protectedFlowBootstrapPromise;
  }

  protectedFlowBootstrapPromise = (async () => {
    reqSignReady = false;
    reqSignThumbprint = null;

    if (!hostJweJwk) {
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

    log('protected-flow ready hostKid=' + out.hostJweKid + ' reqSignKid=' + out.reqSignKid + ' thumb=' + out.reqSignThumbprint);
    return out;
  })();

  try {
    return await protectedFlowBootstrapPromise;
  } finally {
    protectedFlowBootstrapPromise = null;
  }
}

self.addEventListener('message', async event => {
  const type = event.data?.type;

  if (type === 'GET_PROTECTED_FLOW_STATE') {
    try {
      const state = await ensureProtectedFlowReady();
      event.source?.postMessage?.({ type: 'PROTECTED_FLOW_STATE', ...state });
    } catch (e) {
      const msg = e?.message || String(e);
      log('ERROR protected-flow bootstrap: ' + msg);
      event.source?.postMessage?.({ type: 'PROTECTED_FLOW_STATE', ok: false, message: msg });
    }
    return;
  }

  if (type === 'RUN_HOST_WRONG_CLIENT_KEY_DEMO') {
    try {
      await registerReqSigningKeyWithServer('host-wrong-client-key', true);
      log('Host wrong client key demo unexpectedly passed');
      event.source?.postMessage?.({
        type: 'HOST_WRONG_CLIENT_KEY_DEMO_DONE',
        ok: false,
        message: 'Unexpected success'
      });
    } catch (e) {
      const msg = e?.message || String(e);
      log('Host wrong client key demo result: ' + msg);
      event.source?.postMessage?.({
        type: 'HOST_WRONG_CLIENT_KEY_DEMO_DONE',
        ok: true,
        message: msg
      });
    }
  }
});

async function addRequestSignature(headers, method, targetUri, bodyBytes) {
  if (!reqSignKeypair || !reqSignKid || !reqSignReady) {
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
    `"x-client-key-id": ${reqSignKid}`;

  const sigBuf = await crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    reqSignKeypair.privateKey,
    new TextEncoder().encode(base)
  );

  headers.set('X-Client-Key-Id', reqSignKid);
  headers.set('X-Req-Created', String(created));
  headers.set('X-Req-Content-Digest', 'sha-256=:' + digestB64 + ':');
  headers.set('X-Req-Signature', bytesToB64(sigBuf));
}

function applyRequestDigestTamper(headers) {
  headers.set('X-Req-Content-Digest', 'sha-256=:' + bytesToB64(new Uint8Array(32)) + ':');
}

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  if (!url.protocol.startsWith('http')) return;
  if (url.origin !== self.location.origin) return;
  if (BOOTSTRAP_PATHS.has(url.pathname)) return;

  event.respondWith((async () => {
    await ensureSigVerifyKeyReady();
    const demo = getDemoForApi(url);

    if (shouldBypassSecurity(url)) {
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

      const response = await fetch(APP_ORIGIN + url.pathname + url.search, init);
      log('BYPASS ' + url.pathname + ' → ' + response.status);
      return response;
    }

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
      await addRequestSignature(init.headers, event.request.method, url.pathname + url.search, requestBodyBytes);

      if (demo === 'req-bad-digest') {
        applyRequestDigestTamper(init.headers);
        log('request demo active: wrong request digest');
      }
    }

    let response;
    try {
      response = await fetch(APP_ORIGIN + url.pathname + url.search, init);
    } catch (e) {
      log('NETWORK ERROR ' + url.pathname + ' ' + (e?.message || String(e)));
      throw e;
    }

    const ct = response.headers.get('Content-Type') || '';
    if (!isProtectedContentType(ct)) {
      log('PASS (unverified type) ' + url.pathname + ' ct=' + ct + ' → ' + response.status);
      return response;
    }

    const bodyBytes = await response.clone().arrayBuffer();

    try {
      await verifyResponse(response, bodyBytes, event.request.method, url.pathname + url.search);

      const outHeaders = new Headers(response.headers);
      outHeaders.delete('content-length');

      return new Response(bodyBytes, {
        status: response.status,
        statusText: response.statusText,
        headers: outHeaders
      });
    } catch (e) {
      log('BLOCK ' + url.pathname + ' reason=' + (e?.message || String(e)) + ' ct=' + ct + ' status=' + response.status);
      return new Response(
        'Blocked by Service Worker (integrity violation): ' + (e?.message || 'unknown'),
        { status: 498, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
      );
    }
  })());
});