const TRUSTED_SIG_PUB_JWK = {
  kty: 'RSA',
  kid: 'sig-key-1',
  use: 'sig',
  alg: 'PS256',
  n: 'nzI9d5xNlXASWarIld5sMQrMtig7NqMaFtb6h-6mUyGH5kKSgorkr2BzEDcmCDTSc0labkv9JldYded516_AnVzQIC4Y_xLuK90J3H0GDLfPWu1PN3BQxkle_HYM-KzwxjEsIi2PHJFNkURqyx7WVZ1IjKTurUYpW3Y0T08XxTGwfsnA0JcBIR0fFt8mUupj59Gud0VjYt7Q_xrGxx07IsHIUDR1B_KwbIkdCM8vY4GWvzp_7I0CFV38rt-tQ3l1c2-WntoXPNqlb4TLS4ZylwVmQIs5ylRdZj0zDeEI76S_U4wZEvWn8RPmLiA2uIoxRoz4hR-la3nqGd5Y2ImJgw',
  e: 'AQAB'
};

let SIG_VERIFY_KEY = null;
let SIG_VERIFY_KID = null;

let REQ_SIGN_KEYPAIR = null;
let REQ_SIGN_KID = null;
let REQ_SIGN_THUMBPRINT = null;
let REQ_SIGN_READY = false;

let HOST_JWE_JWK = null;
let HOST_JWE_KID = null;
let PROTECTED_FLOW_BOOTSTRAP_PROMISE = null;

const APP_ORIGIN = 'https://app.masteroppgave2026.no';
const METRICS_URL = APP_ORIGIN + '/metrics';

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

function ms3(v) {
  return Number(Number(v).toFixed(3));
}

async function ensureSigVerifyKeyReady() {
  if (SIG_VERIFY_KEY) {
    return;
  }

  SIG_VERIFY_KEY = await crypto.subtle.importKey(
    'jwk',
    TRUSTED_SIG_PUB_JWK,
    { name: 'RSA-PSS', hash: 'SHA-256' },
    false,
    ['verify']
  );
  SIG_VERIFY_KID = TRUSTED_SIG_PUB_JWK.kid || '?';
  log('signature verification key loaded from local SW keystore (kid=' + SIG_VERIFY_KID + ')');
}

function shouldBypassSecurity(url) {
  return (
    url.searchParams.get('sw-bypass') === '1' ||
    url.pathname.startsWith('/unsigned/')
  );
}

function shouldSignRequest(url, method) {
  method = String(method || 'GET').toUpperCase();
  if (method === 'GET' || method === 'HEAD') return false;

  return (
    url.pathname === '/api/login' ||
    url.pathname === '/api/echo'
  );
}

async function postMetric(eventName, fields = {}) {
  const payload = {
    event: eventName,
    at: new Date().toISOString(),
    source: 'service-worker',
    ...fields
  };

  try {
    await fetch(METRICS_URL, {
      method: 'POST',
      mode: 'no-cors',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  } catch (e) {
    console.warn('[SW] metric send failed', e);
  }
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

function safeHeader(headers, name) {
  try {
    return headers.get(name);
  } catch {
    return null;
  }
}

function approximateSelectedHeaderBytes(headers, names) {
  let total = 0;
  const enc = new TextEncoder();
  for (const name of names) {
    const value = headers.get(name);
    if (value != null) {
      total += enc.encode(name).length + 2 + enc.encode(value).length + 1;
    }
  }
  return total + 1;
}

function buildResponseSignatureBase(method, targetUri, status, contentDigest, signatureInputValue) {
  const params = signatureInputValue.replace(/^sig1=/, '');
  return (
    `"@method": "${String(method).toLowerCase()}"\n` +
    `"@target-uri": "${targetUri}"\n` +
    `"@status": ${status}\n` +
    `content-digest: ${contentDigest}\n` +
    `"@signature-params": ${params}`
  );
}

async function verifyResponseDetailed(response, bodyBytes, method, targetUri) {
  await ensureSigVerifyKeyReady();

  const diag = {
    method,
    targetUri,
    status: response.status,
    receivedDigest: safeHeader(response.headers, 'Content-Digest'),
    computedDigest: null,
    digestMatches: false,
    verificationKeyId: SIG_VERIFY_KID,
    signatureInput: safeHeader(response.headers, 'Signature-Input'),
    signature: safeHeader(response.headers, 'Signature'),
    signatureBase: null,
    signatureValid: null,
    digestMs: null,
    signatureMs: null,
    totalMs: null,
    error: null
  };

  try {
    const digestStarted = performance.now();
    const actualHash = await crypto.subtle.digest('SHA-256', bodyBytes);
    const actualB64 = bytesToB64(actualHash);
    diag.computedDigest = `sha-256=:${actualB64}:`;

    if (!diag.receivedDigest || !diag.signatureInput || !diag.signature) {
      diag.error = 'missing security headers';
      return diag;
    }

    const expectedB64 = parseDigestHeader(diag.receivedDigest);
    if (!expectedB64) {
      diag.error = 'bad Content-Digest format';
      return diag;
    }

    diag.digestMatches = actualB64 === expectedB64;
    diag.digestMs = ms3(performance.now() - digestStarted);

    if (!diag.digestMatches) {
      diag.error = 'digest mismatch';
      diag.totalMs = diag.digestMs;
      return diag;
    }

    const sigStarted = performance.now();
    const sigB64 = parseSigHeader(diag.signature);
    if (!sigB64) {
      diag.error = 'bad Signature format';
      diag.totalMs = ms3((diag.digestMs || 0) + (performance.now() - sigStarted));
      return diag;
    }

    diag.signatureBase = buildResponseSignatureBase(
      method,
      targetUri,
      response.status,
      diag.receivedDigest,
      diag.signatureInput
    );

    diag.signatureValid = await crypto.subtle.verify(
      { name: 'RSA-PSS', saltLength: 32 },
      SIG_VERIFY_KEY,
      b64ToBytes(sigB64),
      new TextEncoder().encode(diag.signatureBase)
    );
    diag.signatureMs = ms3(performance.now() - sigStarted);
    diag.totalMs = ms3((diag.digestMs || 0) + (diag.signatureMs || 0));

    if (!diag.signatureValid) {
      diag.error = 'signature verification failed';
    }

    return diag;
  } catch (e) {
    diag.error = e?.message || String(e);
    return diag;
  }
}

async function verifyResponse(response, bodyBytes, method, targetUri) {
  const diag = await verifyResponseDetailed(response, bodyBytes, method, targetUri);

  if (!diag.digestMatches || !diag.signatureValid) {
    log('Response verification FAILED\n' + JSON.stringify(diag, null, 2));
    throw new Error(diag.error || 'response verification failed');
  }

  await postMetric('response_verify', {
    path: targetUri,
    method,
    status: response.status,
    digest_ms: diag.digestMs,
    signature_ms: diag.signatureMs,
    total_ms: diag.totalMs,
    resp_sign_ms: safeHeader(response.headers, 'X-Metric-Sign-Ms'),
    resp_body_bytes: safeHeader(response.headers, 'X-Metric-Resp-Body-Bytes'),
    resp_header_bytes: safeHeader(response.headers, 'X-Metric-Resp-Header-Bytes'),
    resp_total_bytes: safeHeader(response.headers, 'X-Metric-Resp-Total-Bytes')
  });

  return diag;
}

async function fetchVerifiedJson(method, targetUri, init = {}) {
  await ensureSigVerifyKeyReady();

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
    const exportStarted = performance.now();
    const jwk = await crypto.subtle.exportKey('jwk', REQ_SIGN_KEYPAIR.publicKey);
    const exportMs = performance.now() - exportStarted;

    jwk.alg = 'PS256';
    jwk.use = 'sig';
    jwk.kid = REQ_SIGN_KID;

    return {
      kid: REQ_SIGN_KID,
      jwk,
      keygenMs: 0,
      exportMs: ms3(exportMs),
      totalMs: ms3(exportMs),
      reused: true
    };
  }

  REQ_SIGN_KID = 'sw-req-' + Date.now() + '-' + Math.random().toString(36).slice(2, 10);

  const keygenStarted = performance.now();
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
  const keygenMs = performance.now() - keygenStarted;

  const exportStarted = performance.now();
  const jwk = await crypto.subtle.exportKey('jwk', REQ_SIGN_KEYPAIR.publicKey);
  const exportMs = performance.now() - exportStarted;

  jwk.alg = 'PS256';
  jwk.use = 'sig';
  jwk.kid = REQ_SIGN_KID;

  return {
    kid: REQ_SIGN_KID,
    jwk,
    keygenMs: ms3(keygenMs),
    exportMs: ms3(exportMs),
    totalMs: ms3(keygenMs + exportMs),
    reused: false
  };
}

async function fetchVerifiedHostJweJwk() {
  await ensureSigVerifyKeyReady();

  const targetUri = '/key-exchange';
  const upstreamUrl = APP_ORIGIN + targetUri;

  const fetchStarted = performance.now();
  const r = await fetch(upstreamUrl, {
    method: 'GET',
    mode: 'cors',
    cache: 'no-store',
    redirect: 'follow',
    credentials: 'omit'
  });
  const fetchMs = performance.now() - fetchStarted;

  if (!r.ok) {
    throw new Error('key-exchange failed HTTP ' + r.status);
  }

  const bodyBytes = await r.clone().arrayBuffer();
  const verifyDiag = await verifyResponse(r, bodyBytes, 'GET', targetUri);

  const parseStarted = performance.now();
  const jwk = JSON.parse(new TextDecoder().decode(bodyBytes));
  const parseMs = performance.now() - parseStarted;

  if (!jwk || jwk.kty !== 'RSA' || !jwk.n || !jwk.e) {
    throw new Error('invalid host JWE key');
  }

  HOST_JWE_JWK = jwk;
  HOST_JWE_KID = jwk.kid || '(no-kid)';

  await postMetric('key_exchange', {
    path: targetUri,
    http_status: r.status,
    fetch_ms: ms3(fetchMs),
    verify_ms: verifyDiag.totalMs,
    parse_ms: ms3(parseMs),
    total_ms: ms3(fetchMs + (verifyDiag.totalMs || 0) + parseMs)
  });

  log('verified host JWE key fetched (kid=' + HOST_JWE_KID + ')');
  return jwk;
}

async function registerReqSigningKeyWithServer() {
  const hostJwk = HOST_JWE_JWK || await fetchVerifiedHostJweJwk();
  const result = await generateReqSigningKeypair();

  const thumbStarted = performance.now();
  const thumbprint = await computeReqSignJwkThumbprint(result.jwk);
  const thumbMs = performance.now() - thumbStarted;

  const proofBase = buildReqKeyRegistrationProofBase(result.kid, thumbprint);

  const proofStarted = performance.now();
  const proofBuf = await crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    REQ_SIGN_KEYPAIR.privateKey,
    new TextEncoder().encode(proofBase)
  );
  const proofMs = performance.now() - proofStarted;

  log('registering request-sign public key with server (kid=' + result.kid + ', thumb=' + thumbprint + ')');

  const regStarted = performance.now();
  const j = await fetchVerifiedJson('POST', '/req-key/register', {
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      kid: result.kid,
      jwk: result.jwk,
      jwkThumbprint: thumbprint,
      proof: bytesToB64(proofBuf)
    })
  });
  const regMs = performance.now() - regStarted;

  if (!j?.ok) throw new Error('request-sign registration not accepted');
  if (j.acceptedKid !== result.kid) throw new Error('request-sign registration kid mismatch');
  if (j.acceptedThumbprint !== thumbprint) throw new Error('request-sign registration thumbprint mismatch');

  REQ_SIGN_THUMBPRINT = thumbprint;
  REQ_SIGN_READY = true;

  await postMetric('req_key_register', {
    req_sign_kid: result.kid,
    req_sign_thumbprint: thumbprint,
    sw_req_keygen_ms: result.keygenMs,
    sw_req_key_export_ms: result.exportMs,
    sw_req_key_total_ms: result.totalMs,
    sw_req_key_reused: result.reused,
    sw_req_key_thumbprint_ms: ms3(thumbMs),
    sw_req_key_proof_ms: ms3(proofMs),
    sw_req_key_register_ms: ms3(regMs)
  });

  return {
    ok: true,
    reqSignKid: result.kid,
    reqSignThumbprint: thumbprint,
    hostJweKid: hostJwk.kid || '(no-kid)',
    hostJweJwk: hostJwk,
    sw_req_keygen_ms: result.keygenMs,
    sw_req_key_export_ms: result.exportMs,
    sw_req_key_total_ms: result.totalMs,
    sw_req_key_reused: result.reused,
    sw_req_key_proof_ms: ms3(proofMs)
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
    const started = performance.now();

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

    const totalMs = performance.now() - started;
    await postMetric('protected_flow_bootstrap', {
      host_jwe_kid: out.hostJweKid,
      req_sign_kid: out.reqSignKid,
      req_sign_thumbprint: out.reqSignThumbprint,
      total_ms: ms3(totalMs)
    });

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

async function runHostWrongClientKeyDemo() {
  const result = await generateReqSigningKeypair();

  const thumbprint = await computeReqSignJwkThumbprint(result.jwk);
  const proofBase = buildReqKeyRegistrationProofBase(result.kid, thumbprint);

  const proofBuf = await crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    REQ_SIGN_KEYPAIR.privateKey,
    new TextEncoder().encode(proofBase)
  );

  const badThumbprint = bytesToB64Url(crypto.getRandomValues(new Uint8Array(32)));

  try {
    await fetchVerifiedJson('POST', '/req-key/register', {
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        kid: result.kid,
        jwk: result.jwk,
        jwkThumbprint: badThumbprint,
        proof: bytesToB64(proofBuf)
      })
    });
    return { ok: false, message: 'demo unexpectedly succeeded' };
  } catch (e) {
    const message = e?.message || String(e);
    await postMetric('wrong_host_key_demo', { ok: true, message });
    return { ok: true, message };
  }
}

self.addEventListener('message', async event => {
  const type = event.data?.type;

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

  if (type === 'RUN_HOST_WRONG_CLIENT_KEY_DEMO') {
    try {
      const result = await runHostWrongClientKeyDemo();
      if (event.source?.postMessage) {
        event.source.postMessage({
          type: 'HOST_WRONG_CLIENT_KEY_DEMO_DONE',
          ...result
        });
      }
    } catch (e) {
      const msg = e?.message || String(e);
      if (event.source?.postMessage) {
        event.source.postMessage({
          type: 'HOST_WRONG_CLIENT_KEY_DEMO_DONE',
          ok: false,
          message: msg
        });
      }
    }
  }
});

async function addRequestSignature(headers, method, targetUri, bodyBytes) {
  if (!REQ_SIGN_KEYPAIR || !REQ_SIGN_KID || !REQ_SIGN_READY) {
    throw new Error('request-signing key not ready');
  }

  const digestStarted = performance.now();
  const digestHash = await crypto.subtle.digest('SHA-256', bodyBytes);
  const digestB64 = bytesToB64(digestHash);
  const digestMs = performance.now() - digestStarted;

  const created = Math.floor(Date.now() / 1000);

  const demo = new URL(targetUri, self.location.origin).searchParams.get('demo');
  const sendDigestB64 = demo === 'req-bad-digest'
    ? bytesToB64(new Uint8Array(32))
    : digestB64;

  const contentDigestHeader = 'sha-256=:' + sendDigestB64 + ':';

  const base =
    `"@method": "${String(method).toLowerCase()}"\n` +
    `"@target-uri": "${targetUri}"\n` +
    `"x-req-created": ${created}\n` +
    `"x-req-content-digest": ${contentDigestHeader}\n` +
    `"x-client-key-id": ${REQ_SIGN_KID}`;

  const signStarted = performance.now();
  const sigBuf = await crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    REQ_SIGN_KEYPAIR.privateKey,
    new TextEncoder().encode(base)
  );
  const signMs = performance.now() - signStarted;

  headers.set('X-Client-Key-Id', REQ_SIGN_KID);
  headers.set('X-Req-Created', String(created));
  headers.set('X-Req-Content-Digest', contentDigestHeader);
  headers.set('X-Req-Signature', bytesToB64(sigBuf));

  await postMetric('request_sign', {
    path: targetUri,
    method,
    req_sign_kid: REQ_SIGN_KID,
    req_body_bytes: bodyBytes.byteLength || 0,
    digest_ms: ms3(digestMs),
    signature_ms: ms3(signMs),
    total_ms: ms3(digestMs + signMs),
    req_sign_header_bytes: approximateSelectedHeaderBytes(headers, [
      'X-Client-Key-Id',
      'X-Req-Created',
      'X-Req-Content-Digest',
      'X-Req-Signature'
    ])
  });
}

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  if (!url.protocol.startsWith('http')) return;
  if (url.origin !== self.location.origin) return;
  if (BOOTSTRAP_PATHS.has(url.pathname)) return;

  event.respondWith((async () => {
    await ensureSigVerifyKeyReady();

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

    const reqStarted = performance.now();
    let res;
    try {
      res = await fetch(upstreamUrl, {
        ...init,
        mode: 'cors',
        cache: 'no-store'
      });
    } catch (e) {
      log('NETWORK ERROR', url.pathname, e?.message || String(e));
      await postMetric('network_error', {
        path: url.pathname + url.search,
        method: event.request.method,
        error: e?.message || String(e)
      });
      throw e;
    }
    const fetchMs = performance.now() - reqStarted;

    const ct = res.headers.get('Content-Type') || '';
    if (!isProtectedContentType(ct)) {
      log('PASS (unverified type)', url.pathname, 'ct=', ct, '→', res.status);
      return res;
    }

    const bodyBytes = await res.clone().arrayBuffer();

    try {
      const method = event.request.method;
      const targetUri = url.pathname + url.search;
      const verifyDiag = await verifyResponse(res, bodyBytes, method, targetUri);

      log('OK', url.pathname, 'ct=', ct, 'status=', res.status);

      const outHeaders = new Headers(res.headers);
      outHeaders.delete('content-length');

      await postMetric('fetch_ok', {
        path: targetUri,
        method,
        status: res.status,
        fetch_ms: ms3(fetchMs),
        verify_ms: verifyDiag.totalMs,
        total_ms: ms3(fetchMs + (verifyDiag.totalMs || 0)),
        resp_body_bytes: bodyBytes.byteLength || 0
      });

      return new Response(bodyBytes, {
        status: res.status,
        statusText: res.statusText,
        headers: outHeaders
      });
    } catch (e) {
      log('BLOCK', url.pathname, 'reason=', e.message || String(e), 'ct=', ct, 'status=', res.status);

      await postMetric('fetch_blocked', {
        path: url.pathname + url.search,
        method: event.request.method,
        status: res.status,
        fetch_ms: ms3(fetchMs),
        error: e?.message || String(e),
        content_type: ct
      });

      return new Response(
        'Blocked by Service Worker (integrity violation): ' + (e.message || 'unknown'),
        { status: 498, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
      );
    }
  })());
});