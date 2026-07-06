<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Bootstrap</title>
  <style>
    body {
      font-family: monospace;
      white-space: pre-wrap;
      margin: 0;
      padding: 12px;
    }
  </style>
</head>
<body>
<pre id="log">Bootstrapping…</pre>

<script>
  const logEl = document.getElementById('log');

  function log(msg) {
    logEl.textContent += '\n' + msg;
    console.log(msg);
  }

  async function main() {
    if (!('serviceWorker' in navigator)) {
      throw new Error('Service Worker not supported');
    }

    log('Registering service worker...');
    await navigator.serviceWorker.register('/sw.js', { scope: '/' });
    await navigator.serviceWorker.ready;

    log('Service worker ready');
    log('Navigating to /login.html ...');
    location.replace('/login.html');
  }

  navigator.serviceWorker?.addEventListener('message', e => {
    if (e.data?.type === 'SW_LOG') {
      log('[SW] ' + e.data.message);
    }
  });

  main().catch(err => {
    log('FATAL: ' + (err?.message || err));
    console.error(err);
  });
</script>
</body>
</html>
