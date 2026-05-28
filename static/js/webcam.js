(function () {
  'use strict';

  const video = document.getElementById('webcam-video');
  const startBtn = document.getElementById('webcam-start');
  const scanBtn = document.getElementById('webcam-scan');
  const stopBtn = document.getElementById('webcam-stop');
  const statusEl = document.getElementById('webcam-status');

  if (!video) return;

  let stream = null;

  async function start() {
    try {
      stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment', width: { ideal: 1280 } },
        audio: false,
      });
      video.srcObject = stream;
      await video.play();
      if (statusEl) statusEl.textContent = 'Live';
      startBtn.disabled = true;
      scanBtn.disabled = false;
      stopBtn.disabled = false;
    } catch {
      alert('Camera access is required for this feature.');
    }
  }

  function stop() {
    stream?.getTracks().forEach((t) => t.stop());
    stream = null;
    video.srcObject = null;
    if (statusEl) statusEl.textContent = 'Camera off';
    startBtn.disabled = false;
    scanBtn.disabled = true;
    stopBtn.disabled = true;
  }

  async function capture() {
    if (!stream) return;
    scanBtn.disabled = true;
    if (statusEl) statusEl.textContent = 'Processing…';
    await new Promise((r) => setTimeout(r, 2000));
    try {
      const res = await fetch('/api/webcam/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      if (data.success && data.scan_id) window.location.href = '/result/' + data.scan_id;
    } catch {
      alert('Scan failed');
      scanBtn.disabled = false;
      if (statusEl) statusEl.textContent = 'Live';
    }
  }

  startBtn?.addEventListener('click', start);
  stopBtn?.addEventListener('click', stop);
  scanBtn?.addEventListener('click', capture);
  window.addEventListener('beforeunload', stop);
})();
