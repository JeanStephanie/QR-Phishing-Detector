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
    stream?.getTracks().forEach((track) => track.stop());
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
    if (statusEl) statusEl.textContent = 'Processing...';

    try {
      if (!video.videoWidth || !video.videoHeight) {
        throw new Error('Camera is not ready');
      }

      const canvas = document.createElement('canvas');
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      const context = canvas.getContext('2d');
      if (!context) throw new Error('Unable to capture camera frame');
      context.drawImage(video, 0, 0, canvas.width, canvas.height);

      const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
      const res = await fetch('/api/webcam/complete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken,
        },
        body: JSON.stringify({ image: canvas.toDataURL('image/jpeg', 0.9) }),
      });
      const data = await res.json().catch(() => ({}));
      if (data.success && data.scan_id) {
        window.location.href = '/result/' + encodeURIComponent(data.scan_id);
        return;
      }
      throw new Error(data.error || data.message || `Scan failed (${res.status})`);
    } catch (error) {
      alert(error.message || 'Scan failed');
      scanBtn.disabled = false;
      if (statusEl) statusEl.textContent = 'Live';
    }
  }

  startBtn?.addEventListener('click', start);
  stopBtn?.addEventListener('click', stop);
  scanBtn?.addEventListener('click', capture);
  window.addEventListener('beforeunload', stop);
})();
