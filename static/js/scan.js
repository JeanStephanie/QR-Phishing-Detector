(function () {
  'use strict';

  const zone = document.getElementById('upload-zone');
  const input = document.getElementById('qr-file-input');
  const previewWrap = document.getElementById('qr-preview-wrap');
  const previewImg = document.getElementById('qr-preview-img');
  const panel = document.getElementById('scan-interface');
  const uploadSection = document.getElementById('upload-section');
  const scanBtn = document.getElementById('start-scan-btn');
  const progress = document.getElementById('scan-progress-fill');
  const form = document.getElementById('scan-upload-form');
  const errorBox = document.getElementById('scan-error');

  if (!zone || !input) return;

  let file = null;

  function showPreview(f) {
    const r = new FileReader();
    r.onload = (e) => {
      previewImg.src = e.target.result;
      previewWrap.classList.add('show');
      if (scanBtn) scanBtn.disabled = false;
    };
    r.readAsDataURL(f);
  }

  function pick(f) {
    if (!f?.type.startsWith('image/')) return;
    file = f;
    if (errorBox) {
      errorBox.textContent = '';
      errorBox.classList.remove('show');
    }
    showPreview(f);
  }

  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('dragover'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('dragover');
    if (e.dataTransfer.files[0]) pick(e.dataTransfer.files[0]);
  });
  input.addEventListener('change', () => { if (input.files[0]) pick(input.files[0]); });

  function setStep(i) {
    document.querySelectorAll('.scan-steps span').forEach((el, idx) => {
      el.classList.remove('active', 'done');
      if (idx < i) el.classList.add('done');
      if (idx === i) el.classList.add('active');
    });
  }

  async function run() {
    if (!file) return;
    if (errorBox) {
      errorBox.textContent = '';
      errorBox.classList.remove('show');
    }
    uploadSection.style.display = 'none';
    previewWrap.classList.remove('show');
    panel.classList.add('show');
    setStep(0);
    if (progress) progress.style.width = '0%';

    const fd = new FormData(form || undefined);
    fd.set('qr_image', file);
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
    const req = fetch(form?.action || '/upload', {
      method: 'POST',
      body: fd,
      headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'X-CSRFToken': csrfToken,
      },
    });

    let pct = 0;
    const tick = setInterval(() => {
      pct += 8 + Math.random() * 10;
      if (pct >= 100) {
        pct = 100;
        clearInterval(tick);
        if (progress) progress.style.width = '100%';
        finish(req);
      } else {
        if (progress) progress.style.width = pct + '%';
        if (pct > 25) setStep(1);
        if (pct > 55) setStep(2);
        if (pct > 80) setStep(3);
      }
    }, 200);
  }

  async function finish(req) {
    try {
      const res = await req;
      const data = await res.json().catch(() => ({}));
      if (data.success && data.redirect) window.location.href = data.redirect;
      else throw new Error(data.error || data.message || `Scan failed (${res.status})`);
    } catch (e) {
      if (errorBox) {
        errorBox.textContent = e.message || 'Scan failed. Please try another QR image.';
        errorBox.classList.add('show');
      }
      panel.classList.remove('show');
      uploadSection.style.display = 'block';
      previewWrap.classList.add('show');
      if (scanBtn) scanBtn.disabled = false;
    }
  }

  scanBtn?.addEventListener('click', (e) => { e.preventDefault(); run(); });
  form?.addEventListener('submit', (e) => { e.preventDefault(); run(); });
})();
