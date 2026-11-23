'use strict';
(() => {
  const form = document.getElementById('productEditor');
  if (!form) return;
  const editor = document.getElementById('imageEditor'), input = document.getElementById('imageUploads');
  const layout = document.getElementById('id_image_layout'), cover = document.getElementById('id_cover');
  document.getElementById('id_images_managed').value = '1';
  const uploads = [], urls = new Map(); let dragged = null;
  function tiles() { return [...editor.querySelectorAll('[data-image-key]')]; }
  function sync(dirty = true) {
    const all = tiles();
    if (!all.some(tile => tile.dataset.imageKey === cover.value)) cover.value = all[0]?.dataset.imageKey || '';
    const coverTile = all.find(tile => tile.dataset.imageKey === cover.value);
    layout.value = all.map(tile => tile.dataset.imageKey).join(',');
    all.forEach(tile => { const button = tile.querySelector('[data-cover]'), active = tile.dataset.imageKey === cover.value; button.setAttribute('aria-pressed', String(active)); button.textContent = active ? '封面' : '设为封面'; });
    const transfer = new DataTransfer(); uploads.forEach(file => { if (file) transfer.items.add(file); });
    input.files = transfer.files;
    // New keys must match the compact file list submitted to the server.
    let n = 0;
    all.forEach(tile => { if (tile.dataset.imageKey.startsWith('n')) tile.dataset.imageKey = `n${n++}`; });
    cover.value = coverTile?.dataset.imageKey || '';
    layout.value = all.map(tile => tile.dataset.imageKey).join(',');
    document.getElementById('imageCount').textContent = `${all.length} / 12`;
    if (dirty) form.dispatchEvent(new Event('input', { bubbles: true }));
  }
  const selected = tiles().find(tile => tile.querySelector('[data-cover]').getAttribute('aria-pressed') === 'true');
  cover.value = selected?.dataset.imageKey || tiles()[0]?.dataset.imageKey || '';
  layout.value = tiles().map(tile => tile.dataset.imageKey).join(',');
  function rebuildFileOrder() {
    const ordered = tiles().filter(tile => tile.file).map(tile => tile.file);
    uploads.splice(0, uploads.length, ...ordered);
  }
  function mark() { rebuildFileOrder(); sync(); }
  input.addEventListener('change', () => {
    const selectedFiles = [...input.files];
    const error = document.getElementById('uploadError'); error.hidden = true;
    if (selectedFiles.length + tiles().length > 12) { error.textContent = '每款软件最多12张图片。'; error.hidden = false; mark(); return; }
    const bad = selectedFiles.find(file => !['image/jpeg', 'image/png', 'image/webp'].includes(file.type) || file.size > 8 * 1024 * 1024);
    if (bad) { error.textContent = '请选择8MB以内的 JPG、PNG 或 WebP 图片。'; error.hidden = false; mark(); return; }
    for (const file of selectedFiles) {
      const tile = document.createElement('div'); tile.className = 'image-tile'; tile.draggable = true; tile.dataset.imageKey = `n${tiles().filter(x => x.file).length}`; tile.file = file;
      const img = document.createElement('img'); const url = URL.createObjectURL(file); urls.set(tile, url); img.src = url; img.alt = file.name;
      const actions = document.createElement('div'); actions.className = 'image-tile-actions';
      const base = editor.querySelector('.image-tile-actions');
      if (base) actions.innerHTML = base.innerHTML;
      else actions.innerHTML = '<button type="button" data-cover aria-pressed="false">设为封面</button><button type="button" data-move="-1" aria-label="图片前移"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="m14 6-6 6 6 6"/></svg></button><button type="button" data-move="1" aria-label="图片后移"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="m10 6 6 6-6 6"/></svg></button><button type="button" data-remove aria-label="移除图片"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="m6 6 12 12M6 18 18 6"/></svg></button>';
      tile.append(img, actions); editor.append(tile);
    }
    mark();
  });
  editor.addEventListener('click', e => {
    const button = e.target.closest('button'), tile = button?.closest('[data-image-key]'); if (!tile) return;
    if (button.hasAttribute('data-cover')) cover.value = tile.dataset.imageKey;
    if (button.hasAttribute('data-remove')) { if (urls.has(tile)) URL.revokeObjectURL(urls.get(tile)); tile.remove(); }
    if (button.dataset.move === '-1' && tile.previousElementSibling) editor.insertBefore(tile, tile.previousElementSibling);
    if (button.dataset.move === '1' && tile.nextElementSibling) editor.insertBefore(tile.nextElementSibling, tile);
    mark();
  });
  editor.addEventListener('dragstart', e => { dragged = e.target.closest('[data-image-key]'); if (!dragged) return; dragged.classList.add('dragging'); e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', dragged.dataset.imageKey); });
  editor.addEventListener('dragover', e => { if (dragged) e.preventDefault(); });
  editor.addEventListener('drop', e => { const target = e.target.closest('[data-image-key]'); if (dragged && target && dragged !== target) { e.preventDefault(); editor.insertBefore(dragged, target); mark(); } });
  editor.addEventListener('dragend', () => { dragged?.classList.remove('dragging'); dragged = null; });
  form.addEventListener('submit', () => { rebuildFileOrder(); sync(false); });
})();
