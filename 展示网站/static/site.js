'use strict';
(() => {
  const drawer = document.getElementById('storeSidebar');
  const shell = document.getElementById('storeShell');
  const opener = document.getElementById('drawerOpen');
  let open = false;
  function setDrawer(value, restore = false) {
    if (!drawer) return;
    open = value;
    drawer.classList.toggle('open', value);
    drawer.inert = innerWidth <= 900 && !value;
    document.getElementById('drawerBackdrop').hidden = !value;
    shell.inert = value;
    opener.setAttribute('aria-expanded', String(value));
    document.body.style.overflow = value ? 'hidden' : '';
    if (value) {
      drawer.setAttribute('role', 'dialog'); drawer.setAttribute('aria-modal', 'true');
      document.getElementById('drawerClose').focus();
    } else {
      drawer.removeAttribute('role'); drawer.removeAttribute('aria-modal');
      if (restore) opener.focus();
    }
  }
  if (drawer) {
    opener.onclick = () => setDrawer(true);
    document.getElementById('drawerClose').onclick = () => setDrawer(false, true);
    document.getElementById('drawerBackdrop').onclick = () => setDrawer(false, true);
    addEventListener('resize', () => setDrawer(false));
    setDrawer(false);
  }

  const lightbox = document.getElementById('lightbox');
  let currentGallery = null, galleryOpener = null;
  function updateGallery(gallery, index) {
    const slides = [...gallery.querySelectorAll('[data-slide]')];
    if (!slides.length) return;
    index = (index + slides.length) % slides.length;
    gallery.dataset.index = String(index);
    slides.forEach((slide, i) => { slide.hidden = i !== index; });
    if (document.body.classList.contains('storefront') && !matchMedia('(prefers-reduced-motion: reduce)').matches) {
      slides[index].animate([{ clipPath: 'inset(0 100% 0 0)' }, { clipPath: 'inset(0 0 0 0)' }], { duration: 280, easing: 'cubic-bezier(.16,1,.3,1)' });
    }
    const counter = gallery.querySelector('[data-counter]');
    if (counter) counter.textContent = `${index + 1} / ${slides.length}`;
    if (lightbox?.open && currentGallery === gallery) updateLightbox();
  }
  function updateLightbox() {
    const slides = [...currentGallery.querySelectorAll('[data-slide]')];
    const index = Number(currentGallery.dataset.index || 0);
    const source = slides[index].querySelector('img');
    const img = document.getElementById('lightboxImage');
    img.src = source.src; img.alt = source.alt;
    document.getElementById('lightboxTitle').textContent = currentGallery.closest('.software').querySelector('h2').textContent;
    document.getElementById('lightboxCount').textContent = `${index + 1} / ${slides.length}`;
    for (const id of ['lightboxPrev', 'lightboxNext']) document.getElementById(id).hidden = slides.length < 2;
  }
  document.querySelectorAll('[data-gallery]').forEach(gallery => {
    let start = null;
    gallery.addEventListener('click', e => {
      const index = Number(gallery.dataset.index || 0);
      if (e.target.closest('[data-prev]')) updateGallery(gallery, index - 1);
      else if (e.target.closest('[data-next]')) updateGallery(gallery, index + 1);
      else if (e.target.closest('[data-slide]')) {
        currentGallery = gallery; galleryOpener = e.target.closest('[data-slide]');
        updateLightbox(); lightbox.showModal(); document.body.style.overflow = 'hidden';
      }
    });
    gallery.addEventListener('touchstart', e => { start = e.touches.length === 1 ? { x: e.touches[0].clientX, y: e.touches[0].clientY } : null; }, { passive: true });
    gallery.addEventListener('touchend', e => {
      if (!start) return;
      const dx = e.changedTouches[0].clientX - start.x, dy = e.changedTouches[0].clientY - start.y; start = null;
      if (Math.abs(dx) > 48 && Math.abs(dx) > Math.abs(dy) * 1.5) {
        e.preventDefault(); updateGallery(gallery, Number(gallery.dataset.index || 0) + (dx < 0 ? 1 : -1));
      }
    }, { passive: false });
    gallery.addEventListener('touchcancel', () => { start = null; }, { passive: true });
    gallery.querySelectorAll('img').forEach(img => img.addEventListener('error', () => {
      img.alt = '图片暂时无法加载';
      const slide = img.closest('[data-slide]');
      if (!slide || slide.querySelector('.image-load-error')) return;
      const message = document.createElement('span');
      message.className = 'image-load-error';
      message.textContent = '图片暂时无法加载，请刷新页面后重试。';
      img.hidden = true;
      slide.disabled = true;
      slide.append(message);
    }));
  });
  if (lightbox) {
    document.getElementById('closeLightbox').onclick = () => lightbox.close();
    document.getElementById('lightboxPrev').onclick = () => updateGallery(currentGallery, Number(currentGallery.dataset.index || 0) - 1);
    document.getElementById('lightboxNext').onclick = () => updateGallery(currentGallery, Number(currentGallery.dataset.index || 0) + 1);
    lightbox.addEventListener('close', () => {
      document.body.style.overflow = '';
      const visibleSlide = currentGallery?.querySelector('[data-slide]:not([hidden])');
      (visibleSlide || galleryOpener)?.focus({ preventScroll: true });
    });
    lightbox.addEventListener('click', e => { if (e.target !== lightbox) return; const r = lightbox.getBoundingClientRect(); if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) lightbox.close(); });
  }
  document.addEventListener('keydown', e => {
    if (open) {
      if (e.key === 'Escape') { e.preventDefault(); setDrawer(false, true); }
      if (e.key === 'Tab') {
        const elements = [...drawer.querySelectorAll('button,a')].filter(x => x.getClientRects().length);
        if (e.shiftKey && document.activeElement === elements[0]) { e.preventDefault(); elements.at(-1).focus(); }
        else if (!e.shiftKey && document.activeElement === elements.at(-1)) { e.preventDefault(); elements[0].focus(); }
      }
    }
    if (lightbox?.open && ['ArrowLeft', 'ArrowRight'].includes(e.key)) { e.preventDefault(); updateGallery(currentGallery, Number(currentGallery.dataset.index || 0) + (e.key === 'ArrowLeft' ? -1 : 1)); }
  });
  document.querySelectorAll('[data-preview-action]').forEach(button => button.onclick = () => { button.closest('.software-copy').querySelector('.inline-feedback').hidden = false; });
  document.querySelectorAll('form[data-confirm]').forEach(form => form.addEventListener('submit', e => { if (!confirm(form.dataset.confirm)) e.preventDefault(); }));
  document.querySelectorAll('[data-dirty-form]').forEach(form => {
    let dirty = false;
    form.addEventListener('input', () => { dirty = true; const status = document.getElementById('saveStatus'); if (status) status.textContent = '有未保存的修改'; });
    form.addEventListener('change', () => { dirty = true; });
    form.addEventListener('submit', () => { dirty = false; });
    addEventListener('beforeunload', e => { if (dirty) { e.preventDefault(); e.returnValue = ''; } });
  });
})();
