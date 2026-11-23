'use strict';
(() => {
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => [...document.querySelectorAll(s)];
  const owner = document.body.dataset.owner;
  const uploadKey = `directlink-upload-${owner}`;
  const actionKey = `directlink-action-${owner}`;
  let upload = null, selectedFile = null, uploading = false, cancelling = false, currentXHR = null;
  const transportBytes = 1024 * 1024;
  let uploadGeneration = 0, activeRun = null;
  function currentRun(run) { return activeRun === run && upload === run.task && uploadGeneration === run.generation && !run.cancelled; }
  function checkRun(run) { if (!currentRun(run)) throw Object.assign(new Error('已取消。'), {cancelled:true}); }
  let actionData = null, actionRows = [], infoRow = null;
  function load(key) { try { return JSON.parse(localStorage.getItem(key)); } catch { return null; } }
  function save(key, value) { if (value) localStorage.setItem(key, JSON.stringify(value)); else localStorage.removeItem(key); }
  function token() { return document.querySelector('[name=csrfmiddlewaretoken]')?.value || ''; }
  function toast(text) { const t = $('#toast'); t.textContent = text; t.hidden = false; clearTimeout(toast.timer); toast.timer = setTimeout(() => { t.hidden = true; }, 4000); }
  function errorAt(id, text) { const e = $(id); e.textContent = text; e.hidden = !text; }
  function show(id) { const d = $(id); if (!d.open) d.showModal(); }
  function rowData(row) { return {id: row.dataset.id, revision: Number(row.dataset.revision), title: row.dataset.title}; }
  function fixed(id) { return new URL(`/d/${id}/`, location.origin).href; }
  function bytes(n) { if (n < 1024) return `${n} B`; const units = ['KB','MB','GB','TB']; let x = n / 1024, i = 0; while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; } return `${x.toFixed(x >= 10 ? 1 : 2)} ${units[i]}`; }
  async function api(url, method = 'GET', data, options = {}) {
    const controller = new AbortController(), abort = () => controller.abort();
    const signal = options.signal;
    if (signal?.aborted) abort();
    signal?.addEventListener('abort',abort,{once:true});
    const timer = setTimeout(abort, options.timeout || 45000);
    try {
      let response, value;
      try {
        response = await fetch(url, {method, credentials:'same-origin', signal:controller.signal, headers: {'X-CSRFToken':token(), ...(data ? {'Content-Type':'application/json'} : {})}, body: data ? JSON.stringify(data) : undefined});
        // The deadline includes receiving the response body, not just its headers.
        value = await response.json();
      } catch { throw Object.assign(new Error('连接中断或等待超时，结果尚未确认。请保留任务并重试。'), {unknown:true}); }
      if (!response.ok) throw Object.assign(new Error(value.error || '操作失败，请重试。'), {unknown:response.status >= 500 && value.definitive !== true, status:response.status});
      return value;
    } finally { clearTimeout(timer); signal?.removeEventListener('abort',abort); }
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); toast('固定链接已复制'); }
    catch { $('#copy-value').value = text; show('#copy-dialog'); $('#copy-value').focus(); $('#copy-value').select(); }
  }
  $$('[data-close]').forEach(b => b.addEventListener('click', () => {
    if (b.dataset.close === 'upload-dialog' && uploading) { toast('请先取消正在进行的上传。'); return; }
    document.getElementById(b.dataset.close).close();
  }));
  if (!$('#new-file')) return;
  function banner() {
    const pendingAction = load(actionKey), pendingUpload = load(uploadKey);
    $('#pending-banner').hidden = !pendingAction && !pendingUpload;
    $('#pending-message').textContent = pendingAction ? '上次操作结果尚未确认，请重试原操作。' : '有一个未完成的上传，可以继续或取消。';
  }
  function newUpload(target = null) {
    if (load(actionKey)) { toast('请先确认上次操作的结果。'); return; }
    if (load(uploadKey)) { resumeUpload(); return; }
    uploadGeneration += 1;
    upload = {key:crypto.randomUUID(), target:target?.id || null, revision:target?.revision || null};
    selectedFile = null;
    $('#cancel-upload').textContent = '取消'; $('#cancel-upload').disabled = false;
    $('#upload-form').reset();
    $('#upload-file').disabled = false; $('#start-upload').disabled = false;
    $('#upload-file').required = true;
    $('#upload-heading').textContent = target ? `更新文件 · ${target.title}` : '新建软件';
    $('#name-field').hidden = !!target;
    $('#upload-hint').textContent = target ? '固定链接保持不变。新文件就绪前，原文件继续下载。' : '名称可不填，上传成功后生成固定链接。';
    $('#chosen-file').textContent = '选择电脑上的文件';
    $('#upload-progress').hidden = true;
    $('#start-upload').textContent = target ? '上传替换' : '上传';
    errorAt('#upload-error', ''); show('#upload-dialog');
  }
  function resumeUpload() {
    uploadGeneration += 1;
    upload = load(uploadKey);
    if (!upload) return;
    $('#cancel-upload').textContent = upload.cancelRequested ? '重试取消' : '取消'; $('#cancel-upload').disabled = false;
    $('#upload-form').reset(); selectedFile = null;
    $('#upload-heading').textContent = '继续上次上传';
    $('#name-field').hidden = true;
    $('#chosen-file').textContent = upload.request?.filename || '未完成任务，请继续确认或取消';
    $('#upload-file').disabled = false; $('#start-upload').disabled = false;
    $('#upload-hint').textContent = upload.cancelRequested ? '已停止本地传输，取消结果尚未确认。请重试取消。' : '重新选择同一文件后继续。已完成上传但未确认结果时可直接重试。';
    $('#upload-file').required = false;
    $('#upload-progress').hidden = true;
    $('#start-upload').textContent = upload.cancelRequested ? '核对取消结果' : '继续处理';
    errorAt('#upload-error',''); show('#upload-dialog');
  }
  $('#new-file').addEventListener('click', () => newUpload());
  $('#empty-new')?.addEventListener('click', () => newUpload());
  $('#pending-retry').addEventListener('click', () => {
    const saved = load(actionKey);
    if (saved) { actionData = saved.request; actionRows = saved.rows; openActionDialog(); }
    else resumeUpload();
  });
  $('#upload-file').addEventListener('change', e => {
    selectedFile = e.target.files[0] || null;
    $('#chosen-file').textContent = selectedFile ? `${selectedFile.name} · ${bytes(selectedFile.size)}` : '选择电脑上的文件';
  });
  const picker = $('.file-picker');
  for (const name of ['dragover', 'dragleave', 'drop']) picker.addEventListener(name, e => {
    e.preventDefault(); picker.classList.toggle('dragging', name === 'dragover');
    if (name === 'drop' && !uploading && e.dataTransfer.files.length) {
      selectedFile = e.dataTransfer.files[0];
      $('#upload-file').files = e.dataTransfer.files;
      $('#chosen-file').textContent = `${selectedFile.name} · ${bytes(selectedFile.size)}`;
    }
  });
  async function fingerprint(file, run) {
    const parts = [];
    for (let offset = 0; offset < file.size; offset += 8 * 1024 * 1024) {
      checkRun(run);
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', await file.slice(offset, offset + 8 * 1024 * 1024).arrayBuffer()));
      checkRun(run);
      parts.push(digest);
      $('#upload-phase').textContent = '正在读取文件';
      $('#upload-percent').textContent = `${Math.round(Math.min(file.size,offset + 8*1024*1024)/file.size*100)}%`;
    }
    const size = new TextEncoder().encode(String(file.size));
    const buffer = new Uint8Array(parts.length * 32 + size.length);
    parts.forEach((part, i) => buffer.set(part, i * 32)); buffer.set(size, parts.length * 32);
    const result = await crypto.subtle.digest('SHA-256', buffer);
    checkRun(run);
    return [...new Uint8Array(result)].map(x => x.toString(16).padStart(2,'0')).join('');
  }
  function paintConfirmed(state, run, phase = '正在上传', waiting = false) {
    checkRun(run);
    const percent = state.received / state.size * 100;
    $('#progress').value = percent; $('#upload-percent').textContent = `${Math.floor(percent)}%`;
    $('#upload-phase').textContent = phase;
    const elapsed = Math.max(.1,(performance.now()-run.started)/1000);
    const added = state.received-run.initialReceived;
    const speed = !waiting && added > 0 ? ` · 平均 ${bytes(added/elapsed)}/秒` : '';
    $('#upload-detail').textContent = `已确认 ${bytes(state.received)} / ${bytes(state.size)}${speed}${waiting ? ` · 本段已等待 ${Math.floor((performance.now()-run.chunkStarted)/1000)} 秒` : ''}`;
  }
  function sendChunk(id, state, data, run) {
    return new Promise((resolve,reject) => {
      const xhr = new XMLHttpRequest(); currentXHR = xhr;
      xhr.open('POST', `/manage/api/uploads/${id}/chunk/?offset=${state.received}`);
      xhr.setRequestHeader('X-CSRFToken',token()); xhr.timeout = 180000;
      run.chunkStarted = performance.now();
      let sent = false;
      const render = () => { if (currentRun(run)) paintConfirmed(state,run,sent ? '等待服务器确认本段' : '正在传输本段',true); };
      const timer = setInterval(render,1000); render();
      const finish = (error,value) => { clearInterval(timer); if (currentXHR === xhr) currentXHR = null; if (error) reject(error); else resolve(value); };
      xhr.upload.onprogress = e => { sent = e.lengthComputable && e.loaded === e.total; render(); };
      xhr.upload.onload = () => { sent = true; render(); };
      xhr.onload = () => {
        let value; try { value = JSON.parse(xhr.responseText); } catch { finish(Object.assign(new Error('未能确认分块结果。'),{unknown:true})); return; }
        if (xhr.status >= 200 && xhr.status < 300) finish(null,value);
        else finish(Object.assign(new Error(value.error || '分块上传失败，请继续原任务。'),{unknown:xhr.status>=500 && value.definitive!==true,status:xhr.status}));
      };
      xhr.onerror = () => finish(Object.assign(new Error('上传连接中断。'),{unknown:true}));
      xhr.ontimeout = () => finish(Object.assign(new Error('本段上传超时。'),{unknown:true}));
      xhr.onabort = () => finish(Object.assign(new Error('传输已停止。'),{cancelled:true}));
      xhr.send(data);
    });
  }
  function waitRetry(ms,run) {
    return new Promise((resolve,reject) => {
      const done = () => { clearTimeout(timer); run.controller.signal.removeEventListener('abort',abort); resolve(); };
      const abort = () => { clearTimeout(timer); run.controller.signal.removeEventListener('abort',abort); reject(Object.assign(new Error('已停止。'),{cancelled:true})); };
      const timer = setTimeout(done,ms);
      run.controller.signal.addEventListener('abort',abort,{once:true});
      if (run.controller.signal.aborted) abort();
    });
  }
  async function nextChunk(task,state,file,run) {
    let failures = 0;
    while (true) {
      checkRun(run);
      try {
        const next = await sendChunk(task.id,state,file.slice(state.received,state.received+transportBytes),run);
        checkRun(run);
        if (next.received <= state.received || next.received > state.size || next.id !== task.id) throw Object.assign(new Error('服务器进度未确认。'),{unknown:true});
        return next;
      } catch (err) {
        checkRun(run);
        if (!err.unknown) throw err;
        // A successful read without any byte advancement must not reset this budget.
        while (true) {
          if (++failures > 3) throw Object.assign(new Error('连接仍不稳定，已确认进度已保留。可点击“继续上传”，或取消本次上传。'),{unknown:true});
          paintConfirmed(state,run,`连接波动，正在恢复（${failures}/3）`,true);
          await waitRetry(failures*1000,run); checkRun(run);
          let confirmed;
          try { confirmed = await api(`/manage/api/uploads/${task.id}/`,'GET',undefined,{signal:run.controller.signal}); }
          catch (readError) { checkRun(run); if (!readError.unknown) throw readError; continue; }
          checkRun(run);
          if (confirmed.status !== 'uploading' && confirmed.status !== 'done') throw new Error('任务已取消或过期，请取消此任务后重新上传。');
          if (confirmed.received > state.received && confirmed.received <= state.size && confirmed.id === task.id) return confirmed;
          if (confirmed.received !== state.received || confirmed.id !== task.id) throw new Error('服务器进度异常，请保留任务并重新确认。');
          break;
        }
      }
    }
  }
  $('#upload-form').addEventListener('submit', async e => {
    e.preventDefault(); if (uploading) return;
    if (upload?.cancelRequested) { $('#cancel-upload').click(); return; }
    const task = upload, file = selectedFile, name = $('#upload-name').value.trim();
    if (!task) return;
    const run = {task, generation:uploadGeneration, cancelled:false,controller:new AbortController()}; activeRun = run;
    uploading = true; $('#start-upload').disabled = true; $('#upload-file').disabled = true;
    $('#upload-progress').hidden = false; errorAt('#upload-error','');
    try {
      if (!task.request && !task.id) {
        if (!file?.size) throw new Error('请选择非空的安装包或压缩文件。');
        const fp = await fingerprint(file, run); checkRun(run);
        task.request = {...task, filename:file.name, size:file.size, fingerprint:fp, name};
        save(uploadKey,task); banner();
      }
      let state = task.id ? await api(`/manage/api/uploads/${task.id}/`,'GET',undefined,{signal:run.controller.signal}) : await api('/manage/api/uploads/','POST',task.request,{signal:run.controller.signal});
      checkRun(run);
      task.id = state.id; save(uploadKey,task);
      if (state.status === 'done') { completeUpload(state); return; }
      if (state.status !== 'uploading') throw new Error('任务已取消或过期，请取消此任务后重新上传。');
      if (state.received < state.size) {
        if (!task.request) throw new Error('本地任务资料不完整，请取消此任务后重新上传。');
        if (!file) throw new Error('请选择上次上传的同一个文件后继续。');
        if (file.size !== state.size || await fingerprint(file,run) !== task.request.fingerprint) throw new Error('选择的文件内容与原文件不同，请选择原文件，或取消后重新上传。');
        checkRun(run);
        run.started = performance.now(); run.initialReceived = state.received;
        paintConfirmed(state,run);
        while (state.received < state.size) {
          checkRun(run);
          state = await nextChunk(task,state,file,run);
          checkRun(run);
          paintConfirmed(state,run);
        }
      }
      checkRun(run);
      $('#upload-phase').textContent = '正在校验并保存'; $('#upload-percent').textContent = ''; $('#progress').value = 100;
      state = await api(`/manage/api/uploads/${task.id}/finish/`,'POST',undefined,{signal:run.controller.signal,timeout:180000});
      checkRun(run);
      completeUpload(state);
    } catch (err) {
      if (!currentRun(run)) return;
      if (!err.unknown && !task.id && task.request) {
        // A definitive create rejection did not allocate a task. Allow a new file/request.
        task.request = null; save(uploadKey,null);
      }
      errorAt('#upload-error',err.message);
      $('#upload-phase').textContent = '上传已暂停'; $('#start-upload').textContent = '继续上传';
    }
    finally { if (currentRun(run)) { uploading = false; currentXHR = null; activeRun = null; $('#start-upload').disabled = false; $('#upload-file').disabled = false; banner(); } }
  });
  function completeUpload(state) {
    save(uploadKey,null); $('#upload-dialog').close(); toast('文件已保存，固定链接可在列表复制。'); location.assign('/manage/?saved=1');
  }
  $('#upload-dialog').addEventListener('cancel', e => { if (uploading) e.preventDefault(); });
  $('#cancel-upload').addEventListener('click', async () => {
    if (cancelling) return;
    cancelling = true; $('#cancel-upload').disabled = true; $('#cancel-upload').textContent = '正在取消…';
    const task = upload, generation = ++uploadGeneration;
    if (activeRun) { activeRun.cancelled = true; activeRun.controller.abort(); }
    activeRun = null; currentXHR?.abort(); currentXHR = null; uploading = true;
    if (task && (task.id || task.request)) { task.cancelRequested = true; save(uploadKey,task); }
    $('#upload-phase').textContent = '本地传输已停止，正在确认取消';
    $('#upload-detail').textContent = '';
    $('#start-upload').disabled = true; $('#upload-file').disabled = true;
    const stillCurrent = () => upload === task && uploadGeneration === generation;
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(),45000);
    const options = {signal:controller.signal};
    try {
      if (!task?.id && task?.request) {
        const state = await api('/manage/api/uploads/','POST',task.request,options);
        task.id = state.id; save(uploadKey,task);
      }
      if (task?.id) {
        try { await api(`/manage/api/uploads/${task.id}/`,'DELETE',undefined,options); }
        catch (err) {
          if (err.status !== 409) throw err;
          const state = await api(`/manage/api/uploads/${task.id}/`,'GET',undefined,options);
          if (state.status !== 'done') throw err;
          if (stillCurrent()) completeUpload(state);
          return;
        }
      }
      if (!stillCurrent()) return;
      uploading = false; $('#start-upload').disabled = false; $('#upload-file').disabled = false;
      save(uploadKey,null); upload = null; $('#upload-dialog').close(); banner();
    } catch (err) {
      if (!stillCurrent()) return;
      uploading = false; $('#start-upload').disabled = false; $('#upload-file').disabled = false;
      if (!err.unknown && !task?.id) {
        save(uploadKey,null); upload=null; $('#upload-dialog').close(); banner();
      } else {
        errorAt('#upload-error',`本地传输已停止，取消结果未确认。${err.message} 点击“重试取消”。`);
        $('#start-upload').textContent = '核对取消结果';
      }
    } finally {
      clearTimeout(timer); cancelling = false;
      if (stillCurrent()) { uploading = false; $('#start-upload').disabled = false; $('#upload-file').disabled = false; }
      $('#cancel-upload').disabled = false; $('#cancel-upload').textContent = upload?.cancelRequested ? '重试取消' : '取消'; banner();
    }
  });
  function selection() {
    const checked = $$('.row-check:checked');
    $('#selection-bar').hidden = !checked.length;
    $('#selection-count').textContent = `已选 ${checked.length} 个`;
    const all = $$('.row-check'); $('#select-page').checked = all.length > 0 && all.length === checked.length;
    $('#select-page').indeterminate = checked.length > 0 && checked.length < all.length;
  }
  $$('.row-check').forEach(c => c.addEventListener('change',selection));
  $('#select-page').addEventListener('change', e => { $$('.row-check').forEach(c => {c.checked=e.target.checked;}); selection(); });
  $('#clear-selection').addEventListener('click', () => { $$('.row-check').forEach(c => {c.checked=false;}); selection(); });
  const names = {pause:'暂停下载',resume:'恢复下载',delete:'删除',rename:'修改名称',restore:'恢复上一次文件',clean:'清理历史文件'};
  function openActionDialog() {
    $('#action-heading').textContent = names[actionData.action];
    $('#action-copy').textContent = actionData.action === 'delete' ? '所选软件的固定链接及文件地址将失效，全部安装包会被删除。' : actionData.action === 'clean' ? '仅清理超过24小时的较早文件，保留当前和上一份。引用旧文件的地址会失效。' : actionData.action === 'pause' ? '固定链接和文件地址将停止接受新下载；已开始的传输可能继续。' : actionData.action === 'restore' ? '固定链接将切回上一份完整文件。' : `处理以下 ${actionRows.length} 个软件。`;
    $('#action-targets').replaceChildren(...actionRows.map(r => { const li = document.createElement('li'); li.textContent=r.title; return li; }));
    $('#rename-field').hidden = actionData.action !== 'rename'; $('#rename-value').value = actionData.name || '';
    $('#action-submit').classList.toggle('danger',actionData.action==='delete');
    $('#action-submit').textContent = names[actionData.action]; errorAt('#action-error',''); show('#action-dialog');
  }
  function prepareAction(verb, rows, name='') {
    if (load(actionKey)) { toast('请先确认上次操作的结果。'); return; }
    actionRows = rows; actionData = {key:crypto.randomUUID(),action:verb,items:rows.map(({id,revision})=>({id,revision})),name}; openActionDialog();
  }
  $$('[data-bulk]').forEach(b => b.addEventListener('click', () => prepareAction(b.dataset.bulk,$$('.row-check:checked').map(c=>rowData(c.closest('tr'))))));
  $('#action-form').addEventListener('submit',async e => {
    e.preventDefault(); const button = $('#action-submit'); button.disabled = true;
    if (!load(actionKey) && actionData.action === 'rename') actionData.name = $('#rename-value').value.trim();
    save(actionKey,{request:actionData,rows:actionRows}); banner();
    try { await api('/manage/api/actions/','POST',actionData); save(actionKey,null); location.reload(); }
    catch (err) { if (!err.unknown) save(actionKey,null); errorAt('#action-error',err.message); banner(); }
    finally {button.disabled=false;}
  });
  $$('.row-actions [data-action],.file-title').forEach(b => b.addEventListener('click',async () => {
    const row = b.closest('tr'); const data = rowData(row); const verb=b.dataset.action;
    if (verb === 'copy') {await copy(fixed(data.id));return;}
    if (verb === 'update') {newUpload(data);return;}
    if (verb === 'info') {
      try {
        const info = await api(`/manage/api/files/${data.id}/`); infoRow=data;
        const pairs=[['名称',info.title],['文件',info.filename],['大小',bytes(info.size)],['固定链接',info.fixed],['文件内容地址',info.content_url],['SHA-256',info.sha256],['保留文件',`${info.history_count} 份`]];
        $('#info-content').replaceChildren(...pairs.flatMap(([label,value])=>{const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=value;return[dt,dd];}));
        show('#info-dialog');
      } catch (err) {toast(err.message);} return;
    }
    prepareAction(verb,[data],row.dataset.name);
  }));
  $('#clean-history').addEventListener('click',()=>{$('#info-dialog').close();prepareAction('clean',[infoRow]);});
  $('#page-size').addEventListener('change',e=>e.target.form.requestSubmit());
  banner();
  if (new URLSearchParams(location.search).get('saved') === '1') { toast('文件已保存，固定链接可在列表复制。'); history.replaceState(null,'','/manage/'); }
})();
