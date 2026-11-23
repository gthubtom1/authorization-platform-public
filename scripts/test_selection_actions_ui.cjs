// Run the shipped action helpers with controlled outcomes, without a platform DB.
const fs = require('node:fs');
const assert = require('node:assert/strict');
const source = fs.readFileSync(process.env.UI_SOURCE || 'docs/ui-preview/preview.js', 'utf8').replace(/\r\n/g, '\n');
const helperStart = source.indexOf('  const recordSelections = new Map();');
const helperEnd = source.indexOf('  function revealLiveApp()', helperStart);
assert(helperStart >= 0 && helperEnd > helperStart);

function fixture(network) {
  let keys = 0;
  const calls = [], feedback = [];
  const fields = [
    { id: 'reason', name: 'reason', value: '人工核对后处理', tagName: 'TEXTAREA', readOnly: false },
    { id: 'amount', value: '2', tagName: 'INPUT', readOnly: false },
    { id: 'unit', value: 'day', tagName: 'SELECT', disabled: false },
  ];
  const dialog = {
    open: false,
    querySelectorAll: () => fields,
    presentation: new Map(),
    querySelector(selector) { return this.presentation.get(selector) || null; },
    showModal() { this.open = true; },
    close() { this.open = false; },
  };
  const document = {
    querySelector: () => null,
    createElement: () => ({ dataset: {}, addEventListener() {}, remove() {} }),
  };
  const api = new Function('document', 'CSS', 'apiRequest', 'requestIdempotencyKey', 'showToast', 'apiErrorMessage',
    source.slice(helperStart, helperEnd) + '\nreturn {prepareDialogWrite, restoreDialogWrite, resumeDialogWrite, submitDialogWrite, submitRecordRevocations, pendingUiWrites};')(
    document, { escape: value => value },
    async (path, options) => { calls.push({path, ...options}); return network(calls.length, path, options); },
    () => `operation-${++keys}`, text => feedback.push(text), error => error.message,
  );
  return { api, dialog, fields, calls, feedback };
}

(async () => {
  const lost = fixture(async n => { if (n === 1) throw Error('response lost'); return {renewed_count: 1}; });
  const selected = ['authorization-A'];
  lost.api.prepareDialogWrite(lost.dialog, 'risk:renew', selected);
  selected[0] = 'authorization-B';
  assert.deepEqual(lost.dialog.__selectedIds, ['authorization-A']);
  const originalBody = {authorization_ids: lost.dialog.__selectedIds, amount: 2, unit: 'day', reason: lost.fields[0].value};
  await assert.rejects(lost.api.submitDialogWrite(lost.dialog, '/renew/', originalBody, 'renew'), /尚未确认/);
  assert(lost.fields[0].readOnly);
  assert(lost.fields[2].disabled);
  lost.dialog.close();
  lost.fields[0].value = '不允许替换原请求';
  lost.dialog.__selectedIds = ['authorization-B'];
  assert(lost.api.resumeDialogWrite(lost.dialog, 'risk:renew'));
  assert.deepEqual(lost.dialog.__selectedIds, ['authorization-A']);
  assert.equal(lost.fields[0].value, originalBody.reason);
  await lost.api.submitDialogWrite(lost.dialog, '/different/', {authorization_ids:['authorization-B'], amount: 99}, 'renew');
  assert.deepEqual(lost.calls[0], lost.calls[1]);
  assert.equal(lost.api.pendingUiWrites.size, 0);
  assert(!lost.fields[0].readOnly);

  const invalid = fixture(async n => {
    if (n === 1) { const error = Error('原因不符合要求'); error.status = 400; throw error; }
    return {};
  });
  invalid.api.prepareDialogWrite(invalid.dialog, 'records:archive', ['card-A']);
  await assert.rejects(invalid.api.submitDialogWrite(invalid.dialog, '/archive/', {reason:'短'}, 'archive'));
  assert(!invalid.fields[0].readOnly);
  assert.equal(invalid.api.pendingUiWrites.size, 0);
  await invalid.api.submitDialogWrite(invalid.dialog, '/archive/', {reason:'修正后的合法原因'}, 'archive');
  assert.notEqual(invalid.calls[0].headers['Idempotency-Key'], invalid.calls[1].headers['Idempotency-Key']);

  const server = fixture(async () => { const error = Error('interrupted'); error.status = 503; throw error; });
  server.api.prepareDialogWrite(server.dialog, 'risk:block', ['authorization-A']);
  await assert.rejects(server.api.submitDialogWrite(server.dialog, '/block/', {reason:'人工核对封禁'}, 'block'));
  await assert.rejects(server.api.submitDialogWrite(server.dialog, '/block/', {reason:'新的原因'}, 'block'));
  assert.deepEqual(server.calls[0], server.calls[1]);

  const queue = fixture(async n => { if (n === 2) throw Error('lost second response'); return {}; });
  queue.api.prepareDialogWrite(queue.dialog, 'invitations:revoke', ['code-A','code-B']);
  await assert.rejects(queue.api.submitRecordRevocations(queue.dialog, '/invitations', '核对后作废'), /已完成 1 条/);
  assert(queue.api.resumeDialogWrite(queue.dialog, 'invitations:revoke'));
  const result = await queue.api.submitRecordRevocations(queue.dialog, '/invitations', '忽略的新原因');
  assert.equal(result.succeeded.length, 2);
  assert.equal(queue.calls.length, 3);
  assert.deepEqual(queue.calls[1], queue.calls[2]);
  assert.equal(queue.calls.filter(call => call.path.includes('code-A')).length, 1);

  // Cancelling a selection before submitting performs no write.
  const cancel = fixture(async () => ({}));
  cancel.api.prepareDialogWrite(cancel.dialog, 'risk:revoke', ['authorization-A']);
  cancel.dialog.close();
  assert.equal(cancel.calls.length, 0);
  assert.equal(cancel.api.pendingUiWrites.size, 0);

  // A shared lifecycle dialog may show a different action before resuming.
  // Its visible destructive confirmation must belong to the frozen request.
  const lifecycle = fixture(async n => { if (n === 1) throw Error('lost delete response'); return {}; });
  const labels = {
    '[data-license-lifecycle-title]': '删除已归档邀请码？',
    '[data-license-lifecycle-impact]': '删除记录并保留墓碑，不可恢复。本次可删除 1 张。',
    '[data-license-lifecycle-confirm]': '确认删除',
  };
  for (const [selector,textContent] of Object.entries(labels)) lifecycle.dialog.presentation.set(selector,{textContent});
  lifecycle.dialog.__writePresentation = {...labels};
  lifecycle.api.prepareDialogWrite(lifecycle.dialog,'invitations:delete',['code-B']);
  await assert.rejects(lifecycle.api.submitDialogWrite(lifecycle.dialog,'/invitations/delete/',{code_ids:['code-B'],reason:'核对后删除'},'delete'));
  lifecycle.dialog.close();
  lifecycle.dialog.__writePresentation = {'[data-license-lifecycle-title]':'归档选中邀请码？'};
  for (const label of lifecycle.dialog.presentation.values()) label.textContent='归档后保留记录';
  assert(lifecycle.api.resumeDialogWrite(lifecycle.dialog,'invitations:delete'));
  for (const [selector,text] of Object.entries(labels)) assert.equal(lifecycle.dialog.presentation.get(selector).textContent,text);
  await lifecycle.api.submitDialogWrite(lifecycle.dialog,'/invitations/archive/',{code_ids:['code-A']},'archive');
  assert.deepEqual(lifecycle.calls[0],lifecycle.calls[1]);
  console.log('Selection actions: frozen targets/body/key, cancel, reopen, uncertain retry, validation correction and partial single-record queue passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
