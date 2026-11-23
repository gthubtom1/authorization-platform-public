// Execute the actual policy dialog code with controlled network outcomes.
// These tests distinguish a committed POST from a failed directory read.
const fs = require('node:fs');
const assert = require('node:assert/strict');
const source = fs.readFileSync('docs/ui-preview/preview.js', 'utf8').replace(/\r\n/g, '\n');
const start = source.indexOf('  const pendingPolicySubmissions = new Map();');
const end = source.indexOf('  function preparePasswordResetDialog', start);
assert(start >= 0 && end > start, 'policy handler must exist');
function fixture(network) {
  const save = { disabled: false, textContent: '', addEventListener: (_, fn) => { handler = fn; } };
  let handler;
  const fields = {
    '#policyMaxDevices': { value: '1' }, '#policyVerifyInterval': { value: '1' },
    '#policyOfflineGrace': { value: '0' }, '#policySwitchLimit': { value: '0' },
    '#policyAllowSwitch': { checked: false }, '#policyProofRequired': { checked: true },
    '[data-policy-error]': { textContent: '' }, '[data-policy-context]': { textContent: '' },
    '[data-policy-save]': save,
  };
  const inputs = Object.entries(fields).filter(([k]) => k.startsWith('#')).map(([,v]) => v);
  const calls = [], toasts = [];
  let keys = 0, closed = 0;
  const dialog = { dataset: { policySoftware: 'sample', policyProfile: 'stable' }, querySelector: s => fields[s], querySelectorAll: () => inputs, close: () => { closed++; } };
  const document = { getElementById: () => dialog };
  const build = new Function('document','catalogItems','isStandaloneStaticPreview','apiRequest','requestIdempotencyKey','loadCatalog','showToast','apiErrorMessage', source.slice(start,end) + '\nreturn {preparePolicyDialog};');
  const api = build(document, [], false, async (_,options) => { calls.push(options); return network(calls.length); }, () => `request-${++keys}`, async () => { throw Error('directory unavailable'); }, message => toasts.push(message), (error,fallback) => error.message || fallback);
  return { save, fields, inputs, calls, toasts, dialog, prepare: () => api.preparePolicyDialog({ dataset: { policySoftware:'sample', policyProfile:'stable' } }), submit: () => handler({ currentTarget:save }), closed: () => closed };
}
(async () => {
  const saved = fixture(async () => ({}));
  await saved.submit();
  assert.equal(saved.closed(), 1);
  assert.equal(saved.calls.length, 1);
  assert(saved.toasts.at(-1).includes('已保存') && saved.toasts.at(-1).includes('刷新失败'));
  assert.equal(saved.fields['[data-policy-error]'].textContent, '');

  const uncertain = fixture(async n => { if(n === 1) throw Error('connection lost'); return {}; });
  await uncertain.submit();
  assert.equal(uncertain.closed(), 0);
  assert(uncertain.inputs.every(input => input.disabled));
  uncertain.prepare(); // Closing/reopening within the page must retain the unknown operation.
  await uncertain.submit();
  assert.equal(uncertain.calls.length, 2);
  assert.equal(uncertain.calls[0].headers['Idempotency-Key'], uncertain.calls[1].headers['Idempotency-Key']);
  assert.equal(uncertain.calls[0].body, uncertain.calls[1].body);
  assert.equal(uncertain.closed(), 1);
  uncertain.prepare();
  await uncertain.submit();
  assert.notEqual(uncertain.calls[1].headers['Idempotency-Key'], uncertain.calls[2].headers['Idempotency-Key']);

  const invalid = fixture(async n => { if(n === 1) { const error = Error('invalid policy'); error.status = 400; throw error; } return {}; });
  await invalid.submit();
  assert(invalid.inputs.every(input => !input.disabled));
  invalid.fields['#policyVerifyInterval'].value = '2';
  await invalid.submit();
  assert.notEqual(invalid.calls[0].headers['Idempotency-Key'], invalid.calls[1].headers['Idempotency-Key']);
  console.log('Policy UI: committed save/refresh failure, unknown replay, reopening, new edit, validation correction passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
