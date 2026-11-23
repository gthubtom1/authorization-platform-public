// Execute the shipped single-card handler with controlled transport outcomes.
// No browser, credentials, database, or platform API is used by this regression.
const fs = require('node:fs');
const assert = require('node:assert/strict');
const source = fs.readFileSync('docs/ui-preview/preview.js', 'utf8').replace(/\r\n/g, '\n');
const start = source.indexOf('  function installAuthorizationRiskManagement(loadData)');
const end = source.indexOf('  function installInvitationIssue', start);
const routeStart = source.indexOf('  function riskManagementRoute(row, kind)');
const routeEnd = source.indexOf('  const managementActionCopy', routeStart);
assert(start >= 0 && end > start && routeStart >= 0 && routeEnd > routeStart);

function fixture(network, reload = async () => {}) {
  let handler, keys = 0, closed = 0;
  const reason = { value: '人工核对异常后冻结', readOnly: false };
  const error = { textContent: '' };
  const button = { disabled: false, textContent: '', addEventListener: (_, fn) => { handler = fn; } };
  const form = { elements: { reason }, checkValidity: () => true, querySelector: () => error };
  const dialog = {
    dataset: {},
    querySelector: selector => selector === 'form' ? form
      : selector === '[data-management-action-title]' ? { textContent: '冻结这张卡' } : button,
    close: () => { closed++; },
  };
  const calls = [], toasts = [];
  const pending = { scope: 'device', kind: 'block', row: { dataset: { authorizationId: 'authorization-a', deviceId: 'opaque-reference', riskActionDeviceUuid: 'stable-device-a' } } };
  const build = new Function('managementActionDialog', 'pendingManagementAction', 'riskManagementAttempts', 'apiRequest', 'requestIdempotencyKey', 'showToast', 'apiErrorMessage', 'managementActionCopy', 'reload',
    source.slice(routeStart, routeEnd) + source.slice(start, end) + '\ninstallAuthorizationRiskManagement(reload);');
  build(dialog, pending, new Map(), async (route, options) => {
    calls.push({ route, ...options });
    return network(calls.length);
  }, () => `risk-${++keys}`, message => toasts.push(message), (failure, fallback) => failure.message || fallback, { block: ['冻结这张卡'] }, reload);
  return { submit: () => handler(), reason, error, calls, toasts, button, dialog, row: pending.row, closed: () => closed };
}

(async () => {
  const unknown = fixture(async n => { if (n === 1) throw Error('response lost'); return {}; });
  await unknown.submit();
  assert.equal(unknown.closed(), 0);
  assert(unknown.reason.readOnly);
  assert(unknown.error.textContent.includes('尚未确认'));
  unknown.row.dataset.deviceId = 'rotated-opaque-reference-after-read';
  await unknown.submit();
  assert.equal(unknown.closed(), 1);
  assert.deepEqual(unknown.calls[0], unknown.calls[1]);

  const committed = fixture(async () => ({}), async () => { throw Error('read unavailable'); });
  await committed.submit();
  assert.equal(committed.calls.length, 1);
  assert.equal(committed.closed(), 1);
  assert.equal(committed.error.textContent, '');
  assert(committed.toasts.at(-1).includes('已完成，列表刷新失败'));

  const rejected = fixture(async n => {
    if (n === 1) { const failure = Error('reason invalid'); failure.status = 400; throw failure; }
    return {};
  });
  await rejected.submit();
  assert(!rejected.reason.readOnly);
  rejected.reason.value = '修正后的人工核对原因';
  await rejected.submit();
  assert.notEqual(rejected.calls[0].headers['Idempotency-Key'], rejected.calls[1].headers['Idempotency-Key']);
  assert.notEqual(rejected.calls[0].body, rejected.calls[1].body);

  const uncertainServer = fixture(async () => { const failure = Error('server interrupted'); failure.status = 503; throw failure; });
  await uncertainServer.submit();
  await uncertainServer.submit();
  assert.deepEqual(uncertainServer.calls[0], uncertainServer.calls[1]);
  assert.equal(uncertainServer.dialog.dataset.operationPending, undefined);
  assert(!uncertainServer.button.disabled);
  console.log('Risk UI: lost-response replay, committed write/read failure, validation correction, server-uncertain retry passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
