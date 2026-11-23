// Execute shipped release handlers: a committed POST must survive a failed GET.
const fs = require('node:fs');
const assert = require('node:assert/strict');
const source = fs.readFileSync(process.env.UI_SOURCE || 'docs/ui-preview/preview.js', 'utf8').replace(/\r\n/g, '\n');
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

function handler(selector, indent) {
  const anchor = source.indexOf(`.querySelector("${selector}")`);
  assert(anchor >= 0, selector);
  const start = source.indexOf('async (event) => {', anchor) + 'async (event) => {'.length;
  const end = source.indexOf(`\n${' '.repeat(indent)}});`, start);
  assert(start > anchor && end > start, selector);
  return new AsyncFunction('context', `with (context) { ${source.slice(start, end)} }`);
}

(async () => {
  for (const [selector, indent, scope, kind] of [
    ['[data-release-publish-link]', 2, 'release:external', 'published'],
    ['[data-release-confirm]', 4, 'release:publish', 'published'],
    ['[data-archive-confirm]', 2, 'release:archive', 'archived'],
    ['[data-rename-confirm]', 2, 'release:version', 'version'],
    ['[data-release-delete-package-confirm]', 2, 'release:delete-package', 'deleted'],
  ]) {
    const field = { value: '2.0.1', checkValidity: () => true };
    const reason = { value: '管理员核对后的操作说明' };
    const error = { textContent: '' }, messages = [], events = [];
    const form = { elements: { version: field, reason }, querySelector:()=>error };
    const confirm = { disabled: false, closest: selector => selector === 'dialog' ? dialog : form };
    const dialog = {
      __writeScope: scope, __selectedIds: ['release-1'],
      querySelector: value => value.includes('error') ? error : value.includes('confirm') ? confirm : null,
      close: () => events.push('closed'),
    };
    let writes = 0, reads = 0;
    const values = {
      releaseChannel: {value:'stable'}, releaseExternalVersion:field,
      releaseExternalNotes:reason, releaseExternalUrl:{value:'https://example.test/app.zip'},
      releaseExternalSha256:{value:''}, releaseSoftware:{value:'tool'},
      releaseNotes:reason, archiveReleaseDialog:dialog, renameReleaseDialog:dialog,
    };
    reason.checkValidity = () => true;
    const context = {
      event: {currentTarget:confirm}, releaseDialog:dialog,
      document:{getElementById:id=>values[id]}, window:{__b1ApiActive:true},
      releaseUploadSoftwareId:()=> 'tool', isStandaloneStaticPreview:false,
      releaseFileState:{item:{release_id:'release-1'}},
      pendingDiscardReleaseId:'release-1', archiveTargetReleaseId:'release-1', renameTargetReleaseId:'release-1',
      pendingDeleteReleasePackageId:'release-1', resetDeletePackageConfirm:()=>{confirm.disabled=false},
      releaseContext:{value:'tool'},
      prepareDialogWrite:()=>{throw Error('scope should already be prepared')},
      submitDialogWrite:async()=>{writes++;return {item:{software_id:'tool'},registry_fallback_version:null}},
      apiRequest:async()=>{writes++;return {item:{software_id:'tool'}}},
      applyReleaseResult:()=>events.push('result'), showReleaseStage:stage=>events.push(stage),
      loadReleasesForSoftware:async()=>{reads++;throw Error('read unavailable after commit')},
      showToast:message=>messages.push(message), apiErrorMessage:()=> 'incorrect write failure',
    };
    await handler(selector, indent)(context);
    assert.equal(writes,1,selector);
    assert.equal(reads,1,selector);
    assert.equal(error.textContent,'',`${kind}: GET failure must not become POST failure`);
    assert(messages.some(message=>message.includes('列表刷新失败')),selector);
    assert(events.includes(kind==='published' ? 'result' : 'closed'),selector);
  }

  // Wizard feedback must stay outside the now-hidden upload/verification stage.
  const start = source.indexOf('  function showToast('), end = source.indexOf('\n  try {',start);
  assert(start>=0 && end>start);
  let insertedAfterTitle=false, insertedInStage=false;
  const title={after:()=>{insertedAfterTitle=true}}, hiddenActions={before:()=>{insertedInStage=true}};
  const feedback={dataset:{},setAttribute(){}};
  const dialog={querySelector:selector=>selector==='h2'?title:selector==='.modal-actions'?hiddenActions:null};
  const toast={classList:{remove(){},add(){}}};
  new Function('document','toast','window',`let toastTimer; ${source.slice(start,end)}; showToast('已发布，只需刷新列表');`)(
    {querySelector:()=>dialog,createElement:()=>feedback},toast,{clearTimeout(){},setTimeout(){}});
  assert(insertedAfterTitle && !insertedInStage,'feedback must remain visible across wizard stages');
  console.log('Release writes: ZIP/external publish, archive, rename and visible wizard feedback survived failed refreshes.');
})().catch(error=>{console.error(error);process.exitCode=1});
