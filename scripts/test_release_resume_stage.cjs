const fs=require('node:fs'),assert=require('node:assert/strict');
const source=fs.readFileSync(process.env.UI_SOURCE||'docs/ui-preview/preview.js','utf8');
const begin=source.indexOf('  function restoreDialogWrite('),end=source.indexOf('\n  async function submitDialogWrite(',begin);
const pending={ids:['original-software'],fields:{releaseExternalVersion:'2.0.0'},context:{}};
const field={id:'releaseExternalVersion',tagName:'INPUT',value:'other',type:'text'};
const dialog={__writeScope:'release:external',querySelectorAll:()=>[field],querySelector:()=>null};
let stage='verify',index=1;
const notice={remove(){}};
new Function('pendingUiWrites','document','CSS','showToast','showReleaseStage','dialog',source.slice(begin,end)+'\nrestoreDialogWrite(dialog);')(
 new Map([['release:external',pending]]),{querySelector:()=>notice},{escape:v=>v},()=>{},(s,i)=>{stage=s;index=i},dialog);
assert.equal(stage,'upload');assert.equal(index,0);assert.equal(field.value,'2.0.0');assert(field.readOnly);
console.log('RELEASE_RESUME_STAGE_PASS');
