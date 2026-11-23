// Execute the delivered page controller with a minimal DOM. No string checks.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
const source = fs.readFileSync(process.argv[2] || path.join(__dirname,'../../软件授权接入包/授权启动器模板/ui/authorization-a-shell.js'),'utf8');
function page({bridge=false,prototype=false}={}) {
  const nodes=new Map(), timers=[], posts=[], storage=new Map([['a.saved_card','LEGACY-CARD']]);let writes=0;
  const node=key=>{
    if (!nodes.has(key)) nodes.set(key,{dataset:{},hidden:false,disabled:false,value:'',textContent:'',listeners:{},style:{},firstChild:null,
      setAttribute(){},focus(){},addEventListener(type,fn){this.listeners[type]=fn;},appendChild(){},removeChild(){}});
    return nodes.get(key);
  };
  const document={querySelector:node,getElementById:node,querySelectorAll:()=>[],documentElement:{style:{setProperty(){}}},body:node('body')};
  const window={location:{search:prototype?'?prototype=1':''},setTimeout(fn){timers.push(fn);return timers.length;},clearTimeout(){},
    localStorage:{getItem:k=>storage.get(k)||null,setItem(k,v){writes++;storage.set(k,v);},removeItem:k=>storage.delete(k)}};
  if (bridge) window.ipc={postMessage:s=>posts.push(JSON.parse(s))};
  const context={window,document,URLSearchParams,navigator:{},console,Set,Number,Date,Object};
  vm.runInNewContext(source,context);
  return {window,node,timers,posts,storage,get writes(){return writes;}};
}
const plain=page();
assert.equal(plain.node('activateButton').disabled,true,'formal page without bridge must be unavailable');
assert.equal(plain.storage.has('a.saved_card'),false,'retired plaintext card must be removed');
plain.node('activationForm').listeners.submit({preventDefault(){}});
assert.equal(plain.timers.length,0,'formal missing bridge must never schedule success');
assert.equal(plain.writes,0);
const prototype=page({prototype:true});
prototype.node('activationForm').listeners.submit({preventDefault(){}});
assert.equal(prototype.timers.length,1);
prototype.timers[0]();assert.equal(prototype.node('.shell').dataset.state,'active');
const live=page({bridge:true});
live.node('credential').value='ONE-REQUEST-CARD';
live.node('activationForm').listeners.submit({preventDefault(){}});
assert.equal(live.posts[0].credential,'ONE-REQUEST-CARD');assert.equal(live.node('credential').value,'');
function snapshot(authorization,intents,modules=[],expiry=1800000000) {
  return {profile:{enabled_modules:['contact','purchase'],copy:{}},snapshot:{display_name:'中文😀',expires_at:expiry,modules,state:{authorization,intents}}};
}
live.window.authorizationAApplySnapshot(snapshot('active',['request_launch']));
assert.equal(live.node('.shell').dataset.state,'active');
assert.equal(live.node('supportLinks').hidden,true,'empty modules must hide purchase/contact');
assert.equal(live.posts.filter(p=>p.name==='request_launch').length,1);
const before=live.node('feedbackMessage').textContent;
live.window.authorizationAApplySnapshot(snapshot('active',['request_launch'],[],1800003600));
assert.notEqual(live.node('feedbackMessage').textContent,before,'renewal must update visible expiry');
live.window.authorizationAApplySnapshot(snapshot('blocked',['activate']));
assert.equal(live.node('.shell').dataset.state,'blocked');
assert.equal(live.writes,0);assert.equal(live.storage.has('a.saved_card'),false);
const wrongCard=snapshot('unavailable',['activate']);wrongCard.snapshot.error='LICENSE_NOT_FOUND';
live.window.authorizationAApplySnapshot(wrongCard);
assert.equal(live.node('activateButton').disabled,false,'a definitive wrong card allows an explicit new activation');
assert.match(live.node('feedbackMessage').textContent,/LICENSE_NOT_FOUND/,'display the actual business refusal');
live.node('credential').value='CORRECTED-CARD';
live.node('activationForm').listeners.submit({preventDefault(){}});
assert.equal(live.posts.at(-1).type,'activate');assert.equal(live.posts.at(-1).credential,'CORRECTED-CARD');
const unknown=snapshot('unavailable',['retry']);unknown.snapshot.error='NETWORK_RETRY';
live.window.authorizationAApplySnapshot(unknown);
live.node('credential').value='MUST-NOT-REPLACE-UNKNOWN-REQUEST';
live.node('activationForm').listeners.submit({preventDefault(){}});
assert.equal(live.posts.at(-1).name,'retry');assert.equal(live.posts.at(-1).credential,undefined);
console.log('PASS: missing bridge, prototype isolation, plaintext cleanup, dynamic state, renewal, empty channels, wrong-card recovery, unknown-request retry');
