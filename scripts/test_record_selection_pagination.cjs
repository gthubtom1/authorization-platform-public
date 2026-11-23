// Exercise the shipped collector through a real, private HTTP socket.
// Server page size is deliberately independent of the requested page size.
const fs = require('node:fs');
const http = require('node:http');
const assert = require('node:assert/strict');
const source = fs.readFileSync(process.env.UI_SOURCE || 'docs/ui-preview/preview.js','utf8');
const start=source.indexOf('  async function selectFilteredRecords(panel) {');
const end=source.indexOf('\n  document.addEventListener("change"',start);
assert(start>=0 && end>start);

async function runCase({total=31,pageSize=5,scope='invitations',alter,initial=['original'],interrupt}={}) {
  const selection={rows:new Map(initial.map(id=>[id,{id}])),generation:0,busy:false};
  const calls=[],messages=[];
  let resumePage, enteredPage;
  const pageEntered=new Promise(resolve=>{enteredPage=resolve});
  const pageReleased=new Promise(resolve=>{resumePage=resolve});
  const server=http.createServer(async(req,res)=>{
    const url=new URL(req.url,'http://localhost');
    const page=Number(url.searchParams.get(scope==='quota-cards'?'card_page':'page'));
    calls.push({method:req.method,page});
    if(interrupt && page===2) {enteredPage();await pageReleased;}
    const items=Array.from({length:Math.max(0,Math.min(pageSize,total-(page-1)*pageSize))},(_,i)=>({public_id:`id-${(page-1)*pageSize+i}`,status:scope==='downstream-licenses'?'unused':'issued'}));
    let data={items,pagination:{page,page_size:pageSize,total,total_pages:Math.max(1,Math.ceil(total/pageSize)),has_next:page*pageSize<total}};
    if(alter) data=alter(data,page);
    if(scope==='quota-cards') data={cards:data.items,cards_pagination:data.pagination};
    res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(data));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const base=`http://127.0.0.1:${server.address().port}`;
  const context={
    recordSelection:()=>selection,recordScope:()=>scope,hasCredentialSearchOverlay:()=>false,
    isStandaloneStaticPreview:false,window:{__b1ApiActive:true},syncRecordSelection(){},
    URLSearchParams,showToast:message=>messages.push(message),
    quotaCardFilterQuery:()=>({}),licenseCardFilterQuery:()=>({}),licenseCardsPrefix:()=>'/licenses',
    nonSecretTableQuery:()=>'',selectionRowFromItem:(_scope,item)=>({id:item.public_id}),
    apiRequest:async path=>(await fetch(base+path)).json(),apiErrorMessage:(_error,fallback)=>fallback,
  };
  const panel={querySelector:()=>null};
  const collect=new Function('context','panel',`with(context){${source.slice(start,end)};return selectFilteredRecords(panel);}`);
  try {
    const pending=collect(context,panel);
    if(interrupt) {
      await pageEntered;
      selection.generation++;selection.rows.clear();
      if(interrupt==='filter') selection.rows.set('new-filter-id',{id:'new-filter-id'});
      selection.busy=false;resumePage();
    }
    await pending;
    assert(calls.every(x=>x.method==='GET'));
    return {ids:[...selection.rows.keys()],calls,messages,busy:selection.busy};
  } finally {server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
}

(async()=>{
  for(const [scope,total,pageSize] of [
    ['invitations',0,5],['invitations',30,5],['invitations',31,5],['invitations',500,5],
    ['quota-cards',31,5],['management-licenses',500,100],['downstream-licenses',31,10],
    ['invitations',500,1],
  ]) {
    const result=await runCase({scope,total,pageSize});
    assert.equal(result.ids.length,total,`${scope}/${total}: ${JSON.stringify(result)}`);
    assert.equal(result.calls.length,Math.max(1,Math.ceil(total/pageSize)));
    assert.equal(result.busy,false);
  }
  const tooMany=await runCase({total:501});
  assert.deepEqual(tooMany.ids,['original']);assert.equal(tooMany.calls.length,1);
  assert(tooMany.messages.some(x=>x.includes('500')&&x.includes('缩小')),'show the actual size limit');
  const badCases=[
    (data,page)=>page===2?{...data,items:data.items.map((item,i)=>({...item,public_id:`id-${i}`}))}:data,
    (data,page)=>page===2?{...data,items:[]}:data,
    (data,page)=>page===2?{...data,items:data.items.map(item=>({...item,public_id:null}))}:data,
    (data,page)=>page===2?{...data,pagination:{...data.pagination,total:30}}:data,
    (data,page)=>page===2?{...data,pagination:{...data.pagination,page:1}}:data,
    data=>({...data,pagination:{...data.pagination,total_pages:1}}),
    data=>({...data,pagination:{...data.pagination,total:2}}),
    (data,page)=>page===2?{...data,pagination:{...data.pagination,has_next:false}}:data,
    data=>({...data,pagination:null}),
  ];
  for(const alter of badCases) {
    const result=await runCase({alter});
    assert.deepEqual(result.ids,['original'],'do not replace selection with partial or contradictory data');
    assert(result.calls.length<=2,'stop immediately on non-progress/invalid metadata');
    assert(result.messages.length>0);assert.equal(result.busy,false);
  }
  const cancelled=await runCase({interrupt:'cancel'});
  assert.deepEqual(cancelled.ids,[]);assert.equal(cancelled.calls.length,2);
  const filtered=await runCase({interrupt:'filter'});
  assert.deepEqual(filtered.ids,['new-filter-id']);assert.equal(filtered.calls.length,2);
  console.log('Record selection: actual page sizes through 500 IDs, 501 refusal, metadata/progress validation, atomic replacement and cancel/filter races passed.');
})().catch(error=>{console.error(error);process.exitCode=1});
