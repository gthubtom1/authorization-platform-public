const {chromium}=require('D:/Tools/Node/node_modules/playwright');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),base=process.env.DL_TEST_BASE||'http://127.0.0.1:8780';
const access=JSON.parse(fs.readFileSync(process.env.DL_TEST_ACCESS||path.join(root,'test-results/local-access.json'),'utf8'));
(async()=>{
 const browser=await chromium.launch({headless:true});const result={};
 try {
  async function session(){
   const context=await browser.newContext();const page=await context.newPage();page.setDefaultTimeout(10000);
   await page.addInitScript(()=>{const original=window.setTimeout;window.setTimeout=(fn,ms,...args)=>original(fn,ms===45000?300:ms,...args);});
   await page.goto(base+'/manage/login/');await page.getByLabel('账号',{exact:true}).fill(access.username);await page.getByLabel('密码',{exact:true}).fill(access.password);
   await Promise.all([page.waitForURL('**/manage/'),page.getByRole('button',{name:'登录',exact:true}).click()]);
   return {context,page};
  }
  async function begin(page,name,size){await page.locator('#new-file').click();await page.locator('#upload-file').setInputFiles({name,mimeType:'application/zip',buffer:Buffer.alloc(size,59)});await page.locator('#start-upload').click();}
  {
   const {context,page}=await session();let held=false,release,ident;const gate=new Promise(r=>release=r);
   await context.route('**/chunk/?offset=*',async route=>{if(!held){held=true;ident=route.request().url().match(/uploads\/([^/]+)/)[1];await gate;await route.continue();}else await route.continue();});
   await page.evaluate(()=>{const send=XMLHttpRequest.prototype.send;XMLHttpRequest.prototype.send=function(body){if(body instanceof Blob)setTimeout(()=>this.upload.dispatchEvent(new ProgressEvent('progress',{lengthComputable:true,loaded:body.size,total:body.size})),30);return send.call(this,body);};});
   await begin(page,'network-confirmation.zip',3*1024*1024);
   await page.waitForFunction(()=>document.querySelector('#progress').value>=0);
   for(let n=0;n<100&&!held;n++)await new Promise(r=>setTimeout(r,30));assert(held);
   await page.waitForTimeout(250);
   assert.equal(await page.locator('#progress').evaluate(e=>e.value),0,'unacknowledged bytes must not be reported as saved');
   assert.match(await page.locator('#upload-detail').innerText(),/已确认/);
   assert(!/MB\/秒/.test(await page.locator('#upload-detail').innerText()),'browser buffer must not invent throughput');
   await page.locator('#cancel-upload').click();await page.locator('#upload-dialog').waitFor({state:'hidden'});release();
   await page.waitForTimeout(200);const state=await page.request.get(base+`/manage/api/uploads/${ident}/`);assert.equal((await state.json()).status,'cancelled');
   result.confirmed_progress_and_cancel=true;await context.close();
  }
  {
   const {context,page}=await session();let dropped=false,maxChunk=0;
   await context.route('**/chunk/?offset=*',async route=>{maxChunk=Math.max(maxChunk,route.request().postDataBuffer().length);if(!dropped){dropped=true;await route.fetch();await route.abort();}else await route.continue();});
   const name=`network-lost-ack-${Date.now()}.zip`;await begin(page,name,3*1024*1024);
   await page.locator('#upload-dialog').waitFor({state:'hidden',timeout:15000});
   assert(dropped);assert(maxChunk<=1024*1024,'slow routes need smaller transport chunks');
   const row=page.locator('tr[data-id]').filter({hasText:name});await row.waitFor();
   const target=await row.evaluate(e=>({id:e.dataset.id,revision:Number(e.dataset.revision)}));
   const response=await page.request.post(base+'/manage/api/actions/',{headers:{'X-CSRFToken':await page.locator('[name=csrfmiddlewaretoken]').first().inputValue()},data:{key:require('node:crypto').randomUUID(),action:'delete',items:[target]}});assert.equal(response.status(),200);
   result.lost_ack_recovers_without_duplicate=true;await context.close();
  }
  {
   const {context,page}=await session();let uploadId,attempts=0,deletes=0;
   await context.route('**/chunk/?offset=*',route=>{attempts++;return route.abort();});
   await begin(page,'network-offline.zip',16);
   await page.locator('#upload-error:not([hidden])').waitFor({timeout:20000});
   assert.equal(attempts,4,'one initial send plus at most three retries without confirmed advancement');
   assert(await page.evaluate(()=>Object.keys(localStorage).some(k=>k.startsWith('directlink-upload-'))),'offline upload must be retained');
   await context.route('**/manage/api/uploads/*/',async route=>{if(route.request().method()==='DELETE'){deletes++;uploadId=route.request().url();await new Promise(r=>setTimeout(r,1000));try{await route.abort();}catch{}}else await route.continue();});
   await page.locator('#cancel-upload').click();
   assert(await page.locator('#cancel-upload').isDisabled());
   await page.locator('#cancel-upload').dispatchEvent('click');
   await page.waitForFunction(()=>!document.querySelector('#cancel-upload').disabled);assert.equal(deletes,1,'duplicate cancel must not issue another DELETE');
   assert.match(await page.locator('#upload-error').innerText(),/取消.*未确认/);
   assert(await page.evaluate(()=>Object.keys(localStorage).some(k=>k.startsWith('directlink-upload-'))));
   await context.unroute('**/manage/api/uploads/*/');await page.locator('#cancel-upload').click();await page.locator('#upload-dialog').waitFor({state:'hidden'});
   assert(uploadId);result.bounded_retry_and_cancel_timeout_retains_task=true;await context.close();
  }
  {
   const {context,page}=await session();let held=false,release;const gate=new Promise(r=>release=r);
   await context.route('**/finish/',async route=>{const response=await route.fetch();held=true;await gate;try{await route.fulfill({response});}catch{}});
   const name=`network-finished-cancel-${Date.now()}.zip`;await begin(page,name,31);
   for(let n=0;n<100&&!held;n++)await new Promise(r=>setTimeout(r,30));assert(held);
   await page.locator('#cancel-upload').click();await page.locator('#upload-dialog').waitFor({state:'hidden'});release();
   await page.locator('#toast').filter({hasText:'文件已保存'}).waitFor();
   const row=page.locator('tr[data-id]').filter({hasText:name});await row.waitFor();
   const target=await row.evaluate(e=>({id:e.dataset.id,revision:Number(e.dataset.revision)}));
   const response=await page.request.post(base+'/manage/api/actions/',{headers:{'X-CSRFToken':await page.locator('[name=csrfmiddlewaretoken]').first().inputValue()},data:{key:require('node:crypto').randomUUID(),action:'delete',items:[target]}});assert.equal(response.status(),200);
   assert(!await page.evaluate(()=>Object.keys(localStorage).some(k=>k.startsWith('directlink-upload-'))));
   result.completed_before_cancel_reports_saved=true;await context.close();
  }
  {
   const {context,page}=await session();let held=false;
   await context.route('**/chunk/?offset=*',route=>route.abort());
   await begin(page,'network-body-timeout.zip',17);await page.locator('#upload-error:not([hidden])').waitFor({timeout:20000});
   await page.evaluate(()=>{
    const original=window.fetch;
    window.fetch=async function(url,options){
     const response=await original(url,options);
     if(options?.method==='DELETE')return new Response(new ReadableStream({start(controller){controller.enqueue(new TextEncoder().encode('{'));options.signal.addEventListener('abort',()=>controller.error(new DOMException('aborted','AbortError')),{once:true});}}),{status:200,headers:{'Content-Type':'application/json'}});
     return response;
    };
   });
   await page.locator('#cancel-upload').click();await page.locator('#upload-error').filter({hasText:'取消结果未确认'}).waitFor();
   assert(!await page.locator('#cancel-upload').isDisabled());
   assert(await page.evaluate(()=>JSON.parse(localStorage.getItem('directlink-upload-'+document.body.dataset.owner)).cancelRequested));
   await page.reload();await page.locator('#pending-retry').click();
   assert.equal(await page.locator('#start-upload').innerText(),'核对取消结果');
   await page.locator('#start-upload').click();await page.locator('#upload-dialog').waitFor({state:'hidden'});
   result.response_body_deadline_and_cancel_survives_reload=true;await context.close();
  }
  {
   const {context,page}=await session();const crypto=require('node:crypto');
   const file=Buffer.alloc(9*1024*1024,27),first=file.subarray(0,8*1024*1024),last=file.subarray(first.length);
   const fingerprint=crypto.createHash('sha256').update(Buffer.concat([crypto.createHash('sha256').update(first).digest(),crypto.createHash('sha256').update(last).digest(),Buffer.from(String(file.length))])).digest('hex');
   const headers={'X-CSRFToken':await page.locator('[name=csrfmiddlewaretoken]').first().inputValue()};
   const name=`network-resume-${Date.now()}.zip`,request={key:crypto.randomUUID(),filename:name,size:file.length,fingerprint,name:''};
   const task=await (await page.request.post(base+'/manage/api/uploads/',{headers,data:request})).json();
   const firstResponse=await page.request.post(base+`/manage/api/uploads/${task.id}/chunk/?offset=0`,{headers:{...headers,'Content-Type':'application/octet-stream'},data:first});assert.equal(firstResponse.status(),200);
   await page.evaluate(task=>localStorage.setItem('directlink-upload-'+document.body.dataset.owner,JSON.stringify(task)),{id:task.id,key:request.key,request});
   let held=false,release;const gate=new Promise(r=>release=r);
   await context.route('**/chunk/?offset=*',async route=>{held=true;await gate;await route.continue();});
   await page.locator('#new-file').click();await page.locator('#upload-file').setInputFiles({name,mimeType:'application/zip',buffer:file});await page.locator('#start-upload').click();
   for(let n=0;n<100&&!held;n++)await new Promise(r=>setTimeout(r,30));assert(held);
   assert.equal(await page.locator('#progress').evaluate(e=>e.value),8/9*100);
   const text=await page.locator('#upload-detail').innerText();assert.match(text,/已确认 8.00 MB/);assert(!text.includes('/秒'),'resumed old bytes cannot become current throughput');
   for(const width of [1440,390]){await page.setViewportSize({width,height:1050});const bounds=await page.locator('#upload-dialog').boundingBox();assert(bounds.x>=0&&bounds.x+bounds.width<=width+1);await page.screenshot({path:path.join(root,`test-results/network-wait-${width}.png`),fullPage:true});}
   release();await page.locator('#upload-dialog').waitFor({state:'hidden'});
   const row=page.locator('tr[data-id]').filter({hasText:name});await row.waitFor();const target=await row.evaluate(e=>({id:e.dataset.id,revision:Number(e.dataset.revision)}));
   assert.equal((await page.request.post(base+'/manage/api/actions/',{headers:{'X-CSRFToken':await page.locator('[name=csrfmiddlewaretoken]').first().inputValue()},data:{key:crypto.randomUUID(),action:'delete',items:[target]}})).status(),200);
   result.resume_excludes_old_bytes_and_preserves_8m_fingerprint=true;await context.close();
  }
  fs.writeFileSync(path.join(root,'test-results/upload-network.json'),JSON.stringify(result,null,2));console.log('UPLOAD_NETWORK_PASS',JSON.stringify(result));
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
