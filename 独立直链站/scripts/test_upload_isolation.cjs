const {chromium}=require('D:/Tools/Node/node_modules/playwright');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),base=process.env.DL_TEST_BASE||'http://127.0.0.1:8780';
const access=JSON.parse(fs.readFileSync(path.join(root,'test-results/local-access.json'),'utf8'));
(async()=>{
 const browser=await chromium.launch({headless:true});
 try {
  for(const phase of ['read','create']){
   const context=await browser.newContext(),page=await context.newPage(),errors=[];
   page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(7000);
   await page.goto(base+'/manage/login/');await page.getByLabel('账号',{exact:true}).fill(access.username);await page.getByLabel('密码',{exact:true}).fill(access.password);
   await Promise.all([page.waitForURL('**/manage/'),page.getByRole('button',{name:'登录',exact:true}).click()]);
   const target=await page.locator('tr[data-id]').first().getAttribute('data-id');
   let held=false,release,created;const gate=new Promise(resolve=>release=resolve);
   if(phase==='create')await context.route('**/manage/api/uploads/',async route=>{
    if(!held&&route.request().method()==='POST'){const response=await route.fetch();created=await response.json();held=true;await gate;await route.fulfill({response});}
    else await route.continue();
   });
   else await page.evaluate(()=>{const original=Blob.prototype.arrayBuffer;window.holdRead=false;Blob.prototype.arrayBuffer=function(...args){if(!window.holdRead){window.holdRead=true;return new Promise((resolve,reject)=>window.releaseRead=()=>original.apply(this,args).then(resolve,reject));}return original.apply(this,args);};});
   await page.locator('#new-file').click();await page.locator('#upload-file').setInputFiles({name:'isolated-A.zip',mimeType:'application/zip',buffer:Buffer.from('original A contents')});await page.locator('#start-upload').click();
   if(phase==='read')await page.waitForFunction(()=>window.holdRead);
   else {for(let n=0;n<100&&!held;n++)await new Promise(r=>setTimeout(r,30));assert(held);}
   await page.locator('#cancel-upload').click();await page.locator('#upload-dialog').waitFor({state:'hidden'});
   await page.locator(`tr[data-id="${target}"] [data-action=update]`).click();
   assert.equal(await page.locator('#upload-file').isDisabled(),false,'B is ready after A cancellation');
   await page.locator('#upload-file').setInputFiles({name:'isolated-B.zip',mimeType:'application/zip',buffer:Buffer.from('different B contents')});
   if(phase==='read')await page.evaluate(()=>window.releaseRead()); else release();
   await page.waitForTimeout(250);
   const stored=await page.evaluate(()=>localStorage.getItem('directlink-upload-'+document.body.dataset.owner));
   assert.equal(stored,null,'late A cannot persist or submit B');assert.equal(errors.length,0);
   await page.locator('#start-upload').click();await page.locator('#upload-dialog').waitFor({state:'hidden'});
   await page.locator('tr[data-id]').filter({hasText:'isolated-B.zip'}).first().waitFor();
   if(created){const state=await page.request.get(base+`/manage/api/uploads/${created.id}/`);assert.equal((await state.json()).status,'cancelled');}
   await context.close();
  }
  fs.writeFileSync(path.join(root,'test-results/upload-isolation.json'),JSON.stringify({read_cancel_switch:true,late_create_cancel_switch:true,new_task_finishes:true}));
  console.log('UPLOAD_ISOLATION_PASS');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
