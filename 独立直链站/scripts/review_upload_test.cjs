const {chromium}=require('D:/Tools/Node/node_modules/playwright');
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),base='http://127.0.0.1:8780';
const access=JSON.parse(fs.readFileSync(path.join(root,'test-results/local-access.json'),'utf8'));
(async()=>{
 const browser=await chromium.launch({headless:true});
 try {
  const context=await browser.newContext();const page=await context.newPage();page.setDefaultTimeout(5000);
  await page.goto(base+'/manage/login/');await page.getByLabel('账号',{exact:true}).fill(access.username);await page.getByLabel('密码',{exact:true}).fill(access.password);
  await Promise.all([page.waitForURL('**/manage/'),page.getByRole('button',{name:'登录',exact:true}).click()]);
  await page.getByRole('button',{name:'新建软件',exact:true}).click();
  await page.locator('#upload-file').setInputFiles({name:'explicit-rejection.txt',mimeType:'text/plain',buffer:Buffer.from('invalid extension')});
  await page.locator('#start-upload').click();await page.locator('#upload-error:not([hidden])').waitFor();
  await page.getByRole('button',{name:'取消',exact:true}).click();await page.locator('#upload-dialog').waitFor({state:'hidden'});
  assert.equal(await page.evaluate(()=>Object.keys(localStorage).some(k=>k.startsWith('directlink-upload-'))),false);
  const filename=`after-rejection-${Date.now()}.zip`;
  await page.getByRole('button',{name:'新建软件',exact:true}).click();
  await page.locator('#upload-file').setInputFiles({name:filename,mimeType:'application/zip',buffer:Buffer.from('valid after rejected upload')});
  await page.locator('#start-upload').click();await page.locator('tr[data-id]').filter({hasText:filename}).waitFor();
  let dropped=false;
  await context.route('**/manage/api/uploads/',async route=>{if(!dropped){dropped=true;await route.fetch();await route.abort();}else await route.continue();});
  await page.getByRole('button',{name:'新建软件',exact:true}).click();
  await page.locator('#upload-file').setInputFiles({name:'unknown-create.zip',mimeType:'application/zip',buffer:Buffer.from('lost create response')});
  await page.locator('#start-upload').click();await page.locator('#upload-error:not([hidden])').waitFor();
  assert.equal(await page.evaluate(()=>Object.keys(localStorage).some(k=>k.startsWith('directlink-upload-'))),true);
  await page.getByRole('button',{name:'取消',exact:true}).click();await page.locator('#upload-dialog').waitFor({state:'hidden'});
  assert.equal(await page.evaluate(()=>Object.keys(localStorage).some(k=>k.startsWith('directlink-upload-'))),false);
  fs.writeFileSync(path.join(root,'test-results/review-upload-result.json'),JSON.stringify({explicit_rejection_cancel:true,new_upload_after_rejection:true,unknown_result_retained_and_cancelled:true},null,2));
  console.log('REVIEW_UPLOAD_PASS');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
