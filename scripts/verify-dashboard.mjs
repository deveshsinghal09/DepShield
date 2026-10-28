import {chromium} from '@playwright/test';
import assert from 'node:assert/strict';
const browser=await chromium.launch({headless:true,...(process.env.CHROME_PATH?{executablePath:process.env.CHROME_PATH}:{})});
const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
const base=process.env.DEPSHIELD_TEST_URL??'http://localhost:3000';
try{
  for(const width of [1536,820,390]){
    await page.setViewportSize({width,height:1000});await page.goto(`${base}/dashboard`);
    await page.locator('[data-ui=dashboard]').waitFor();await page.waitForTimeout(1500);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`overflow ${width}`);
    assert.ok(await page.locator('.recharts-sector').count()>0);
    await page.getByRole('textbox',{name:'Search packages or CVEs'}).fill('not-a-real-dependency-999');
    await page.getByText('Nothing to show',{exact:true}).waitFor();
    await page.getByRole('textbox',{name:'Search packages or CVEs'}).fill('');
    if(width===1536){
      assert.equal(await page.getByRole('button',{name:/sidebar animation/}).count(),0);
      assert.ok(await page.locator('[data-ui=sidebar-3d] canvas').evaluate(c=>Boolean(c.getContext('webgl2'))));
    }
    await page.screenshot({path:`tmp/dashboard-verified-${width}.png`,fullPage:false});
  }
  await page.setViewportSize({width:1536,height:1000});await page.emulateMedia({reducedMotion:'reduce'});await page.reload();
  await page.locator('[data-ui=sidebar-3d] canvas').waitFor();
  await page.getByRole('link',{name:'View all dependencies'}).click();await page.waitForURL('**/dependencies?scan=*');
  assert.equal(await page.locator('[data-ui=sidebar-3d]').count(),1);
  assert.deepEqual(errors,[]);console.log('PASS dashboard: real WebGL, no pause button, reduced motion, filtering, responsive charts, shared feature navigation, no runtime errors');
}finally{await browser.close();}
