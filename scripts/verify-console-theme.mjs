import {chromium} from '@playwright/test';
import assert from 'node:assert/strict';
const browser=await chromium.launch({headless:true,...(process.env.CHROME_PATH?{executablePath:process.env.CHROME_PATH}:{})});
const page=await browser.newPage({reducedMotion:'reduce'});const errors=[];page.on('pageerror',e=>errors.push(e.message));
try{
for(const width of [1440,390]){
 await page.setViewportSize({width,height:950});
 for(const route of ['/dashboard','/scan','/dependencies','/attack-paths','/attack-replay','/remediation','/comparison','/history','/policies','/story']){
  const response=await page.goto(`http://localhost:3000${route}`);assert.equal(response.status(),200,route);
  await page.locator('.dashboard-shell').waitFor();await page.waitForTimeout(250);
  assert.equal(await page.getByRole('button',{name:/Pause 3D|sidebar animation/}).count(),0);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`${route} ${width}`);
  if(['/attack-replay','/remediation','/comparison'].includes(route))await page.screenshot({path:`tmp/console-${route.slice(1)}-${width}.png`});
 }
}
assert.deepEqual(errors,[]);console.log('PASS: 10 routes at desktop/mobile, shared theme, no pause button, no overflow or runtime errors');
}finally{await browser.close();}
