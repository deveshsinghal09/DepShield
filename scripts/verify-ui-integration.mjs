import { chromium } from '@playwright/test';
import assert from 'node:assert/strict';

const base=process.env.DEPSHIELD_TEST_URL??'http://localhost:3000';
const browser=await chromium.launch({headless:true,...(process.env.CHROME_PATH?{executablePath:process.env.CHROME_PATH}:{})});
const page=await browser.newPage({viewport:{width:1505,height:900},reducedMotion:'reduce'});
const errors=[];
page.on('pageerror',error=>errors.push(error.message));
try {
  await page.goto(base);
  await page.getByRole('heading',{name:'Dependency risk. Under your control.'}).waitFor();
  assert.equal(await page.getByText(/Clients|Satisfaction|Revenue|next integration|SAMPLE STATS/).count(),0);
  await page.getByRole('button',{name:'Scan project',exact:true}).first().click();
  await page.waitForURL('**/scan');
  await page.getByRole('heading',{name:'Scan your project'}).waitFor();
  assert.equal(await page.locator('[data-ui="security-stage"]').count(),0);
  // Exercise the real upload API and SQLite persistence, without adding vulnerable packages.
  const manifest={name:'depshield-ui-integration-check',version:'1.0.0',private:true};
  const lock={name:manifest.name,version:'1.0.0',lockfileVersion:3,requires:true,packages:{'':{name:manifest.name,version:'1.0.0'}}};
  const responsePromise=page.waitForResponse(r=>r.url().endsWith('/api/scans')&&r.request().method()==='POST',{timeout:180000});
  await page.getByLabel('Choose package.json and package-lock.json',{exact:true}).setInputFiles([
    {name:'package.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(manifest))},
    {name:'package-lock.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(lock))},
  ]);
  await page.getByRole('button',{name:'Start scan',exact:true}).click();
  const response=await responsePromise;
  assert.equal(response.status(),201,await response.text());
  const {data:scan}=await response.json();
  await page.waitForURL(`**/dashboard?scan=${scan.id}`);
  for(const route of ['/dashboard','/dependencies','/attack-paths','/remediation','/attack-replay','/comparison','/history','/policies','/story', '/']){
    const result=await page.goto(`${base}${route}?scan=${scan.id}`);
    assert.equal(result.status(),200,route);
    await page.locator('[data-ui="app-shell"]').waitFor();
    assert.equal(await page.locator('[data-ui="security-stage"]').count(),0,route);
    assert.ok(await page.locator('main').innerText(),route);
  }
  for(const width of [1505,820,390]){
    await page.setViewportSize({width,height:900});await page.goto(base);
    await page.locator('[data-ui="scan-summary"]').waitFor();
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
    if(width<1024){
      await page.getByRole('button',{name:'Open menu'}).click();
      await page.getByRole('dialog').getByRole('button',{name:'Explore',exact:true}).click();
      await page.getByRole('dialog').getByRole('link',{name:'Dependencies',exact:true}).click();
      await page.waitForURL('**/dependencies');
      await page.locator('[data-ui="app-shell"]').waitFor();
    }
  }
  assert.deepEqual(errors,[]);
  console.log(`PASS: real scan upload persisted (${scan.id}), all feature routes, mobile navigation, homepage metrics and no runtime errors.`);
} finally {await browser.close();}
