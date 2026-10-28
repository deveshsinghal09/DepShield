import { chromium } from '@playwright/test';
import assert from 'node:assert/strict';
import path from 'node:path';

const base = process.env.DEPSHIELD_TEST_URL ?? 'http://localhost:3000';
const browser = await chromium.launch({headless:true, ...(process.env.CHROME_PATH ? {executablePath:process.env.CHROME_PATH} : {})});
const page = await browser.newPage({viewport:{width:1440,height:1000}});
const errors = [];
page.on('pageerror', error => errors.push(error.message));
try {
  await page.goto(base + '/dashboard');
  await page.locator('a[data-ui="scan-button"]').first().click();
  await page.waitForURL('**/scan');
  const input = page.getByLabel('Choose package.json and package-lock.json', {exact:true});
  await input.setInputFiles({name:'other.json', mimeType:'application/json', buffer:Buffer.from('{}')});
  await page.getByRole('alert').filter({hasText:'not other JSON files'}).waitFor();
  assert.equal(await page.getByRole('button',{name:'Start scan',exact:true}).isDisabled(),true);
  await input.setInputFiles({name:'package.json',mimeType:'application/json',buffer:Buffer.from('broken')});
  await input.setInputFiles(path.resolve('vulnerable-demo/package-lock.json'));
  await page.getByRole('button',{name:'Start scan',exact:true}).click();
  await page.getByRole('alert').filter({hasText:'valid JSON object'}).waitFor();
  await input.setInputFiles(path.resolve('vulnerable-demo/package.json'));
  // A server error must preserve selection and allow retry.
  await page.route('**/api/scans', route => route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:{message:'Test service unavailable. Retry.'}})}));
  await page.getByRole('button',{name:'Start scan',exact:true}).click();
  await page.getByRole('alert').filter({hasText:'Test service unavailable'}).waitFor();
  await page.unroute('**/api/scans');
  for (const mode of ['files','folder']) {
    if (mode === 'folder') {
      await page.goto(base + '/scan');
      await page.getByLabel('Choose a project folder',{exact:true}).setInputFiles(path.resolve('vulnerable-demo'));
    }
    let posts = 0;
    const count = request => { if(request.method()==='POST' && request.url().endsWith('/api/scans')) posts++; };
    page.on('request',count);
    const responsePromise = page.waitForResponse(r => r.url().endsWith('/api/scans') && r.request().method()==='POST', {timeout:180000});
    await page.getByRole('button',{name:'Start scan',exact:true}).click();
    const response = await responsePromise;
    assert.equal(response.status(),201, await response.text());
    const {data} = await response.json();
    await page.waitForURL('**/dashboard?scan=' + data.id);
    assert.ok(data.dependencies > 0);
    assert.equal(posts,1);
    page.off('request',count);
    console.log('PASS real ' + mode + ' scan: ' + data.id + ', ' + data.dependencies + ' dependencies');
  }
  await page.goto(base + '/scan');
  await page.setViewportSize({width:390,height:844});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth), false);
  assert.deepEqual(errors,[]);
  console.log('PASS navigation, staged selection, invalid JSON, retry, real file/folder scans, responsive layout');
} finally { await browser.close(); }
