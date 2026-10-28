import {readFile,writeFile,mkdir} from 'node:fs/promises';
// Mechanical migration of the approved standalone reference, without changing its LUTs or typography.
const html=await readFile('public/index.html','utf8');
let css=html.match(/<style>([\s\S]*?)<\/style>/)[1];
await mkdir('public/fonts',{recursive:true});
let fontIndex=0;
for(const match of [...css.matchAll(/data:font\/woff2;base64,([A-Za-z0-9+/=]+)/g)]) {
 const name=fontIndex++===0?'space-grotesk':'jetbrains-mono';
 await writeFile(`public/fonts/${name}.woff2`,Buffer.from(match[1],'base64'));
 css=css.replace(match[0],`/fonts/${name}.woff2`);
}
await mkdir('src/components/security',{recursive:true});
css=css.replaceAll('html.intro ','.security-stage.intro ').replaceAll('.nav-open ','.security-stage.nav-open ');
css=css.replace('.screen{','.security-stage{');
await writeFile('src/components/security/security.css',css);
const tables=[...html.matchAll(/<filter id="(grade2?)"[\s\S]*?<\/filter>/g)].map(m=>({id:m[1],channels:[...m[0].matchAll(/tableValues="([^"]+)"/g)].map(v=>v[1])}));
await writeFile('src/components/security/video-grade.json',JSON.stringify(tables,null,2)+'\n');
console.log('Migrated exact reference styles, local font assets and video LUTs.');
