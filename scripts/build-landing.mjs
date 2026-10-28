import { readFile, writeFile, mkdir } from 'node:fs/promises';

// Generates the deliverable, public/index.html. No runtime framework or font requests.
const briefPath = process.argv[2];
if (!briefPath) throw new Error('Pass the supplied reference brief path to embed its exact color-grade tables.');
const brief = await readFile(briefPath, 'utf8');
const filters = [...brief.matchAll(/<filter id="grade2?"[\s\S]*?<\/filter>/g)].map(match => match[0]).join('\n');
if ((filters.match(/<filter /g) || []).length !== 2) throw new Error('Expected both reference video filters.');
const fontURL = 'https://cdn.jsdelivr.net/fontsource/fonts/space-grotesk:vf@latest/latin-wght-normal.woff2';
const response = await fetch(fontURL);
if (!response.ok) throw new Error(`Space Grotesk download failed: ${response.status}`);
const sg = Buffer.from(await response.arrayBuffer()).toString('base64');
const jb = (await readFile('node_modules/@fontsource-variable/jetbrains-mono/files/jetbrains-mono-latin-wght-normal.woff2')).toString('base64');
let html = await readFile('ui/index.template.html', 'utf8');
html = html.replace('{{SG_FONT}}', sg).replace('{{JB_FONT}}', jb).replace('{{FILTERS}}', filters);
await mkdir('public', {recursive: true});
await writeFile('public/index.html', html);
console.log(`Generated public/index.html (${Buffer.byteLength(html)} bytes), embedded fonts and exact reference LUTs.`);
