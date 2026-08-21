"use strict";
const fs=require("node:fs");
const path=require("node:path");
const mode=process.argv[2];
if(mode!=="safe"&&mode!=="vulnerable"){console.error("Usage: node scripts/set-version.js safe|vulnerable");process.exit(2)}
const directory=path.resolve(__dirname,".."),filename=path.join(directory,"package.json"),lockFilename=path.join(directory,"package-lock.json"),manifest=JSON.parse(fs.readFileSync(filename,"utf8")),lock=JSON.parse(fs.readFileSync(lockFilename,"utf8"));
const version=mode==="safe"?manifest.depshieldDemo.safeVersion:manifest.depshieldDemo.vulnerableVersion;
manifest.dependencies.lodash=version;
lock.packages[""].dependencies.lodash=version;
const lodash=lock.packages["node_modules/lodash"];
const metadata={"4.17.11":{resolved:"https://registry.npmjs.org/lodash/-/lodash-4.17.11.tgz",integrity:"sha512-cQKh8igo5QUhZ7lg38DYWAxMvjSAKG0A8wGSVimP07SIUEK2UO+arSRKbRZWtelMtN5V0Hkwh5ryOto/SshYIg=="},"4.17.21":{resolved:"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",integrity:"sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="}}[version];
lodash.version=version; lodash.resolved=metadata.resolved; lodash.integrity=metadata.integrity;
fs.writeFileSync(filename,`${JSON.stringify(manifest,null,2)}\n`); fs.writeFileSync(lockFilename,`${JSON.stringify(lock,null,2)}\n`);
console.log(`[vulnerable-demo] lodash pinned to ${version}. Run npm install in vulnerable-demo, restart the demo, upload both manifests, and rescan.`);
