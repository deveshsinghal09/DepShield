# Intentionally vulnerable local fixture

> **Warning:** this application deliberately pins `lodash@4.17.11`, a historical version affected by prototype pollution (CVE-2019-10744). Keep it on your own machine. Do not expose port 4100, publish the app, or deploy this folder.

The server binds only to `127.0.0.1`. Its single proof route uses a fixed in-memory object, records whether a marker becomes observable, removes the marker, and performs no shell, filesystem, database, or outbound network action. It does not accept a target, attack payload, arbitrary URL, or command.

From the repository root:

```powershell
npm run demo:install
npm run demo:start
```

In another terminal run DepShield, upload this folder's `package.json` and `package-lock.json`, and use Attack Replay. Remediate with `npm run demo:remediate`, then run `npm install --ignore-scripts --audit=false` inside `vulnerable-demo`; reset the teaching fixture with `npm run demo:reset`.
