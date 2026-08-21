"use strict";
const express=require("express");
const lodash=require("lodash");
const app=express();
const host="127.0.0.1",port=4100,marker="depshieldPrototypeMarker";

app.disable("x-powered-by");
app.use((request,response,next)=>{const address=request.socket.remoteAddress??"";if(address!=="127.0.0.1"&&address!=="::1"&&address!=="::ffff:127.0.0.1")return response.status(403).json({error:"This intentionally vulnerable fixture accepts localhost traffic only."});next()});
app.get("/health",(_request,response)=>response.json({status:"ok",scope:"localhost-only",dependency:`lodash@${require("lodash/package.json").version}`}));
app.post("/demo/prototype-pollution",(_request,response)=>{
  delete Object.prototype[marker];
  const before=({})[marker]??null;
  const fixedFixture=JSON.parse('{"constructor":{"prototype":{"depshieldPrototypeMarker":"observable-local-marker"}}}');
  lodash.defaultsDeep({},fixedFixture);
  const observed=({})[marker]??null;
  delete Object.prototype[marker];
  response.json({demo:"CVE-2019-10744",dependency:`lodash@${require("lodash/package.json").version}`,before,observed,vulnerable:observed==="observable-local-marker",cleanupVerified:({})[marker]===undefined,safety:"Fixed in-memory fixture; no shell, file, or outbound network action."});
});
app.use((_request,response)=>response.status(404).json({error:"Only /health and the fixed demonstration route are available."}));
app.listen(port,host,()=>console.log(`[vulnerable-demo] localhost only: http://${host}:${port}`));
