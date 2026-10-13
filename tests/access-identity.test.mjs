import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {resolve} from 'node:path';
import {createServer} from 'node:net';
import {request} from 'node:http';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {Store} from '../server/store.mjs';
import {Vault} from '../server/vault.mjs';
import {Hub} from '../server/hub.mjs';
import {Tunnels} from '../server/tunnels.mjs';
import {createApps} from '../server/app.mjs';

const TEAM='synthetic-team.cloudflareaccess.com',AUD='a'.repeat(64),HOST='line.example.com',KID='synthetic-key';
async function freePort(){const s=createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const port=s.address().port;await new Promise(r=>s.close(r));return port;}
function call(port,path,headers={},body){
  return new Promise((done,reject)=>{
    const req=request({host:'127.0.0.1',port,path,method:body?'POST':'GET',headers:{Host:HOST,...headers,...(body?{'Content-Type':'application/json',Accept:'application/json, text/event-stream'}:{})}},res=>{let text='';res.on('data',d=>text+=d);res.on('end',()=>{let json=null;try{json=JSON.parse(text);}catch{}done({status:res.statusCode,json});});});
    req.on('error',reject);req.end(body?JSON.stringify(body):undefined);
  });
}

async function fixture(t){
  const {publicKey,privateKey}=await generateKeyPair('RS256'),other=await generateKeyPair('RS256');
  const jwk={...await exportJWK(publicKey),kid:KID,alg:'RS256',use:'sig'};
  // jose fetches the Access JWKS over HTTPS; serve it locally instead.
  const realFetch=globalThis.fetch;
  globalThis.fetch=async(input,init)=>String(input?.url??input)===`https://${TEAM}/cdn-cgi/access/certs`?new Response(JSON.stringify({keys:[jwk]}),{headers:{'Content-Type':'application/json'}}):realFetch(input,init);
  t.after(()=>{globalThis.fetch=realFetch;});
  const sign=(claims,{key=privateKey,aud=AUD,iss=`https://${TEAM}`}={})=>new SignJWT(claims).setProtectedHeader({alg:'RS256',kid:KID}).setIssuer(iss).setAudience(aud).setIssuedAt().setExpirationTime('5m').sign(key);

  const store=new Store(':memory:'),vault=new Vault(randomBytes(32),'synthetic'),hub=new Hub(store,vault);
  const gatewayPort=await freePort(),adminPort=await freePort(),tunnels=new Tunnels(store,vault,resolve('.'),gatewayPort);
  store.setSetting('tunnel',{provider:'cloudflare',hostname:HOST,teamDomain:TEAM,audience:AUD});
  const apps=createApps({hub,tunnels,root:resolve('.'),adminPort,gatewayPort});
  const gateway=apps.gateway.listen(gatewayPort,'127.0.0.1');
  t.after(()=>{hub.close();tunnels.close();gateway.closeAllConnections();gateway.close();store.close();});
  const a=await hub.addAccount({label:'Synthetic',kind:'demo'});hub.designate(a.id,'demo-group',true);hub.designate(a.id,'demo-openchat',true);
  const reader=hub.createToken({name:'Dot reader',grants:[{accountId:a.id,read:true,send:false,chatIds:['demo-group']}]});
  return {store,hub,gatewayPort,sign,other,account:a,reader};
}

test('an allowlisted Access sign-in gets the chosen token scope without a LineBridge token',async t=>{
  const f=await fixture(t),{configureIdentity}=await import('../server/access-identity.mjs');
  const me=await f.sign({email:'Me@Example.com',sub:'user-1'}),oauth={Authorization:'Bearer oauth:opaque-managed-token'};

  // Disabled by default: an opaque OAuth bearer is just an invalid credential.
  assert.equal((await call(f.gatewayPort,'/api/v1/accounts',{...oauth,'Cf-Access-Jwt-Assertion':me})).status,401);

  configureIdentity(f.hub,{emails:['me@example.com'],tokenId:f.reader.id});
  const allowed=await call(f.gatewayPort,'/api/v1/accounts',{...oauth,'Cf-Access-Jwt-Assertion':me});
  assert.equal(allowed.status,200);assert.equal(allowed.json[0].permissions.send,false);
  assert.deepEqual((await call(f.gatewayPort,`/api/v1/accounts/${f.account.id}/chats`,{'Cf-Access-Jwt-Assertion':me})).json.map(c=>c.id),['demo-group'],'Scope follows the chosen token, with or without an OAuth bearer');

  const tools=await call(f.gatewayPort,'/mcp',{...oauth,'Cf-Access-Jwt-Assertion':me},{jsonrpc:'2.0',id:1,method:'tools/list',params:{}});
  assert.equal(tools.status,200);assert.ok(tools.json.result.tools.some(tool=>tool.name==='line_read_messages'));

  // Refusals: unknown person, no assertion, forged signature, other app, service token without a LineBridge token.
  assert.equal((await call(f.gatewayPort,'/api/v1/accounts',{'Cf-Access-Jwt-Assertion':await f.sign({email:'someone@example.com'})})).status,403);
  assert.equal((await call(f.gatewayPort,'/api/v1/accounts',oauth)).status,401);
  assert.equal((await call(f.gatewayPort,'/api/v1/accounts',{'Cf-Access-Jwt-Assertion':await f.sign({email:'me@example.com'},{key:f.other.privateKey})})).status,401);
  assert.equal((await call(f.gatewayPort,'/api/v1/accounts',{'Cf-Access-Jwt-Assertion':await f.sign({email:'me@example.com'},{aud:'b'.repeat(64)})})).status,401);
  const service=await f.sign({common_name:'service-token-id.access',type:'app'});
  assert.equal((await call(f.gatewayPort,'/api/v1/accounts',{'Cf-Access-Jwt-Assertion':service})).status,403);

  // The existing service-token path keeps working alongside sign-in.
  assert.equal((await call(f.gatewayPort,'/api/v1/accounts',{Authorization:`Bearer ${f.reader.token}`,'Cf-Access-Jwt-Assertion':service})).status,200);
  assert.equal((await call(f.gatewayPort,'/api/v1/accounts',{Authorization:`Bearer ${f.reader.token}`})).status,401,'A LineBridge token still needs Access');

  // Revoking the chosen token immediately removes sign-in access.
  f.store.revoke(f.reader.id);
  assert.equal((await call(f.gatewayPort,'/api/v1/accounts',{'Cf-Access-Jwt-Assertion':me})).status,401);
});

test('identity settings require an active remote token and can be disabled',async t=>{
  const f=await fixture(t),{configureIdentity,identityConfig}=await import('../server/access-identity.mjs');
  assert.throws(()=>configureIdentity(f.hub,{emails:['me@example.com'],tokenId:null}),{code:'identity_token_required'});
  assert.throws(()=>configureIdentity(f.hub,{emails:['not-an-email'],tokenId:f.reader.id}));
  assert.throws(()=>configureIdentity(f.hub,{emails:['me@example.com'],tokenId:'missing'}),{code:'identity_token_inactive'});
  const local=f.hub.createToken({name:'Local',grants:[{accountId:f.account.id,read:true,send:true,chatIds:['demo-group'],localOnly:true}]});
  assert.throws(()=>configureIdentity(f.hub,{emails:['me@example.com'],tokenId:local.id}),{code:'identity_token_local'});
  assert.deepEqual(configureIdentity(f.hub,{emails:['ME@example.com','me@example.com'],tokenId:f.reader.id}),{emails:['me@example.com'],tokenId:f.reader.id});
  assert.deepEqual(configureIdentity(f.hub,{emails:[],tokenId:null}),{emails:[],tokenId:null});
  assert.deepEqual(identityConfig(f.store),{emails:[],tokenId:null});
  const me=await f.sign({email:'me@example.com'});
  assert.equal((await call(f.gatewayPort,'/api/v1/accounts',{'Cf-Access-Jwt-Assertion':me})).status,401,'Disabled sign-in grants nothing');
});
