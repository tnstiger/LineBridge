import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {resolve} from 'node:path';
import {Store} from '../server/store.mjs';
import {Vault} from '../server/vault.mjs';
import {Tunnels} from '../server/tunnels.mjs';

test('an explicitly started connection is restored after restart; stop or provider change cancels it',async t=>{
  const store=new Store(':memory:'),vault=new Vault(randomBytes(32),'synthetic');t.after(()=>store.close());
  const make=()=>{const tunnels=new Tunnels(store,vault,resolve('.'),54321);let starts=0;tunnels.start=async()=>{starts++;return {status:'starting'};};t.after(()=>tunnels.close());return {tunnels,starts:()=>starts};};
  store.setSetting('tunnel',{provider:'cloudflare',hostname:'line.example.com',teamDomain:'t.cloudflareaccess.com',audience:'a'});

  let s=make();assert.equal(await s.tunnels.restore(),null,'Nothing is restored before an explicit start');assert.equal(s.starts(),0);
  s.tunnels.rememberStart();
  s=make();assert.deepEqual(await s.tunnels.restore(),{status:'starting'});assert.equal(s.starts(),1);
  s.tunnels.forgetStart();
  s=make();await s.tunnels.restore();assert.equal(s.starts(),0,'An explicit stop is respected');

  s.tunnels.rememberStart();store.setSetting('tunnel',{provider:'tailscale',hostname:'',teamDomain:'',audience:''});
  s=make();await s.tunnels.restore();assert.equal(s.starts(),0,'A different provider is never started automatically');
  s.tunnels.rememberStart();assert.equal(store.setting('tunnelAutostart',null),null,'Interactive providers are not remembered');

  store.setSetting('tunnel',{provider:'cloudflare',hostname:'line.example.com',teamDomain:'t.cloudflareaccess.com',audience:'a'});store.setSetting('tunnelAutostart','cloudflare');
  const failing=new Tunnels(store,vault,resolve('.'),54321);t.after(()=>failing.close());failing.start=async()=>{throw new Error('cloudflared missing');};
  assert.equal(await failing.restore(),null);assert.equal(failing.state.status,'restore_failed');
});
