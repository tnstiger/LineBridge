import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Store } from '../server/store.mjs';
import { Vault, VaultStorage } from '../server/vault.mjs';
import { Hub, adminActor, localActor } from '../server/hub.mjs';
import { SendRejectedError } from '../server/errors.mjs';

async function setup(t,factory){
  const store=new Store(':memory:'),vault=new Vault(randomBytes(32),'test'),hub=new Hub(store,vault,factory);
  t.after(()=>{hub.close();store.close();});
  const account=await hub.addAccount({label:'Sandbox',kind:'demo'});
  return {store,vault,hub,account};
}
const mint=(hub,account,send=false)=>hub.createToken({name:'Test AI',days:7,grants:[{accountId:account.id,read:true,send}]});

test('the local AI needs no token but sees only selected accounts/chats and obeys local permissions',async t=>{
  const {hub,store,account}=await setup(t),other=await hub.addAccount({label:'Other sandbox',kind:'demo'});
  assert.deepEqual(hub.accounts(localActor),[]);
  hub.designate(account.id,'demo-group',true);
  assert.equal(hub.accounts(localActor).length,1);
  assert.deepEqual(hub.accounts(localActor)[0].permissions,{accountId:account.id,read:true,send:true});
  assert.equal((await hub.read(localActor,account.id,'demo-group')).untrustedContent,true);
  await assert.rejects(hub.read(localActor,other.id,'demo-group'),{code:'scope_denied'});
  await assert.rejects(hub.read(localActor,account.id,'demo-openchat'),{code:'chat_not_designated'});
  hub.setLocalAccess(account.id,{read:true,send:false});
  await assert.rejects(hub.send(localActor,account.id,'demo-group','hello','local-send-001'),{code:'scope_denied'});
  hub.setLocalAccess(account.id,{read:false,send:true});
  await assert.rejects(hub.read(localActor,account.id,'demo-group'),{code:'scope_denied'});
  const sent=await hub.send(localActor,account.id,'demo-group','hello','local-send-002');assert.equal(sent.delivery,'sandbox_only');
  assert.equal((await hub.send(localActor,account.id,'demo-group','hello','local-send-002')).replayed,true);
  assert.ok(store.audits().some(a=>a.actor==='local-agent'&&a.action==='messages.send'));
  hub.setLocalAccess(account.id,{read:false,send:false});assert.deepEqual(hub.accounts(localActor),[]);
  store.setSetting('aiEnabled',false);assert.throws(()=>hub.accounts(localActor),{code:'gateway_paused'});
  assert.equal(hub.tokens().length,0);
});

test('local access changes are checked before queued sends and after upstream reads',async t=>{
  const {hub,account}=await setup(t);hub.designate(account.id,'demo-group',true);
  let release;const first=hub.serialized(account.id,()=>new Promise(resolve=>{release=resolve;}));await new Promise(resolve=>setImmediate(resolve));
  const send=hub.send(localActor,account.id,'demo-group','hello','queued-local-001');hub.setLocalAccess(account.id,{read:true,send:false});release();await first;
  await assert.rejects(send,{code:'scope_denied'});
  const original=hub.driver(account.id).read.bind(hub.driver(account.id));
  hub.driver(account.id).read=async(...args)=>{const result=await original(...args);hub.setLocalAccess(account.id,{read:false,send:false});return result;};
  await assert.rejects(hub.read(localActor,account.id,'demo-group'),{code:'scope_denied'});
});

test('an AI sees only granted accounts and designated chats, with independent send permission',async t=>{
  const {hub,account}=await setup(t),other=await hub.addAccount({label:'Other account',kind:'demo'}),token=mint(hub,account),actor=hub.authenticate(token.token);
  assert.equal(hub.accounts(actor).length,1);assert.deepEqual(hub.chats(actor,account.id),[]);
  await assert.rejects(hub.read(actor,account.id,'demo-group'),{code:'chat_not_designated'});
  hub.designate(account.id,'demo-group',true);
  assert.equal(hub.chats(actor,account.id).length,1);
  assert.equal((await hub.read(actor,account.id,'demo-group')).untrustedContent,true);
  await assert.rejects(hub.read(actor,other.id,'demo-group'),{code:'scope_denied'});
  await assert.rejects(hub.send(actor,account.id,'demo-group','hello','test-message-001'),{code:'scope_denied'});
});
test('token revocation, expiry, global pause and chat removal take effect on existing actors',async t=>{
  const {hub,store,account}=await setup(t);hub.designate(account.id,'demo-group',true);
  const token=mint(hub,account),actor=hub.authenticate(token.token);
  hub.designate(account.id,'demo-group',false);await assert.rejects(hub.read(actor,account.id,'demo-group'),{code:'chat_not_designated'});
  store.setSetting('aiEnabled',false);assert.throws(()=>hub.accounts(actor),{code:'gateway_paused'});assert.equal(hub.accounts(adminActor).length,1);
  store.setSetting('aiEnabled',true);store.revoke(token.id);assert.throws(()=>hub.accounts(actor),{code:'invalid_token'});
  const expired=mint(hub,account);store.db.prepare('UPDATE tokens SET expires_at=? WHERE id=?').run('2000-01-01T00:00:00.000Z',expired.id);
  assert.throws(()=>hub.authenticate(expired.token),{code:'invalid_token'});
  assert.throws(()=>hub.authenticate('wrong'),{code:'unauthorized'});
});
test('duplicate sends replay the result once; a reused key with different text is rejected',async t=>{
  const {hub,account}=await setup(t);hub.designate(account.id,'demo-group',true);
  const actor=hub.authenticate(mint(hub,account,true).token);
  const [first,second]=await Promise.all([hub.send(actor,account.id,'demo-group','hello','unique-send-001'),hub.send(actor,account.id,'demo-group','hello','unique-send-001')]);
  assert.equal(first.messageId,second.messageId);assert.equal(second.replayed,true);
  assert.equal((await hub.read(actor,account.id,'demo-group')).messages.filter(m=>m.text==='hello').length,1);
  await assert.rejects(hub.send(actor,account.id,'demo-group','different','unique-send-001'),{code:'idempotency_conflict'});
});
test('unknown send outcomes are retained and never automatically retried',async t=>{
  const {hub,store,account}=await setup(t);hub.designate(account.id,'demo-group',true);
  let calls=0;hub.driver(account.id).send=async()=>{calls++;throw new Error('simulated timeout with raw auth token');};
  const actor=hub.authenticate(mint(hub,account,true).token);
  await assert.rejects(hub.send(actor,account.id,'demo-group','private body','unknown-send-001'),{code:'delivery_unknown'});
  await assert.rejects(hub.send(actor,account.id,'demo-group','private body','unknown-send-001'),{code:'delivery_unknown'});
  assert.equal(calls,1);assert.equal(store.send(actor.id,'unknown-send-001').state,'unknown');
  assert.ok(!JSON.stringify(store.audits()).includes('private body'));
});
test('rejected sends preserve an actionable error without claiming unknown delivery, and may be retried',async t=>{
  const {hub,store,account}=await setup(t);let calls=0;
  hub.driver(account.id).send=async()=>{calls++;throw new SendRejectedError(502,'send_preparation_failed','No message was sent.');};
  await assert.rejects(hub.send(adminActor,account.id,'demo-group','hello','rejected-send-001'),{code:'send_preparation_failed'});
  assert.equal(calls,1);assert.equal(store.send(adminActor.id,'rejected-send-001').state,'rejected');
  // Nothing was sent, so the same key runs again once the cause is fixed.
  hub.driver(account.id).send=async()=>{calls++;return {messageId:'accepted',delivery:'sandbox_only'};};
  assert.equal((await hub.send(adminActor,account.id,'demo-group','hello','rejected-send-001')).messageId,'accepted');assert.equal(calls,2);
  assert.equal(store.send(adminActor.id,'rejected-send-001').state,'sent');
  assert.equal((await hub.send(adminActor,account.id,'demo-group','hello','rejected-send-002')).messageId,'accepted');
});
test('credentials are encrypted with account/key binding; token hashes and audit logs exclude secrets',async t=>{
  const {hub,store,vault,account}=await setup(t),storage=new VaultStorage(store,vault,account.id);
  await storage.set('auth','private-session-token');assert.equal(await storage.get('auth'),'private-session-token');
  const stored=store.secret(account.id,'auth');assert.ok(!stored.includes('private-session-token'));
  assert.throws(()=>vault.unseal(stored,'different-account:auth'));
  const token=mint(hub,account);assert.ok(!JSON.stringify(hub.tokens()).includes(token.token));assert.ok(!JSON.stringify(store.audits()).includes(token.token));
});
test('permission is checked again before a queued operation is dispatched',async t=>{
  const {hub,store,account}=await setup(t);hub.designate(account.id,'demo-group',true);
  let release;const first=hub.serialized(account.id,()=>new Promise(resolve=>{release=resolve;}));
  await new Promise(resolve=>setImmediate(resolve));
  const token=mint(hub,account),actor=hub.authenticate(token.token),read=hub.read(actor,account.id,'demo-group');
  store.revoke(token.id);release();await first;await assert.rejects(read,{code:'invalid_token'});
});

test('maintenance drain commits an in-flight send result and rejects queued sends before reservation',async t=>{
  const {hub,store,account}=await setup(t);hub.designate(account.id,'demo-group',true);
  const actor=hub.authenticate(mint(hub,account,true).token),grants=hub.tokens();
  let release,started;const dispatched=new Promise(r=>{started=r;});let sends=0;
  hub.driver(account.id).send=async()=>{sends++;started();return new Promise(r=>{release=r;});};
  const accepted=hub.send(actor,account.id,'demo-group','synthetic','drain-accepted');await dispatched;
  const queued=hub.send(actor,account.id,'demo-group','synthetic queued','drain-queued');
  const rejected=assert.rejects(queued,{code:'service_stopping'});let finished=false;
  const draining=hub.drain().then(()=>{finished=true;});await new Promise(r=>setImmediate(r));assert.equal(finished,false);
  release({messageId:'synthetic-accepted',delivery:'sandbox_only'});await accepted;await rejected;await draining;
  assert.equal(sends,1);assert.equal(store.send(actor.id,'drain-accepted').state,'sent');assert.equal(store.send(actor.id,'drain-queued'),undefined);
  assert.deepEqual(hub.tokens(),grants);await hub.drain();
});

test('shutdown cancellation of a pending monitor start preserves the saved monitoring preference',async t=>{
  const {hub,store,account}=await setup(t);let cancel,started;
  const waiting=new Promise(r=>{started=r;});
  hub.driver(account.id).startMonitor=async()=>{started();await new Promise((_resolve,reject)=>{cancel=reject;});};
  const monitor=hub.monitor(account.id,true),failed=assert.rejects(monitor);await waiting;
  const draining=hub.drain();cancel(new Error('synthetic shutdown cancellation'));await failed;await draining;
  assert.equal(store.setting(`monitor:${account.id}`),true);
});
