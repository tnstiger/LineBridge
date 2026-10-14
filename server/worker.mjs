import {WORKER_LINE_MAX} from './limits.mjs';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {randomUUID} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {HubError,SendRejectedError} from './errors.mjs';
import {VaultStorage} from './vault.mjs';
import {ACCOUNT_CHECK_TIMEOUT_MS,accountCheckError} from './account-health.mjs';

const encode=value=>JSON.stringify(value,(_,v)=>typeof v==='bigint'?{$bigint:String(v)}:v);
const decode=value=>JSON.parse(value,(_,v)=>v&&typeof v==='object'&&'$bigint' in v?BigInt(v.$bigint):v);
// LINE runs in a private child with no database or HTTP listener. Storage and
// captured messages are acknowledged only after the parent commits them.
export class ProtocolWorker {
  constructor(store,vault,capture) {Object.assign(this,{store,vault,capture});this.pending=new Map();this.events=new Map();}
  start() {
    if(this.closing)throw new HubError(503,'service_stopping','The LINE worker is draining.');
    if(this.child){
      if(this.childExited)throw new HubError(502,'upstream_unavailable','The LINE worker stopped.');
      return;
    }
    const child=spawn(process.execPath,[fileURLToPath(new URL('../protocol/worker.mjs',import.meta.url))],{windowsHide:true,stdio:['pipe','pipe','ignore']});
    this.child=child;this.childExited=false;this.drained=false;this.drainIncomplete=false;
    child.stdin.on('error',()=>{});
    const input=createInterface({input:child.stdout,crlfDelay:Infinity});
    input.on('line',line=>{
      if(this.child!==child)return;
      if(line.length>WORKER_LINE_MAX){child.kill();return;}
      try{this.handle(decode(line));}catch{child.kill();}
    });
    // exit can precede the final stdout data. Keep the parser, pending RPCs and
    // child identity until close, while refusing new work on the exited child.
    child.on('exit',()=>{if(this.child===child)this.childExited=true;});
    child.on('error',()=>{if(this.child===child){this.childExited=true;this.drainIncomplete=true;}});
    child.on('close',()=>{
      if(this.child!==child)return;
      if(this.pending.size)this.drainIncomplete=true;
      this.child=null;
      for(const request of this.pending.values()){clearTimeout(request.timer);request.reject(new HubError(502,'upstream_unavailable','The LINE worker stopped.'))}
      this.pending.clear();
      if(!this.closing)for(const emit of this.events.values())emit.fault?.('protocol_error');
    });
  }
  write(value){if(this.child&&!this.childExited)this.child.stdin.write(`${encode(value)}\n`);}
  handle(message) {
    if(message.type==='shutdown_complete'){this.drained=true;}
    else if(message.type==='result'){
      const request=this.pending.get(message.id);if(!request)return;
      clearTimeout(request.timer);this.pending.delete(message.id);
      if(message.error){const e=message.error;request.reject(request.method==='check'?accountCheckError(e):new (e.rejected_send?SendRejectedError:HubError)(e.status||502,e.code||'upstream_unavailable',e.message||'LINE operation failed.'));}
      else request.resolve(message.result);
    }else if(message.type==='authorize_send'){
      const request=this.pending.get(message.id);
      let ok=false;
      // Bind authorization to a still-pending send; expired/cancelled operations
      // cannot dispatch later. The callback rechecks current parent-owned scope.
      if(['send','send_file'].includes(request?.method)&&request.beforeDispatch){try{request.beforeDispatch();ok=true;}catch{}}
      this.write({type:'authorize_send_ack',id:message.id,ok});
    }else if(message.type==='event'){
      const emit=this.events.get(message.accountId);if(message.event==='monitor_status')emit?.monitor?.(message.value);else emit?.[message.event]?.(message.value);
    }else if(message.type==='storage'||message.type==='capture'){
      let ok=false;
      try{
        if(!this.store.account(message.accountId))throw new Error('Unknown account');
        if(message.type==='capture')this.capture(message.accountId,message.chatId,message.message);
        else {
          if(typeof message.key!=='string'||message.key.length>256)throw new Error('Invalid storage key');
          if(message.operation==='delete')this.store.deleteSecret(message.accountId,message.key);
          else if(message.operation==='set')this.store.putSecret(message.accountId,message.key,this.vault.seal(message.value,`${message.accountId}:${message.key}`));
          else throw new Error('Invalid storage operation');
        }
        ok=true;
      }catch{}
      this.write({type:message.type==='capture'?'capture_ack':'storage_ack',id:message.id,ok});
    }
  }
  call(method,params={},timeout=40000,signal,beforeDispatch){
    if(this.closing)return Promise.reject(new HubError(503,'service_stopping','The LINE worker is draining.'));
    if(signal?.aborted)return Promise.reject(signal.reason);
    try{this.start();}catch(error){return Promise.reject(error);}const id=randomUUID();
    return new Promise((resolve,reject)=>{
      const finish=(callback,value)=>{clearTimeout(timer);signal?.removeEventListener('abort',cancel);this.pending.delete(id);callback(value);};
      // A deadline/cancellation still settles promptly; a later shutdown ACK
      // cannot turn an unobserved outcome during drain into a complete drain.
      const abandon=error=>{if(this.closing)this.drainIncomplete=true;finish(reject,error);};
      const cancel=()=>abandon(signal.reason);
      const timer=setTimeout(()=>abandon(method==='check'?accountCheckError({name:'TimeoutError'}):new HubError(502,'upstream_unavailable','The LINE operation timed out.')),timeout);
      this.pending.set(id,{method,beforeDispatch,resolve:value=>finish(resolve,value),reject:error=>finish(reject,error),timer});
      signal?.addEventListener('abort',cancel,{once:true});this.write({id,method,params});
    });
  }
  driver(account,emit){
    const worker=this,id=account.id,storage=new VaultStorage(this.store,this.vault,id);
    this.events.set(id,emit);
    const call=(method,params)=>worker.call(method,{...params,accountId:id});
    return {
      ready:false,
      async login(qr){const profile=await worker.call('connect',{accountId:id,account,storage:storage.getAll(),qr},240000);this.ready=true;return profile;},
      check:signal=>worker.call('check',{accountId:id},ACCOUNT_CHECK_TIMEOUT_MS+5000,signal),discover:()=>call('discover'),
      read:(chat,limit,cursor)=>call('read',{chat,limit,cursor}),
      media:(chat,message)=>worker.call('media',{accountId:id,chat,message},message?.media?.kind==='file'||['FILE','14'].includes(String(message?.contentType))?90000:40000),
      sendFlex:(chat,input)=>call('send_flex',{chat,input}),
      textCapability:chat=>call('text_capability',{chat}),
      send:(chat,text,options,beforeDispatch)=>worker.call('send',{accountId:id,chat,text,options},40000,undefined,beforeDispatch),
      sendFile:(chat,input,beforeDispatch)=>worker.call('send_file',{accountId:id,chat,input},90000,undefined,beforeDispatch),
      resolveMessageNames:(chat,messages)=>call('resolve_names',{chat,messages}),
      startMonitor:(chats,reset,refreshIntervalMs)=>call('monitor_start',{chats,reset,refreshIntervalMs}),
      setRefreshInterval:refreshIntervalMs=>call('monitor_interval',{refreshIntervalMs}),
      updateMonitor:chats=>call('monitor_update',{chats}),
      stopMonitor:()=>call('monitor_stop'),
      stop(){this.ready=false;worker.events.delete(id);if(worker.child&&!worker.closing)void call('disconnect').catch(()=>{});}
    };
  }
  drain(){
    if(this.drainPromise)return this.drainPromise;
    this.closing=true;const child=this.child;
    if(!child)return Promise.resolve();
    this.drainPromise=new Promise((resolve,reject)=>{
      child.once('close',(code)=>{
        if(this.child===child)this.child=null;
        this.events.clear();
        if(code===0&&this.drained&&!this.drainIncomplete)resolve();else reject(new HubError(503,'worker_drain_failed','The LINE worker did not confirm a complete drain.'));
      });
      this.write({type:'shutdown'});
    });
    return this.drainPromise;
  }
  close(){
    this.closing=true;this.drainIncomplete=true;
    for(const request of this.pending.values()){clearTimeout(request.timer);request.reject(new HubError(502,'upstream_unavailable','The LINE worker stopped.'));}
    this.pending.clear();this.events.clear();if(!this.childExited)this.child?.kill();this.child=null;
  }
}
