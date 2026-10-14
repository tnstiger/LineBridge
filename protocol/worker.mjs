import {WORKER_LINE_MAX} from '../server/limits.mjs';
import {createInterface} from 'node:readline';
import {randomUUID} from 'node:crypto';
import {BaseStorage} from '@evex/linejs/storage';
import {LineDriver} from '../server/drivers.mjs';
import {HubError,SendRejectedError,publicError} from '../server/errors.mjs';
import {LiveMonitor} from './monitor.mjs';
import {accountCheckError} from '../server/account-health.mjs';

// This process owns only LINE RPCs. The parent owns policy, storage and HTTP.
// stdout is a private JSON pipe; never attach the adapter's raw logging events.
console.log=()=>{};console.error=()=>{};
const drivers=new Map(),writes=new Map(),monitors=new Map(),controlJobs=new Map();
const jobs=new Set();let closing=false;
const controlMethods=new Set(['connect','disconnect','monitor_start','monitor_stop','monitor_update','monitor_interval']);
function control(accountId,operation){
  const job=(controlJobs.get(accountId)??Promise.resolve()).catch(()=>{}).then(operation);
  controlJobs.set(accountId,job);
  const settled=()=>{if(controlJobs.get(accountId)===job)controlJobs.delete(accountId);};
  void job.then(settled,settled);return job;
}
async function stopMonitor(accountId){
  const monitor=monitors.get(accountId);monitor?.stop();await monitor?.done();monitors.delete(accountId);
}
const emit=value=>process.stdout.write(JSON.stringify(value,(_,v)=>typeof v==='bigint'?{$bigint:String(v)}:v)+'\n');
function authorizeDispatch(id){
  return new Promise((resolve,reject)=>{
    const denied=()=>reject(new SendRejectedError(403,'send_authorization_revoked','Send authorization expired or changed during preparation. No message was sent.'));
    const timer=setTimeout(()=>{writes.delete(id);denied();},5000);
    writes.set(id,{resolve:()=>{clearTimeout(timer);resolve();},reject:()=>{clearTimeout(timer);denied();}});
    emit({type:'authorize_send',id});
  });
}
class PipeStorage extends BaseStorage {
  constructor(accountId,initial){super();this.accountId=accountId;this.data=new Map(Object.entries(initial));}
  async get(key){return this.data.get(key);}
  async set(key,value){await this.persist('set',key,value);this.data.set(key,value);}
  async delete(key){await this.persist('delete',key);this.data.delete(key);}
  async clear(){for(const key of this.data.keys())await this.delete(key);}
  getAll(){return Object.fromEntries(this.data);}
  async migrate(storage){for(const [key,value] of this.data)await storage.set(key,value);}
  async persist(operation,key,value){
    const id=randomUUID();
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{writes.delete(id);reject(new Error('vault_write_failed'));},10000);
      writes.set(id,{resolve:()=>{clearTimeout(timer);resolve();},reject:()=>{clearTimeout(timer);reject(new Error('vault_write_failed'));}});
      emit({type:'storage',id,accountId:this.accountId,operation,key,value});
    });
  }
}
async function handle(request){
  const {id,method,params={}}=request,accountId=params.accountId;
  try{
    let result;
    const operation=async()=>{
    if(closing)throw new HubError(503,'service_stopping','The LINE worker is draining.');
    if(method==='connect'){
      await stopMonitor(accountId);
      if(closing)throw new HubError(503,'service_stopping','The LINE worker is draining.');
      drivers.get(accountId)?.stop();
      const storage=new PipeStorage(accountId,params.storage ?? {});
      let driver;
      const event=(event,value)=>{if(drivers.get(accountId)===driver)emit({type:'event',accountId,event,value});};
      driver=new LineDriver(params.account,storage,{qr:v=>event('qr',v),pin:v=>event('pin',v),fault:v=>event('fault',v)});
      // Do not hold the lifecycle queue during login: disconnect/reconnect must
      // still be able to cancel an outstanding QR or token request.
      drivers.set(accountId,driver);result=driver.login(!!params.qr);
    }else{
      const driver=drivers.get(accountId);if(!driver)throw new HubError(409,'account_disconnected','Account is not connected.');
      switch(method){
        case 'disconnect':await stopMonitor(accountId);driver.stop();drivers.delete(accountId);result={ok:true};break;
        case 'check':result=await driver.check();break;
        case 'discover':result=await driver.discover();break;
        case 'read':result=await driver.read(params.chat,params.limit,params.cursor);break;
        case 'media':result=await driver.media(params.chat,params.message);break;
        case 'send_flex':result=await driver.sendFlex(params.chat,params.input);break;
        case 'resolve_names':result=await driver.resolveMessageNames(params.chat,(params.messages ?? []).slice(0,100));break;
        case 'text_capability':result=await driver.textCapability(params.chat);break;
        case 'send':result=await driver.send(params.chat,params.text,params.options,()=>authorizeDispatch(id));break;
        case 'send_file':result=await driver.sendFile(params.chat,params.input,()=>authorizeDispatch(id));break;
        case 'monitor_start':{
          await stopMonitor(accountId);
          if(closing)throw new HubError(503,'service_stopping','The LINE worker is draining.');
          if(params.reset)for(const key of Object.keys(driver.storage.getAll()))if(key.startsWith('monitor.'))await driver.storage.delete(key);
          if(closing)throw new HubError(503,'service_stopping','The LINE worker is draining.');
          const monitor=new LiveMonitor(driver,(event,value)=>emit({type:'event',accountId,event,value}),async(chatId,message)=>{
            const ackId=randomUUID();await new Promise((resolve,reject)=>{
              const timer=setTimeout(()=>{writes.delete(ackId);reject(new Error('capture_failed'));},10000);
              writes.set(ackId,{resolve:()=>{clearTimeout(timer);resolve();},reject:()=>{clearTimeout(timer);reject(new Error('capture_failed'));}});
              emit({type:'capture',id:ackId,accountId,chatId,message});
            });
          },{refreshIntervalMs:params.refreshIntervalMs,diagnostics:process.env.LINE_BRIDGE_MONITOR_DIAGNOSTICS==='1'});monitor.update(params.chats ?? []);monitors.set(accountId,monitor);result={ok:true};break;
        }
        case 'monitor_update':monitors.get(accountId)?.update(params.chats ?? []);result={ok:true};break;
        case 'monitor_interval':monitors.get(accountId)?.setRefreshInterval(params.refreshIntervalMs);result={ok:true};break;
        case 'monitor_stop':await stopMonitor(accountId);result={ok:true};break;
        default:throw new Error('Unknown worker operation');
      }
    }
    };
    // ACKs stay outside this queue so an old monitor can finish durable writes
    // before its replacement starts. Different accounts also remain independent.
    if(controlMethods.has(method))await control(accountId,operation);else await operation();
    result=await result;
    emit({type:'result',id,result});
  }catch(error){
    const checked=method==='check'?accountCheckError(error):error,safe=publicError(checked);
    emit({type:'result',id,error:{status:safe.status,code:safe.code,message:safe.message,rejected_send:error instanceof SendRejectedError,...(method==='check'?{accountDiagnostic:checked.accountDiagnostic}:{})}});
  }
}
const input=createInterface({input:process.stdin,crlfDelay:Infinity});
async function shutdown(){
  if(closing)return;closing=true;
  for(const monitor of monitors.values())monitor.stop();
  // Cancel login waits, but let already dispatched work report its outcome.
  for(const driver of drivers.values())if(!driver.ready)driver.stop();
  await Promise.allSettled([...jobs]);
  await Promise.allSettled([...monitors.values()].map(monitor=>monitor.done()));
  for(const driver of drivers.values())driver.stop();
  // Storage/capture ACKs are still handled by the input loop while draining.
  while(writes.size)await new Promise(resolve=>setTimeout(resolve,10));
  emit({type:'shutdown_complete'});input.close();process.stdin.destroy();
}
input.on('line',line=>{
  if(line.length>WORKER_LINE_MAX){process.exit(2);return;}
  try{const message=JSON.parse(line,(_,v)=>v&&typeof v==='object'&&'$bigint'in v?BigInt(v.$bigint):v);
    if(['storage_ack','capture_ack','authorize_send_ack'].includes(message.type)){const pending=writes.get(message.id);writes.delete(message.id);message.ok?pending?.resolve():pending?.reject();}
    else if(message.type==='shutdown')void shutdown();
    else {const job=handle(message);jobs.add(job);void job.finally(()=>jobs.delete(job));}
  }catch{process.exit(2);}
});
input.on('close',()=>{if(closing)return;for(const m of monitors.values())m.stop();for(const d of drivers.values())d.stop();process.exit(0);});
