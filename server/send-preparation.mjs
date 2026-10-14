import {preparationCauses} from '../client/send-diagnostic.mjs';
import {existingKeyE2EE} from './encryption-policy.mjs';

function cause(error){
  const names={'NoE2EEKey':'SELF_KEY_MISSING','No E2EEKey':'RECIPIENT_KEY_MISSING','Not support E2EE':'E2EE_UNSUPPORTED',TypeError:'SDK_TYPE_ERROR',TimeoutError:'TIMEOUT',AbortError:'CANCELLED'};
  if(Object.hasOwn(names,error?.name))return names[error.name];
  if(error?.name==='RequestError'){
    const code=error?.data?.errorCode??error?.data?.code??error?.code;
    return preparationCauses.includes(code)?code:'LINE_REJECTED';
  }
  return 'SDK_ERROR';
}
export class PreparationFailure extends Error {
  constructor(stage,original){super('Letter Sealing preparation failed.');Object.defineProperty(this,'original',{value:original});this.diagnostic=`${stage}_${cause(original)}`;}
}

// Per-operation views preserve SDK behavior and shared live clients. Do not
// monkeypatch the live SDK, add key registration, retry, or change encryption.
export function prepareText(client,chat,text,negotiation){return prepareSealed(client,chat,text,'NONE',negotiation);}
// Files seal {keyMaterial,fileName} with contentType FILE through the same
// existing-key view: no key registration, retry or encryption downgrade.
export function prepareFile(client,chat,keyMaterial,fileName,negotiation){return prepareSealed(client,chat,{keyMaterial,fileName},14,negotiation);}
async function prepareSealed(client,chat,data,contentType,negotiation){
  let stage='MESSAGE_PREPARATION';
  const failures=new WeakMap();
  const e2ee=existingKeyE2EE(client),view=Object.create(client),talk=Object.create(client.talk);
  view.talk=talk;e2ee.client=view;
  const wrap=(target,original,name,nextStage,receiver)=>{
    if(typeof original[name]!=='function')return;
    target[name]=function(...args){
      stage=nextStage;
      // Preserve the original exception while inside the SDK: it may handle
      // an explicit LINE response itself. Record context without mutating it.
      const failed=error=>{if(error&&(typeof error==='object'||typeof error==='function')&&!failures.has(error))failures.set(error,nextStage);throw error;};
      try{const result=original[name].apply(receiver??this,args);return result&&typeof result.then==='function'?result.catch(failed):result;}catch(error){return failed(error);}
    };
  };
  for(const name of ['getE2EESelfKeyData','getE2EESelfKeyDataByKeyId'])wrap(e2ee,client.e2ee,name,'SELF_KEY_LOOKUP');
  wrap(e2ee,client.e2ee,'getE2EELocalPublicKey',chat.kind==='group'?'GROUP_KEY_LOOKUP':'RECIPIENT_KEY_NEGOTIATION');
  wrap(talk,client.talk,'negotiateE2EEPublicKey','RECIPIENT_KEY_NEGOTIATION',client.talk);
  if(negotiation!==undefined)talk.negotiateE2EEPublicKey=async()=>{stage='RECIPIENT_KEY_NEGOTIATION';return negotiation;};
  wrap(talk,client.talk,'getLastE2EEGroupSharedKey','GROUP_KEY_LOOKUP',client.talk);
  wrap(e2ee,client.e2ee,'encryptE2EETextMessage','ENCRYPTION');
  try{return await e2ee.encryptE2EEMessage(chat.id,data,contentType);}
  catch(error){throw new PreparationFailure(error&&typeof error==='object'?failures.get(error)??stage:stage,error);}
}
