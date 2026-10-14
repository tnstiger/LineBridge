import {lookup} from 'node:dns/promises';
import {isIP} from 'node:net';
import {Agent,fetch as undiciFetch} from 'undici';
import {fail} from './errors.mjs';
import {boundedResponse,FILE_MAX_BYTES,FILE_TIMEOUT_MS} from './media.mjs';

// ChatGPT hands a tool a short-lived HTTPS download_url for a file in the
// conversation. This service runs on the user's computer, so a URL supplied by
// an AI must never reach loopback, private, link-local or other internal
// addresses (including via DNS or redirects). HTTPS only, no redirects, bounded.
function blockedAddress(address){
  const v=isIP(address);
  if(v===4){
    const [a,b]=address.split('.').map(Number);
    return a===0||a===10||a===127||a>=224||(a===100&&b>=64&&b<=127)||(a===169&&b===254)||(a===172&&b>=16&&b<=31)||(a===192&&b===168)||(a===192&&b===0)||(a===198&&(b===18||b===19));
  }
  if(v===6){
    const x=address.toLowerCase();
    if(x==='::'||x==='::1')return true;
    const mapped=x.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);if(mapped)return blockedAddress(mapped[1]);
    return /^(fc|fd|fe8|fe9|fea|feb|ff)/.test(x)||x.startsWith('64:ff9b:')||x.startsWith('2001:db8');
  }
  return true;
}

export async function resolvePublic(hostname,resolver=lookup){
  if(isIP(hostname)){if(blockedAddress(hostname))fail(400,'file_url_blocked','The file URL points to a non-public address.');return hostname;}
  let records;
  try{records=await resolver(hostname,{all:true,verbatim:true});}catch{fail(400,'file_url_unreachable','The file URL host could not be resolved.');}
  if(!records.length||records.some(r=>blockedAddress(r.address)))fail(400,'file_url_blocked','The file URL points to a non-public address.');
  return records[0].address;
}

export async function fetchFileUrl(value,{resolver=lookup,fetchImpl}={}){
  let url;
  try{url=new URL(String(value));}catch{fail(400,'invalid_file_url','Supply a valid HTTPS file URL.');}
  if(url.protocol!=='https:'||url.username||url.password||String(value).length>4096)fail(400,'invalid_file_url','Only HTTPS file URLs without credentials are accepted.');
  const address=await resolvePublic(url.hostname.replace(/^\[|\]$/g,''),resolver);
  // Connect to the address that was checked, so DNS cannot change in between.
  const dispatcher=new Agent({connect:{lookup:(_host,_opts,cb)=>cb(null,[{address,family:isIP(address)}])}});
  const signal=AbortSignal.timeout(FILE_TIMEOUT_MS);
  try{
    const response=await (fetchImpl??undiciFetch)(url,{redirect:'manual',signal,dispatcher,headers:{Accept:'*/*'}});
    if(response.status>=300&&response.status<400){await response.body?.cancel();fail(400,'file_url_redirect','The file URL redirected; redirects are not followed.');}
    if(!response.ok){await response.body?.cancel();fail(502,'file_url_failed',`The file URL returned HTTP ${response.status}.`);}
    return await boundedResponse(response,signal,FILE_MAX_BYTES);
  }catch(error){
    if(error?.status)throw error;
    fail(502,'file_url_failed','The file could not be downloaded from its URL.');
  }finally{await dispatcher.close().catch(()=>{});}
}
