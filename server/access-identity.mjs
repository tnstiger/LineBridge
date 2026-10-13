import {z} from 'zod';
import {fail} from './errors.mjs';

// Cloudflare Access Managed OAuth lets clients that can only do OAuth (ChatGPT,
// Dot and similar MCP connectors) sign in as a person. Cloudflare resolves the
// opaque OAuth token at its edge and forwards a signed Cf-Access-Jwt-Assertion
// carrying the person's email. Allowlisted people receive the scope of one
// existing AI token chosen by the user; nobody else gets in.
const KEY='accessIdentity';
const email=z.string().trim().toLowerCase().max(254).regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/,'Invalid email address');
const input=z.object({emails:z.array(email).max(20),tokenId:z.string().min(1).max(100).nullable()}).strict();
const active=token=>!!token&&!token.revoked&&Date.parse(token.expires_at)>Date.now();

export function identityConfig(store){
  const value=store.setting(KEY,null);
  return value&&Array.isArray(value.emails)?{emails:value.emails,tokenId:value.tokenId??null}:{emails:[],tokenId:null};
}

export function identityEnabled(store){const c=identityConfig(store);return c.emails.length>0&&!!c.tokenId;}

export function configureIdentity(hub,value){
  const data=input.parse(value);data.emails=[...new Set(data.emails)];
  if(data.emails.length&&!data.tokenId)fail(400,'identity_token_required','Choose the AI token whose scope signed-in people receive.');
  if(data.tokenId){
    const token=hub.store.token(data.tokenId);
    if(!active(token))fail(409,'identity_token_inactive','Choose an active AI token.');
    if(token.grants.some(g=>g.localOnly))fail(409,'identity_token_local','The local setup profile cannot be used for Cloudflare sign-in.');
  }
  hub.store.setSetting(KEY,data);
  hub.store.audit('local-admin','access-identity.update',null,null,data.emails.length&&data.tokenId?'enabled':'disabled');
  return identityConfig(hub.store);
}

// Called only after the Access assertion signature, issuer and audience verified.
export function identityActor(hub,payload){
  const c=identityConfig(hub.store);
  // Service-token assertions carry no email, so they never match a person.
  const mail=typeof payload?.email==='string'?payload.email.trim().toLowerCase():'';
  if(!mail||!c.tokenId||!c.emails.includes(mail))fail(403,'access_identity_denied','This Cloudflare Access identity is not allowed to use LineBridge.');
  const actor=hub.actor({id:c.tokenId});hub.store.touchToken(c.tokenId);
  return actor;
}
