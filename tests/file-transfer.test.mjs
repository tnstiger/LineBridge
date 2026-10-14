import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {Store} from '../server/store.mjs';
import {Vault} from '../server/vault.mjs';
import {Hub} from '../server/hub.mjs';
import {LineDriver,normalizeMessage} from '../server/drivers.mjs';
import {mediaDescriptor,archivedMedia,fileResult,safeFileName,fileMimeType,FILE_MAX_BYTES} from '../server/media.mjs';
import {extractFileText} from '../server/file-text.mjs';
import {fetchFileUrl,resolvePublic} from '../server/file-fetch.mjs';
import {createMcp} from '../server/mcp.mjs';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {InMemoryTransport} from '@modelcontextprotocol/sdk/inMemory.js';

// One-page PDF with a text layer: "Invoice NT$5,900 total".
const invoice=Buffer.from('JVBERi0xLjMKJZOMi54gUmVwb3J0TGFiIEdlbmVyYXRlZCBQREYgZG9jdW1lbnQgKG9wZW5zb3VyY2UpCjEgMCBvYmoKPDwKL0YxIDIgMCBSCj4+CmVuZG9iagoyIDAgb2JqCjw8Ci9CYXNlRm9udCAvSGVsdmV0aWNhIC9FbmNvZGluZyAvV2luQW5zaUVuY29kaW5nIC9OYW1lIC9GMSAvU3VidHlwZSAvVHlwZTEgL1R5cGUgL0ZvbnQKPj4KZW5kb2JqCjMgMCBvYmoKPDwKL0NvbnRlbnRzIDcgMCBSIC9NZWRpYUJveCBbIDAgMCA1OTUuMjc1NiA4NDEuODg5OCBdIC9QYXJlbnQgNiAwIFIgL1Jlc291cmNlcyA8PAovRm9udCAxIDAgUiAvUHJvY1NldCBbIC9QREYgL1RleHQgL0ltYWdlQiAvSW1hZ2VDIC9JbWFnZUkgXQo+PiAvUm90YXRlIDAgL1RyYW5zIDw8Cgo+PiAKICAvVHlwZSAvUGFnZQo+PgplbmRvYmoKNCAwIG9iago8PAovUGFnZU1vZGUgL1VzZU5vbmUgL1BhZ2VzIDYgMCBSIC9UeXBlIC9DYXRhbG9nCj4+CmVuZG9iago1IDAgb2JqCjw8Ci9BdXRob3IgKGFub255bW91cykgL0NyZWF0aW9uRGF0ZSAoRDoyMDI2MTAxNDA4MzY1NiswOCcwMCcpIC9DcmVhdG9yIChhbm9ueW1vdXMpIC9LZXl3b3JkcyAoKSAvTW9kRGF0ZSAoRDoyMDI2MTAxNDA4MzY1NiswOCcwMCcpIC9Qcm9kdWNlciAoUmVwb3J0TGFiIFBERiBMaWJyYXJ5IC0gXChvcGVuc291cmNlXCkpIAogIC9TdWJqZWN0ICh1bnNwZWNpZmllZCkgL1RpdGxlICh1bnRpdGxlZCkgL1RyYXBwZWQgL0ZhbHNlCj4+CmVuZG9iago2IDAgb2JqCjw8Ci9Db3VudCAxIC9LaWRzIFsgMyAwIFIgXSAvVHlwZSAvUGFnZXMKPj4KZW5kb2JqCjcgMCBvYmoKPDwKL0ZpbHRlciBbIC9BU0NJSTg1RGVjb2RlIC9GbGF0ZURlY29kZSBdIC9MZW5ndGggMTE3Cj4+CnN0cmVhbQpHYXBRaDBFPUYsMFVcSDNUXHBOWVReUUtrP3RjPklQLDtXI1UxXjIzaWhQRU1fP0NXNEtJU2k5ME1qR14yLEZTIzxSQzZaLydINzQ6MCRjazspLVYrIkE0cD5RUiheLC5ZTT1dS1A1ci8uPCM6ZiFpNlk7fj5lbmRzdHJlYW0KZW5kb2JqCnhyZWYKMCA4CjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAwMDA2MSAwMDAwMCBuIAowMDAwMDAwMDkyIDAwMDAwIG4gCjAwMDAwMDAxOTkgMDAwMDAgbiAKMDAwMDAwMDQwMiAwMDAwMCBuIAowMDAwMDAwNDcwIDAwMDAwIG4gCjAwMDAwMDA3MzEgMDAwMDAgbiAKMDAwMDAwMDc5MCAwMDAwMCBuIAp0cmFpbGVyCjw8Ci9JRCAKWzxlNTA2MGJlYzNjOTBmODhlOTQ5ODNjMDE1ZmMxMGRlYz48ZTUwNjBiZWMzYzkwZjg4ZTk0OTgzYzAxNWZjMTBkZWM+XQolIFJlcG9ydExhYiBnZW5lcmF0ZWQgUERGIGRvY3VtZW50IC0tIGRpZ2VzdCAob3BlbnNvdXJjZSkKCi9JbmZvIDUgMCBSCi9Sb290IDQgMCBSCi9TaXplIDgKPj4Kc3RhcnR4cmVmCjk5NwolJUVPRgo=','base64');

test('file messages get a bounded descriptor; legacy archived FILE rows still resolve',()=>{
  assert.deepEqual(mediaDescriptor({contentType:'FILE',contentMetadata:{FILE_NAME:'發票.pdf',FILE_SIZE:'5900',OID:'secret-object-id'}}),{kind:'file',encrypted:false,fileName:'發票.pdf',size:5900});
  assert.deepEqual(mediaDescriptor({contentType:14,chunks:['x'],contentMetadata:{OID:'o',SID:'emf'}}),{kind:'file',encrypted:true});
  assert.equal(JSON.stringify(normalizeMessage({id:'1',contentType:'FILE',contentMetadata:{FILE_NAME:'a.pdf',OID:'o'}})).includes('"o"'),false,'Object locators are never archived');
  assert.deepEqual(archivedMedia({contentType:'FILE'}),{kind:'file'});assert.deepEqual(archivedMedia({contentType:'14'}),{kind:'file'});
  assert.equal(safeFileName('../../etc/passwd'),'_.._etc_passwd');assert.equal(safeFileName('a‮gpj.exe'),'a_gpj.exe');assert.equal(safeFileName(42),'');
  assert.equal(fileMimeType(invoice,'whatever.bin'),'application/pdf','Content wins over the extension');
  assert.equal(fileMimeType(Buffer.from('PK\x03\x04rest'),'report.xlsx'),'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  assert.equal(fileMimeType(Buffer.from('hello'),'notes.txt'),'text/plain');
  const result=fileResult(invoice,'發票.pdf');assert.equal(result.mimeType,'application/pdf');assert.equal(result.bytes,invoice.length);assert.equal(result.untrustedContent,true);
  assert.throws(()=>fileResult(Buffer.alloc(FILE_MAX_BYTES+1),'big.pdf'),{code:'media_too_large'});
  assert.throws(()=>fileResult(Buffer.alloc(0),'empty.pdf'),{code:'media_unavailable'});
});

test('PDF text layers and plain text are extracted; other formats report no text',async()=>{
  const pdf=await extractFileText(invoice,'application/pdf');
  assert.equal(pdf.textAvailable,true);assert.match(pdf.text,/Invoice NT\$5,900 total/);assert.equal(pdf.pages,1);
  assert.deepEqual(await extractFileText(Buffer.from('a,b\n1,2'),'text/csv'),{textAvailable:true,text:'a,b\n1,2',truncated:false});
  assert.equal((await extractFileText(Buffer.from('%PDF-1.4 broken'),'application/pdf')).textAvailable,false);
  assert.equal((await extractFileText(Buffer.from('x'),'image/png')).textAvailable,false);
});

test('file URLs must be public HTTPS without redirects or internal addresses',async()=>{
  const publicDns=async()=>[{address:'93.184.216.34',family:4}];
  for(const url of ['http://example.com/f','file:///etc/passwd','https://user:pw@example.com/f','not a url'])await assert.rejects(fetchFileUrl(url,{resolver:publicDns}),{code:'invalid_file_url'});
  for(const host of ['127.0.0.1','10.0.0.5','192.168.1.2','169.254.169.254','172.20.0.1','100.64.0.1','::1','fd00::1','::ffff:127.0.0.1'])await assert.rejects(resolvePublic(host),{code:'file_url_blocked'},host);
  await assert.rejects(fetchFileUrl('https://internal.example/f',{resolver:async()=>[{address:'192.168.0.10',family:4}]}),{code:'file_url_blocked'});
  await assert.rejects(fetchFileUrl('https://mixed.example/f',{resolver:async()=>[{address:'93.184.216.34',family:4},{address:'127.0.0.1',family:4}]}),{code:'file_url_blocked'},'Any internal record blocks the host');
  await assert.rejects(fetchFileUrl('https://files.example/f',{resolver:publicDns,fetchImpl:async()=>new Response(null,{status:302,headers:{Location:'http://127.0.0.1/'}})}),{code:'file_url_redirect'});
  await assert.rejects(fetchFileUrl('https://files.example/f',{resolver:publicDns,fetchImpl:async()=>new Response('gone',{status:404})}),{code:'file_url_failed'});
  await assert.rejects(fetchFileUrl('https://files.example/f',{resolver:publicDns,fetchImpl:async()=>new Response(new Uint8Array(1),{headers:{'Content-Length':String(FILE_MAX_BYTES+1)}})}),{code:'media_too_large'});
  let seen;
  const bytes=await fetchFileUrl('https://files.example/invoice.pdf',{resolver:publicDns,fetchImpl:async(url,init)=>{seen={url:String(url),redirect:init.redirect};return new Response(invoice);}});
  assert.deepEqual(bytes,invoice);assert.deepEqual(seen,{url:'https://files.example/invoice.pdf',redirect:'manual'});
});

async function fixture(t){
  const store=new Store(':memory:'),vault=new Vault(randomBytes(32),'synthetic'),hub=new Hub(store,vault);
  t.after(()=>{hub.close();store.close();});
  const a=await hub.addAccount({label:'Synthetic',kind:'demo'});await hub.connect(a.id);
  for(const chat of ['demo-group','demo-openchat'])hub.designate(a.id,chat,true);
  await hub.monitor(a.id,true);
  const reader=hub.createToken({name:'Reader',grants:[{accountId:a.id,read:true,send:false}]});
  const sender=hub.createToken({name:'Sender',grants:[{accountId:a.id,read:true,send:true,chatIds:['demo-group','demo-openchat']}]});
  return {store,hub,id:a.id,reader:hub.authenticate(reader.token),sender:hub.authenticate(sender.token)};
}

test('sending a file needs send scope, is idempotent per file and never reaches OpenChat',async t=>{
  const f=await fixture(t),data=invoice.toString('base64');
  await assert.rejects(f.hub.sendFile(f.reader,f.id,'demo-group',{fileName:'發票.pdf',data},'file-send-0001'),{code:'scope_denied'});
  await assert.rejects(f.hub.sendFile(f.sender,f.id,'demo-group',{fileName:'',data},'file-send-0001'),{code:'invalid_file_name'});
  await assert.rejects(f.hub.sendFile(f.sender,f.id,'demo-group',{fileName:'a.pdf',data:'not base64!'},'file-send-0001'),{code:'invalid_file'});
  await assert.rejects(f.hub.sendFile(f.sender,f.id,'demo-group',{fileName:'a.pdf',data},'short'),{code:'idempotency_required'});
  const sent=await f.hub.sendFile(f.sender,f.id,'demo-group',{fileName:'發票.pdf',data},'file-send-0001');
  assert.equal(sent.protection,'letter_sealing');assert.equal(sent.fileName,'發票.pdf');assert.equal(sent.bytes,invoice.length);assert.equal(sent.replayed,false);
  assert.equal((await f.hub.sendFile(f.sender,f.id,'demo-group',{fileName:'發票.pdf',data},'file-send-0001')).replayed,true);
  await assert.rejects(f.hub.sendFile(f.sender,f.id,'demo-group',{fileName:'other.pdf',data},'file-send-0001'),{code:'idempotency_conflict'});
  await assert.rejects(f.hub.sendFile(f.sender,f.id,'demo-openchat',{fileName:'a.pdf',data},'file-send-0002'),{code:'file_send_unsupported'});
  const audit=f.store.audits().filter(r=>r.action==='file.send').map(r=>r.outcome);
  assert.deepEqual(audit.sort(),['ok','rejected']);
  assert.equal(JSON.stringify(f.store.audits()).includes(data.slice(0,40)),false,'File bytes never reach the audit log');
});

test('reading a file returns text and bytes through MCP; scope and kind are enforced',async t=>{
  const f=await fixture(t);
  f.hub.capture(f.id,'demo-group',{id:'file-1',senderId:'person',text:'',timestamp:'2026-10-14T00:00:00.000Z',contentType:'FILE',media:{kind:'file',encrypted:true}});
  f.hub.capture(f.id,'demo-group',{id:'text-1',senderId:'person',text:'hello',timestamp:'2026-10-14T00:00:01.000Z',contentType:'NONE'});
  let asked;f.hub.driver(f.id).media=async(chat,message)=>{asked=message.media;return {fileName:'發票.pdf',data:invoice.toString('base64')};};
  const read=await f.hub.readFile(f.reader,f.id,'demo-group','file-1');
  assert.deepEqual(asked,{kind:'file',encrypted:true});assert.equal(read.fileName,'發票.pdf');assert.match(read.text,/NT\$5,900/);
  await assert.rejects(f.hub.readFile(f.reader,f.id,'demo-group','text-1'),{code:'media_metadata_missing'});
  assert.ok(f.store.audits().some(r=>r.action==='file.read'&&r.outcome==='ok'));

  const [clientSide,serverSide]=InMemoryTransport.createLinkedPair(),client=new Client({name:'test',version:'1'});
  await createMcp(f.hub,f.reader).connect(serverSide);await client.connect(clientSide);t.after(()=>client.close());
  const tools=(await client.listTools()).tools,send=tools.find(x=>x.name==='line_send_file');
  assert.ok(tools.some(x=>x.name==='line_read_file'));
  assert.deepEqual(send._meta,{'openai/fileParams':['file']});
  assert.deepEqual(send.inputSchema.properties.file.required.sort(),['download_url','file_id']);
  assert.deepEqual(Object.keys(send.inputSchema.properties.file.properties).sort(),['download_url','file_id','file_name','mime_type']);
  const reply=await client.callTool({name:'line_read_file',arguments:{accountId:f.id,chatId:'demo-group',messageId:'file-1'}});
  assert.equal(reply.isError,undefined);
  assert.equal(JSON.parse(reply.content[0].text).mimeType,'application/pdf');
  assert.match(reply.content[1].text,/untrusted[\s\S]*Invoice NT\$5,900/);
  assert.equal(reply.content[2].type,'resource');assert.equal(reply.content[2].resource.blob,invoice.toString('base64'));
  const denied=await client.callTool({name:'line_send_file',arguments:{accountId:f.id,chatId:'demo-group',fileName:'a.pdf',dataBase64:invoice.toString('base64'),idempotencyKey:'mcp-file-0001'}});
  assert.equal(denied.isError,true);assert.equal(JSON.parse(denied.content[0].text).error,'scope_denied');
});

test('the driver seals before upload, authorizes before upload and never falls back to plain transport',async()=>{
  const calls=[],chat={id:'c'+'1'.repeat(32),kind:'group'};
  const make=({sealFails=false,uploadFails=false}={})=>{
    const client={
      e2ee:{encryptByKeyMaterial:async bytes=>{calls.push('encrypt');return {keyMaterial:'a2V5',encryptedData:Buffer.concat([bytes,Buffer.alloc(32)])};},
        encryptE2EEMessage:async(to,data,contentType)=>{calls.push(['seal',to,data.fileName,contentType]);if(sealFails)throw Object.assign(new Error('x'),{name:'No E2EEKey'});return [Buffer.from('chunk')];}},
      obs:{uploadObjectForService:async options=>{calls.push(['upload',options.obsPath.split('/').slice(0,2).join('/'),options.oType]);if(uploadFails)throw new Error('network');return {objId:'obj_1'};}},
      talk:{sendMessage:async options=>{calls.push(['message',options.contentType,options.contentMetadata.SID,options.contentMetadata.OID,options.chunks.length]);return {id:'987',createdTime:1760400000000};}},
      request:{request:async()=>{throw new Error('unused');}},getReqseq:async()=>1
    };
    return {client,monitorRequest:(_signal,fn)=>fn()};
  };
  const authorize=()=>{calls.push('authorize');};
  const result=await LineDriver.prototype.sendFile.call(make(),chat,{fileName:'發票.pdf',data:invoice.toString('base64')},authorize);
  assert.deepEqual(result.protection,'letter_sealing');assert.equal(result.messageId,'987');
  assert.deepEqual(calls,['encrypt',['seal',chat.id,'發票.pdf',14],'authorize',['upload','talk/emf','file'],['message',14,'emf','obj_1',1]]);

  calls.length=0;
  await assert.rejects(LineDriver.prototype.sendFile.call(make({sealFails:true}),chat,{fileName:'a.pdf',data:'YQ=='},authorize),{code:'send_preparation_failed'});
  assert.ok(!calls.some(c=>Array.isArray(c)&&c[0]==='upload'),'No upload without sealing');
  calls.length=0;
  await assert.rejects(LineDriver.prototype.sendFile.call(make({uploadFails:true}),chat,{fileName:'a.pdf',data:'YQ=='},authorize),{code:'file_upload_failed'});
  assert.ok(!calls.some(c=>Array.isArray(c)&&c[0]==='message'),'No message after a failed upload');
  calls.length=0;
  await assert.rejects(LineDriver.prototype.sendFile.call(make(),chat,{fileName:'a.pdf',data:'YQ=='},()=>{throw Object.assign(new Error('revoked'),{});}),{code:'file_upload_failed'});
  await assert.rejects(LineDriver.prototype.sendFile.call(make(),{...chat,kind:'openchat'},{fileName:'a.pdf',data:'YQ=='},authorize),{code:'file_send_unsupported'});
});
