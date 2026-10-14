import {spawn,execFile} from 'node:child_process';
import {accessSync,constants,writeFileSync} from 'node:fs';
import {join,delimiter,isAbsolute} from 'node:path';
import {promisify} from 'node:util';
import {createInterface} from 'node:readline';
import {z} from 'zod';
import {fail} from './errors.mjs';
import {installNgrok} from './connector-install.mjs';

const exec=promisify(execFile),tsProviders=new Set(['tailscale','tailscale_funnel']);
const providers=['local','cloudflare','cloudflare_quick','tailscale','tailscale_funnel','ngrok'];
const localConfig={provider:'local',hostname:'',teamDomain:'',audience:''};
const configSchema=z.object({provider:z.enum(providers),hostname:z.string().trim().max(253).default(''),teamDomain:z.string().trim().max(253).default(''),audience:z.string().trim().max(512).default(''),ngrokDomain:z.string().trim().max(253).optional(),httpsPort:z.union([z.literal(443),z.literal(8443),z.literal(10000)]).optional()}).strict();
export const validHostname=host=>typeof host==='string'&&host.length<=253&&host.split('.').every(s=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(s));
export function findExecutable(name,candidates=[]){
  const files=[...candidates,...(process.env.PATH??'').split(delimiter).map(p=>join(p,process.platform==='win32'?`${name}.exe`:name))];
  return files.find(p=>{if(!p||!isAbsolute(p))return false;try{accessSync(p,process.platform==='win32'?constants.F_OK:constants.X_OK);return true;}catch{return false;}})??null;
}
export function quickHostname(line){const url=line.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com(?=[\s|]|$)/)?.[0];return url?new URL(url).hostname:null;}
export function tailscaleAuth(value){try{const u=new URL(value);return value.length<=8192&&u.protocol==='https:'&&u.hostname==='login.tailscale.com'&&!u.port&&!u.username&&!u.password&&(u.pathname.startsWith('/a/')||u.pathname==='/f/funnel')?u.href:null;}catch{return null;}}
export function publicHostname(value){try{const u=new URL(value);return u.protocol==='https:'&&!u.port&&!u.username&&!u.password&&!u.search&&!u.hash&&u.pathname==='/'&&validHostname(u.hostname)?u.hostname:null;}catch{return null;}}
const tsPort=c=>c.httpsPort??(c.provider==='tailscale_funnel'?443:8443);
const routeMatches=(current,route)=>{const handlers=current.Web?.[route.host]?.Handlers;return !!handlers&&Object.keys(handlers).length===1&&handlers['/']?.Proxy===route.proxy&&!!current.AllowFunnel?.[route.host]===route.funnel;};
const AUTOSTART=new Set(['cloudflare','cloudflare_quick','ngrok']);
export class Tunnels {
  constructor(store,vault,root,gatewayPort,metricsPort=gatewayPort+1,data=join(root,'data')){
    Object.assign(this,{store,vault,root,gatewayPort,metricsPort,data});this.state={status:'not_started'};this.busy=false;
    this.cloudflare=findExecutable('cloudflared',[process.env.LINE_BRIDGE_CLOUDFLARED,join(root,'tools',process.platform==='win32'?'cloudflared.exe':'cloudflared')]);
    this.tailscale=findExecutable('tailscale',[process.env.LINE_BRIDGE_TAILSCALE,process.platform==='win32'?'C:\\Program Files\\Tailscale\\tailscale.exe':'/Applications/Tailscale.app/Contents/MacOS/Tailscale']);
    const binary=name=>process.platform==='win32'?`${name}.exe`:name;
    this.ngrok=findExecutable('ngrok',[process.env.LINE_BRIDGE_NGROK,join(data,'tools',binary('ngrok')),join(root,'tools',binary('ngrok')),'/opt/homebrew/bin/ngrok','/usr/local/bin/ngrok']);
  }
  config(){const saved=this.store.setting('tunnel',localConfig);return providers.includes(saved?.provider)?saved:{...localConfig};}
  idle(){if(this.child||this.ownedRoute||tsProviders.has(this.config().provider)&&this.state.status==='running')fail(409,'tunnel_running','Stop the tunnel before changing its configuration.');}
  available(){if(this.busy)fail(409,'tunnel_busy','Wait for the current connection operation to finish.');}
  async operation(job){this.available();this.busy=true;try{return await job();}finally{this.busy=false;}}
  configure(input){
    this.available();this.idle();const c=configSchema.parse(input),previous=this.config();
    if(c.provider!=='cloudflare')c.hostname=c.teamDomain=c.audience='';
    for(const host of [c.hostname,c.teamDomain,c.ngrokDomain])if(host&&!validHostname(host))fail(400,'invalid_hostname','Enter a DNS hostname without a URL scheme, path or spaces.');
    if(c.teamDomain&&!/^[a-z0-9-]+\.cloudflareaccess\.com$/i.test(c.teamDomain))fail(400,'invalid_team_domain','Use your-team.cloudflareaccess.com as the Access team domain.');
    c.hostname=c.hostname.toLowerCase();c.teamDomain=c.teamDomain.toLowerCase();
    if(c.provider==='ngrok'){c.ngrokDomain=(c.ngrokDomain??'').toLowerCase();this.store.setSetting('ngrokDomain',c.ngrokDomain);}else delete c.ngrokDomain;
    if(tsProviders.has(c.provider))c.httpsPort=tsPort(c);else delete c.httpsPort;
    if(previous.provider==='cloudflare')this.store.setSetting('cloudflareNamed',previous);
    this.store.setSetting('tunnel',c);if(c.provider==='cloudflare')this.store.setSetting('cloudflareNamed',c);
    this.quickHost=this.ngrokHost=null;this.state={status:'configured'};return c;
  }
  gatewayHostname(){const c=this.config();return c.provider==='cloudflare_quick'?this.quickHost??'':c.provider==='ngrok'?this.ngrokHost??'':c.hostname;}
  async ts(args,timeout=5000){
    if(!this.tailscale)fail(409,'tailscale_missing','Install Tailscale first.');
    try{const {stdout}=await exec(this.tailscale,args,{windowsHide:true,timeout,maxBuffer:1024*1024,env:{...process.env,TAILSCALE_BE_CLI:'1'}});return args.includes('--json')&&stdout.trim()?JSON.parse(stdout):{};}
    catch(error){
      const output=String(error.stdout??'')+'\n'+String(error.stderr??'');
      for(const url of output.match(/https:\/\/[^\s]+/g)??[]){const authUrl=tailscaleAuth(url);if(authUrl&&new URL(authUrl).pathname==='/f/funnel'){const e=new Error('Funnel requires device authorization.');e.code='funnel_authorization_required';e.authUrl=authUrl;throw e;}}
      fail(502,args[0]==='funnel'?'funnel_unavailable':'tailscale_unavailable','Tailscale could not complete the operation.');
    }
  }
  async connectTailscale(){
    if(this.loginBusy)fail(409,'tailscale_busy','Tailscale sign-in is already in progress.');
    this.loginBusy=true;try{
      const before=await this.ts(['status','--json']);if(before.BackendState==='Running')return {connected:true,state:'Running'};
      let stdout='';try{({stdout}=await exec(this.tailscale,['up','--json','--timeout=4s'],{windowsHide:true,timeout:7000,maxBuffer:1024*1024,env:{...process.env,TAILSCALE_BE_CLI:'1'}}));}catch(e){stdout=e.stdout??'';}
      const after=await this.ts(['status','--json']);if(after.BackendState==='Running')return {connected:true,state:'Running'};
      let authUrl=tailscaleAuth(after.AuthURL);
      if(!authUrl){for(const line of stdout.split('\n'))try{authUrl=tailscaleAuth(JSON.parse(line).AuthURL);if(authUrl)break;}catch{}}
      if(authUrl)return {connected:false,state:after.BackendState,authUrl};
      if(after.BackendState==='NeedsMachineAuth')return {connected:false,state:'NeedsMachineAuth'};
      fail(502,'tailscale_unavailable','Open the installed Tailscale client to complete sign-in.');
    }finally{this.loginBusy=false;}
  }
  async status(){
    const c={...this.config()};let connected=c.provider==='local';
    if(c.provider==='cloudflare_quick')c.hostname=this.quickHost??'';
    if(c.provider==='ngrok')c.hostname=this.ngrokHost??'';
    if(this.child){
      if(c.provider==='ngrok')connected=await this.ngrokReady();
      else try{connected=(await fetch(`http://127.0.0.1:${this.metricsPort}/ready`,{signal:AbortSignal.timeout(1200),redirect:'error'})).ok&&(c.provider!=='cloudflare_quick'||!!c.hostname);}catch{}
      if(connected)this.state.status='running';
    }
    const tailscale={installed:!!this.tailscale,state:'unknown'};
    if(this.tailscale)try{
      const s=await this.ts(['status','--json'],2500);tailscale.state=s.BackendState;
      if(tsProviders.has(c.provider)&&c.hostname){const serve=await this.ts(['serve','status','--json'],2500);connected=s.BackendState==='Running'&&routeMatches(serve,{host:`${c.hostname.split(':')[0]}:${tsPort(c)}`,proxy:`http://127.0.0.1:${this.gatewayPort}`,funnel:c.provider==='tailscale_funnel'});}
    }catch{tailscale.state='unavailable';}
    return {...c,...this.state,status:c.provider==='local'?'running':this.state.status,connected,cloudflaredInstalled:!!this.cloudflare,hasConnectorToken:!!this.store.setting('cloudflareConnector',null),tailscale,
      ngrok:{installed:!!this.ngrok,hasAuthtoken:!!this.store.setting('ngrokAuthtoken',null),domain:this.store.setting('ngrokDomain','')},
      url:c.provider==='local'?`http://127.0.0.1:${this.gatewayPort}`:c.hostname?`https://${c.hostname}`:null,
      accessConfigured:c.provider==='cloudflare'&&!!c.hostname&&!!c.teamDomain&&!!c.audience,accessLastValidated:this.accessLastValidated??null,
      namedConfig:this.store.setting('cloudflareNamed',c.provider==='cloudflare'?c:{}),scope:{local:'this PC',cloudflare_quick:'temporary HTTPS',cloudflare:'Access-protected HTTPS',tailscale:'private tailnet',tailscale_funnel:'public HTTPS',ngrok:'public HTTPS'}[c.provider]};
  }
  async ngrokReady(){
    if(!this.child||!this.ngrokHost)return false;
    try{const response=await fetch(`http://127.0.0.1:${this.metricsPort}/api/tunnels`,{signal:AbortSignal.timeout(1200),redirect:'error'});if(!response.ok)return false;const data=await response.json();return data.tunnels?.some(t=>publicHostname(t.public_url)===this.ngrokHost&&t.config?.addr===`http://127.0.0.1:${this.gatewayPort}`)??false;}catch{return false;}
  }
  setNgrokToken(token){
    this.available();this.idle();if(typeof token!=='string'||token.length<10||token.length>4096||!/^[A-Za-z0-9_-]+$/.test(token))fail(400,'invalid_ngrok_token','Paste a valid ngrok authtoken.');
    this.store.setSetting('ngrokAuthtoken',this.vault.seal(token,'ngrok.authtoken'));return {saved:true};
  }
  forgetNgrokToken(){this.available();this.idle();this.store.setSetting('ngrokAuthtoken',null);return {saved:false};}
  async install(provider){return this.operation(async()=>{this.idle();if(provider!=='ngrok')fail(400,'invalid_input','Only the ngrok connector is installed on demand.');this.ngrok=await installNgrok(this.data);return {installed:true,provider:'ngrok'};});}
  spawnConnector(binary,args,env,onLine){
    const child=spawn(binary,args,{windowsHide:true,env,stdio:['ignore','pipe','pipe']});this.child=child;this.state={status:'starting'};
    for(const input of [child.stdout,child.stderr]){const lines=createInterface({input});lines.on('line',line=>{if(this.child===child&&line.length<16384)onLine(line);});}
    const failed=()=>{if(this.child===child){this.child=null;this.quickHost=this.ngrokHost=null;this.state={status:'connector_failed'};}};child.on('error',failed);child.on('exit',failed);
    return {status:'starting'};
  }
  setConnectorToken(token){
    if(typeof token!=='string'||token.length<30||token.length>16000||/\s/.test(token))fail(400,'invalid_connector_token','Paste a valid Cloudflare connector token.');
    this.store.setSetting('cloudflareConnector',this.vault.seal(token,'cloudflare.connector'));
  }
  async start(token){return this.operation(async()=>{
    const c=this.config();this.idle();
    if(c.provider==='local')return {status:'running',url:`http://127.0.0.1:${this.gatewayPort}`};
    if(tsProviders.has(c.provider)){
      const login=await this.connectTailscale();if(!login.connected)return login;
      const s=await this.ts(['status','--json']),dns=s.Self?.DNSName?.replace(/\.$/,'');if(!validHostname(dns))fail(502,'tailscale_unavailable','Tailscale did not return a DNS name.');
      const port=tsPort(c),host=`${dns}:${port}`,existing=await this.ts(['serve','status','--json']),proxy=`http://127.0.0.1:${this.gatewayPort}`,funnel=c.provider==='tailscale_funnel',route={host,port,proxy,funnel};
      if(existing.Web?.[host]||existing.TCP?.[port]){
        if(!routeMatches(existing,route))fail(409,'serve_conflict','This Tailscale HTTPS port already serves a different route.');
        this.ownedRoute=null;
      }else{
        try{await this.ts([funnel?'funnel':'serve','--bg',`--https=${port}`,...(funnel?['--yes']:[]),proxy],15000);}
        catch(error){if(error.code==='funnel_authorization_required'){this.state={status:'authorization_required'};return {status:'authorization_required',authUrl:error.authUrl,state:'NeedsFunnelAuth'};}throw error;}
        this.ownedRoute=route;
      }
      const hostname=port===443?dns:host;this.store.setSetting('tunnel',{...c,hostname});this.state={status:'running'};return {status:'running',url:`https://${hostname}`};
    }
    if(c.provider==='ngrok'){
      if(!this.ngrok)fail(409,'ngrok_missing','Install ngrok first.');const cipher=this.store.setting('ngrokAuthtoken',null);if(!cipher)fail(409,'ngrok_token_required','Save your ngrok authtoken first.');
      const env={...process.env,NGROK_AUTHTOKEN:this.vault.unseal(cipher,'ngrok.authtoken')};delete env.NGROK_API_KEY;
      const config=join(this.data,'linebridge-ngrok.yml');writeFileSync(config,`version: 3\nagent:\n  web_addr: 127.0.0.1:${this.metricsPort}\n  console_ui: false\n  inspect_db_size: 0\n  remote_management: false\n  update_check: false\n`,{mode:0o600});
      this.ngrokHost=null;return this.spawnConnector(this.ngrok,['http',`http://127.0.0.1:${this.gatewayPort}`,`--config=${config}`,'--inspect=false','--log=stderr','--log-format=json','--name=linebridge',...(c.ngrokDomain?[`--url=https://${c.ngrokDomain}`]:[])],env,line=>{try{const host=publicHostname(JSON.parse(line).url);if(host)this.ngrokHost=host;}catch{}});
    }
    if(!this.cloudflare)fail(409,'cloudflared_missing','Install cloudflared on this machine first.');
    const env={...process.env};delete env.TUNNEL_TOKEN;delete env.TUNNEL_TOKEN_FILE;
    let args;
    if(c.provider==='cloudflare_quick'){
      const config=join(this.data,'linebridge-quick.yml');writeFileSync(config,'no-autoupdate: true\n',{mode:0o600});
      args=['tunnel','--config',config,'--no-autoupdate','--metrics',`127.0.0.1:${this.metricsPort}`,'--url',`http://127.0.0.1:${this.gatewayPort}`];
    }else{
      if(!c.hostname||!c.teamDomain||!c.audience)fail(409,'access_setup_required','Configure the hostname, Access team domain and application AUD first.');
      if(token)this.setConnectorToken(token);const cipher=this.store.setting('cloudflareConnector',null);if(!cipher)fail(409,'connector_token_required','A Cloudflare connector token is required.');
      env.TUNNEL_TOKEN=this.vault.unseal(cipher,'cloudflare.connector');args=['tunnel','--no-autoupdate','--metrics',`127.0.0.1:${this.metricsPort}`,'run'];
    }
    const child=spawn(this.cloudflare,args,{windowsHide:true,env,stdio:['ignore','ignore','pipe']});this.child=child;this.quickHost=null;this.state={status:'starting'};
    const lines=createInterface({input:child.stderr});lines.on('line',line=>{if(this.child===child&&c.provider==='cloudflare_quick'){const host=quickHostname(line);if(host)this.quickHost=host;}});
    const failed=()=>{if(this.child===child){this.child=null;this.quickHost=null;this.state={status:'connector_failed'};}};child.on('error',failed);child.on('exit',failed);
    return {status:'starting'};
  });}
  // Remember an explicit start so a service restart brings the connection back.
  // Only providers that start without user interaction are restored; an
  // explicit stop, a provider change or a failed restore clears the intent.
  rememberStart(){const p=this.config().provider;this.store.setSetting('tunnelAutostart',AUTOSTART.has(p)?p:null);}
  forgetStart(){this.store.setSetting('tunnelAutostart',null);}
  async restore(){
    const wanted=this.store.setting('tunnelAutostart',null);
    if(!wanted||wanted!==this.config().provider||!AUTOSTART.has(wanted))return null;
    try{return await this.start();}catch{this.state={status:'restore_failed'};return null;}
  }
  async stop(){return this.operation(async()=>{
    await this.close();
    this.state={status:'stopped'};return this.state;
  });}
  async close(){
    const child=this.child;this.child=null;this.quickHost=this.ngrokHost=null;
    if(child){child.kill();if(child.exitCode===null&&child.signalCode===null)await Promise.race([new Promise(r=>child.once('exit',r)),new Promise(r=>{const timer=setTimeout(r,2000);timer.unref();})]);}
    if(this.ownedRoute){const route=this.ownedRoute,current=await this.ts(['serve','status','--json']);if(routeMatches(current,route))await this.ts([route.funnel?'funnel':'serve',`--https=${route.port}`,'off'],15000);this.ownedRoute=null;}
  }
}
