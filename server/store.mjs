import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';

export class Store {
  constructor(path) {
    this.db = new DatabaseSync(path,{timeout:5000});
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY,label TEXT NOT NULL,kind TEXT NOT NULL,device TEXT NOT NULL,connected INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS secrets(account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,key TEXT NOT NULL,value TEXT NOT NULL,PRIMARY KEY(account_id,key));
      CREATE TABLE IF NOT EXISTS chats(account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,id TEXT NOT NULL,name TEXT NOT NULL,kind TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(account_id,id));
      CREATE TABLE IF NOT EXISTS tokens(id TEXT PRIMARY KEY,name TEXT NOT NULL,hash TEXT NOT NULL UNIQUE,grants TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,last_used TEXT);
      CREATE TABLE IF NOT EXISTS audit(id TEXT PRIMARY KEY,at TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,account_id TEXT,chat_id TEXT,outcome TEXT NOT NULL,details TEXT);
      CREATE TABLE IF NOT EXISTS sends(actor TEXT NOT NULL,key TEXT NOT NULL,fingerprint TEXT NOT NULL,state TEXT NOT NULL,result TEXT,at TEXT NOT NULL,PRIMARY KEY(actor,key));
      CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS audit_at ON audit(at DESC);
      CREATE TABLE IF NOT EXISTS messages(seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL UNIQUE,account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,chat_id TEXT NOT NULL,message_id TEXT NOT NULL,cipher TEXT NOT NULL,at TEXT NOT NULL,UNIQUE(account_id,chat_id,message_id));
      CREATE INDEX IF NOT EXISTS messages_chat ON messages(account_id,chat_id,seq);
      CREATE VIRTUAL TABLE IF NOT EXISTS message_search USING fts5(terms,content='',contentless_delete=1,detail=none,tokenize='ascii');
      CREATE TRIGGER IF NOT EXISTS messages_search_delete AFTER DELETE ON messages BEGIN DELETE FROM message_search WHERE rowid=old.seq; END;`);
    if(!this.db.prepare('PRAGMA table_info(audit)').all().some(column=>column.name==='details'))this.db.exec('ALTER TABLE audit ADD COLUMN details TEXT');
    if(!this.db.prepare('PRAGMA table_info(messages)').all().some(column=>column.name==='message_time'))this.db.exec('ALTER TABLE messages ADD COLUMN message_time INTEGER');
    this.db.exec('CREATE INDEX IF NOT EXISTS messages_time ON messages(account_id,message_time,seq)');
    // A process crash after dispatch leaves an unknown outcome; never resend it automatically.
    this.db.prepare("UPDATE sends SET state='unknown' WHERE state='pending'").run();
  }
  accounts() { return this.db.prepare('SELECT * FROM accounts ORDER BY created_at').all(); }
  account(id) { return this.db.prepare('SELECT * FROM accounts WHERE id=?').get(id); }
  addAccount(label, kind, device) {
    const id = randomUUID();
    this.db.prepare('INSERT INTO accounts(id,label,kind,device,created_at) VALUES(?,?,?,?,?)').run(id,label,kind,device,new Date().toISOString());
    return this.account(id);
  }
  connect(id, value) { this.db.prepare('UPDATE accounts SET connected=? WHERE id=?').run(value ? 1 : 0,id); }
  removeAccount(id) { this.db.prepare('DELETE FROM accounts WHERE id=?').run(id); }
  secret(id,key) { return this.db.prepare('SELECT value FROM secrets WHERE account_id=? AND key=?').get(id,key)?.value; }
  secrets(id) { return this.db.prepare('SELECT key,value FROM secrets WHERE account_id=?').all(id); }
  putSecret(id,key,value) { this.db.prepare('INSERT INTO secrets VALUES(?,?,?) ON CONFLICT(account_id,key) DO UPDATE SET value=excluded.value').run(id,key,value); }
  deleteSecret(id,key) { this.db.prepare('DELETE FROM secrets WHERE account_id=? AND key=?').run(id,key); }
  deleteSecrets(id) { this.db.prepare('DELETE FROM secrets WHERE account_id=?').run(id); }
  chats(id) { return this.db.prepare('SELECT * FROM chats WHERE account_id=? ORDER BY name').all(id); }
  chat(account,id) { return this.db.prepare('SELECT * FROM chats WHERE account_id=? AND id=?').get(account,id); }
  putChat(account,chat) { this.db.prepare('INSERT INTO chats(account_id,id,name,kind) VALUES(?,?,?,?) ON CONFLICT(account_id,id) DO UPDATE SET name=excluded.name,kind=excluded.kind').run(account,chat.id,chat.name,chat.kind); }
  designate(account,id,enabled) { this.db.prepare('UPDATE chats SET enabled=? WHERE account_id=? AND id=?').run(enabled ? 1 : 0,account,id);this.setSetting(`chatScopeRevision:${account}`,this.setting(`chatScopeRevision:${account}`,0)+1); }
  addToken(name,hash,grants,days) {
    const id = randomUUID(), at = new Date();
    this.db.prepare('INSERT INTO tokens(id,name,hash,grants,created_at,expires_at) VALUES(?,?,?,?,?,?)').run(id,name,hash,JSON.stringify(grants),at.toISOString(),new Date(+at+days*86400000).toISOString());
    return this.token(id);
  }
  token(id) { const r = this.db.prepare('SELECT * FROM tokens WHERE id=?').get(id); return r && { ...r, grants: JSON.parse(r.grants) }; }
  setTokenGrants(id,grants) { this.db.prepare('UPDATE tokens SET grants=? WHERE id=?').run(JSON.stringify(grants),id);this.setSetting(`tokenGrantRevision:${id}`,this.setting(`tokenGrantRevision:${id}`,0)+1); }
  tokenByHash(hash) { const r = this.db.prepare('SELECT id FROM tokens WHERE hash=?').get(hash); return r && this.token(r.id); }
  tokens() { return this.db.prepare('SELECT id FROM tokens ORDER BY created_at DESC').all().map(r => this.token(r.id)); }
  revoke(id) { this.db.prepare('UPDATE tokens SET revoked=1 WHERE id=?').run(id);this.setSetting(`tokenRevocation:${id}`,this.setting(`tokenRevocation:${id}`,0)+1); }
  touchToken(id) { this.db.prepare('UPDATE tokens SET last_used=? WHERE id=?').run(new Date().toISOString(),id); }
  audit(actor,action,account,chat,outcome,details=null) {
    this.db.prepare('INSERT INTO audit(id,at,actor,action,account_id,chat_id,outcome,details) VALUES(?,?,?,?,?,?,?,?)').run(randomUUID(),new Date().toISOString(),actor,action,account ?? null,chat ?? null,outcome,details===null?null:JSON.stringify(details));
    // System debug records arrive every few seconds; cap them separately so they
    // never evict the security trail (logins, grants, setup changes, revocations).
    const debug=actor==='system'&&action.startsWith('debug.');
    this.db.exec(`DELETE FROM audit WHERE id IN (SELECT id FROM audit WHERE ${debug?'':'NOT '}(actor='system' AND action LIKE 'debug.%') ORDER BY at DESC,rowid DESC LIMIT -1 OFFSET 2000)`);
  }
  audits(limit=80) { return this.db.prepare('SELECT * FROM audit ORDER BY at DESC,rowid DESC LIMIT ?').all(limit).map(({details,...row})=>({...row,...(details?{details:JSON.parse(details)}:{})})); }
  send(actor,key) { return this.db.prepare('SELECT * FROM sends WHERE actor=? AND key=?').get(actor,key); }
  // A rejected send never reached recipients; the same key may try again.
  retryRejected(actor,key,fingerprint) { return this.db.prepare("UPDATE sends SET state='pending',result=NULL,at=? WHERE actor=? AND key=? AND fingerprint=? AND state='rejected'").run(new Date().toISOString(),actor,key,fingerprint).changes===1; }
  reserve(actor,key,fingerprint) { this.db.prepare("INSERT INTO sends VALUES(?,?,?,'pending',NULL,?)").run(actor,key,fingerprint,new Date().toISOString()); }
  finishSend(actor,key,state,result) { this.db.prepare('UPDATE sends SET state=?,result=? WHERE actor=? AND key=?').run(state,result ? JSON.stringify(result) : null,actor,key); }
  setting(key,defaultValue) { const r=this.db.prepare('SELECT value FROM settings WHERE key=?').get(key); return r ? JSON.parse(r.value) : defaultValue; }
  setSetting(key,value) { this.db.prepare('INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key,JSON.stringify(value));if(key.startsWith('localSetup:')){const revision=`localSetupRevision:${key.slice('localSetup:'.length)}`;this.setSetting(revision,this.setting(revision,0)+1);} }
  transaction(job){this.db.exec('BEGIN IMMEDIATE');try{const result=job();this.db.exec('COMMIT');return result;}catch(error){this.db.exec('ROLLBACK');throw error;}}
  close() { this.db.close(); }
}
