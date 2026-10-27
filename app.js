(function(){
const APP_VERSION='0.6.2.0';
const KEY='belegbox-v1';
let T0=sod(new Date());
function sod(d){const x=new Date(d);x.setHours(0,0,0,0);return x}
function iso(d){return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0')}
function parse(s){const p=String(s).split('-').map(Number);return new Date(p[0],p[1]-1,p[2])}
function addMonths(d,n){const x=new Date(d);const day=x.getDate();x.setDate(1);x.setMonth(x.getMonth()+n);
  const last=new Date(x.getFullYear(),x.getMonth()+1,0).getDate();x.setDate(Math.min(day,last));return x}
function addDays(d,n){const x=new Date(d);x.setDate(x.getDate()+n);return x}
function days(d){return Math.round((sod(d)-T0)/864e5)}
const fmtD=d=>d.toLocaleDateString('de-DE',{day:'2-digit',month:'2-digit',year:'numeric'});
const eur=n=>Number(n||0).toLocaleString('de-DE',{style:'currency',currency:'EUR'});
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const uid=()=>Math.random().toString(36).slice(2,10);
const inDays=n=>n===0?'heute':n===1?'morgen':n<0?'vor '+(-n)+' Tagen':'in '+n+' Tagen';

const NACHWEIS={beleg:'Kassenbon / Rechnung',konto:'Kontoauszug',mail:'Bestellmail',keiner:'Kein Nachweis'};
const INTERVALL={1:'monatlich',3:'vierteljährlich',12:'jährlich'};
const DEV_KAT=['Technik','Küche','Haushalt','Werkzeug','Möbel','Sonstiges'];
const CON_KAT=['Streaming','Handy & Internet','Versicherung','Energie','Fitness','Software','Sonstiges'];

function samples(){
  const m=(mo,d)=>iso(addDays(addMonths(T0,mo),d||0));
  return {
    devices:[
      {id:uid(),ex:1,name:'OLED-Fernseher 55"',kategorie:'Technik',hersteller:'LG',modell:'OLED55C3',sn:'307KRSL4X912',raum:'Wohnzimmer',kauf:m(-24,40),geschaetzt:false,preis:1299,haendler:'MediaMarkt',garantieMonate:0,nachweis:'beleg'},
      {id:uid(),ex:1,name:'Waschmaschine',kategorie:'Haushalt',hersteller:'Bosch',modell:'WGG14403',sn:'FD9812 004417',raum:'Bad',kauf:m(-38),geschaetzt:false,preis:649,haendler:'Otto',garantieMonate:60,nachweis:'konto'},
      {id:uid(),ex:1,name:'Kaffeevollautomat',kategorie:'Küche',hersteller:"De'Longhi",modell:'Magnifica Evo',sn:'2234A0091',raum:'Küche',kauf:m(-8),geschaetzt:false,preis:549,haendler:'Amazon',garantieMonate:0,nachweis:'mail'},
      {id:uid(),ex:1,name:'Laptop',kategorie:'Technik',hersteller:'Lenovo',modell:'ThinkPad E14',sn:'PF4XK29L',raum:'Arbeitszimmer',kauf:m(-23,12),geschaetzt:false,preis:1099,haendler:'Cyberport',garantieMonate:36,nachweis:'mail'},
      {id:uid(),ex:1,name:'Akku-Bohrschrauber',kategorie:'Werkzeug',hersteller:'Makita',modell:'DDF484',sn:'',raum:'Keller',kauf:m(-74),geschaetzt:true,preis:180,haendler:'',garantieMonate:0,nachweis:'keiner'},
      {id:uid(),ex:1,name:'Kühlschrank',kategorie:'Küche',hersteller:'Liebherr',modell:'CNd 5203',sn:'84.112.556.3',raum:'Küche',kauf:m(-62),geschaetzt:true,preis:799,haendler:'',garantieMonate:0,nachweis:'keiner'}
    ],
    contracts:[
      {id:uid(),ex:1,anbieter:'Fitnessstudio',kategorie:'Fitness',kosten:29.9,intervall:1,beginn:m(-12,100),laufzeit:12,verl:12,frist:90,kundennr:'M-20931',status:'aktiv'},
      {id:uid(),ex:1,anbieter:'Handyvertrag Vodafone',kategorie:'Handy & Internet',kosten:34.99,intervall:1,beginn:m(-24,45),laufzeit:24,verl:1,frist:30,kundennr:'118 442 907',status:'aktiv'},
      {id:uid(),ex:1,anbieter:'Netflix',kategorie:'Streaming',kosten:13.99,intervall:1,beginn:m(-20,-9),laufzeit:1,verl:1,frist:0,kundennr:'',status:'aktiv'},
      {id:uid(),ex:1,anbieter:'Stadtwerke Strom',kategorie:'Energie',kosten:78,intervall:1,beginn:m(-15),laufzeit:12,verl:1,frist:30,kundennr:'4410-2287',status:'aktiv'},
      {id:uid(),ex:1,anbieter:'Hausratversicherung',kategorie:'Versicherung',kosten:89.4,intervall:12,beginn:m(-34,20),laufzeit:12,verl:12,frist:90,kundennr:'HR-7781204',status:'aktiv'},
      {id:uid(),ex:1,anbieter:'Disney+',kategorie:'Streaming',kosten:9.99,intervall:1,beginn:m(-6,12),laufzeit:1,verl:1,frist:0,kundennr:'',status:'gekuendigt'}
    ]
  };
}

/* Verschlüsselter Tresor (Format 2)
   - Ein zufälliger Datenschlüssel (256 Bit) verschlüsselt alle Einträge mit AES-256-GCM.
   - Der Datenschlüssel liegt nur verpackt im Speicher: einmal mit dem Passwort (PBKDF2, SHA-256),
     optional zusätzlich mit dem Fingerabdruck (Passkey mit PRF-Erweiterung, HKDF).
   - Klartext und Schlüssel existieren nur im Arbeitsspeicher, solange die App entsperrt ist. */
const VKEY='belegbox-vault-v1', ITER=600000, IDLE_MS=5*60e3, BG_MS=60e3;
let db=null, key=null, dekRaw=null, vmeta=null, tab='home', filter='alle';
const te=new TextEncoder(), td=new TextDecoder();
const rnd=n=>crypto.getRandomValues(new Uint8Array(n));
function toB64(buf){const u=new Uint8Array(buf);let s='';for(let i=0;i<u.length;i+=0x8000)s+=String.fromCharCode.apply(null,u.subarray(i,i+0x8000));return btoa(s)}
function fromB64(s){const b=atob(s);const u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u}
async function deriveKey(pw,salt,iter){
  const base=await crypto.subtle.importKey('raw',te.encode(pw),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:iter,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function bioKek(prfOut,salt){
  const base=await crypto.subtle.importKey('raw',prfOut,'HKDF',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt,info:te.encode('belegbox-bio-v1')},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function seal(k,bytes){const iv=rnd(12);return {iv:toB64(iv),ct:toB64(await crypto.subtle.encrypt({name:'AES-GCM',iv},k,bytes))}}
async function open_(k,box){return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:fromB64(box.iv)},k,fromB64(box.ct)))}
const importDek=raw=>crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']);
function readVault(){try{const r=localStorage.getItem(VKEY);return r?JSON.parse(r):null}catch(e){return null}}
async function persist(){
  if(!key||!db||!vmeta)return;
  const box=await seal(key,te.encode(JSON.stringify(db)));
  const json=JSON.stringify(Object.assign({},vmeta,{v:2,iv:box.iv,ct:box.ct,saved:Date.now()}));
  // Zweitkopie zuerst (IndexedDB), dann Hauptspeicher – fällt einer weg, stellt boot() aus dem anderen wieder her
  try{await filePut(MIRROR,json)}catch(e){}
  localStorage.setItem(VKEY,json);
}
/* ---------- Automatische Sicherung in ein privates GitHub-Repo ----------
   Hochgeladen wird nur bereits Verschlüsseltes: vault.json (= Tresor wie im Browser) und files/<id>.bin (IV + Chiffretext).
   Zugangsdaten liegen verschlüsselt im Tresor (db.meta.gh). Im Repo wird nie automatisch etwas gelöscht. */
const GH_API='https://api.github.com',GH_LS='belegbox-gh-status';
let ghTimer=0,ghBusy=false,ghAgain=null,ghPending=null;
let ghStat=(()=>{try{return JSON.parse(localStorage.getItem(GH_LS))||{}}catch(e){return {}}})();
function setGhStat(o){const prev=ghStat.err||'';ghStat=Object.assign({},ghStat,o);try{localStorage.setItem(GH_LS,JSON.stringify(ghStat))}catch(e){}
  const el=document.getElementById('ghStatus');if(el)el.innerHTML=ghStatusText();if(db&&!root.firstElementChild&&o.err!==undefined&&(o.err||'')!==prev)render()}
function ghCfg(){const g=db&&db.meta&&db.meta.gh;return g&&g.token&&g.owner&&g.repo?Object.assign({},g):null}
async function ghFetch(g,method,path,body,raw){
  const r=await fetch(`${GH_API}/repos/${encodeURIComponent(g.owner)}/${encodeURIComponent(g.repo)}${path}`,{method,cache:'no-store',
    headers:Object.assign({Authorization:'Bearer '+g.token,Accept:raw?'application/vnd.github.raw+json':'application/vnd.github+json'},body?{'Content-Type':'application/json'}:{}),
    body:body?JSON.stringify(body):undefined});
  if(r.status===404&&method==='GET')return null;
  if(!r.ok){const e=new Error('GitHub '+r.status);e.status=r.status;throw e}
  return raw?r.arrayBuffer():r.status===204?null:r.json();
}
const ghErrText=e=>e&&e.conflict?'Im Repo liegt ein anderer Tresor. Öffne „Daten“, um zu entscheiden.'
  :e&&e.status===401?'Der GitHub-Zugangsschlüssel ist ungültig oder abgelaufen.'
  :e&&(e.status===403||e.status===404)?'Kein Zugriff auf das Repo. Prüfe Name und Rechte des Schlüssels (Contents: Read and write).'
  :e&&e.status===422?'GitHub hat die Datei abgelehnt (zu groß?).'
  :'Keine Verbindung zu GitHub. Es wird später erneut versucht.';
function ghStatusText(){
  if(ghBusy)return '<span class="spin"></span> Wird gesichert …';
  if(ghStat.err)return `<span style="color:var(--crit)">${esc(ghStat.err)}</span>`;
  if(ghStat.at){const m=Math.round((Date.now()-ghStat.at)/60000);return `Zuletzt gesichert ${m<1?'gerade eben':m<60?'vor '+m+' Min.':m<1440?'vor '+Math.round(m/60)+' Std.':'am '+fmtD(new Date(ghStat.at))}.`}
  return 'Noch nicht gesichert.';
}
async function ghRemoteVault(g){
  const cur=await ghFetch(g,'GET','/contents/vault.json');if(!cur)return {cur:null,json:null};
  let json=null;
  try{json=cur.content&&cur.encoding==='base64'?td.decode(fromB64(cur.content.replace(/\s/g,''))):td.decode(new Uint8Array(await ghFetch(g,'GET','/contents/vault.json',null,true)))}catch(e){}
  return {cur,json};
}
function ghQueue(delay){const g=ghCfg();if(!g)return;ghPending=g;clearTimeout(ghTimer);ghTimer=setTimeout(()=>ghSync(),delay==null?4000:delay)}
async function ghSync(force){
  const g=ghPending||ghCfg();if(!g)return;
  if(ghBusy){ghAgain={force};return}
  ghBusy=true;clearTimeout(ghTimer);ghPending=null;setGhStat({});
  try{
    let local=null;try{local=localStorage.getItem(VKEY)}catch(e){}
    if(!local||!vaultOk(local))throw new Error('local');
    const lv=JSON.parse(local);
    // 1) Belege/Dokumente, die im Repo noch fehlen (Dateien ändern sich nie, daher reicht der Name)
    const ids=allDocIds();
    if(ids.length){
      const list=await ghFetch(g,'GET','/contents/files');const have=new Set((list||[]).map(x=>String(x.name).replace(/\.bin$/,'')));
      for(const id of ids){if(have.has(id))continue;const f=await fileGet(id).catch(()=>null);if(!f)continue;
        const u=new Uint8Array(12+f.ct.byteLength);u.set(new Uint8Array(f.iv),0);u.set(new Uint8Array(f.ct),12);
        await ghFetch(g,'PUT',`/contents/files/${id}.bin`,{message:'Belegbox: Dokument',content:toB64(u)})}
    }
    // 2) Tresor – aber nie einen fremden Tresor überschreiben
    for(let attempt=0;attempt<2;attempt++){
      const {cur,json}=await ghRemoteVault(g);
      if(json===local)break;
      if(cur&&!force){let rv=null;try{rv=JSON.parse(json)}catch(e){}
        if(!rv||(rv.vid!==lv.vid)){const e=new Error('conflict');e.conflict=true;throw e}}
      try{await ghFetch(g,'PUT','/contents/vault.json',{message:'Belegbox-Sicherung '+new Date().toLocaleString('de-DE'),content:toB64(te.encode(local)),sha:cur?cur.sha:undefined});break}
      catch(e){if(e.status!==409||attempt)throw e}
    }
    setGhStat({at:Date.now(),err:'',conflict:false});
  }catch(e){
    if(e.message==='local'){ghBusy=false;return}
    setGhStat({err:ghErrText(e),conflict:!!e.conflict});
    if(!e.conflict&&!(e.status>=400&&e.status<500))setTimeout(()=>ghQueue(0),5*60e3); // Netzwerkfehler: später nochmal
  }finally{
    ghBusy=false;const el=document.getElementById('ghStatus');if(el)el.innerHTML=ghStatusText();
    if(ghAgain){const a=ghAgain;ghAgain=null;ghSync(a.force)}
  }
}
// Beim Wegwechseln aus der App ausstehende Sicherung sofort starten
document.addEventListener('visibilitychange',()=>{if(document.hidden&&ghTimer&&ghPending)ghSync()});
/* Wiederherstellen aus GitHub (ohne entsperrten Tresor) */
async function ghRestore(g,onStep){
  const {json}=await ghRemoteVault(g);if(!json||!vaultOk(json))throw new Error('Im Repo wurde keine Belegbox-Sicherung gefunden.');
  const files={},list=await ghFetch(g,'GET','/contents/files')||[];let n=0;
  for(const it of list){if(!/\.bin$/.test(it.name))continue;onStep&&onStep(++n,list.length);
    const b=new Uint8Array(await ghFetch(g,'GET','/contents/files/'+encodeURIComponent(it.name),null,true));
    files[it.name.replace(/\.bin$/,'')]={iv:toB64(b.slice(0,12)),ct:toB64(b.slice(12))}}
  return {vault:JSON.parse(json),files};
}

/* Zweitkopie des verschlüsselten Tresors + Start-Prüfung */
const MIRROR='__vault__';
let bootInfo={orphans:0,broken:false};
const vaultOk=j=>{try{const v=JSON.parse(j);return !!(v&&typeof v.salt==='string'&&typeof v.ct==='string')}catch(e){return false}};
const vaultTime=j=>{try{return Number(JSON.parse(j).saved)||0}catch(e){return 0}};
async function boot(){
  try{
    let raw=null;try{raw=localStorage.getItem(VKEY)}catch(e){}
    const m=await fileGet(MIRROR).catch(()=>null);
    const ok=!!raw&&vaultOk(raw),mOk=typeof m==='string'&&vaultOk(m);
    if(mOk&&(!ok||vaultTime(m)>vaultTime(raw))){
      if(raw&&!ok){try{localStorage.setItem(VKEY+'-defekt-'+Date.now(),raw)}catch(e){}}
      localStorage.setItem(VKEY,m);
      if(!ok)setTimeout(()=>toast('Der Tresor fehlte im Hauptspeicher und wurde aus der Zweitkopie wiederhergestellt.'),800);
    }else if(ok&&m!==raw){filePut(MIRROR,raw).catch(()=>{})}
    if(!ok&&!mOk){bootInfo.broken=!!raw;
      bootInfo.orphans=(await fileKeys().catch(()=>[])).filter(k=>!String(k).startsWith('__')).length}
  }catch(e){}
  showLock();
}
let saving=Promise.resolve();
function save(){saving=saving.then(persist).then(()=>ghQueue()).catch(()=>toast('Speichern fehlgeschlagen. Der Speicher ist vermutlich voll: Entferne ein paar Fotos.'));return saving}
async function openWithDek(raw,v){
  const k=await importDek(raw);
  const pt=await open_(k,v);
  db=JSON.parse(td.decode(pt));key=k;dekRaw=raw;
  vmeta={iter:v.iter,salt:v.salt,wrapPw:v.wrapPw,bio:v.bio||null,vid:v.vid||toB64(rnd(12))};
}
async function unlock(pw){
  const v=readVault();const salt=fromB64(v.salt);
  const kek=await deriveKey(pw,salt,v.iter||ITER);
  if(v.v===2){await openWithDek(await open_(kek,v.wrapPw),v);return} // wirft bei falschem Passwort
  // Format 1 (bis 0.2.0.2): direkt mit dem Passwortschlüssel verschlüsselt → auf Format 2 umstellen
  const pt=await open_(kek,v);db=JSON.parse(td.decode(pt));
  dekRaw=rnd(32);key=await importDek(dekRaw);
  vmeta={iter:v.iter||ITER,salt:v.salt,wrapPw:await seal(kek,dekRaw),bio:null,vid:toB64(rnd(12))};
  await save();
}
async function createVault(pw,withEx){
  const salt=rnd(16);const kek=await deriveKey(pw,salt,ITER);
  dekRaw=rnd(32);key=await importDek(dekRaw);
  vmeta={iter:ITER,salt:toB64(salt),wrapPw:await seal(kek,dekRaw),bio:null,vid:toB64(rnd(12))};
  let old=null;try{old=JSON.parse(localStorage.getItem(KEY))}catch(e){}
  db=old&&Array.isArray(old.devices)?old:withEx?samples():{devices:[],contracts:[]};
  await persist();
  try{localStorage.removeItem(KEY)}catch(e){} // alte unverschlüsselte Daten entfernen
}
async function changePassword(oldPw,newPw){
  const old=await deriveKey(oldPw,fromB64(vmeta.salt),vmeta.iter||ITER);
  await open_(old,vmeta.wrapPw); // prüft das alte Passwort
  const salt=rnd(16);const kek=await deriveKey(newPw,salt,ITER);
  vmeta=Object.assign({},vmeta,{iter:ITER,salt:toB64(salt),wrapPw:await seal(kek,dekRaw)});
  await save();
}
function lock(anim){saving.then(()=>{key=null;db=null;if(dekRaw)dekRaw.fill(0);dekRaw=null;vmeta=null;closeViewer();closeSheet(false);setFan(false);main.innerHTML='';shown={};showLock(anim===true)})}

/* Fingerabdruck / Gesichtserkennung über einen Passkey mit PRF-Erweiterung */
const bioPossible=()=>!!(window.PublicKeyCredential&&navigator.credentials&&window.isSecureContext);
async function prfFrom(cred){const r=cred.getClientExtensionResults&&cred.getClientExtensionResults();
  return r&&r.prf&&r.prf.results&&r.prf.results.first?new Uint8Array(r.prf.results.first):null}
async function bioGet(credId,prfSalt){
  const cred=await navigator.credentials.get({publicKey:{challenge:rnd(32),rpId:location.hostname,timeout:60000,userVerification:'required',
    allowCredentials:[{type:'public-key',id:credId}],extensions:{prf:{eval:{first:prfSalt}}}}});
  return prfFrom(cred);
}
async function enableBio(){
  if(!bioPossible())throw new Error('Dieser Browser unterstützt kein Entsperren per Fingerabdruck.');
  const prfSalt=rnd(32);
  const cred=await navigator.credentials.create({publicKey:{
    rp:{name:'Belegbox',id:location.hostname},user:{id:rnd(16),name:'Belegbox',displayName:'Belegbox'},challenge:rnd(32),
    pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],timeout:60000,attestation:'none',
    authenticatorSelection:{authenticatorAttachment:'platform',residentKey:'preferred',userVerification:'required'},
    extensions:{prf:{eval:{first:prfSalt}}}}});
  const ext=cred.getClientExtensionResults?cred.getClientExtensionResults():{};
  const NOPRF='Dein Passwortmanager unterstützt das Entsperren per Fingerabdruck nicht (häufig bei Samsung Pass). Stell als Passkey-Anbieter den Google Passwortmanager ein und versuch es erneut. Den eben angelegten Passkey „Belegbox“ kannst du löschen.';
  if(ext.prf&&ext.prf.enabled===false)throw new Error(NOPRF);
  const credId=new Uint8Array(cred.rawId);
  let out=await prfFrom(cred);
  if(!out){ // manche Anbieter melden die Unterstützung erst beim ersten Entsperren
    try{out=await bioGet(credId,prfSalt)}catch(x){if(x&&x.name==='NotAllowedError')throw x}
  }
  if(!out)throw new Error(NOPRF);
  const hk=rnd(16);
  vmeta=Object.assign({},vmeta,{bio:{credId:toB64(credId),prfSalt:toB64(prfSalt),hkdfSalt:toB64(hk),box:await seal(await bioKek(out,hk),dekRaw)}});
  out.fill(0);await save();
}
function disableBio(){vmeta=Object.assign({},vmeta,{bio:null});return save()}
async function unlockBio(){
  const v=readVault();const b=v.bio;
  const out=await bioGet(fromB64(b.credId),fromB64(b.prfSalt));
  if(!out)throw new Error('nocred');
  const raw=await open_(await bioKek(out,fromB64(b.hkdfSalt)),b.box);out.fill(0);
  await openWithDek(raw,v);
}

/* Bankdaten gar nicht erst speichern */
function looksBanky(s){const x=String(s||'').replace(/[\s-]/g,'').toUpperCase();
  if(/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(x))return true;
  if(/^[3-6]\d{14,15}$/.test(x)){let sum=0,alt=false;for(let i=x.length-1;i>=0;i--){let n=+x[i];if(alt){n*=2;if(n>9)n-=9}sum+=n;alt=!alt}return sum%10===0}
  return false}
/* Freitext (Notizen): IBANs (mit Prüfsumme) und Kartennummern (mit Luhn) auch mitten im Text erkennen */
function ibanOk(x){x=x.replace(/\s/g,'').toUpperCase();if(!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(x))return false;
  const r=(x.slice(4)+x.slice(0,4)).replace(/[A-Z]/g,c=>String(c.charCodeAt(0)-55));let m=0;for(const ch of r)m=(m*10+ +ch)%97;return m===1}
function textBanky(t){t=String(t||'');
  for(const m of t.match(/[A-Za-z]{2}\d{2}(?:[ ]?[A-Za-z0-9]){11,30}/g)||[])if(ibanOk(m))return true;
  for(const m of t.match(/(?:\d[ -]?){15,16}/g)||[])if(looksBanky(m))return true;
  return false}
const maskVal=s=>{s=String(s||'');return s.length<=4?s:'•••• '+s.slice(-4)};

function toast(msg){const r=document.getElementById('toastRoot');clearTimeout(toast.t);clearTimeout(toast.t2);
  r.innerHTML=`<div class="toast" role="status">${esc(msg)}</div>`;
  toast.t=setTimeout(()=>{const t=r.firstElementChild;if(!t)return;if(!motion()){r.innerHTML='';return}
    t.classList.add('out');toast.t2=setTimeout(()=>{if(t.isConnected)t.remove()},220)},4000)}

/* Bewegung, Vibration, kleine Effekte */
const RM=window.matchMedia?matchMedia('(prefers-reduced-motion: reduce)'):{matches:false};
const motion=()=>!RM.matches&&!!Element.prototype.animate;
const buzz=p=>{try{if(navigator.vibrate&&!document.hidden)navigator.vibrate(p)}catch(e){}};
const clamp=(v,a,b)=>Math.max(a,Math.min(b,v));
function celebrate(text){buzz([12,50,24]);
  if(!motion()){if(text)toast(text);return}
  const cols=['var(--accent)','var(--ok)','var(--gold)','var(--warn)'];
  const el=document.createElement('div');el.className='yay';el.setAttribute('aria-hidden','true');
  el.innerHTML=`<div class="card"><svg viewBox="0 0 52 52"><circle class="yc" cx="26" cy="26" r="23"/><path class="yk" d="M15 27l7 7 15-16"/></svg>${
    Array.from({length:10},(_,i)=>`<i style="--a:${i*36}deg;--c:${cols[i%4]}"></i>`).join('')}${text?`<b>${esc(text)}</b>`:''}</div>`;
  document.body.appendChild(el);setTimeout(()=>el.remove(),1600);
}
/* Zahlen hochzählen lassen */
let shown={};
function countUps(fromZero){
  main.querySelectorAll('[data-count]').forEach(el=>{
    const k=el.dataset.count,to=Number(el.dataset.v)||0,f=el.dataset.f==='eur'?eur:(n=>String(Math.round(n)));
    const from=fromZero?0:(k in shown?shown[k]:to);shown[k]=to;
    if(!motion()||from===to){el.textContent=f(to);return}
    const t0=performance.now(),D=fromZero?900:650;el.textContent=f(from);
    const step=now=>{if(!el.isConnected)return;const p=Math.min(1,(now-t0)/D),e=1-Math.pow(1-p,3);
      el.textContent=f(p<1?from+(to-from)*e:to);if(p<1)requestAnimationFrame(step)};
    requestAnimationFrame(step)})
}

const FINGER='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6.5 8.5a6 6 0 0 1 11 3.3c0 1.6-.1 3.2-.4 4.7"/><path d="M4 12.5c0-1 .1-2 .4-2.9"/><path d="M9 21c.8-2.2 1-4.6 1-7a2 2 0 0 1 4 0c0 1 0 2-.1 3"/><path d="M12.5 21.5c.4-.9.7-1.8.9-2.8"/><path d="M6.6 19.4c.7-1.7 1-3.5 1-5.4a4.4 4.4 0 0 1 .7-2.4"/><path d="M16.5 20c.2-.6.3-1.3.4-1.9"/></svg>';
const VAULT='<div class="vault" aria-hidden="true"><div class="door"><svg viewBox="0 0 56 56"><circle class="face" cx="28" cy="28" r="27"/>'
  +[0,1,2,3,4,5,6,7].map(i=>{const a=i*Math.PI/4;return '<circle class="bolt" cx="'+(28+22*Math.cos(a)).toFixed(2)+'" cy="'+(28+22*Math.sin(a)).toFixed(2)+'" r="1.8"/>'}).join('')
  +'<g class="wheel"><circle cx="28" cy="28" r="5.5"/><path d="M28 14v28M15.88 21l24.24 14M15.88 35l24.24-14"/>'
  +[[28,14],[40.12,21],[40.12,35],[28,42],[15.88,35],[15.88,21]].map(p=>'<circle class="knob" cx="'+p[0]+'" cy="'+p[1]+'" r="2.3"/>').join('')
  +'</g></svg></div></div>';
const SHIELD='<svg viewBox="0 0 24 24" fill="none" stroke="var(--accent-ink)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>';
let lockTok=0;
function showLock(closing){
  const tok=++lockTok;
  document.body.classList.add('locked');
  const L=document.getElementById('lock');L.classList.remove('leaving');L.getAnimations&&L.getAnimations().forEach(a=>a.cancel());
  const vault=readVault();const setup=!vault;
  const bio=!setup&&vault.bio&&bioPossible();
  L.innerHTML=`<div class="lock"><form class="lockcard" id="lf" novalidate>
    ${VAULT}
    ${setup?`<h2>Tresor einrichten</h2>
      <p>Alle Einträge und Fotos werden mit deinem Passwort verschlüsselt, bevor sie gespeichert werden. Ohne Passwort sind sie nicht lesbar.</p>
      <label class="field"><span>Passwort (mind. 10 Zeichen)</span><input id="lp1" type="password" autocomplete="new-password" minlength="10"></label>
      <label class="field"><span>Passwort wiederholen</span><input id="lp2" type="password" autocomplete="new-password"></label>
      <label class="check"><input id="lex" type="checkbox" checked> Mit Beispieleinträgen starten</label>
      ${bootInfo.broken?`<div class="note" style="background:var(--crit-soft)"><b>Achtung:</b> Auf diesem Gerät liegt ein Tresor, der sich nicht lesen lässt. Speichere ihn zuerst, bevor du neu anfängst.
        <button type="button" class="linkbtn" id="lraw" style="display:block;color:var(--crit)">Beschädigten Tresor als Datei speichern</button></div>`:''}
      ${bootInfo.orphans?`<div class="note" style="background:var(--crit-soft)"><b>Achtung:</b> Auf diesem Gerät liegen noch ${bootInfo.orphans>1?bootInfo.orphans+' verschlüsselte Dokumente':'ein verschlüsseltes Dokument'}, aber kein Tresor. Hast du eine Sicherung, stell sie unten wieder her, statt neu anzufangen.</div>`:''}
      ${bootInfo.broken||bootInfo.orphans?'<label class="check"><input id="lnew" type="checkbox"> Ich möchte trotzdem einen neuen, leeren Tresor anlegen</label>':''}
      <div class="note">Es gibt keine Wiederherstellung. Wer das Passwort vergisst, verliert die Daten. Notier es dir an einem sicheren Ort, z. B. im Passwortmanager.</div>`
    :`<h2>Belegbox ist gesperrt</h2><p>${bio?'Entsperre mit deinem Fingerabdruck oder deinem Passwort.':'Gib dein Passwort ein, um deine Daten zu entschlüsseln.'}</p>
      ${bio?`<button type="button" class="btn primary bio" id="lbio">${FINGER}Mit Fingerabdruck entsperren</button><div class="or"><span>oder mit Passwort</span></div>`:''}
      <label class="field"><span>Passwort</span><input id="lp1" type="password" autocomplete="current-password"></label>`}
    <p class="hint" id="lerr" style="color:var(--crit)" hidden></p>
    <button type="submit" class="btn${bio?'':' primary'}" id="lgo">${setup?'Tresor anlegen':'Entsperren'}</button>
    ${setup?`<label class="linkbtn" style="cursor:pointer">Neues Handy? Sicherung wiederherstellen<input id="lrestore" type="file" accept=".belegbox,application/json" hidden></label>
      <button type="button" class="linkbtn" id="lghOpen">Aus GitHub wiederherstellen</button>
      <div class="ghbox" id="lgh" hidden>
        <div class="label">Wiederherstellen aus GitHub</div>
        <div class="grid2"><label class="field"><span>Konto / Organisation</span><input id="lgo_o" value="jazm-belegbox" autocomplete="off" autocapitalize="off"></label>
          <label class="field"><span>Repo</span><input id="lgo_r" value="belegbox-daten" autocomplete="off" autocapitalize="off"></label></div>
        <label class="field"><span>Zugangsschlüssel (github_pat_…)</span><input id="lgo_t" type="password" autocomplete="off"></label>
        <p class="hint" id="lgo_msg" hidden></p>
        <button type="button" class="btn primary" id="lgo_go">Sicherung von GitHub laden</button></div>`
      :'<button type="button" class="linkbtn" id="lreset">Passwort vergessen? Tresor zurücksetzen</button>'}
    <p class="hint" style="text-align:center">Version ${APP_VERSION}</p>
  </form></div>`;
  const f=L.querySelector('#lf'),err=L.querySelector('#lerr'),go=L.querySelector('#lgo'),V=L.querySelector('.vault');
  // Beim Sperren schließt sich die Tresortür
  if(closing&&motion()){V.classList.add('open','instant');void V.offsetWidth;V.classList.remove('instant');void V.offsetWidth;
    requestAnimationFrame(()=>V.classList.remove('open'));L.animate([{opacity:0},{opacity:1}],{duration:220,easing:'ease-out'})}
  const shake=()=>{buzz([30,50,30]);if(!motion())return;
    [V,...L.querySelectorAll('.field')].forEach(el=>{el.classList.remove('no');void el.offsetWidth;el.classList.add('no')});
    setTimeout(()=>L.querySelectorAll('.no').forEach(el=>el.classList.remove('no')),450)};
  const fail=m=>{V.classList.remove('busy');err.textContent=m;err.hidden=false;go.disabled=false;go.textContent=setup?'Tresor anlegen':'Entsperren';shake()};
  f.addEventListener('submit',async e=>{e.preventDefault();err.hidden=true;
    const p1=L.querySelector('#lp1').value;
    if(!window.crypto||!crypto.subtle)return fail('Dieser Browser unterstützt keine Verschlüsselung. Öffne die Seite in einem aktuellen Browser.');
    if(setup){const p2=L.querySelector('#lp2').value,ln=L.querySelector('#lnew');
      if(ln&&!ln.checked)return fail('Bitte zuerst eine Sicherung wiederherstellen – oder bestätigen, dass du neu anfangen möchtest.');
      if(p1.length<10)return fail('Das Passwort braucht mindestens 10 Zeichen.');
      if(p1!==p2)return fail('Die beiden Passwörter stimmen nicht überein.');}
    go.disabled=true;go.textContent=setup?'Wird verschlüsselt …':'Wird entschlüsselt …';V.classList.add('busy');
    try{ setup?await createVault(p1,L.querySelector('#lex').checked):await unlock(p1) }
    catch(x){return fail(setup?'Der Tresor konnte nicht angelegt werden. Prüfe, ob der Browser Speicher erlaubt.':'Das Passwort ist falsch.')}
    opened();
  });
  // Entsperrt: Rad dreht, Tür schwingt auf, App kommt dahinter hervor
  function opened(){
    V.classList.remove('busy');
    document.body.classList.remove('locked');lastAct=Date.now();tab='home';filter='alle';shown={};askPersist();buzz([10,40,18]);setTimeout(cleanFiles,5000);setTimeout(()=>ghQueue(0),3000);
    if(!motion()){L.innerHTML='';render('rise');return}
    L.classList.add('leaving');V.classList.add('open');
    setTimeout(()=>{if(tok!==lockTok||!db)return;
      render('rise');
      document.querySelector('.app').animate([{opacity:0,transform:'scale(.96)'},{opacity:1,transform:'none'}],{duration:460,easing:'cubic-bezier(.2,.85,.25,1)'});
      const a=L.animate([{opacity:1,transform:'none'},{opacity:0,transform:'scale(1.06)'}],{duration:340,easing:'ease-in',fill:'forwards'});
      a.onfinish=()=>{if(tok===lockTok){L.innerHTML='';L.classList.remove('leaving')}a.cancel()};
    },640);
  }
  const lb=L.querySelector('#lbio');
  if(lb)lb.onclick=async()=>{err.hidden=true;lb.disabled=true;
    try{await unlockBio();opened()}
    catch(x){lb.disabled=false;
      if(x&&x.name==='NotAllowedError'){err.textContent='Abgebrochen. Tippe erneut oder nutze dein Passwort.'}
      else{err.textContent='Entsperren per Fingerabdruck hat nicht geklappt. Bitte nutze dein Passwort.';shake()}
      err.hidden=false}};
  const lr=L.querySelector('#lraw');if(lr)lr.onclick=()=>{let r='';try{r=localStorage.getItem(VKEY)||''}catch(e){}deliverFile('belegbox-tresor-beschaedigt.txt',r,'text/plain')};
  const gho=L.querySelector('#lghOpen');
  if(gho){gho.onclick=()=>{const b=L.querySelector('#lgh');b.hidden=!b.hidden;if(!b.hidden)L.querySelector('#lgo_t').focus()};
    L.querySelector('#lgo_go').onclick=async()=>{const m=L.querySelector('#lgo_msg'),bt=L.querySelector('#lgo_go');
      const g={owner:L.querySelector('#lgo_o').value.trim(),repo:L.querySelector('#lgo_r').value.trim(),token:L.querySelector('#lgo_t').value.trim()};
      if(!g.owner||!g.repo||!g.token){m.textContent='Bitte alle drei Felder ausfüllen.';m.style.color='var(--crit)';m.hidden=false;return}
      bt.disabled=true;m.style.color='';m.hidden=false;m.textContent='Lade Tresor …';V.classList.add('busy');
      try{const o=await ghRestore(g,(i,n)=>{m.textContent=`Lade Dokumente … ${i} von ${n}`});V.classList.remove('busy');await restoreVault(o)}
      catch(x){V.classList.remove('busy');bt.disabled=false;m.style.color='var(--crit)';m.textContent=x&&x.status?ghErrText(x):(x&&x.message||'Das hat nicht geklappt.');shake()}}}
  const rf=L.querySelector('#lrestore');
  if(rf)rf.addEventListener('change',async()=>{const file=rf.files[0];if(!file)return;
    try{restoreVault(await readBackupFile(file))}catch(x){fail(x.message)}});
  const rs=L.querySelector('#lreset');
  if(rs){let armed=false;rs.onclick=()=>{if(!armed){armed=true;buzz(10);rs.classList.add('sure');rs.textContent='Wirklich alles löschen? Nochmal tippen';return}
    try{localStorage.removeItem(VKEY)}catch(e){}fileClear().catch(()=>{});showLock()}}
  if(!bio){const first=L.querySelector('input');if(first)first.focus({preventScroll:true})}
}

/* Dateien weitergeben: Teilen-Menü (z. B. Google Drive), sonst normaler Download */
async function deliverFile(name,text,type){
  const file=new File([text],name,{type});
  if(navigator.canShare&&navigator.canShare({files:[file]})){
    try{await navigator.share({files:[file],title:name});return true}
    catch(e){if(e&&e.name==='AbortError')return false}
  }
  const a=document.createElement('a');a.href=URL.createObjectURL(file);a.download=name;
  document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove()},1500);return true;
}

/* ---------- Belege & Dokumente (PDF/Bild) ----------
   Große Dateien liegen nicht im kleinen Tresor-Speicher, sondern einzeln in IndexedDB –
   jede mit demselben Datenschlüssel AES-256-GCM-verschlüsselt (ID als Zusatzdaten gebunden).
   Im Tresor stehen nur Name, Größe und ein kleines Vorschaubild. */
const IDB_NAME='belegbox-files',STORE='files';
let idbP=null;
function idb(){return idbP||(idbP=new Promise((res,rej)=>{const r=indexedDB.open(IDB_NAME,1);
  r.onupgradeneeded=()=>r.result.createObjectStore(STORE);r.onsuccess=()=>res(r.result);r.onerror=()=>{idbP=null;rej(r.error)}}))}
async function idbDo(mode,fn){const d=await idb();return new Promise((res,rej)=>{const tx=d.transaction(STORE,mode);const r=fn(tx.objectStore(STORE));
  tx.oncomplete=()=>res(r&&r.result);tx.onerror=()=>rej(tx.error);tx.onabort=()=>rej(tx.error)})}
const fileGet=id=>idbDo('readonly',st=>st.get(id)),filePut=(id,v)=>idbDo('readwrite',st=>st.put(v,id)),
  fileDel=id=>idbDo('readwrite',st=>st.delete(id)),fileClear=()=>idbDo('readwrite',st=>st.clear()),fileKeys=()=>idbDo('readonly',st=>st.getAllKeys());
async function sealFile(id,buf){const iv=rnd(12);return {iv,ct:await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:te.encode(id)},key,buf)}}
async function openDoc(id){const r=await fileGet(id);if(!r)throw new Error('missing');
  return crypto.subtle.decrypt({name:'AES-GCM',iv:r.iv,additionalData:te.encode(id)},key,r.ct)}
const allDocIds=()=>db?[...db.devices,...db.contracts].flatMap(x=>(x.docs||[]).map(d=>d.id)):[];
async function cleanFiles(){if(!db)return;try{const keep=new Set(allDocIds());for(const k of await fileKeys())if(!String(k).startsWith('__')&&!keep.has(k))await fileDel(k)}catch(e){}}
const fmtSize=n=>n>=1e6?(n/1e6).toLocaleString('de-DE',{maximumFractionDigits:1})+' MB':Math.max(1,Math.round(n/1e3))+' KB';

/* PDF-Anzeige mit pdf.js (liegt im Repo unter vendor/, wird erst bei Bedarf geladen) */
let pdfjsP=null;
function pdfjs(){return pdfjsP||(pdfjsP=import('./vendor/pdfjs/pdf.min.mjs').then(m=>{m.GlobalWorkerOptions.workerSrc='vendor/pdfjs/pdf.worker.min.mjs';return m}).catch(e=>{pdfjsP=null;throw e}))}
async function pdfOpen(buf){const lib=await pdfjs();return lib.getDocument({data:new Uint8Array(buf.slice(0)),isEvalSupported:false,disableAutoFetch:true,disableStream:true,enableXfa:false}).promise}
const pdfClose=doc=>{try{if(doc.loadingTask)doc.loadingTask.destroy();else if(doc.destroy)doc.destroy()}catch(e){}};
async function pdfThumb(buf){const doc=await pdfOpen(buf);
  try{const p=await doc.getPage(1),v1=p.getViewport({scale:1}),vp=p.getViewport({scale:240/v1.width});
    const cv=document.createElement('canvas');cv.width=Math.ceil(vp.width);cv.height=Math.ceil(vp.height);
    const c=cv.getContext('2d');c.fillStyle='#fff';c.fillRect(0,0,cv.width,cv.height);
    await p.render({canvas:cv,viewport:vp}).promise;return {thumb:cv.toDataURL('image/jpeg',.7),pages:doc.numPages}}
  finally{pdfClose(doc)}}
function loadImg(f){return new Promise((res,rej)=>{const u=URL.createObjectURL(f),im=new Image();
  im.onload=()=>{URL.revokeObjectURL(u);res(im)};im.onerror=e=>{URL.revokeObjectURL(u);rej(e)};im.src=u})}
async function prepImage(f){const im=await loadImg(f);
  const draw=max=>{const k=Math.min(1,max/Math.max(im.naturalWidth,im.naturalHeight));const cv=document.createElement('canvas');
    cv.width=Math.max(1,Math.round(im.naturalWidth*k));cv.height=Math.max(1,Math.round(im.naturalHeight*k));
    const c=cv.getContext('2d');c.fillStyle='#fff';c.fillRect(0,0,cv.width,cv.height);c.drawImage(im,0,0,cv.width,cv.height);return cv};
  const blob=await new Promise((r,j)=>draw(2200).toBlob(b=>b?r(b):j(new Error('blob')),'image/jpeg',.85));
  return {blob,thumb:draw(240).toDataURL('image/jpeg',.7)}}
async function prepDoc(f,isPdf){const id='f'+uid()+uid();
  if(isPdf){const buf=await f.arrayBuffer();let thumb='',pages=0;try{const t=await pdfThumb(buf);thumb=t.thumb;pages=t.pages}catch(e){console.warn('PDF-Vorschau fehlgeschlagen',e)}
    return {buf,meta:{id,name:f.name||'Beleg.pdf',type:'application/pdf',size:buf.byteLength,thumb,pages,added:iso(T0)}}}
  const r=await prepImage(f),buf=await r.blob.arrayBuffer();
  return {buf,meta:{id,name:(f.name||'Bild').replace(/\.[^.]+$/,'')+'.jpg',type:'image/jpeg',size:buf.byteLength,thumb:r.thumb,added:iso(T0)}}}
function docRow(d,edit,cov){const pdf=d.type==='application/pdf';
  const inner=`<div class="dthumb">${d.thumb?`<img src="${d.thumb}" alt="">`:`<span>${pdf?'PDF':'BILD'}</span>`}</div>
    <div class="dmain"><b>${esc(d.name)}</b><span>${pdf?'PDF'+(d.pages?' · '+d.pages+' Seite'+(d.pages>1?'n':''):''):'Bild'} · ${fmtSize(d.size)}</span>
    ${cov!==undefined&&d.thumb?`<button type="button" class="cov" data-cov="${d.id}" aria-pressed="${cov}">${cov?'★ Titelbild':'☆ Als Titelbild'}</button>`:''}</div>`;
  return `<div class="docrow">${edit?`<div class="dbtn">${inner}</div><button type="button" class="x" data-rm="${d.id}" aria-label="Entfernen">✕</button>`
    :`<button type="button" class="dbtn" data-doc="${d.id}">${inner}<span class="dgo">Ansehen</span></button>`}</div>`}
function docSection(it){const ds=it.docs||[];if(!ds.length)return '';
  return `<div class="label" style="margin-bottom:8px">Belege & Dokumente</div><div class="doclist" style="margin-bottom:16px">${ds.map(d=>docRow(d,false)).join('')}</div>`}
function bindDocs(s,it){s.querySelectorAll('[data-doc]').forEach(b=>b.onclick=()=>{const d=(it.docs||[]).find(x=>x.id===b.dataset.doc);if(d)openViewer(d)})}
const DOCFIELD=`<div class="field"><span>Belege & Dokumente (PDF oder Bild, auch mehrere)</span><div class="doclist" id="docList"></div>
  <label class="btn docadd"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>Datei hinzufügen<input id="docIn" type="file" accept="application/pdf,.pdf,image/*" multiple hidden></label></div>`;
function docEditor(s,docs,opt){
  let cover=opt&&opt.cover||null;const covOn=!!opt;
  const list=s.querySelector('#docList'),inp=s.querySelector('#docIn'),pending=new Map(),removed=[];let busy=0;
  const draw=()=>{list.innerHTML=docs.map(d=>docRow(d,true,covOn?d.id===cover:undefined)).join('')+(busy?'<div class="docrow"><div class="dbtn"><div class="dthumb"><span class="spin"></span></div><div class="dmain"><b>Wird gelesen …</b></div></div></div>':'');
    list.querySelectorAll('[data-rm]').forEach(b=>b.onclick=()=>{const id=b.dataset.rm;docs=docs.filter(x=>x.id!==id);
      if(pending.has(id))pending.delete(id);else removed.push(id);if(cover===id)cover=null;buzz(6);draw()});
    list.querySelectorAll('[data-cov]').forEach(b=>b.onclick=()=>{cover=cover===b.dataset.cov?null:b.dataset.cov;buzz(6);draw()})};
  inp.addEventListener('change',async()=>{const files=[...inp.files];inp.value='';
    for(const f of files){
      const isPdf=f.type==='application/pdf'||/\.pdf$/i.test(f.name);
      if(!isPdf&&!/^image\//.test(f.type)){toast(`„${f.name}“ ist weder PDF noch Bild.`);continue}
      if(f.size>25e6){toast(`„${f.name}“ ist größer als 25 MB.`);continue}
      busy++;draw();
      try{const r=await prepDoc(f,isPdf);pending.set(r.meta.id,r.buf);docs.push(r.meta);buzz(8)}
      catch(x){toast(`„${f.name}“ konnte nicht gelesen werden.`)}
      busy--;draw()}});
  draw();
  return {get docs(){return docs},get cover(){return cover&&docs.some(x=>x.id===cover)?cover:null},busy:()=>busy>0,
    async commit(){for(const [id,buf] of pending)await filePut(id,await sealFile(id,buf));pending.clear()},
    cleanup(){removed.forEach(id=>fileDel(id).catch(()=>{}))}};
}
/* Betrachter: entschlüsselt nur im Arbeitsspeicher, nichts landet unverschlüsselt im Download-Ordner */
let viewerTok=0;
async function openViewer(d){
  const tok=++viewerTok,V=document.getElementById('viewer');
  V.innerHTML=`<div class="vhead"><button type="button" class="x" id="vx" aria-label="Schließen">✕</button><b>${esc(d.name)}</b>
    <button type="button" class="ghost" id="vzoom" aria-pressed="false">Zoom</button><button type="button" class="ghost" id="vshare">Teilen</button></div>
    <div class="vbody" id="vbody"><div class="vload"><span class="spin"></span>Wird entschlüsselt …</div></div>`;
  V.hidden=false;document.body.style.overflow='hidden';buzz(6);
  if(motion())V.animate([{opacity:0,transform:'translateY(30px)'},{opacity:1,transform:'none'}],{duration:280,easing:'cubic-bezier(.2,.85,.25,1)'});
  const body=V.querySelector('#vbody'),zb=V.querySelector('#vzoom');
  V.querySelector('#vx').onclick=closeViewer;
  zb.onclick=()=>{const on=body.classList.toggle('z2');zb.setAttribute('aria-pressed',String(on));buzz(5)};
  let buf;
  try{buf=await openDoc(d.id)}catch(x){if(tok===viewerTok)body.innerHTML='<div class="vload">Die Datei fehlt auf diesem Gerät oder ist beschädigt.</div>';return}
  if(tok!==viewerTok)return;
  V.querySelector('#vshare').onclick=()=>deliverFile(d.name,buf,d.type);
  if(d.type!=='application/pdf'){V._url=URL.createObjectURL(new Blob([buf],{type:d.type}));body.innerHTML=`<img src="${V._url}" alt="${esc(d.name)}">`;return}
  try{
    const doc=await pdfOpen(buf);if(tok!==viewerTok){pdfClose(doc);return}V._doc=doc;body.innerHTML='';
    const W=Math.max(200,body.clientWidth-16),dpr=Math.min(2.5,window.devicePixelRatio||1),n=Math.min(doc.numPages,40);
    for(let i=1;i<=n;i++){const p=await doc.getPage(i);if(tok!==viewerTok)return;
      const v1=p.getViewport({scale:1}),vp=p.getViewport({scale:Math.min(4,W*dpr*1.4/v1.width)});
      const cv=document.createElement('canvas');cv.width=Math.ceil(vp.width);cv.height=Math.ceil(vp.height);body.appendChild(cv);
      await p.render({canvas:cv,viewport:vp}).promise}
    if(doc.numPages>n)body.insertAdjacentHTML('beforeend',`<div class="vload">Weitere ${doc.numPages-n} Seiten über „Teilen“ öffnen.</div>`);
  }catch(x){if(tok===viewerTok)body.innerHTML=`<div class="vload">${x&&x.name==='PasswordException'?'Diese PDF ist mit einem Passwort geschützt.':'Die PDF konnte hier nicht angezeigt werden.'} Öffne sie über „Teilen“ mit einer PDF-App.</div>`}
}
function closeViewer(){viewerTok++;const V=document.getElementById('viewer');if(!V||V.hidden)return;
  if(V._doc){pdfClose(V._doc);V._doc=null}if(V._url){URL.revokeObjectURL(V._url);V._url=null}
  V.hidden=true;V.innerHTML='';if(!root.firstElementChild)document.body.style.overflow=''}

/* Verschlüsselte Sicherung: enthält nur den bereits verschlüsselten Tresor */
async function exportBackup(){
  db.meta=Object.assign({},db.meta,{lastBackup:iso(T0),dirty:0});
  await save();
  const v=readVault();if(!v){toast('Es gibt noch nichts zu sichern.');return}
  const files={};
  for(const id of allDocIds()){const r=await fileGet(id).catch(()=>null);if(r)files[id]={iv:toB64(r.iv),ct:toB64(r.ct)}}
  const payload=JSON.stringify({app:'belegbox',format:2,exported:new Date().toISOString(),version:APP_VERSION,vault:v,files});
  const ok=await deliverFile('belegbox-sicherung-'+iso(T0)+'.belegbox',payload,'application/json');
  if(ok){celebrate('Gesichert');toast('Sicherung erstellt. Leg die Datei an einem zweiten Ort ab, z. B. in deiner Cloud.');render()}
}
function readBackupFile(file){return new Promise((res,rej)=>{const r=new FileReader();
  r.onload=()=>{try{const o=JSON.parse(r.result);const v=o&&o.app==='belegbox'&&o.vault;
      if(!v||typeof v.salt!=='string'||typeof v.iv!=='string'||typeof v.ct!=='string')throw new Error('format');res({vault:v,files:o.files&&typeof o.files==='object'?o.files:{}})}
    catch(e){rej(new Error('Das ist keine gültige Belegbox-Sicherung.'))}};
  r.onerror=()=>rej(new Error('Die Datei konnte nicht gelesen werden.'));
  if(file.size>400e6)return rej(new Error('Die Datei ist zu groß für eine Belegbox-Sicherung.'));
  r.readAsText(file)})}
async function restoreVault(o){let fileErr=false;
  try{await fileClear();for(const [id,f] of Object.entries(o.files||{}))await filePut(id,{iv:fromB64(f.iv),ct:fromB64(f.ct).buffer})}catch(x){fileErr=true}
  const vj=JSON.stringify(o.vault);try{await filePut(MIRROR,vj)}catch(e){}
  localStorage.setItem(VKEY,vj);bootInfo={orphans:0,broken:false};key=null;db=null;closeViewer();closeSheet(false);main.innerHTML='';showLock();
  toast(fileErr?'Sicherung geladen, aber nicht alle Dokumente passten in den Speicher. Entsperre mit dem Passwort, das beim Sichern galt.':'Sicherung geladen. Entsperre sie mit dem Passwort, das beim Sichern galt.')}

/* Kalenderexport (.ics) mit Erinnerung 7 Tage und 1 Tag vorher */
function icsEsc(s){return String(s).replace(/\\/g,'\\\\').replace(/;/g,'\\;').replace(/,/g,'\\,').replace(/\r?\n/g,'\\n')}
function icsDay(d){return d.getFullYear()+String(d.getMonth()+1).padStart(2,'0')+String(d.getDate()).padStart(2,'0')}
function buildIcs(neutral){
  const stamp=new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d+Z$/,'Z');
  const ev=[];
  db.contracts.filter(c=>c.status!=='gekuendigt').forEach(c=>{const i=contractInfo(c);if(!i.by)return;
    ev.push({uid:c.id+'-frist',date:i.by,title:neutral?'Belegbox: Kündigungsfrist':'Kündigungsfrist: '+c.anbieter,
      desc:neutral?'Details in der Belegbox.':`Spätestens heute kündigen, sonst verlängert sich ${c.anbieter} am ${fmtD(i.end)}.`})});
  db.devices.forEach(d=>{const i=deviceInfo(d);
    [['gew','Gewährleistung',i.gew],['gar','Herstellergarantie',i.gar]].forEach(([k,t,dt])=>{if(!dt||days(dt)<0)return;
      ev.push({uid:d.id+'-'+k,date:dt,title:neutral?'Belegbox: '+t+' endet':t+' endet: '+d.name,
        desc:neutral?'Details in der Belegbox.':`${t} für ${d.name} läuft heute ab. Mängel vorher melden.`})})});
  const L=['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//Belegbox//DE','CALSCALE:GREGORIAN','METHOD:PUBLISH','X-WR-CALNAME:Belegbox-Fristen'];
  ev.forEach(e=>{L.push('BEGIN:VEVENT','UID:'+e.uid+'@belegbox','DTSTAMP:'+stamp,'DTSTART;VALUE=DATE:'+icsDay(e.date),
    'DTEND;VALUE=DATE:'+icsDay(addDays(e.date,1)),'SUMMARY:'+icsEsc(e.title),'DESCRIPTION:'+icsEsc(e.desc),'TRANSP:TRANSPARENT',
    'BEGIN:VALARM','ACTION:DISPLAY','DESCRIPTION:'+icsEsc(e.title),'TRIGGER:-P7D','END:VALARM',
    'BEGIN:VALARM','ACTION:DISPLAY','DESCRIPTION:'+icsEsc(e.title),'TRIGGER:-P1D','END:VALARM','END:VEVENT')});
  L.push('END:VCALENDAR');
  return {text:L.join('\r\n')+'\r\n',count:ev.length};
}

/* Browser bitten, die Daten nicht bei Speicherknappheit zu löschen */
let persisted=null;
async function askPersist(){try{if(navigator.storage&&navigator.storage.persist){persisted=await navigator.storage.persisted()||await navigator.storage.persist()}}catch(e){}}

/* Automatische Sperre */
let lastAct=Date.now(),hiddenAt=0;
['pointerdown','keydown','scroll','touchstart'].forEach(ev=>addEventListener(ev,()=>{lastAct=Date.now()},{passive:true}));
setInterval(()=>{if(key&&Date.now()-lastAct>IDLE_MS)lock()},10000);
document.addEventListener('visibilitychange',()=>{if(document.hidden)hiddenAt=Date.now();else if(key&&hiddenAt&&Date.now()-hiddenAt>BG_MS)lock()});

/* Berechnungen */
/* Laufzeit-Modus: 'beginn' = aus Vertragsbeginn + Mindestlaufzeit, 'ende' = bekanntes Laufzeitende, 'offen' = unbefristet */
const FRIST=n=>{n=Number(n||0);return !n?'ohne Frist':n%30===0?(n/30)+' Monat'+(n>30?'e':'')+' Frist':n+' Tage Frist'};
const PER=n=>n==12?'12 Monate':n+' Monat'+(n>1?'e':'');
function contractInfo(c){
  const m=c.modus||'beginn',fr=Number(c.frist||0);
  if(m==='offen'){ // jederzeit kündbar: endet frühestens nach Ablauf der Frist
    const from=c.status==='gekuendigt'&&c.gekuendigtAm?parse(c.gekuendigtAm):T0;
    return {end:addDays(from,fr),by:null,k:0,offen:true};
  }
  const anchor=m==='ende'&&c.ende?parse(c.ende):null,start=anchor?null:parse(c.beginn);
  for(let k=0;k<600;k++){
    const end=anchor?addMonths(anchor,k*Number(c.verl||1)):addMonths(start,Number(c.laufzeit||1)+k*Number(c.verl||1));
    const by=addDays(end,-fr);
    if(c.status==='gekuendigt'){ if(days(end)>=0||k>500) return {end,by:null,k}; continue }
    if(days(by)>=0) return {end,by,k};
  }
  return {end:anchor||start,by:null,k:0};
}
/* Optionaler anderer Preis nach der Mindestlaufzeit */
function priceChange(c){if(c.kostenNach==null||c.kostenNach==='')return null;const n=Number(c.kostenNach);
  if(!(n>=0)||n===Number(c.kosten||0))return null;const m=c.modus||'beginn';
  const date=m==='offen'?null:m==='ende'?(c.ende?parse(c.ende):null):(c.beginn?addMonths(parse(c.beginn),Number(c.laufzeit||1)):null);
  return date?{date,preis:n}:null}
function price(c){const p=priceChange(c);return p&&days(p.date)<=0?p.preis:Number(c.kosten||0)}
function monthly(c){return price(c)/Number(c.intervall||1)}
function deviceInfo(d){
  const kauf=parse(d.kauf);
  const gew=addMonths(kauf,24);
  const gar=Number(d.garantieMonate)>0?addMonths(kauf,Number(d.garantieMonate)):null;
  const ends=[{typ:'Gewährleistung',date:gew},gar&&{typ:'Herstellergarantie',date:gar}].filter(Boolean).filter(x=>days(x.date)>=0).sort((a,b)=>b.date-a.date);
  return {kauf,gew,gar,best:ends[0]||null};
}
/* Ratenkauf: feste Monatsrate, erste Rate an einem Datum, danach jeden Monat am selben Tag */
function rateInfo(d){const r=d.rate;if(!r||!(Number(r.betrag)>0)||!(Number(r.anzahl)>0)||!r.start)return null;
  const n=Math.round(Number(r.anzahl)),b=Number(r.betrag),start=parse(r.start);let paid=0;
  while(paid<n&&days(addMonths(start,paid))<=0)paid++;
  const total=b*n+Number(r.anzahlung||0);
  return {n,b,paid,rest:n-paid,restschuld:(n-paid)*b,next:paid<n?addMonths(start,paid):null,last:addMonths(start,n-1),
    total,mehr:Number(d.preis)>0?total-Number(d.preis):null,aktiv:paid<n,f:paid/n}}
function devPill(d){
  const i=deviceInfo(d);
  if(!i.best) return '<span class="pill p-none">Kein Schutz</span>';
  const n=days(i.best.date);
  return n<=60?`<span class="pill p-warn">${i.best.typ==='Gewährleistung'?'Gewährl.':'Garantie'} endet ${inDays(n)}</span>`
              :`<span class="pill p-ok">Schutz bis ${fmtD(i.best.date)}</span>`;
}
function conPill(c){
  const i=contractInfo(c);
  if(c.status==='gekuendigt') return `<span class="pill p-none">Gekündigt · endet ${fmtD(i.end)}</span>`;
  if(i.offen) return `<span class="pill p-ok">Jederzeit kündbar · ${FRIST(c.frist)}</span>`;
  const n=days(i.by);
  const cls=n<=14?'p-crit':n<=45?'p-warn':'p-ok';
  return `<span class="pill ${cls}">Kündigen bis ${fmtD(i.by)}</span>`;
}
function upcoming(){
  const ev=[];
  db.contracts.filter(c=>c.status!=='gekuendigt').forEach(c=>{const i=contractInfo(c);if(!i.by)return;const n=days(i.by);
    if(n<=60) ev.push({date:i.by,n,title:c.anbieter,sub:`Kündigungsfrist · sonst Verlängerung um ${c.verl==12?'1 Jahr':c.verl+' Monat'+(c.verl>1?'e':'')}`,kind:'c',id:c.id})});
  db.devices.forEach(d=>{const i=deviceInfo(d);
    [['Gewährleistung',i.gew],['Herstellergarantie',i.gar]].forEach(([t,dt])=>{if(!dt)return;const n=days(dt);
      if(n>=0&&n<=90) ev.push({date:dt,n,title:d.name,sub:t+' läuft ab',kind:'d',id:d.id})});
    const ri=rateInfo(d);if(ri&&ri.aktiv){const n=days(ri.last);if(n>=0&&n<=60)ev.push({date:ri.last,n,title:d.name,sub:`Letzte Rate · danach ${eur(ri.b)} weniger im Monat`,kind:'d',id:d.id})}});
  db.contracts.filter(c=>c.status!=='gekuendigt').forEach(c=>{const p=priceChange(c);if(!p)return;const n=days(p.date);
    if(n>=0&&n<=60) ev.push({date:p.date,n,title:c.anbieter,sub:`Neuer Preis ${eur(p.preis)} ${INTERVALL[c.intervall]||''} (bisher ${eur(c.kosten)})`,kind:'c',id:c.id})});
  return ev.sort((a,b)=>a.n-b.n);
}

/* Render */
const main=document.getElementById('main');
const NOTEICON='<svg class="ni" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-label="hat Notiz"><path d="M5 4h14v11l-5 5H5z"/><path d="M14 20v-5h5M8 9h8M8 13h4"/></svg>';
const noteBlock=it=>it.notiz?`<div class="label" style="margin-bottom:8px">Notizen & Hinweise</div><div class="notetext">${esc(it.notiz)}</div>`:'';
/* Kleines Bild für „Demnächst fällig“: Logo, Gerätefoto oder PDF-Vorschau, sonst Anfangsbuchstabe */
function evMini(e){
  if(e.kind==='c'){const c=db.contracts.find(x=>x.id===e.id);if(!c)return '';
    return c.logo?`<span class="mini logo"><img src="${c.logo}" alt=""></span>`:`<span class="mini">${esc(c.anbieter.charAt(0).toUpperCase())}</span>`}
  const d=db.devices.find(x=>x.id===e.id);if(!d)return '';
  const t=devThumb(d);
  return t?`<span class="mini"><img src="${t.src}" alt=""${t.top?' style="object-position:top"':''}></span>`:`<span class="mini">${esc((d.hersteller||d.name||'?').charAt(0).toUpperCase())}</span>`}
function conTile(c){return c.logo?`<div class="tile logo"><img src="${c.logo}" alt=""></div>`:`<div class="tile">${esc(c.anbieter.charAt(0).toUpperCase())}</div>`}
/* Kachelbild eines Geräts: gewähltes Titelbild > Foto > erstes Bild-Dokument > erste PDF-Seite */
function devThumb(d){const ds=(d.docs||[]).filter(x=>x.thumb);
  const c=d.cover&&ds.find(x=>x.id===d.cover);if(c)return {src:c.thumb,top:c.type==='application/pdf'};
  if(d.foto)return {src:d.foto,top:false};
  const im=ds.find(x=>x.type!=='application/pdf');if(im)return {src:im.thumb,top:false};
  return ds[0]?{src:ds[0].thumb,top:true}:null}
function tileFor(d){const t=devThumb(d);
  return t?`<div class="tile"><img src="${t.src}" alt=""${t.top?' style="object-position:top"':''}></div>`:`<div class="tile">${esc((d.hersteller||d.name||'?').charAt(0).toUpperCase())}</div>`}
function render(mode){
  if(!db)return;
  document.querySelectorAll('nav.tabs button').forEach(b=>b.setAttribute('aria-current',b.dataset.tab===tab?'page':'false'));
  setInd(TABS.indexOf(tab));
  const hasEx=db.devices.some(x=>x.ex)||db.contracts.some(x=>x.ex);
  document.getElementById('banner').innerHTML=hasEx?`<div class="banner"><span>Du siehst Beispieleinträge, damit du die App ausprobieren kannst.</span><button type="button" id="clearEx">Beispiele entfernen</button></div>`:'';
  const own=db.devices.some(x=>!x.ex)||db.contracts.some(x=>!x.ex);
  const lb=db.meta&&db.meta.lastBackup?parse(db.meta.lastBackup):null;
  const dirty=db.meta&&db.meta.dirty||0;
  const ghOn=!!ghCfg(),ghOk=ghOn&&!ghStat.err&&ghStat.at;
  if(ghOn&&ghStat.err){document.getElementById('banner').insertAdjacentHTML('beforeend',`<div class="banner" style="background:var(--crit-soft)"><span><b>GitHub-Sicherung:</b> ${esc(ghStat.err)}</span><button type="button" id="ghFix" style="color:var(--crit)">Ansehen</button></div>`);
    document.getElementById('ghFix').onclick=openMenu}
  if(own&&!ghOk&&(!lb||days(lb)<-14||dirty>=5)){
    document.getElementById('banner').insertAdjacentHTML('beforeend',`<div class="banner" style="background:var(--warn-soft)"><span>${!lb?'Du hast noch keine Sicherung.':dirty>=5?dirty+' Änderungen seit der letzten Sicherung.':'Letzte Sicherung vor '+(-days(lb))+' Tagen.'} Ohne Sicherung sind bei Handyverlust, Browserwechsel oder gelöschten Websitedaten alle Daten weg.</span><button type="button" id="bkNow" style="color:var(--warn)">Jetzt sichern</button></div>`);
    document.getElementById('bkNow').onclick=exportBackup;
  }
  const ce=document.getElementById('clearEx'); if(ce) ce.onclick=()=>{db.devices=db.devices.filter(x=>!x.ex);db.contracts=db.contracts.filter(x=>!x.ex);save();buzz(10);render('rows')};
  main.innerHTML= tab==='home'?viewHome(): tab==='geraete'?viewDevices(): viewContracts();
  main.querySelectorAll('[data-open]').forEach(el=>el.onclick=()=>openDetail(el.dataset.kind,el.dataset.open,el));
  main.querySelectorAll('[data-filter]').forEach(el=>el.onclick=()=>{if(filter===el.dataset.filter)return;filter=el.dataset.filter;buzz(5);render('rows')});
  main.querySelectorAll('[data-goto]').forEach(el=>el.onclick=()=>goTab(el.dataset.goto));
  const sec=main.firstElementChild;
  sec.querySelectorAll('.list>.row').forEach((r,i)=>r.style.setProperty('--j',Math.min(i,10)));
  if(mode&&motion()){
    sec.classList.add('enter');
    if(mode==='rise'){sec.classList.add('rise');[...sec.children].forEach((c,i)=>c.style.setProperty('--i',i))}
    else sec.classList.add('rows');
  }
  countUps(mode==='rise'||mode==='tab');
}

function viewHome(){
  const act=db.contracts.filter(c=>c.status!=='gekuendigt');
  const raten=db.devices.map(d=>rateInfo(d)).filter(r=>r&&r.aktiv);
  const mon=act.reduce((s,c)=>s+monthly(c),0)+raten.reduce((s,r)=>s+r.b,0);
  const wert=db.devices.reduce((s,d)=>s+Number(d.preis||0),0);
  const ohne=db.devices.filter(d=>d.nachweis==='keiner').length;
  const byKat={};act.forEach(c=>byKat[c.kategorie]=(byKat[c.kategorie]||0)+monthly(c));
  if(raten.length)byKat['Ratenkäufe']=raten.reduce((s,r)=>s+r.b,0);
  const kats=Object.entries(byKat).sort((a,b)=>b[1]-a[1]);const max=kats[0]?kats[0][1]:1;
  const ev=upcoming();
  return `<section class="view">
    <div class="summary">
      <div><div class="label">Fixkosten pro Monat</div>
        <div class="bigcost"><span class="num" data-count="mon" data-v="${mon}" data-f="eur">${eur(mon)}</span><small><span data-count="jahr" data-v="${mon*12}" data-f="eur">${eur(mon*12)}</span> im Jahr</small></div></div>
      ${kats.length?`<div class="bars">${kats.map(([k,v])=>`<div class="bar"><span>${esc(k)}</span><div class="track"><div class="fill" style="width:${Math.max(4,v/max*100)}%"></div></div><span class="num">${eur(v)}</span></div>`).join('')}</div>`:''}
      <div class="facts">
        <div><b data-count="akt" data-v="${act.length}">${act.length}</b><span>aktive Verträge</span></div>
        <div><b data-count="ger" data-v="${db.devices.length}">${db.devices.length}</b><span>Geräte · ${eur(wert)}</span></div>
        <div><b data-count="ohne" data-v="${ohne}">${ohne}</b><span>ohne Kaufnachweis</span></div>
      </div>
    </div>
    <div class="sechead"><h2>Demnächst fällig</h2><span class="label">nächste 90 Tage</span></div>
    <div class="list">${ev.length?ev.map(e=>`<button type="button" class="row" data-kind="${e.kind}" data-open="${e.id}">
        <div class="date"><b>${e.date.getDate()}</b><span>${e.date.toLocaleDateString('de-DE',{month:'short'}).replace('.','')}</span></div>
        <div class="evmain">${evMini(e)}<div style="min-width:0"><div class="t">${esc(e.title)}</div><div class="s">${esc(e.sub)}</div></div></div>
        <span class="pill ${e.n<=14?'p-crit':e.n<=45?'p-warn':'p-ok'}">${inDays(e.n)}</span></button>`).join('')
      :`<div class="empty">Keine Fristen in den nächsten 90 Tagen.</div>`}</div>
    ${ohne?`<div class="sechead"><h2>Ohne Nachweis</h2><button type="button" class="ghost" data-goto="geraete">Alle Geräte</button></div>
    <div class="list">${db.devices.filter(d=>d.nachweis==='keiner').map(devRow).join('')}</div>
    <p class="hint">Tipp: Bestellhistorie bei Online-Händlern, alte Bestellmails und Kontoauszüge durchsuchen. Für die Gewährleistung reicht oft jeder plausible Kaufnachweis.</p>`:''}
  </section>`;
}
/* Garantie-Ring: wie viel vom Schutz noch übrig ist, grün → gelb → rot */
function prot(d){const i=deviceInfo(d);if(!i.best)return null;
  const total=Math.max(1,(i.best.date-i.kauf)/864e5),left=days(i.best.date);
  return {f:clamp(left/total,0,1),left,typ:i.best.typ,months:Math.round(total/30.44)}}
function ringColor(f){return f>=.5?`color-mix(in srgb, var(--ok) ${Math.round((f-.5)*200)}%, var(--gold))`:`color-mix(in srgb, var(--gold) ${Math.round(f*200)}%, var(--crit))`}
function ring(f,size,w){const r=(size-w)/2,c=+(2*Math.PI*r).toFixed(2),h=size/2;
  return `<svg class="ring" viewBox="0 0 ${size} ${size}" style="--c:${c}" aria-hidden="true"><circle class="trk" cx="${h}" cy="${h}" r="${r}" stroke-width="${w}"/>${f==null?'':
    `<circle class="arc" cx="${h}" cy="${h}" r="${r}" stroke-width="${w}" stroke-dasharray="${c}" stroke-dashoffset="${(c*(1-f)).toFixed(2)}" transform="rotate(-90 ${h} ${h})" style="stroke:${ringColor(f)}"/>`}</svg>`}
function tileWrap(d){const p=prot(d);return `<div class="tw">${ring(p?p.f:null,46,3.5)}${tileFor(d)}</div>`}
function devRow(d){const i=deviceInfo(d);return `<button type="button" class="row" data-kind="d" data-open="${d.id}">
  ${tileWrap(d)}<div class="main"><div class="t">${esc(d.name)}${d.notiz?NOTEICON:''}</div><div class="s">${esc([d.hersteller,d.raum].filter(Boolean).join(' · '))}${d.hersteller||d.raum?' · ':''}gekauft ${d.geschaetzt?'ca. ':''}${i.kauf.getFullYear()}</div><div class="pl">${devPill(d)}${(r=>r&&r.aktiv?` <span class="pill p-none">Rate ${eur(r.b)} · noch ${r.rest}</span>`:'')(rateInfo(d))}</div></div>
  <span class="amt num">${d.preis?eur(d.preis):'–'}</span></button>`}
function viewDevices(){
  const F={alle:['Alle',()=>true],schutz:['Schutz aktiv',d=>!!deviceInfo(d).best],bald:['Läuft bald ab',d=>{const b=deviceInfo(d).best;return b&&days(b.date)<=60}],ohne:['Ohne Nachweis',d=>d.nachweis==='keiner'],raten:['Ratenkauf',d=>!!rateInfo(d)]};
  const list=db.devices.filter(F[filter]?F[filter][1]:()=>true).sort((a,b)=>a.name.localeCompare(b.name,'de'));
  return `<section class="view">
    <div class="sechead"><h2>Geräte</h2><span class="label num">${list.length} von ${db.devices.length}</span></div>
    <div class="chips">${Object.entries(F).map(([k,v])=>`<button type="button" class="chip" data-filter="${k}" aria-pressed="${filter===k}">${v[0]}</button>`).join('')}</div>
    <div class="list">${list.length?list.map(devRow).join(''):`<div class="empty">Hier ist noch nichts. Tippe auf „Neu“, um dein erstes Gerät mit Kaufdatum und Beleg anzulegen.</div>`}</div>
  </section>`;
}
function viewContracts(){
  const F={alle:['Alle',()=>true],aktiv:['Aktiv',c=>c.status!=='gekuendigt'],bald:['Frist bald',c=>c.status!=='gekuendigt'&&days(contractInfo(c).by)<=45],gek:['Gekündigt',c=>c.status==='gekuendigt']};
  const list=db.contracts.filter(F[filter]?F[filter][1]:()=>true).sort((a,b)=>{const x=contractInfo(a),y=contractInfo(b);return (x.by||x.end)-(y.by||y.end)});
  return `<section class="view">
    <div class="sechead"><h2>Abos & Verträge</h2><span class="label num">${list.length} von ${db.contracts.length}</span></div>
    <div class="chips">${Object.entries(F).map(([k,v])=>`<button type="button" class="chip" data-filter="${k}" aria-pressed="${filter===k}">${v[0]}</button>`).join('')}</div>
    <div class="list">${list.length?list.map(c=>`<button type="button" class="row" data-kind="c" data-open="${c.id}">
      ${conTile(c)}
      <div class="main"><div class="t">${esc(c.anbieter)}${c.notiz?NOTEICON:''}</div><div class="s">${esc(c.kategorie)} · ${eur(price(c))} ${INTERVALL[c.intervall]||''}</div><div class="pl">${conPill(c)}</div></div>
      <span class="amt num">${eur(monthly(c))}<small>/Monat</small></span></button>`).join('')
      :`<div class="empty">Noch keine Verträge. Tippe auf „Neu“ und trage Kosten, Laufzeit und Kündigungsfrist ein.</div>`}</div>
  </section>`;
}

/* Sheet: fährt hoch (oder wächst aus dem angetippten Eintrag), lässt sich nach unten wegziehen */
const root=document.getElementById('sheetRoot');
let sheetTok=0;
function openSheet(html,onMount,from){
  const replacing=!!root.firstElementChild;++sheetTok;
  root.innerHTML=`<div class="scrim${replacing?' swap':''}" id="scrim"><div class="sheet" role="dialog" aria-modal="true"><div class="grab"></div>${html}</div></div>`;
  const sc=root.firstElementChild,sh=sc.firstElementChild;
  sc.addEventListener('click',e=>{if(e.target===sc)closeSheet()});
  root.querySelectorAll('[data-close]').forEach(b=>b.onclick=()=>closeSheet());
  document.body.style.overflow='hidden';
  if(onMount)onMount(sh);
  if(motion()){
    if(replacing)sh.animate([{opacity:0,transform:'translateY(14px) scale(.985)'},{opacity:1,transform:'none'}],{duration:260,easing:'cubic-bezier(.2,.85,.25,1)'});
    else if(from&&from.isConnected)grow(sh,from.getBoundingClientRect());
    else sh.animate([{transform:'translateY(100%)'},{transform:'none'}],{duration:420,easing:'cubic-bezier(.2,.9,.25,1)'});
  }
  dragSheet(sc,sh);
}
function grow(sh,f){
  const r=sh.getBoundingClientRect();
  const l=Math.max(0,f.left-r.left),rr=Math.max(0,r.right-f.right),b=Math.max(0,r.height-f.height);
  sh.animate([{transform:`translateY(${f.top-r.top}px)`,clipPath:`inset(0px ${rr}px ${b}px ${l}px round 14px)`},
              {transform:'translateY(0)',clipPath:'inset(0px 0px 0px 0px round 20px 20px 0px 0px)'}],{duration:440,easing:'cubic-bezier(.2,.85,.2,1)'});
  [...sh.children].forEach((c,i)=>c.animate([{opacity:0},{opacity:1}],{duration:280,delay:110+Math.min(i,6)*28,easing:'ease-out',fill:'backwards'}));
}
function dragSheet(sc,sh){
  let y0=0,x0=0,dy=0,mode=null,v=0,ly=0,lt=0,hit=false;
  sh.addEventListener('touchstart',e=>{if(e.touches.length!==1){mode='x';return}
    const t=e.touches[0];y0=ly=t.clientY;x0=t.clientX;lt=performance.now();dy=0;v=0;mode=null;hit=false},{passive:true});
  sh.addEventListener('touchmove',e=>{if(mode==='x'||mode==='scroll'||sc.classList.contains('closing'))return;
    const t=e.touches[0],d=t.clientY-y0,dx=t.clientX-x0;
    if(!mode){if(Math.abs(d)<7&&Math.abs(dx)<7)return;
      if(d>0&&sh.scrollTop<=0&&Math.abs(d)>Math.abs(dx)&&!(e.target.closest&&e.target.closest('input[type=range]'))){mode='drag';y0=t.clientY;sc.classList.add('drag');sh.getAnimations().forEach(a=>a.finish())}
      else{mode='scroll';return}}
    if(e.cancelable)e.preventDefault();
    const raw=t.clientY-y0;dy=Math.max(0,raw);
    const now=performance.now();v=.7*((t.clientY-ly)/Math.max(1,now-lt))+.3*v;ly=t.clientY;lt=now;
    sh.style.transform=`translateY(${raw>0?raw:raw*.12}px)`;
    sc.style.setProperty('--k',String(1-Math.min(1,dy/(sh.offsetHeight||1))));
    const over=dy>Math.min(sh.offsetHeight*.3,220);if(over!==hit){hit=over;if(over)buzz(6)}
  },{passive:false});
  const end=()=>{if(mode!=='drag'){mode=null;return}mode=null;sc.classList.remove('drag');
    if(hit||(v>.55&&dy>24)){closeSheet();return}
    const from=sh.style.transform;sh.style.transform='';sc.style.removeProperty('--k');
    if(motion()&&from)sh.animate([{transform:from},{transform:'translateY(0)'}],{duration:360,easing:'cubic-bezier(.2,.9,.3,1.15)'})};
  sh.addEventListener('touchend',end);sh.addEventListener('touchcancel',end);
}
function closeSheet(anim){
  document.body.style.overflow='';
  const sc=root.firstElementChild;if(!sc)return;
  if(anim===false||!motion()){++sheetTok;root.innerHTML='';return}
  if(sc.classList.contains('closing'))return;
  const tok=++sheetTok,sh=sc.firstElementChild;
  const from=sh.style.transform||'translateY(0)';
  sh.getAnimations().forEach(a=>a.cancel());
  sc.classList.add('closing');sc.classList.remove('drag');sc.style.setProperty('--k','0');
  sh.animate([{transform:from},{transform:'translateY(105%)'}],{duration:260,easing:'cubic-bezier(.4,0,.9,.6)',fill:'forwards'});
  setTimeout(()=>{if(tok===sheetTok)root.innerHTML=''},280);
}
document.addEventListener('keydown',e=>{if(e.key!=='Escape')return;if(!document.getElementById('viewer').hidden)closeViewer();else if(fanOpen)setFan(false);else if(root.firstElementChild)closeSheet()});
const head=t=>`<div class="sheethead"><h2>${t}</h2><button type="button" class="x" data-close aria-label="Schließen">✕</button></div>`;

function openDetail(kind,id,from){
  if(kind==='d'){
    const d=db.devices.find(x=>x.id===id); if(!d)return; const i=deviceInfo(d);
    const p=prot(d);
    openSheet(head(esc(d.name))+`<div style="margin:-6px 0 14px">${devPill(d)}</div>
      ${p?`<div class="prot tiltme"><div class="rw">${ring(p.f,60,5)}<span class="num">${Math.round(p.f*100)}%</span></div>
        <div><b>noch ${p.left} Tag${p.left===1?'':'e'} ${p.typ}</b><span class="hint">${p.months} Monate Schutz ab Kauf</span></div></div>`:''}
      ${d.foto?`<img class="photo tiltme" src="${d.foto}" alt="Foto von ${esc(d.name)}">`:''}
      <dl class="kv">
        <dt>Hersteller / Modell</dt><dd>${esc([d.hersteller,d.modell].filter(Boolean).join(' ')||'–')}</dd>
        <dt>Seriennummer</dt><dd class="num">${esc(d.sn||'–')}</dd>
        <dt>Standort</dt><dd>${esc(d.raum||'–')}</dd>
        <dt>Kaufdatum</dt><dd>${d.geschaetzt?'ca. ':''}${fmtD(i.kauf)}${d.geschaetzt?' (geschätzt)':''}</dd>
        <dt>Preis / Händler</dt><dd>${d.preis?eur(d.preis):'–'}${d.haendler?' · '+esc(d.haendler):''}</dd>
        <dt>Gewährleistung</dt><dd>bis ${fmtD(i.gew)} ${days(i.gew)<0?'<span class="pill p-none">abgelaufen</span>':''}</dd>
        <dt>Herstellergarantie</dt><dd>${i.gar?'bis '+fmtD(i.gar)+(days(i.gar)<0?' <span class="pill p-none">abgelaufen</span>':''):'keine'}</dd>
        <dt>Nachweis</dt><dd>${NACHWEIS[d.nachweis]||'–'}</dd>
      </dl>
      ${(r=>!r?'':`<div class="label" style="margin-bottom:8px">Ratenkauf</div>
        <div class="rate">
          <div class="rhead"><b>${r.aktiv?`${r.paid} von ${r.n} Raten bezahlt`:'Komplett abbezahlt'}</b><span class="num">${eur(r.b)}/Monat</span></div>
          <div class="track"><div class="fill" style="width:${Math.max(r.f>0?3:0,r.f*100)}%"></div></div>
          <dl class="kv" style="margin:12px 0 0">
            ${r.aktiv?`<dt>Restschuld</dt><dd><b class="num">${eur(r.restschuld)}</b></dd><dt>Nächste Rate</dt><dd>${fmtD(r.next)} (${inDays(days(r.next))})</dd>`:''}
            <dt>${r.aktiv?'Letzte Rate':'Letzte Rate war'}</dt><dd>${fmtD(r.last)}</dd>
            <dt>Gesamtkosten</dt><dd>${eur(r.total)}${r.mehr!=null&&Math.abs(r.mehr)>=.01?` <span class="pill ${r.mehr>0?'p-warn':'p-ok'}">${r.mehr>0?'+'+eur(r.mehr)+' ggü. Kaufpreis':eur(-r.mehr)+' günstiger'}</span>`:r.mehr!=null?' <span class="pill p-ok">0 % Finanzierung</span>':''}</dd>
            ${d.rate.anzahlung?`<dt>Anzahlung</dt><dd>${eur(d.rate.anzahlung)}</dd>`:''}
            ${d.rate.bank?`<dt>Finanziert über</dt><dd>${esc(d.rate.bank)}</dd>`:''}
            ${d.rate.vnr?`<dt>Finanzierungs-Nr.</dt><dd class="num"><span data-rmask>${esc(maskVal(d.rate.vnr))}</span><button type="button" class="reveal" data-rshow>Anzeigen</button></dd>`:''}
          </dl></div>`)(rateInfo(d))}
      ${noteBlock(d)}
      ${docSection(d)}
      <div class="actions"><button type="button" class="btn primary" id="edit">Bearbeiten</button><button type="button" class="btn danger" id="del">Löschen</button></div>`,
      s=>{const pr=s.querySelector('.prot');if(pr&&motion())pr.classList.add('enter');bindDocs(s,d);
          const rs=s.querySelector('[data-rshow]');if(rs){let o=false;rs.onclick=()=>{o=!o;s.querySelector('[data-rmask]').textContent=o?d.rate.vnr:maskVal(d.rate.vnr);rs.textContent=o?'Verbergen':'Anzeigen'}}
          s.querySelector('#edit').onclick=()=>openForm('d',d);armDelete(s,()=>{(d.docs||[]).forEach(x=>fileDel(x.id).catch(()=>{}));db.devices=db.devices.filter(x=>x.id!==id)})},from);
  } else {
    const c=db.contracts.find(x=>x.id===id); if(!c)return; const i=contractInfo(c);
    openSheet(head((c.logo?`<img class="hlogo" src="${c.logo}" alt="">`:'')+esc(c.anbieter))+`<div style="margin:-6px 0 14px">${conPill(c)}</div>
      <dl class="kv">
        <dt>Kategorie</dt><dd>${esc(c.kategorie)}</dd>
        <dt>Kosten</dt><dd>${eur(price(c))} ${INTERVALL[c.intervall]||''} · <span class="num">${eur(monthly(c))}</span>/Monat</dd>
        ${(()=>{const p=priceChange(c);if(!p)return '';const past=days(p.date)<=0;
          return `<dt>Preisänderung</dt><dd>${past?`seit ${fmtD(p.date)} ${eur(p.preis)} (vorher ${eur(c.kosten)})`:`ab ${fmtD(p.date)} ${eur(p.preis)} statt ${eur(c.kosten)} <span class="pill ${p.preis>c.kosten?'p-warn':'p-ok'}">${p.preis>c.kosten?'teurer':'günstiger'}</span>`}</dd>`})()}
        ${c.beginn?`<dt>Beginn</dt><dd>${fmtD(parse(c.beginn))}</dd>`:''}
        <dt>Laufzeit</dt><dd>${i.offen?'Unbefristet, jederzeit kündbar':(c.modus==='ende'?`Laufzeitende ${fmtD(parse(c.ende))} eingetragen`:`Mindestens ${PER(c.laufzeit)}`)+`, danach je ${PER(c.verl)}`}</dd>
        <dt>Kündigungsfrist</dt><dd>${Number(c.frist)?c.frist+' Tage':'jederzeit'}</dd>
        <dt>${c.status==='gekuendigt'?'Endet am':i.offen?'Bei Kündigung heute endet er am':'Nächstes Laufzeitende'}</dt><dd>${fmtD(i.end)}${c.status!=='gekuendigt'&&i.k>0?` <span class="pill p-none">schon ${i.k}× verlängert</span>`:''}</dd>
        ${i.by?`<dt>Spätestens kündigen</dt><dd><b>${fmtD(i.by)}</b> (${inDays(days(i.by))})</dd>`:''}
        ${[['kundennr','Kundennummer'],['vertragsnr','Vertragsnummer']].map(([f,l])=>`<dt>${l}</dt><dd class="num">${c[f]?`<span data-mask="${f}">${esc(maskVal(c[f]))}</span><button type="button" class="reveal" data-show="${f}">Anzeigen</button><button type="button" class="reveal" data-copy="${f}">Kopieren</button>`:'–'}</dd>`).join('')}
      </dl>
      ${noteBlock(c)}
      ${docSection(c)}
      <div class="actions">
        <button type="button" class="btn primary" id="edit">Bearbeiten</button>
        ${c.status!=='gekuendigt'?'<button type="button" class="btn" id="cancel">Als gekündigt markieren</button>':'<button type="button" class="btn" id="cancel">Wieder aktiv</button>'}
        <button type="button" class="btn" id="dup">Kopie anlegen</button>
        <button type="button" class="btn danger" id="del">Löschen</button></div>`,
      s=>{bindDocs(s,c);s.querySelectorAll('[data-show]').forEach(b=>{const f=b.dataset.show,sp=s.querySelector(`[data-mask="${f}"]`);let open=false;
            b.onclick=()=>{open=!open;sp.textContent=open?c[f]:maskVal(c[f]);b.textContent=open?'Verbergen':'Anzeigen'}});
          s.querySelectorAll('[data-copy]').forEach(b=>b.onclick=async()=>{const f=b.dataset.copy;
            try{await navigator.clipboard.writeText(c[f]);buzz(8);toast((f==='kundennr'?'Kundennummer':'Vertragsnummer')+' kopiert.')}
            catch(x){toast('Kopieren hat nicht geklappt. Tippe auf „Anzeigen“ und markiere die Nummer.')}});
          s.querySelector('#dup').onclick=()=>openForm('c',null,false,c);
          s.querySelector('#edit').onclick=()=>openForm('c',c);
          s.querySelector('#cancel').onclick=()=>{const was=c.status==='gekuendigt';c.status=was?'aktiv':'gekuendigt';if(was)delete c.gekuendigtAm;else c.gekuendigtAm=iso(T0);save();render();openDetail('c',id);
            if(was){buzz(8);toast('Wieder als aktiv markiert.')}
            else{celebrate('Gekündigt');toast(`Stark! Ab dem ${fmtD(contractInfo(c).end)} sparst du ${eur(monthly(c)*12)} im Jahr.`)}};
          armDelete(s,()=>{(c.docs||[]).forEach(x=>fileDel(x.id).catch(()=>{}));db.contracts=db.contracts.filter(x=>x.id!==id)})},from);
  }
}
function armDelete(s,fn){const b=s.querySelector('#del');let armed=false;
  b.onclick=()=>{if(!armed){armed=true;buzz(10);b.classList.add('sure');b.textContent='Wirklich löschen?';setTimeout(()=>{if(b.isConnected){armed=false;b.classList.remove('sure');b.textContent='Löschen'}},4000);return}
    buzz([10,40,30]);fn();if(db)db.meta=Object.assign({},db.meta,{dirty:(db.meta&&db.meta.dirty||0)+1});save();closeSheet();render('rows')}}

/* Logo: quadratisch, max. 160 px, Transparenz bleibt erhalten */
function shrinkLogo(file){return new Promise((res,rej)=>{if(file.size>8e6)return rej(new Error('big'));const r=new FileReader();r.onload=()=>{const img=new Image();
  img.onload=()=>{const S=160,w=img.naturalWidth||S,h=img.naturalHeight||S,k=Math.min(S/w,S/h,1)||1;const cv=document.createElement('canvas');
    cv.width=Math.max(1,Math.round(w*k));cv.height=Math.max(1,Math.round(h*k));cv.getContext('2d').drawImage(img,0,0,cv.width,cv.height);
    let out=cv.toDataURL('image/webp',.85);if(!out.startsWith('data:image/webp'))out=cv.toDataURL('image/png');res(out)};
  img.onerror=rej;img.src=r.result};r.onerror=rej;r.readAsDataURL(file)})}
function shrink(file){return new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>{const img=new Image();
  img.onload=()=>{const k=Math.min(1,520/Math.max(img.width,img.height));const cv=document.createElement('canvas');
    cv.width=Math.round(img.width*k);cv.height=Math.round(img.height*k);cv.getContext('2d').drawImage(img,0,0,cv.width,cv.height);res(cv.toDataURL('image/jpeg',.72))};
  img.onerror=rej;img.src=r.result};r.onerror=rej;r.readAsDataURL(file)})}

function openForm(kind,item,camera,tpl){
  const src0=item||tpl;
  kind=kind||(tab==='vertraege'?'c':'d');
  const opt=(arr,sel)=>arr.map(v=>`<option${v===sel?' selected':''}>${v}</option>`).join('');
  const dev=`
    <label class="field"><span>Bezeichnung *</span><input id="f_name" required placeholder="z. B. Geschirrspüler"></label>
    <div class="grid2"><label class="field"><span>Kategorie</span><select id="f_kat">${opt(DEV_KAT,'Technik')}</select></label>
      <label class="field"><span>Standort</span><input id="f_raum" placeholder="Küche"></label></div>
    <div class="grid2"><label class="field"><span>Hersteller</span><input id="f_her"></label>
      <label class="field"><span>Modell</span><input id="f_mod"></label></div>
    <label class="field"><span>Seriennummer</span><input id="f_sn" placeholder="steht auf dem Typenschild"></label>
    <div class="grid2"><label class="field"><span>Kaufdatum *</span><input id="f_kauf" type="date" required value="${iso(T0)}"></label>
      <label class="field"><span>Preis (€)</span><input id="f_preis" type="number" step="0.01" min="0" inputmode="decimal"></label></div>
    <label class="check"><input id="f_ges" type="checkbox"> Kaufdatum nur geschätzt</label>
    <label class="check"><input id="f_rk" type="checkbox"> Auf Raten gekauft / finanziert</label>
    <div class="ratebox" id="f_rbox" hidden>
      <div class="grid2"><label class="field"><span>Monatsrate (€) *</span><input id="f_rb" type="number" step="0.01" min="0" inputmode="decimal"></label>
        <label class="field"><span>Anzahl Raten *</span><input id="f_rn" type="number" step="1" min="1" max="120" inputmode="numeric" placeholder="z. B. 24"></label></div>
      <div class="grid2"><label class="field"><span>Erste Rate am *</span><input id="f_rs" type="date"></label>
        <label class="field"><span>Anzahlung (€)</span><input id="f_ra" type="number" step="0.01" min="0" inputmode="decimal" placeholder="optional"></label></div>
      <div class="grid2"><label class="field"><span>Finanziert über</span><input id="f_rf" placeholder="z. B. Klarna, Santander"></label>
        <label class="field"><span>Finanzierungs-Nr.</span><input id="f_rv" autocomplete="off"></label></div>
      <div class="prev" id="f_rprev" aria-live="polite"></div>
    </div>
    <div class="grid2"><label class="field"><span>Händler</span><input id="f_hae"></label>
      <label class="field"><span>Herstellergarantie</span><select id="f_gar"><option value="0">keine</option><option value="12">1 Jahr</option><option value="24">2 Jahre</option><option value="36">3 Jahre</option><option value="60">5 Jahre</option></select></label></div>
    <label class="field"><span>Kaufnachweis</span><select id="f_nach">${Object.entries(NACHWEIS).map(([k,v])=>`<option value="${k}">${v}</option>`).join('')}</select></label>
    <label class="field"><span>${item&&item.foto?'Foto ersetzen':'Foto von Beleg oder Typenschild'}</span><input id="f_foto" type="file" accept="image/*"></label>
    ${item&&item.foto?'<label class="check"><input id="f_fotoDel" type="checkbox"> Vorhandenes Foto entfernen</label>':''}
    <label class="field"><span>Notizen & Hinweise</span><textarea id="x_note" rows="3" placeholder="${kind==='d'?'z. B. Zubehör im Keller, Reparatur 2025, Ersatzteilnummer …':'z. B. Kündigung nur schriftlich, Ansprechpartner, Treuebonus …'}"></textarea></label>
    ${DOCFIELD}
    <p class="hint">Bei Kontoauszügen vorher alles außer der Buchung schwärzen. Die gesetzliche Gewährleistung von 2 Jahren ab Kauf wird automatisch berechnet.</p>`;
  const con=`
    <label class="field"><span>Anbieter *</span><input id="c_anb" required placeholder="z. B. Spotify"></label>
    <div class="logofield"><div class="tile logo" id="c_logoPrev"${src0&&src0.logo?'':' hidden'}>${src0&&src0.logo?`<img src="${src0.logo}" alt="">`:''}</div>
      <label class="field" style="flex:1"><span>Logo (optional)</span><input id="c_logo" type="file" accept="image/*"></label>
      <button type="button" class="reveal" id="c_logoDel"${src0&&src0.logo?'':' hidden'}>Entfernen</button></div>
    <p class="hint">Tipp: Logo auf der Anbieter-Webseite per langem Druck speichern oder einen Screenshot zuschneiden.</p>
    <label class="field"><span>Kategorie</span><select id="c_kat">${opt(CON_KAT,'Streaming')}</select></label>
    <div class="grid2"><label class="field"><span>Kundennummer</span><input id="c_kd" autocomplete="off"></label>
      <label class="field"><span>Vertragsnummer</span><input id="c_vnr" autocomplete="off"></label></div>
    <div class="grid2"><label class="field"><span>Kosten (€) *</span><input id="c_kost" type="number" step="0.01" min="0" required inputmode="decimal"></label>
      <label class="field"><span>Zahlweise</span><select id="c_int"><option value="1">monatlich</option><option value="3">vierteljährlich</option><option value="12">jährlich</option></select></label></div>
    <label class="field" data-m="beginn ende"><span id="c_knL">Anderer Preis nach der Mindestlaufzeit (€, optional)</span><input id="c_kn" type="number" step="0.01" min="0" inputmode="decimal" placeholder="leer lassen, wenn der Preis gleich bleibt"></label>
    <label class="field"><span>Laufzeit</span><select id="c_mod"><option value="beginn">Aus dem Vertragsbeginn berechnen</option><option value="ende">Aktuelles Laufzeitende selbst angeben</option><option value="offen">Unbefristet, jederzeit kündbar</option></select></label>
    <label class="field" data-m="ende"><span>Aktuelles Laufzeitende *</span><input id="c_end" type="date"></label>
    <div class="grid2" data-m="beginn"><label class="field"><span>Vertragsbeginn *</span><input id="c_beg" type="date" required value="${iso(T0)}"></label>
      <label class="field"><span>Mindestlaufzeit</span><select id="c_lz"><option value="1">1 Monat</option><option value="3">3 Monate</option><option value="6">6 Monate</option><option value="12" selected>12 Monate</option><option value="24">24 Monate</option><option value="36">36 Monate</option></select></label></div>
    <div class="grid2"><label class="field" data-m="beginn ende"><span>Verlängert sich um</span><select id="c_verl"><option value="1">1 Monat</option><option value="3">3 Monate</option><option value="6">6 Monate</option><option value="12">12 Monate</option><option value="24">24 Monate</option></select></label>
      <label class="field"><span>Kündigungsfrist</span><select id="c_fr"><option value="0">jederzeit</option><option value="7">7 Tage</option><option value="14">14 Tage</option><option value="30" selected>1 Monat</option><option value="60">2 Monate</option><option value="90">3 Monate</option></select></label></div>
    <p class="hint" data-m="beginn">Trag immer den <b>ursprünglichen</b> Vertragsbeginn ein, auch wenn der Vertrag schon verlängert wurde. Die App rechnet die Verlängerungen selbst weiter.</p>
    <div class="prev" id="c_prev" aria-live="polite"></div>
    <div class="note" id="c_law" hidden>Verträge, die ab dem 1. März 2022 geschlossen wurden, verlängern sich nach der Mindestlaufzeit meist nur noch auf unbestimmte Zeit und sind dann monatlich kündbar (1 Monat Frist). Prüf kurz deine Unterlagen.
      <button type="button" class="linkbtn" id="c_lawGo" style="display:block;padding-top:6px;color:var(--warn)">Als „unbefristet, 1 Monat Frist“ übernehmen</button></div>
    <label class="field"><span>Notizen & Hinweise</span><textarea id="x_note" rows="3" placeholder="${kind==='d'?'z. B. Zubehör im Keller, Reparatur 2025, Ersatzteilnummer …':'z. B. Kündigung nur schriftlich, Ansprechpartner, Treuebonus …'}"></textarea></label>
    ${DOCFIELD}`;
  openSheet(head(item?'Bearbeiten':tpl?'Vertrag kopieren':'Neuer Eintrag')+`<form id="frm" novalidate>
    ${tpl?`<p class="hint">Kopie von <b>${esc(tpl.anbieter)}</b>. Vertragsnummer und Beginn sind leer bzw. auf heute gesetzt, alles andere ist übernommen.</p>`:''}
    <div class="seg"${item||tpl?' hidden':''}><button type="button" data-k="d" aria-pressed="${kind==='d'}">Gerät</button><button type="button" data-k="c" aria-pressed="${kind==='c'}">Abo / Vertrag</button></div>
    ${kind==='d'?dev:con}<p class="hint" id="err" style="color:var(--crit)" hidden></p>
    <div class="actions"><button type="submit" class="btn primary">Speichern</button><button type="button" class="btn" data-close>Abbrechen</button></div></form>`,
  s=>{
    let logoVal=src0&&src0.logo?src0.logo:undefined;
    const D=docEditor(s,item&&item.docs?item.docs.slice():[],kind==='d'?{cover:item&&item.cover}:null); // Kopien übernehmen keine Dateien
    s.querySelectorAll('.seg button').forEach(b=>b.onclick=()=>openForm(b.dataset.k));
    const v=id=>s.querySelector('#'+id).value.trim();
    const src=item||tpl;
    if(src){ // Felder vorbelegen; fehlende Auswahlwerte ergänzen
      const set=(id,val)=>{const el=s.querySelector('#'+id);if(!el||val==null)return;
        if(el.tagName==='SELECT'&&![...el.options].some(o=>o.value===String(val))){const o=document.createElement('option');o.value=String(val);o.textContent=String(val);el.appendChild(o)}
        el.value=String(val)};
      if(kind==='d'){set('f_name',src.name);set('f_kat',src.kategorie);set('f_raum',src.raum);set('f_her',src.hersteller);set('f_mod',src.modell);
        set('f_sn',src.sn);set('f_kauf',src.kauf);set('f_preis',src.preis||'');set('f_hae',src.haendler);set('f_gar',src.garantieMonate||0);set('f_nach',src.nachweis);set('x_note',src.notiz||'');
        s.querySelector('#f_ges').checked=!!src.geschaetzt;
        if(src.rate){s.querySelector('#f_rk').checked=true;set('f_rb',src.rate.betrag);set('f_rn',src.rate.anzahl);set('f_rs',src.rate.start);
          set('f_ra',src.rate.anzahlung||'');set('f_rf',src.rate.bank||'');if(item)set('f_rv',src.rate.vnr||'')}}
      else{set('c_anb',src.anbieter);set('c_kat',src.kategorie);set('c_kd',src.kundennr);set('c_kost',src.kosten);set('c_kn',src.kostenNach==null?'':src.kostenNach);set('c_int',src.intervall);
        set('c_lz',src.laufzeit);set('c_verl',src.verl);set('x_note',src.notiz||'');set('c_fr',src.frist);set('c_mod',src.modus||'beginn');set('c_end',src.ende||'');
        if(item){if(item.beginn)set('c_beg',item.beginn);set('c_vnr',item.vertragsnr||'')}}
    }
    s.querySelector('#frm').addEventListener('submit',async e=>{e.preventDefault();const err=s.querySelector('#err');let first=false;
      const commitDocs=async()=>{if(D.busy()){err.textContent='Eine Datei wird noch gelesen. Einen Moment …';err.hidden=false;return false}
        try{await D.commit();return true}catch(x){err.textContent='Die Datei konnte nicht gespeichert werden. Vermutlich ist der Speicher voll.';err.hidden=false;return false}};
      if([...s.querySelectorAll('input:not([type])')].some(i=>looksBanky(i.value))||textBanky(s.querySelector('#x_note').value)){
        err.textContent='Ein Feld sieht nach einer IBAN oder Kartennummer aus. Solche Nummern speichert die Belegbox bewusst nicht. Trag höchstens die letzten vier Ziffern ein.';err.hidden=false;return}
      if(kind==='d'){
        if(!v('f_name')||!v('f_kauf')){err.textContent='Bitte Bezeichnung und Kaufdatum ausfüllen.';err.hidden=false;return}
        let foto=item&&item.foto||'';const f=s.querySelector('#f_foto').files[0];
        const fd=s.querySelector('#f_fotoDel');if(fd&&fd.checked)foto='';
        if(f){try{foto=await shrink(f)}catch(x){err.textContent='Das Foto konnte nicht gelesen werden. Versuch es mit einem JPG oder PNG.';err.hidden=false;return}}
        let rate=null;
        if(s.querySelector('#f_rk').checked){
          if(!(parseFloat(v('f_rb'))>0)||!(parseInt(v('f_rn'))>0)||!v('f_rs')){err.textContent='Bitte Monatsrate, Anzahl Raten und erste Rate ausfüllen.';err.hidden=false;return}
          rate={betrag:parseFloat(v('f_rb')),anzahl:parseInt(v('f_rn')),start:v('f_rs'),anzahlung:parseFloat(v('f_ra'))||0,bank:v('f_rf'),vnr:v('f_rv')}}
        if(!await commitDocs())return;
        const dd={name:v('f_name'),kategorie:v('f_kat'),raum:v('f_raum'),hersteller:v('f_her'),modell:v('f_mod'),sn:v('f_sn'),
          kauf:v('f_kauf'),geschaetzt:s.querySelector('#f_ges').checked,preis:parseFloat(v('f_preis'))||0,haendler:v('f_hae'),
          garantieMonate:Number(v('f_gar')),nachweis:v('f_nach'),foto,docs:D.docs,cover:D.cover,rate,notiz:v('x_note')};
        if(item){Object.assign(item,dd);delete item.ex}else{first=!db.devices.some(x=>!x.ex);db.devices.push(Object.assign({id:uid()},dd))}
        tab='geraete';
      } else {
        const md=v('c_mod');
        if(!v('c_anb')||!v('c_kost')){err.textContent='Bitte Anbieter und Kosten ausfüllen.';err.hidden=false;return}
        if(md==='beginn'&&!v('c_beg')){err.textContent='Bitte den Vertragsbeginn ausfüllen.';err.hidden=false;return}
        if(md==='ende'&&!v('c_end')){err.textContent='Bitte das aktuelle Laufzeitende ausfüllen.';err.hidden=false;return}
        if(!await commitDocs())return;
        let logo=logoVal;
        if(logo===undefined){ // gleicher Anbieter hat schon ein Logo? Dann übernehmen
          const twin=db.contracts.find(x=>x!==item&&x.logo&&x.anbieter.trim().toLowerCase()===v('c_anb').toLowerCase());logo=twin?twin.logo:''}
        const cc={logo,anbieter:v('c_anb'),kategorie:v('c_kat'),kundennr:v('c_kd'),vertragsnr:v('c_vnr'),kosten:parseFloat(v('c_kost'))||0,kostenNach:v('c_kn')===''?null:(parseFloat(v('c_kn'))||0),
          intervall:Number(v('c_int')),modus:md,beginn:md==='beginn'?v('c_beg'):(item&&item.beginn||''),ende:md==='ende'?v('c_end'):'',laufzeit:Number(v('c_lz')),verl:Number(v('c_verl')),frist:Number(v('c_fr')),docs:D.docs,notiz:v('x_note')};
        if(item){Object.assign(item,cc);delete item.ex}else db.contracts.push(Object.assign({id:uid(),status:'aktiv'},cc));
        tab='vertraege';
      }
      filter='alle';db.meta=Object.assign({},db.meta,{dirty:(db.meta&&db.meta.dirty||0)+1});save();D.cleanup();closeSheet();render(item?undefined:'rows');
      if(item){buzz(12);toast('Änderungen gespeichert.');openDetail(kind,item.id)}
      else celebrate(first?'Dein erstes Gerät!':'Gespeichert');
    });
    if(kind==='d'){ // Ratenkauf ein-/ausklappen und live durchrechnen
      const rk=s.querySelector('#f_rk'),box=s.querySelector('#f_rbox'),pv=s.querySelector('#f_rprev');
      const upd=()=>{box.hidden=!rk.checked;if(!rk.checked)return;
        const rs=s.querySelector('#f_rs');if(!rs.value&&v('f_kauf'))rs.value=iso(addMonths(parse(v('f_kauf')),1));
        const r=rateInfo({preis:parseFloat(v('f_preis'))||0,rate:{betrag:v('f_rb'),anzahl:v('f_rn'),start:rs.value,anzahlung:v('f_ra')}});
        pv.innerHTML=!r?'':`<div class="label">So rechnet die App</div>
          <div>${r.aktiv?`<b>${r.paid}</b> von ${r.n} Raten bezahlt · Restschuld <b>${eur(r.restschuld)}</b>`:'Bereits komplett abbezahlt'}</div>
          <div>Letzte Rate <b>${fmtD(r.last)}</b> · gesamt <b>${eur(r.total)}</b>${r.mehr!=null&&r.mehr>.005?` (${eur(r.mehr)} mehr als der Kaufpreis)`:''}</div>`};
      s.querySelector('#frm').addEventListener('input',upd);s.querySelector('#frm').addEventListener('change',upd);
      rk.addEventListener('change',()=>{buzz(5);if(rk.checked&&motion())box.animate([{opacity:0,transform:'translateY(-6px)'},{opacity:1,transform:'none'}],{duration:220,easing:'ease-out'})});
      upd();
    }
    if(kind==='c'){ // Logo wählen, Vorschau sofort zeigen
      const li=s.querySelector('#c_logo'),lp=s.querySelector('#c_logoPrev'),ld=s.querySelector('#c_logoDel');
      li.addEventListener('change',async()=>{const f=li.files[0];if(!f)return;
        try{logoVal=await shrinkLogo(f);lp.innerHTML=`<img src="${logoVal}" alt="">`;lp.hidden=false;ld.hidden=false;buzz(6)}
        catch(x){toast('Das Bild konnte nicht gelesen werden. Versuch es mit PNG, JPG oder SVG.')}li.value=''});
      ld.onclick=()=>{logoVal='';lp.hidden=true;lp.innerHTML='';ld.hidden=true;buzz(6)};
    }
    if(kind==='c'){ // Vorschau: was die App aus den Angaben ausrechnet
      const pv=s.querySelector('#c_prev'),law=s.querySelector('#c_law');
      const upd=()=>{const md=v('c_mod'),beg=v('c_beg');
        s.querySelectorAll('[data-m]').forEach(el=>el.hidden=!el.dataset.m.split(' ').includes(md));
        s.querySelector('#c_knL').textContent=md==='ende'?'Anderer Preis nach diesem Laufzeitende (€, optional)':'Anderer Preis nach der Mindestlaufzeit (€, optional)';
        law.hidden=true;
        if((md==='beginn'&&!beg)||(md==='ende'&&!v('c_end'))){pv.innerHTML='';return}
        const t={modus:md,ende:v('c_end'),beginn:beg,laufzeit:Number(v('c_lz')),verl:Number(v('c_verl')),frist:Number(v('c_fr')),status:'aktiv',kosten:parseFloat(v('c_kost'))||0,kostenNach:v('c_kn')};
        const i=contractInfo(t),pc=priceChange(t);
        if(i.offen){pv.innerHTML=`<div class="label">So rechnet die App</div><div>Jederzeit kündbar mit ${FRIST(t.frist)}.</div>
          <div>Bei Kündigung heute endet er am <b>${fmtD(i.end)}</b>.</div>`;return}
        pv.innerHTML=`<div class="label">So rechnet die App</div>
          <div>Nächstes Laufzeitende <b>${fmtD(i.end)}</b>${i.k>0?` · schon <b>${i.k}×</b> verlängert`:''}</div>
          <div>Spätestens kündigen <b>${i.by?fmtD(i.by):'–'}</b>${i.by?` (${inDays(days(i.by))})`:''}</div>
          ${pc?(days(pc.date)<=0?`<div>Aktueller Preis <b>${eur(pc.preis)}</b> (seit ${fmtD(pc.date)})</div>`
            :`<div>Ab ${fmtD(pc.date)} <b>${eur(pc.preis)}</b> statt ${eur(t.kosten)}${pc.preis>t.kosten?' · wer das vermeiden will, kündigt bis '+fmtD(addDays(pc.date,-t.frist)):''}</div>`):''}`;
        law.hidden=!(md==='beginn'&&beg>='2022-03-01'&&t.verl>1)};
      s.querySelector('#frm').addEventListener('input',upd);s.querySelector('#frm').addEventListener('change',upd);
      s.querySelector('#c_lawGo').onclick=()=>{s.querySelector('#c_mod').value='offen';s.querySelector('#c_fr').value='30';buzz(6);upd()};
      upd();
    }
    if(camera&&kind==='d'){ // „Beleg fotografieren“: Kamera direkt öffnen
      const fi=s.querySelector('#f_foto');fi.setAttribute('capture','environment');s.querySelector('#f_nach').value='beleg';fi.click();
    }else{const first=s.querySelector('input');if(first)first.focus({preventScroll:true})}
  });
}

function openMenu(){
  openSheet(head('Daten & Sicherheit')+`
    <div class="secline"><svg viewBox="0 0 24 24" fill="none" stroke="var(--ok)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>
      Verschlüsselt mit AES-256${vmeta&&vmeta.bio?' · Fingerabdruck an':''} · sperrt nach 5 Min. ohne Eingabe oder 1 Min. im Hintergrund</div>
    <p class="hint" style="margin-bottom:14px">${ghCfg()?'Deine Daten liegen verschlüsselt in diesem Browser und als verschlüsselte Sicherung in deinem privaten GitHub-Repo. Sonst wird nichts gesendet.':'Deine Daten liegen nur verschlüsselt in diesem Browser und werden nirgendwohin gesendet.'} Dein Passwort wird nicht gespeichert.</p>
    <form id="pwf" novalidate style="margin-bottom:18px">
      <div class="label">Passwort ändern</div>
      <label class="field"><span>Aktuelles Passwort</span><input id="pw0" type="password" autocomplete="current-password"></label>
      <div class="grid2"><label class="field"><span>Neues Passwort</span><input id="pw1" type="password" autocomplete="new-password"></label>
        <label class="field"><span>Wiederholen</span><input id="pw2" type="password" autocomplete="new-password"></label></div>
      <p class="hint" id="pwerr" style="color:var(--crit)" hidden></p>
      <div class="actions"><button type="submit" class="btn" id="pwgo">Passwort ändern</button></div>
    </form>
    ${bioPossible()?`<div class="label" style="margin-bottom:8px">Fingerabdruck</div>
    <p class="hint" style="margin-bottom:10px">${vmeta&&vmeta.bio?'Entsperren per Fingerabdruck ist eingeschaltet. Das Passwort funktioniert weiterhin und bleibt für den Notfall wichtig.':'Entsperre die Belegbox mit Fingerabdruck oder Gesichtserkennung statt mit dem Passwort. Dafür wird ein Passkey „Belegbox“ in deinem Passwortmanager angelegt.'}</p>
    <div class="actions" style="margin-bottom:6px"><button type="button" class="btn${vmeta&&vmeta.bio?'':' primary'}" id="bioBtn">${vmeta&&vmeta.bio?'Ausschalten':'Einschalten'}</button></div>
    <p class="hint" id="bioMsg" hidden></p><div style="height:12px"></div>`:''}
    <div class="label" style="margin-bottom:8px">Automatische Sicherung (GitHub)</div>
    ${ghCfg()?`<p class="hint" style="margin-bottom:6px">Nach jeder Änderung landet der verschlüsselte Tresor in <b>${esc(db.meta.gh.owner)}/${esc(db.meta.gh.repo)}</b>. GitHub sieht nur verschlüsselte Daten.</p>
      <p class="hint" id="ghStatus" style="margin-bottom:10px;display:flex;gap:8px;align-items:center">${ghStatusText()}</p>
      ${ghStat.conflict?`<div class="note" style="background:var(--crit-soft);margin-bottom:10px">Im Repo liegt ein anderer Tresor (z. B. von einem früheren Gerät). Er bleibt in der Versionsgeschichte von GitHub erhalten, wenn du ihn ersetzt.
        <div class="actions" style="margin-top:8px"><button type="button" class="btn primary" id="ghPull">Stattdessen den GitHub-Stand laden</button><button type="button" class="btn danger" id="ghForce">Durch diesen Tresor ersetzen</button></div></div>`:''}
      <div class="actions" style="margin-bottom:18px"><button type="button" class="btn primary" id="ghNow">Jetzt sichern</button><button type="button" class="btn" id="ghOff">Trennen</button></div>`
    :`<p class="hint" style="margin-bottom:10px">Sichert den verschlüsselten Tresor und alle Dokumente nach jeder Änderung in ein <b>privates</b> GitHub-Repo – auch wenn Browserdaten gelöscht werden, bleibt alles erhalten.</p>
      <div class="grid2"><label class="field"><span>Konto / Organisation</span><input id="gh_o" value="jazm-belegbox" autocomplete="off" autocapitalize="off"></label>
        <label class="field"><span>Repo</span><input id="gh_r" value="belegbox-daten" autocomplete="off" autocapitalize="off"></label></div>
      <label class="field" style="margin-top:12px"><span>Zugangsschlüssel (github_pat_…)</span><input id="gh_t" type="password" autocomplete="off"></label>
      <p class="hint" id="gh_msg" hidden></p>
      <div class="actions" style="margin:10px 0 18px"><button type="button" class="btn primary" id="gh_go">Verbinden & sichern</button></div>`}
    <div class="label" style="margin-bottom:8px">Kalender</div>
    <p class="hint" style="margin-bottom:10px">Exportiert alle Kündigungsfristen und Garantie-Enden als Termine mit Erinnerung 7 Tage und 1 Tag vorher. Nach neuen Einträgen einfach erneut exportieren, bestehende Termine werden aktualisiert.</p>
    <label class="check" style="margin-bottom:10px"><input id="icsNeutral" type="checkbox" checked> Neutrale Titel (keine Anbieter oder Geräte im Kalender)</label>
    <div class="actions" style="margin-bottom:18px"><button type="button" class="btn" id="icsGo">Fristen in Kalender exportieren</button></div>
    <div class="label" style="margin-bottom:8px">Sicherung</div>
    <p class="hint" style="margin-bottom:10px">Die Sicherung ist mit deinem aktuellen Passwort verschlüsselt und enthält auch alle PDFs und Dokumente. ${db.meta&&db.meta.lastBackup?'Letzte Sicherung: '+fmtD(parse(db.meta.lastBackup))+'.':'Bisher keine Sicherung.'}</p>
    <div class="actions" style="margin-bottom:6px"><button type="button" class="btn primary" id="bkGo">Sicherung erstellen</button>
      <label class="btn" style="cursor:pointer">Sicherung laden<input id="bkIn" type="file" accept=".belegbox,application/json" hidden></label></div>
    <p class="hint" id="bkMsg" hidden></p>
    <div id="bkConfirm" hidden style="margin:8px 0"><p class="hint" style="color:var(--crit);margin-bottom:8px">Die Daten auf diesem Gerät werden durch die Sicherung ersetzt.</p>
      <div class="actions"><button type="button" class="btn danger sure" id="bkYes">Ersetzen</button><button type="button" class="btn" id="bkNo">Abbrechen</button></div></div>
    <p class="hint" style="margin:6px 0 18px">${persisted===true?'Dauerhafter Speicher ist aktiv.':persisted===false?'Der Browser hat dauerhaften Speicher nicht zugesagt. Installiere die App auf dem Startbildschirm und sichere regelmäßig.':''}</p>
    <div class="label" style="margin-bottom:8px">Einträge</div>
    <div class="actions"><button type="button" class="btn" id="m_ex">Beispieldaten laden</button><button type="button" class="btn danger" id="del">Alle Einträge löschen</button></div>`,
  s=>{s.querySelector('#pwf').addEventListener('submit',async e=>{e.preventDefault();const er=s.querySelector('#pwerr'),go=s.querySelector('#pwgo');
       const p0=s.querySelector('#pw0').value,p1=s.querySelector('#pw1').value,p2=s.querySelector('#pw2').value;
       const fail=m=>{er.textContent=m;er.hidden=false;go.disabled=false;go.textContent='Passwort ändern'};
       if(p1.length<10)return fail('Das neue Passwort braucht mindestens 10 Zeichen.');
       if(p1!==p2)return fail('Die neuen Passwörter stimmen nicht überein.');
       er.hidden=true;go.disabled=true;go.textContent='Wird neu verschlüsselt …';
       try{await changePassword(p0,p1)}catch(x){return fail('Das aktuelle Passwort ist falsch.')}
       closeSheet();celebrate('Neu verschlüsselt');toast('Passwort geändert. Deine Daten sind neu verschlüsselt.')});
     const bb=s.querySelector('#bioBtn');
     if(bb)bb.onclick=async()=>{const m=s.querySelector('#bioMsg');m.hidden=true;bb.disabled=true;
       try{ if(vmeta.bio){await disableBio();closeSheet();toast('Fingerabdruck ausgeschaltet. Den Passkey „Belegbox“ kannst du im Passwortmanager löschen.')}
            else{await enableBio();closeSheet();celebrate('Fingerabdruck an');toast('Fingerabdruck eingeschaltet. Probier es gleich mit „Sperren“ aus.')} }
       catch(x){bb.disabled=false;m.textContent=x&&x.name==='NotAllowedError'?'Abgebrochen.':(x&&x.name==='InvalidStateError'?'Für dieses Gerät gibt es schon einen Belegbox-Passkey. Lösche ihn im Passwortmanager und versuch es erneut.':(x&&x.message)||'Das hat nicht geklappt.');
         m.style.color='var(--crit)';m.hidden=false}};
     const ghGo=s.querySelector('#gh_go');
     if(ghGo)ghGo.onclick=async()=>{const m=s.querySelector('#gh_msg');
       const g={owner:s.querySelector('#gh_o').value.trim(),repo:s.querySelector('#gh_r').value.trim(),token:s.querySelector('#gh_t').value.trim()};
       const say=(t,bad)=>{m.textContent=t;m.style.color=bad?'var(--crit)':'';m.hidden=false};
       if(!g.owner||!g.repo||!g.token)return say('Bitte alle drei Felder ausfüllen.',true);
       ghGo.disabled=true;say('Prüfe Zugang …');
       try{const info=await ghFetch(g,'GET','');
         if(!info)throw Object.assign(new Error(),{status:404});
         if(!info.private){ghGo.disabled=false;return say('Dieses Repo ist öffentlich. Aus Sicherheitsgründen sichert die Belegbox nur in private Repos.',true)}
         if(info.permissions&&info.permissions.push===false){ghGo.disabled=false;return say('Der Schlüssel darf in dieses Repo nicht schreiben. Setze „Contents“ auf „Read and write“.',true)}
       }catch(x){ghGo.disabled=false;return say(ghErrText(x),true)}
       db.meta=Object.assign({},db.meta,{gh:g});setGhStat({err:'',at:0,conflict:false});await save();
       openMenu();ghSync().then(()=>{if(!ghStat.err){celebrate('GitHub verbunden');toast('Automatische Sicherung ist aktiv.')}else openMenu()})};
     const ghN=s.querySelector('#ghNow');if(ghN)ghN.onclick=async()=>{await ghSync();if(!ghStat.err){buzz(10);toast('Auf GitHub gesichert.')}};
     const ghP=s.querySelector('#ghPull');if(ghP){let armed=false;ghP.onclick=async()=>{
       if(!armed){armed=true;ghP.textContent='Ersetzt die Daten auf diesem Gerät – nochmal tippen';return}
       ghP.disabled=true;ghP.textContent='Lade von GitHub …';
       try{const o=await ghRestore(ghCfg());await saving;await restoreVault(o);setGhStat({err:'',conflict:false})}catch(x){ghP.disabled=false;ghP.textContent='Stattdessen den GitHub-Stand laden';toast(x&&x.status?ghErrText(x):(x&&x.message||'Das hat nicht geklappt.'))}}}
     const ghF=s.querySelector('#ghForce');if(ghF)ghF.onclick=async()=>{await ghSync(true);openMenu();if(!ghStat.err)celebrate('Gesichert')};
     const ghX=s.querySelector('#ghOff');if(ghX){let armed=false;ghX.onclick=()=>{if(!armed){armed=true;ghX.classList.add('danger','sure');ghX.textContent='Wirklich trennen?';return}
       const m=Object.assign({},db.meta);delete m.gh;db.meta=m;setGhStat({err:'',at:0,conflict:false});save();openMenu();toast('GitHub getrennt. Im Repo bleibt alles liegen.')}}
     s.querySelector('#icsGo').onclick=async()=>{const r=buildIcs(s.querySelector('#icsNeutral').checked);
       if(!r.count){toast('Gerade stehen keine Fristen an.');return}
       if(await deliverFile('belegbox-fristen.ics',r.text,'text/calendar'))toast(r.count+' Termine exportiert. Öffne die Datei mit deinem Kalender.')};
     s.querySelector('#bkGo').onclick=exportBackup;
     let pending=null;const msg=s.querySelector('#bkMsg'),cf=s.querySelector('#bkConfirm'),bi=s.querySelector('#bkIn');
     bi.addEventListener('change',async()=>{const file=bi.files[0];if(!file)return;msg.hidden=true;
       try{pending=await readBackupFile(file);cf.hidden=false}catch(x){msg.textContent=x.message;msg.style.color='var(--crit)';msg.hidden=false}bi.value=''});
     s.querySelector('#bkNo').onclick=()=>{pending=null;cf.hidden=true};
     s.querySelector('#bkYes').onclick=()=>{if(pending)saving.then(()=>restoreVault(pending))};
     s.querySelector('#m_ex').onclick=()=>{const sm=samples();db.devices=db.devices.filter(x=>!x.ex).concat(sm.devices);db.contracts=db.contracts.filter(x=>!x.ex).concat(sm.contracts);save();closeSheet();render('rise')};
     armDelete(s,()=>{db={devices:[],contracts:[]};fileClear().catch(()=>{})})});
}

/* ---------- Tabs: Antippen oder Wischen ---------- */
const TABS=['home','geraete','vertraege'];
const ind=document.querySelector('nav.tabs .ind');
function setInd(x,drag){if(!ind)return;ind.classList.toggle('drag',!!drag);ind.style.setProperty('--ti',String(x))}
let tabBusy=false;
function goTab(t,fromX){
  if(!db||tabBusy)return;
  const a=TABS.indexOf(tab),b=TABS.indexOf(t);
  if(a===b){window.scrollTo({top:0,behavior:motion()?'smooth':'auto'});return}
  const dir=b>a?1:-1;tab=t;filter='alle';setInd(b);buzz(6);
  if(fanOpen)setFan(false);
  if(!motion()){render();window.scrollTo(0,0);return}
  tabBusy=true;setTimeout(()=>{tabBusy=false},700);
  const W=main.clientWidth||innerWidth,x0=fromX||0,op=main.style.opacity||'1';
  main.style.transform='';main.style.opacity='';
  const out=main.animate([{transform:`translateX(${x0}px)`,opacity:op},{transform:`translateX(${-dir*W*.45}px)`,opacity:0}],
    {duration:fromX?150:120,easing:'cubic-bezier(.4,0,1,1)',fill:'forwards'});
  out.onfinish=()=>{window.scrollTo(0,0);render('tab');out.cancel();
    main.animate([{transform:`translateX(${dir*W*.3}px)`,opacity:0},{transform:'none',opacity:1}],{duration:340,easing:'cubic-bezier(.2,.85,.25,1)'})
      .onfinish=()=>{tabBusy=false}};
}
document.querySelectorAll('nav.tabs button').forEach(b=>b.onclick=()=>goTab(b.dataset.tab));

/* ---------- Neu-Knopf als Fächer ---------- */
const fab=document.getElementById('fab'),fan=document.getElementById('fan');
let fanOpen=false;
function setFan(open){
  if(open===fanOpen)return;fanOpen=open;
  fab.classList.toggle('open',open);fab.setAttribute('aria-expanded',String(open));fab.setAttribute('aria-label',open?'Schließen':'Neu');
  if(open){fan.hidden=false;void fan.offsetWidth;fan.classList.add('show');buzz(6)}
  else{fan.classList.remove('show');setTimeout(()=>{if(!fanOpen)fan.hidden=true},motion()?260:0)}
}
fab.onclick=()=>setFan(!fanOpen);
fan.addEventListener('click',e=>{const b=e.target.closest('[data-new]');setFan(false);if(!b)return;
  const k=b.dataset.new;if(k==='photo')openForm('d',null,true);else openForm(k)});

/* ---------- Wischen zwischen Tabs & Zum Aktualisieren ziehen ---------- */
const appEl=document.querySelector('.app'),ptr=document.getElementById('ptr');
let G=null,refreshing=false,swReg=null;
document.addEventListener('touchstart',e=>{G=null;
  if(e.touches.length!==1||!key||!db||tabBusy||fanOpen||root.firstElementChild)return;
  const t=e.target;if(!appEl.contains(t)||(t.closest&&t.closest('input,select,textarea')))return;
  const ch=t.closest&&t.closest('.chips'),p=e.touches[0];
  G={x:p.clientX,y:p.clientY,mode:null,chips:!!(ch&&ch.scrollWidth>ch.clientWidth+2),dx:0,dy:0,v:0,lx:p.clientX,ly:p.clientY,lt:performance.now(),
     W:appEl.clientWidth||innerWidth,idx:TABS.indexOf(tab),hit:false,edge:false};
},{passive:true});
document.addEventListener('touchmove',e=>{
  if(!G)return;const p=e.touches[0],dx=p.clientX-G.x,dy=p.clientY-G.y;
  if(!G.mode){
    if(Math.abs(dx)<10&&Math.abs(dy)<10)return;
    if(Math.abs(dx)>Math.abs(dy)*1.3&&!G.chips)G.mode='h';
    else if(dy>0&&window.scrollY<=0&&!refreshing&&Math.abs(dy)>Math.abs(dx))G.mode='v';
    else{G=null;return}
  }
  if(e.cancelable)e.preventDefault();
  const now=performance.now(),dt=Math.max(1,now-G.lt);
  if(G.mode==='h'){
    G.v=.7*((p.clientX-G.lx)/dt)+.3*G.v;G.lx=p.clientX;G.lt=now;
    G.edge=(G.idx===0&&dx>0)||(G.idx===TABS.length-1&&dx<0);
    const x=G.edge?dx*.2:dx;G.dx=x;
    main.style.transform=`translateX(${x}px)`;main.style.opacity=String(1-Math.min(.35,Math.abs(x)/G.W*.5));
    setInd(G.edge?G.idx:G.idx-x/G.W,true);
    const over=!G.edge&&Math.abs(x)>G.W*.28;if(over!==G.hit){G.hit=over;if(over)buzz(5)}
  }else{
    G.ly=p.clientY;G.lt=now;
    const pull=Math.min(120,dy*.5);G.dy=pull;
    appEl.style.transform=`translateY(${pull}px)`;
    ptr.style.opacity=String(Math.min(1,pull/28));ptr.style.transform=`translateY(${pull-52}px) rotate(${Math.min(1,pull/72)*300}deg)`;
    const over=pull>=72;if(over!==G.hit){G.hit=over;ptr.classList.toggle('armed',over);if(over)buzz(8)}
  }
},{passive:false});
function gEnd(e){
  if(!G||!G.mode){G=null;return}const g=G;G=null;const ok=e.type==='touchend';
  if(g.mode==='h'){
    const go=ok&&!g.edge&&(Math.abs(g.dx)>g.W*.28||(Math.abs(g.v)>.45&&Math.sign(g.v)===Math.sign(g.dx)&&Math.abs(g.dx)>30));
    if(go){goTab(TABS[g.idx-Math.sign(g.dx)],g.dx);return}
    const from=main.style.transform,op=main.style.opacity;main.style.transform='';main.style.opacity='';setInd(g.idx);
    if(motion()&&from)main.animate([{transform:from,opacity:op||'1'},{transform:'none',opacity:1}],{duration:360,easing:'cubic-bezier(.2,.9,.3,1.15)'});
  }else{
    const from=appEl.style.transform;appEl.style.transform='';
    if(motion()&&from)appEl.animate([{transform:from},{transform:'none'}],{duration:400,easing:'cubic-bezier(.2,.9,.3,1.1)'});
    if(ok&&g.hit)refresh();else hidePtr();
  }
}
document.addEventListener('touchend',gEnd);document.addEventListener('touchcancel',gEnd);
function hidePtr(){
  const from=ptr.style.transform;ptr.style.transform='';ptr.style.opacity='';ptr.classList.remove('armed','spin');
  if(motion()&&from)ptr.animate([{transform:from,opacity:1},{transform:'translateY(-70px) scale(.5)',opacity:0}],{duration:260,easing:'ease-in'});
}
async function refresh(){
  refreshing=true;ptr.classList.add('armed','spin');ptr.style.transform='translateY(16px)';ptr.style.opacity='1';buzz(10);
  const t=Date.now();let upd=false;
  T0=sod(new Date()); // Fristen ab heute neu berechnen
  try{if(swReg){await swReg.update();upd=!!(swReg.waiting||swReg.installing)}}catch(x){}
  await new Promise(r=>setTimeout(r,Math.max(0,750-(Date.now()-t))));
  refreshing=false;hidePtr();if(!db)return;
  render('rise');toast(upd?'Neue Version gefunden. Tippe oben auf „Aktualisieren“.':'Alles aktuell. Fristen sind neu berechnet.');
}

/* ---------- Kippen & Glanz über den Lagesensor ---------- */
let tgt=[0,0],cur=[0,0],base=null,traf=0,tiltOn=false;
addEventListener('deviceorientation',e=>{
  if(!key||!motion()||e.beta==null||e.gamma==null||document.hidden)return;
  const g=e.gamma,b=e.beta;
  if(!base)base=[g,b];
  base[0]+=(g-base[0])*.02;base[1]+=(b-base[1])*.02; // passt sich langsam an die Haltung an
  tgt=[clamp((g-base[0])/14,-1,1),clamp((b-base[1])/14,-1,1)];
  if(!tiltOn){tiltOn=true;document.documentElement.classList.add('tilt')}
  if(!traf)traf=requestAnimationFrame(tstep);
});
function tstep(){traf=0;
  cur[0]+=(tgt[0]-cur[0])*.16;cur[1]+=(tgt[1]-cur[1])*.16;
  const st=document.documentElement.style;
  st.setProperty('--tx',cur[0].toFixed(3));st.setProperty('--ty',cur[1].toFixed(3));st.setProperty('--gm',Math.min(1,Math.hypot(cur[0],cur[1])*1.5).toFixed(3));
  if(Math.abs(tgt[0]-cur[0])+Math.abs(tgt[1]-cur[1])>.004)traf=requestAnimationFrame(tstep);
}

document.getElementById('menuBtn').onclick=()=>{setFan(false);openMenu()};
document.getElementById('lockBtn').onclick=()=>lock(true);
boot();

/* Service Worker: offline nutzbar, Hinweis bei neuer Version */
if('serviceWorker' in navigator){
  let reloading=false;const hadController=!!navigator.serviceWorker.controller;
  // Nur neu laden, wenn eine bestehende Version abgelöst wird – nicht beim allerersten Installieren
  navigator.serviceWorker.addEventListener('controllerchange',()=>{if(reloading||!hadController)return;reloading=true;location.reload()});
  navigator.serviceWorker.register('sw.js').then(reg=>{swReg=reg;
    const offer=w=>{const r=document.getElementById('updRoot');
      r.innerHTML='<div class="upd" role="status"><span>Neue Version der Belegbox verfügbar</span><button type="button" id="updGo">Aktualisieren</button><button type="button" id="updX" aria-label="Später">✕</button></div>';
      document.getElementById('updGo').onclick=()=>saving.then(()=>w.postMessage('SKIP_WAITING'));
      document.getElementById('updX').onclick=()=>{r.innerHTML=''}};
    if(reg.waiting&&navigator.serviceWorker.controller)offer(reg.waiting);
    reg.addEventListener('updatefound',()=>{const w=reg.installing;if(!w)return;
      w.addEventListener('statechange',()=>{if(w.state==='installed'&&navigator.serviceWorker.controller)offer(w)})});
    setInterval(()=>reg.update().catch(()=>{}),60*60e3);
  }).catch(()=>{});
}
})();
