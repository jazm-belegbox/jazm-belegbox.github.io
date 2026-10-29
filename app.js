(function(){
const APP_VERSION='0.10.1.0';
/* Eigener Speicher je Adresse: die Live-App unter / behält ihre Namen, eine Test-App unter /test/ bekommt eigene */
const BASE=location.pathname.replace(/[^/]*$/,'');
const NS=BASE==='/'?'':BASE.replace(/^\/|\/$/g,'').replace(/[^a-z0-9]+/gi,'-').toLowerCase()+'-';
const IS_TEST=!!NS;
const KEY=NS+'belegbox-v1';
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
const spanTxt=n=>{if(n<60)return n+' Tag'+(n===1?'':'en');const m=Math.round(n/30.44);
  if(m<24)return m+' Monaten';const y=Math.floor(m/12),r=m%12;return y+' Jahren'+(r?' und '+r+' Monat'+(r>1?'en':''):'')};
const restTxt=n=>{if(n<60)return n+' Tag'+(n===1?'':'e');const m=Math.round(n/30.44);
  if(m<24)return m+' Monate';const y=Math.floor(m/12),r=m%12;return y+' Jahre'+(r?' und '+r+' Monat'+(r>1?'e':''):'')};
const inDays=n=>n===0?'heute':n===1?'morgen':n<0?'vor '+(-n)+' Tagen':'in '+spanTxt(n);

const NACHWEIS={beleg:'Kassenbon / Rechnung',konto:'Kontoauszug',mail:'Bestellmail',keiner:'Kein Nachweis'};
const INTERVALL={1:'monatlich',3:'vierteljährlich',6:'halbjährlich',12:'jährlich'};
const DEV_KAT=['Technik','Küche','Haushalt','Werkzeug','Möbel','Gesundheit','Sonstiges'];
const CON_KAT=['Streaming','Handy & Internet','Versicherung','Energie','Fitness','Software','Gesundheit','Sonstiges'];

/* Beispieldaten gibt es nicht mehr; ältere, unveränderte Beispieleinträge lassen sich über den Hinweis oben entfernen. */

/* Verschlüsselter Tresor (Format 2)
   - Ein zufälliger Datenschlüssel (256 Bit) verschlüsselt alle Einträge mit AES-256-GCM.
   - Der Datenschlüssel liegt nur verpackt im Speicher: einmal mit dem Passwort (PBKDF2, SHA-256),
     optional zusätzlich mit dem Fingerabdruck (Passkey mit PRF-Erweiterung, HKDF).
   - Klartext und Schlüssel existieren nur im Arbeitsspeicher, solange die App entsperrt ist. */
const VKEY=NS+'belegbox-vault-v1', ITER=600000, IDLE_MS=5*60e3, BG_MS=60e3;
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
let vaultJson=null; // aktueller verschlüsselter Tresor (Text), wird beim Start aus dem Speicher geladen
function readVault(){try{return vaultJson?JSON.parse(vaultJson):null}catch(e){return null}}
/* Speichern: zuerst IndexedDB (viel Platz) – schlägt das fehl, gilt das Speichern als fehlgeschlagen.
   Danach eine Zweitkopie in localStorage (max. ca. 5 MB). Passt sie nicht mehr hinein, wird die alte Kopie
   entfernt, damit nie ein veralteter Stand geladen werden kann. */
async function writeVaultStr(json){
  await filePut(MIRROR,json);vaultJson=json;
  try{localStorage.setItem(VKEY,json)}catch(e){try{localStorage.removeItem(VKEY)}catch(x){}}
}
async function persist(){
  if(!key||!db||!vmeta)return;
  const box=await seal(key,te.encode(JSON.stringify(db)));
  const json=JSON.stringify(Object.assign({},vmeta,{v:2,iv:box.iv,ct:box.ct,saved:Date.now()}));
  await writeVaultStr(json);
}
/* ---------- Automatische Sicherung in ein privates GitHub-Repo ----------
   Hochgeladen wird nur bereits Verschlüsseltes: vault.json (= Tresor wie im Browser) und files/<id>.bin (IV + Chiffretext).
   Zugangsdaten liegen verschlüsselt im Tresor (db.meta.gh). Im Repo wird nie automatisch etwas gelöscht. */
const GH_API='https://api.github.com',GH_LS=NS+'belegbox-gh-status';
let ghTimer=0,ghBusy=false,ghAgain=null,ghPending=null;
let ghStat=(()=>{try{return JSON.parse(localStorage.getItem(GH_LS))||{}}catch(e){return {}}})();
function setGhStat(o){const prev=ghStat.err||'';ghStat=Object.assign({},ghStat,o);if(db)setTimeout(()=>{try{const g=ghCfg();DS.lockDot(document.getElementById('lockBtn'),{ghErr:g?(ghStat.err||''):'',ghOk:!!(g&&ghStat.at&&!ghStat.err),own:db.devices.length+db.contracts.length>0,days:db.meta&&db.meta.lastBackup?-days(parse(db.meta.lastBackup)):null,dirty:db.meta&&db.meta.dirty||0})}catch(e){}},0);try{localStorage.setItem(GH_LS,JSON.stringify(ghStat))}catch(e){}
  const el=document.getElementById('ghStatus');if(el)el.innerHTML=ghStatusText();if(db&&!root.firstElementChild&&o.err!==undefined&&(o.err||'')!==prev)render()}
function ghCfg(){const g=db&&db.meta&&db.meta.gh;return g&&g.token&&g.owner&&g.repo?Object.assign({},g):null}
/* Optionaler Ordner im Repo: so können alle drei Boxen in ein gemeinsames Repo sichern */
const bkDir=v=>String(v||'').trim().replace(/^\/+|\/+$/g,'').replace(/[^\w.\/-]/g,'');
async function ghFetch(g,method,path,body,raw){
  path=g.dir&&path.startsWith('/contents/')?'/contents/'+encodeURI(g.dir)+'/'+path.slice(10):g.dir&&path==='/contents'?'/contents/'+encodeURI(g.dir):path;
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
  if(ghBusy)return '⏳ Wird gesichert …';
  if(ghStat.err)return `<span style="color:var(--crit)">${esc(ghStat.err)}</span>`;
  if(ghStat.at){const m=Math.round((Date.now()-ghStat.at)/60000);return `✓ Zuletzt gesichert ${m<1?'gerade eben':m<60?'vor '+m+' Min.':m<1440?'vor '+Math.round(m/60)+' Std.':'am '+fmtD(new Date(ghStat.at))}.`}
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
    const local=vaultJson; // genau der Stand, der zuletzt erfolgreich gespeichert wurde
    if(!local||!vaultOk(local))throw new Error('local');
    const lv=JSON.parse(local);
    // 1) Belege/Dokumente, die im Repo noch fehlen (Dateien ändern sich nie, daher reicht der Name)
    const ids=allDocIds();
    if(ids.length){
      const list=await ghFetch(g,'GET','/contents/files');const have=new Set((list||[]).map(x=>String(x.name).replace(/\.bin$/,'')));
      for(const id of ids){if(have.has(id))continue;const f=await fileGet(id).catch(()=>null);if(!f)continue;
        const u=new Uint8Array(12+f.ct.byteLength);u.set(new Uint8Array(f.iv),0);u.set(new Uint8Array(f.ct),12);
        await ghFetch(g,'PUT',`/contents/files/${id}.bin`,{message:'MyBelegBox: Dokument',content:toB64(u)})}
    }
    // 2) Tresor – aber nie einen fremden Tresor überschreiben
    for(let attempt=0;attempt<2;attempt++){
      const {cur,json}=await ghRemoteVault(g);
      if(json===local)break;
      if(cur&&!force){let rv=null;try{rv=JSON.parse(json)}catch(e){}
        if(!rv||(rv.vid!==lv.vid)){const e=new Error('conflict');e.conflict=true;throw e}}
      try{await ghFetch(g,'PUT','/contents/vault.json',{message:'MyBelegBox-Sicherung '+new Date().toLocaleString('de-DE'),content:toB64(te.encode(local)),sha:cur?cur.sha:undefined});break}
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
  const {json}=await ghRemoteVault(g);if(!json||!vaultOk(json))throw new Error('Im Repo wurde keine MyBelegBox-Sicherung gefunden.');
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
    if(mOk&&(!ok||vaultTime(m)>=vaultTime(raw))){ // IndexedDB ist neuer oder gleich alt: das ist der Stand
      vaultJson=m;
      if(raw&&!ok){try{localStorage.setItem(VKEY+'-defekt-'+Date.now(),raw)}catch(e){}}
      if(raw!==m){try{localStorage.setItem(VKEY,m)}catch(e){try{localStorage.removeItem(VKEY)}catch(x){}}}
    }else if(ok){ // nur localStorage hat einen (neueren) Stand – z. B. erster Start nach dem Update: in IndexedDB übernehmen
      vaultJson=raw;await filePut(MIRROR,raw).catch(()=>{});
      if(mOk)setTimeout(()=>toast('Der Tresor wurde aus der Zweitkopie wiederhergestellt.'),800);
    }
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
async function createVault(pw){
  const salt=rnd(16);const kek=await deriveKey(pw,salt,ITER);
  dekRaw=rnd(32);key=await importDek(dekRaw);
  vmeta={iter:ITER,salt:toB64(salt),wrapPw:await seal(kek,dekRaw),bio:null,vid:toB64(rnd(12))};
  let old=null;try{old=JSON.parse(localStorage.getItem(KEY))}catch(e){}
  db=old&&Array.isArray(old.devices)?old:{devices:[],contracts:[]};
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
function lock(anim){saving.then(()=>{if(histPushed){histPushed=false;ignorePop=true;try{history.back()}catch(e){ignorePop=false}}key=null;db=null;if(dekRaw)dekRaw.fill(0);dekRaw=null;vmeta=null;closeViewer();closeSheet(false);setFan(false);main.innerHTML='';shown={};showLock(anim===true)})}

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
    rp:{name:'MyBelegBox',id:location.hostname},user:{id:rnd(16),name:'MyBelegBox',displayName:'MyBelegBox'},challenge:rnd(32),
    pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],timeout:60000,attestation:'none',
    authenticatorSelection:{authenticatorAttachment:'platform',residentKey:'preferred',userVerification:'required'},
    extensions:{prf:{eval:{first:prfSalt}}}}});
  const ext=cred.getClientExtensionResults?cred.getClientExtensionResults():{};
  const NOPRF='Dein Passwortmanager unterstützt das Entsperren per Fingerabdruck nicht (häufig bei Samsung Pass). Stell als Passkey-Anbieter den Google Passwortmanager ein und versuch es erneut. Den eben angelegten Passkey „MyBelegBox“ kannst du löschen.';
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
/* Feier-Effekt: gemeinsamer Baustein in ds.js; großes Konfetti bei besonderen Momenten */
const BIG_YAY=new Set(['Gekündigt','Update online','GitHub verbunden','Erste Sicherung','Dein erstes Gerät!']);
function celebrate(text){if(!motion()){buzz([12,50,24]);if(text)toast(text);return}DS.yay(text,BIG_YAY.has(text))}
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
const CAM='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 8h3l2-3h6l2 3h3a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1z"/><circle cx="12" cy="13" r="3.5"/></svg>';
const SHIELD='<svg viewBox="0 0 24 24" fill="none" stroke="var(--accent-ink)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>';
let lockTok=0;
let autoBioNext=true,bioPrompt=null;
function showLock(closing){
  const tok=++lockTok;
  document.body.classList.add('locked');
  const L=document.getElementById('lock');L.classList.remove('leaving');L.getAnimations&&L.getAnimations().forEach(a=>a.cancel());
  const vault=readVault();const setup=!vault;
  const bio=!setup&&vault.bio&&bioPossible();
  L.innerHTML=`<div class="lock"><form class="lockcard" id="lf" novalidate>
    ${VAULT}
    ${setup?`<h2>MyBelegBox</h2>
      <p>Lege ein Passwort fest (mind. 10 Zeichen). Ohne Passwort sind die Daten nicht wiederherstellbar.</p>
      <label class="field"><span>Passwort (mind. 10 Zeichen)</span><input id="lp1" type="password" placeholder="Passwort" autocomplete="new-password" minlength="10"></label>
      <label class="field"><span>Passwort wiederholen</span><input id="lp2" type="password" placeholder="Passwort wiederholen" autocomplete="new-password"></label>
      ${bootInfo.broken?`<div class="note" style="background:var(--crit-soft)"><b>Achtung:</b> Auf diesem Gerät liegt ein Tresor, der sich nicht lesen lässt. Speichere ihn zuerst, bevor du neu anfängst.
        <button type="button" class="linkbtn" id="lraw" style="display:block;color:var(--crit)">Beschädigten Tresor als Datei speichern</button></div>`:''}
      ${bootInfo.orphans?`<div class="note" style="background:var(--crit-soft)"><b>Achtung:</b> Auf diesem Gerät liegen noch ${bootInfo.orphans>1?bootInfo.orphans+' verschlüsselte Dokumente':'ein verschlüsseltes Dokument'}, aber kein Tresor. Hast du eine Sicherung, stell sie unten wieder her, statt neu anzufangen.</div>`:''}
      ${bootInfo.broken||bootInfo.orphans?'<label class="check"><input id="lnew" type="checkbox"> Ich möchte trotzdem einen neuen, leeren Tresor anlegen</label>':''}`
    :`<h2>MyBelegBox</h2><p>Deine Belege und Verträge, verschlüsselt auf diesem Gerät.</p>
      <label class="field"><span>Passwort</span><input id="lp1" type="password" placeholder="Passwort" autocomplete="current-password"></label>`}
    <p class="hint" id="lerr" style="color:var(--crit)" hidden></p>
    <button type="submit" class="btn primary" id="lgo">${setup?'MyBelegBox anlegen':'Entsperren'}</button>
    ${bio?`<button type="button" class="btn bio" id="lbio">${FINGER}Mit Fingerabdruck entsperren</button>`:''}
    ${setup?`<label class="linkbtn" style="cursor:pointer">Neues Handy? Sicherung wiederherstellen<input id="lrestore" type="file" accept=".belegbox,application/json" hidden></label>
      <button type="button" class="linkbtn" id="lghOpen">Aus GitHub wiederherstellen</button>
      <div class="ghbox" id="lgh" hidden>
        <label class="field"><span>Konto / Organisation</span><input id="lgo_o" value="jazm-belegbox" autocomplete="off" autocapitalize="off"></label>
        <label class="field"><span>Repo</span><input id="lgo_r" value="belegbox-daten" autocomplete="off" autocapitalize="off"></label>
        <label class="field"><span>Ordner im Repo (optional)</span><input id="lgo_d" value="" placeholder="leer lassen oder z. B. belegbox" autocomplete="off" autocapitalize="off"></label>
        <label class="field"><span>Zugangsschlüssel (github_pat_…)</span><input id="lgo_t" type="password" autocomplete="off"></label>
        <p class="hint" id="lgo_msg" hidden></p>
        <button type="button" class="btn primary" id="lgo_go">Sicherung von GitHub laden</button></div>`
      :'<button type="button" class="linkbtn" id="lreset">Passwort vergessen? Tresor zurücksetzen</button>'}
    <p class="hint lver">Version ${APP_VERSION}${IS_TEST?' · <b style="color:var(--warn)">Test-App, eigener Speicher</b>':''}</p>
  </form></div>`;
  const f=L.querySelector('#lf'),err=L.querySelector('#lerr'),go=L.querySelector('#lgo'),V=L.querySelector('.vault');
  // Beim Sperren schließt sich die Tresortür
  if(closing&&motion()){V.classList.add('open','instant');void V.offsetWidth;V.classList.remove('instant');void V.offsetWidth;
    requestAnimationFrame(()=>V.classList.remove('open'));L.animate([{opacity:0},{opacity:1}],{duration:220,easing:'ease-out'})}
  const shake=()=>{buzz([30,50,30]);if(!motion())return;
    [V,...L.querySelectorAll('.field')].forEach(el=>{el.classList.remove('no');void el.offsetWidth;el.classList.add('no')});
    setTimeout(()=>L.querySelectorAll('.no').forEach(el=>el.classList.remove('no')),450)};
  const fail=m=>{V.classList.remove('busy');err.textContent=m;err.hidden=false;go.disabled=false;go.textContent=setup?'MyBelegBox anlegen':'Entsperren';shake()};
  f.addEventListener('submit',async e=>{e.preventDefault();err.hidden=true;
    const p1=L.querySelector('#lp1').value;
    if(!window.crypto||!crypto.subtle)return fail('Dieser Browser unterstützt keine Verschlüsselung. Öffne die Seite in einem aktuellen Browser.');
    if(setup){const p2=L.querySelector('#lp2').value,ln=L.querySelector('#lnew');
      if(ln&&!ln.checked)return fail('Bitte zuerst eine Sicherung wiederherstellen – oder bestätigen, dass du neu anfangen möchtest.');
      if(p1.length<10)return fail('Das Passwort braucht mindestens 10 Zeichen.');
      if(p1!==p2)return fail('Die Passwörter stimmen nicht überein.');}
    go.disabled=true;go.textContent=setup?'Wird verschlüsselt …':'Wird entschlüsselt …';V.classList.add('busy');
    try{ setup?await createVault(p1):await unlock(p1) }
    catch(x){return fail(setup?'Der Tresor konnte nicht angelegt werden. Prüfe, ob der Browser Speicher erlaubt.':'Das Passwort ist falsch.')}
    opened();
  });
  // Entsperrt: Rad dreht, Tür schwingt auf, App kommt dahinter hervor
  function opened(){
    V.classList.remove('busy');
    document.body.classList.remove('locked');lastAct=Date.now();tab='home';filter='alle';shown={};askPersist();buzz([10,40,18]);setTimeout(cleanFiles,5000);setTimeout(()=>ghQueue(0),3000);
    afterUnlock();
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
  const tryBio=async auto=>{if(!lb||lb.disabled||!lb.isConnected)return;err.hidden=true;lb.disabled=true;
    try{await unlockBio();opened()}
    catch(x){lb.disabled=false;
      if(x&&x.name==='NotAllowedError'){if(auto)return;err.textContent='Abgebrochen. Tippe erneut oder nutze dein Passwort.'}
      else{err.textContent='Entsperren per Fingerabdruck hat nicht geklappt. Bitte nutze dein Passwort.';shake()}
      err.hidden=false}};
  if(lb){lb.onclick=()=>tryBio(false);
    // Beim Öffnen der App bzw. Zurückholen aus dem Hintergrund sofort nach dem Fingerabdruck fragen
    bioPrompt=()=>{if(!document.hidden&&!key)setTimeout(()=>tryBio(true),closing?0:350)};
    if(autoBioNext&&!closing){autoBioNext=false;bioPrompt()}}
  else bioPrompt=null;
  autoBioNext=false;
  const lr=L.querySelector('#lraw');if(lr)lr.onclick=()=>{let r='';try{r=localStorage.getItem(VKEY)||''}catch(e){}deliverFile('belegbox-tresor-beschaedigt.txt',r,'text/plain')};
  const gho=L.querySelector('#lghOpen');
  if(gho){gho.onclick=()=>{const b=L.querySelector('#lgh');b.hidden=!b.hidden;if(!b.hidden)L.querySelector('#lgo_t').focus()};
    L.querySelector('#lgo_go').onclick=async()=>{const m=L.querySelector('#lgo_msg'),bt=L.querySelector('#lgo_go');
      const g={owner:L.querySelector('#lgo_o').value.trim(),repo:L.querySelector('#lgo_r').value.trim(),token:L.querySelector('#lgo_t').value.trim()};const dd=bkDir(L.querySelector('#lgo_d').value);if(dd)g.dir=dd;
      if(!g.owner||!g.repo||!g.token){m.textContent='Bitte alle drei Felder ausfüllen.';m.style.color='var(--crit)';m.hidden=false;return}
      bt.disabled=true;m.style.color='';m.hidden=false;m.textContent='Lade Tresor …';V.classList.add('busy');
      try{const o=await ghRestore(g,(i,n)=>{m.textContent=`Lade Dokumente … ${i} von ${n}`});V.classList.remove('busy');await restoreVault(o)}
      catch(x){V.classList.remove('busy');bt.disabled=false;m.style.color='var(--crit)';m.textContent=x&&x.status?ghErrText(x):(x&&x.message||'Das hat nicht geklappt.');shake()}}}
  const rf=L.querySelector('#lrestore');
  if(rf)rf.addEventListener('change',async()=>{const file=rf.files[0];if(!file)return;
    try{restoreVault(await readBackupFile(file))}catch(x){fail(x.message)}});
  const rs=L.querySelector('#lreset');
  if(rs){let armed=false;rs.onclick=()=>{if(!armed){armed=true;buzz(10);rs.classList.add('sure');rs.textContent='Wirklich alles löschen? Nochmal tippen';return}
    try{localStorage.removeItem(VKEY)}catch(e){}vaultJson=null;fileClear().catch(()=>{});showLock()}}
  if(!bio){const first=L.querySelector('input');if(first)first.focus({preventScroll:true})}
}

/* Dateien weitergeben: Teilen-Menü (z. B. Google Drive), sonst normaler Download */
async function deliverFile(name,text,type){
  const file=new File([text],name,{type});allowAway();
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
const IDB_NAME=NS+'belegbox-files',STORE='files';
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
  V.hidden=false;document.body.style.overflow='hidden';buzz(6);layerOpened();
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
  V.hidden=true;V.innerHTML='';if(!root.firstElementChild)document.body.style.overflow='';layerClosed()}

/* Verschlüsselte Sicherung: enthält nur den bereits verschlüsselten Tresor */
async function exportBackup(){
  const first=!(db.meta&&db.meta.lastBackup);db.meta=Object.assign({},db.meta,{lastBackup:iso(T0),dirty:0});
  await save();
  const v=readVault();if(!v){toast('Es gibt noch nichts zu sichern.');return}
  const files={};
  for(const id of allDocIds()){const r=await fileGet(id).catch(()=>null);if(r)files[id]={iv:toB64(r.iv),ct:toB64(r.ct)}}
  const payload=JSON.stringify({app:'belegbox',format:2,exported:new Date().toISOString(),version:APP_VERSION,vault:v,files});
  const ok=await deliverFile('belegbox-sicherung-'+iso(T0)+'.belegbox',payload,'application/json');
  if(ok){celebrate(first?'Erste Sicherung':'Gesichert');toast('Sicherung erstellt. Leg die Datei an einem zweiten Ort ab, z. B. in deiner Cloud.');render()}
}
function readBackupFile(file){return new Promise((res,rej)=>{const r=new FileReader();
  r.onload=()=>{try{const o=JSON.parse(r.result);const v=o&&o.app==='belegbox'&&o.vault;
      if(!v||typeof v.salt!=='string'||typeof v.iv!=='string'||typeof v.ct!=='string')throw new Error('format');res({vault:v,files:o.files&&typeof o.files==='object'?o.files:{}})}
    catch(e){rej(new Error('Das ist keine gültige MyBelegBox-Sicherung.'))}};
  r.onerror=()=>rej(new Error('Die Datei konnte nicht gelesen werden.'));
  if(file.size>400e6)return rej(new Error('Die Datei ist zu groß für eine MyBelegBox-Sicherung.'));
  r.readAsText(file)})}
async function restoreVault(o){let fileErr=false;
  try{await fileClear();for(const [id,f] of Object.entries(o.files||{}))await filePut(id,{iv:fromB64(f.iv),ct:fromB64(f.ct).buffer})}catch(x){fileErr=true}
  const vj=JSON.stringify(o.vault);
  try{await writeVaultStr(vj)}catch(e){toast('Die Sicherung passt nicht in den Speicher des Handys. Gib im Browser Speicherplatz frei und versuch es erneut.');return}
  bootInfo={orphans:0,broken:false};key=null;db=null;closeViewer();closeSheet(false);main.innerHTML='';showLock();
  toast(fileErr?'Sicherung geladen, aber nicht alle Dokumente passten in den Speicher. Entsperre mit dem Passwort, das beim Sichern galt.':'Sicherung geladen. Entsperre sie mit dem Passwort, das beim Sichern galt.')}

/* Kalenderexport (.ics) mit Erinnerung 7 Tage und 1 Tag vorher */
function icsEsc(s){return String(s).replace(/\\/g,'\\\\').replace(/;/g,'\\;').replace(/,/g,'\\,').replace(/\r?\n/g,'\\n')}
function icsDay(d){return d.getFullYear()+String(d.getMonth()+1).padStart(2,'0')+String(d.getDate()).padStart(2,'0')}
function buildIcs(neutral){
  const stamp=new Date().toISOString().replace(/[-:]/g,'').replace(/\.\d+Z$/,'Z');
  const ev=[];
  db.contracts.filter(c=>c.status!=='gekuendigt').forEach(c=>{const i=contractInfo(c);if(!i.by)return;
    ev.push({uid:c.id+'-frist',date:i.by,title:neutral?'MyBelegBox: Kündigungsfrist':'Kündigungsfrist: '+c.anbieter,
      desc:neutral?'Details in der MyBelegBox.':`Spätestens heute kündigen, sonst verlängert sich ${c.anbieter} am ${fmtD(i.end)}.`})});
  db.devices.forEach(d=>{const i=deviceInfo(d);
    [['gew','Gewährleistung',i.gew],['gar','Herstellergarantie',i.gar]].forEach(([k,t,dt])=>{if(!dt||days(dt)<0)return;
      ev.push({uid:d.id+'-'+k,date:dt,title:neutral?'MyBelegBox: '+t+' endet':t+' endet: '+d.name,
        desc:neutral?'Details in der MyBelegBox.':`${t} für ${d.name} läuft heute ab. Mängel vorher melden.`})})});
  const L=['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//MyBelegBox//DE','CALSCALE:GREGORIAN','METHOD:PUBLISH','X-WR-CALNAME:MyBelegBox-Fristen'];
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
['pointerdown','keydown','scroll','touchstart','input','change'].forEach(ev=>addEventListener(ev,()=>{lastAct=Date.now()},{passive:true,capture:true}));
/* Wer Datei-Auswahl, Kamera oder Teilen-Menü öffnet, ist kurz in einer anderen App – dann nicht sperren
   (höchstens 10 Minuten lang, danach greift die Sperre wieder) */
let awayUntil=0;const allowAway=ms=>{awayUntil=Date.now()+(ms||10*60e3)};
document.addEventListener('click',e=>{const t=e.target;if(!t||!t.closest)return;
  const inp=t.matches('input[type=file]')?t:(t.closest('label')&&t.closest('label').querySelector('input[type=file]'));if(inp)allowAway()},true);
setInterval(()=>{if(key&&Date.now()-lastAct>IDLE_MS)lock()},10000);
document.addEventListener('visibilitychange',()=>{if(document.hidden){hiddenAt=Date.now();return}
  const away=Date.now()<awayUntil;awayUntil=0;
  if(key&&hiddenAt&&Date.now()-hiddenAt>BG_MS&&!away){autoBioNext=true;lock()}
  else if(!key&&bioPrompt)bioPrompt()});

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
  db.contracts.filter(c=>c.status!=='gekuendigt').forEach(c=>{const i=contractInfo(c);if(!i.by)return;const n=days(i.by);const w=weiterOn(c);
    if(n<=60) ev.push({date:i.by,n,title:c.anbieter,sub:w?'Läuft bewusst weiter':'Letzter Kündigungstag',kind:'c',id:c.id,weiter:w})});
  db.devices.forEach(d=>{const i=deviceInfo(d);
    [['Gewährleistung',i.gew],['Herstellergarantie',i.gar]].forEach(([t,dt])=>{if(!dt)return;const n=days(dt);
      if(n>=0&&n<=90) ev.push({date:dt,n,title:d.name,sub:'Ende '+t,kind:'d',id:d.id})});
    const ri=rateInfo(d);if(ri&&ri.aktiv){const n=days(ri.last);if(n>=0&&n<=60)ev.push({date:ri.last,n,title:d.name,sub:`Letzte Rate · dann ${eur(ri.b)} weniger`,kind:'d',id:d.id})}});
  db.contracts.filter(c=>c.status!=='gekuendigt').forEach(c=>{const p=priceChange(c);if(!p)return;const n=days(p.date);
    if(n>=0&&n<=60) ev.push({date:p.date,n,title:c.anbieter,sub:`Neuer Preis ${eur(p.preis)} (bisher ${eur(c.kosten)})`,kind:'c',id:c.id})});
  return ev.sort((a,b)=>a.n-b.n);
}

/* Render */
const main=document.getElementById('main');
const NOTEICON='<svg class="ni" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-label="hat Notiz"><path d="M5 4h14v11l-5 5H5z"/><path d="M14 20v-5h5M8 9h8M8 13h4"/></svg>';
const noteBlock=it=>it.notiz?`<div class="label" style="margin-bottom:8px">Notizen & Hinweise</div><div class="notetext">${esc(it.notiz)}</div>`:'';
/* Kleines Bild für „Demnächst fällig“: Logo, Gerätefoto oder PDF-Vorschau, sonst Anfangsbuchstabe */
function evMini(e){
  if(e.kind==='c'){const c=db.contracts.find(x=>x.id===e.id);if(!c)return '';
    return c.logo?`<span class="mini logo"><img src="${c.logo}" alt=""></span>`:`<span class="mini ic">${catIcon(c.kategorie)}</span>`}
  const d=db.devices.find(x=>x.id===e.id);if(!d)return '';
  const t=devThumb(d);
  return t?`<span class="mini"><img src="${t.src}" alt=""${t.top?' style="object-position:top"':''}></span>`:`<span class="mini ic">${catIcon(d.kategorie)}</span>`}
const ICON_PATHS={
  'Technik':'<rect x="3" y="5" width="18" height="12" rx="2"/><path d="M8 21h8M12 17v4"/>',
  'Küche':'<path d="M5 9h12v6a5 5 0 0 1-5 5h-2a5 5 0 0 1-5-5z"/><path d="M17 11h1.5a2.5 2.5 0 0 1 0 5H17"/><path d="M9 3c-1 1.2 1 2 0 3.5M13 3c-1 1.2 1 2 0 3.5"/>',
  'Haushalt':'<rect x="4" y="3" width="16" height="18" rx="2"/><circle cx="12" cy="13" r="4.5"/><path d="M8 6.5h.01M11 6.5h.01"/>',
  'Werkzeug':'<path d="M14.7 6.3a4 4 0 0 0 5 5L12 19a2.1 2.1 0 0 1-3-3l7.7-7.7a4 4 0 0 0-2-2z"/><path d="M5 19l2-2"/>',
  'Möbel':'<path d="M5 11V7a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v4"/><path d="M3 13a2 2 0 0 1 4 0v2h10v-2a2 2 0 0 1 4 0v4H3z"/><path d="M5 17v2M19 17v2"/>',
  'Streaming':'<rect x="3" y="5" width="18" height="14" rx="3"/><path d="M10 9.5v5l4.5-2.5z"/>',
  'Handy & Internet':'<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/>',
  'Versicherung':'<path d="M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6z"/>',
  'Energie':'<path d="M13 2L5 13h6l-1 9 8-11h-6z"/>',
  'Fitness':'<path d="M6.5 7v10M17.5 7v10M3.5 9.5v5M20.5 9.5v5M6.5 12h11"/>',
  'Software':'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M8 13l-2 2 2 2M12 17h4"/>',
  'Sonstiges':'<path d="M21 8l-9-5-9 5 9 5z"/><path d="M3 8v8l9 5 9-5V8M12 13v8"/>'
};
function catIcon(k){return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON_PATHS[k]||ICON_PATHS.Sonstiges}</svg>`}
function conTile(c){return c.logo?`<div class="tile logo"><img src="${c.logo}" alt=""></div>`:`<div class="tile ic">${catIcon(c.kategorie)}</div>`}
/* Kachelbild eines Geräts: gewähltes Titelbild > Foto > erstes Bild-Dokument > erste PDF-Seite */
function devThumb(d){const ds=(d.docs||[]).filter(x=>x.thumb);
  const c=d.cover&&ds.find(x=>x.id===d.cover);if(c)return {src:c.thumb,top:c.type==='application/pdf'};
  if(d.foto)return {src:d.foto,top:false};
  const im=ds.find(x=>x.type!=='application/pdf');if(im)return {src:im.thumb,top:false};
  return ds[0]?{src:ds[0].thumb,top:true}:null}
function tileFor(d){const t=devThumb(d);
  return t?`<div class="tile"><img src="${t.src}" alt=""${t.top?' style="object-position:top"':''}></div>`:`<div class="tile ic">${catIcon(d.kategorie)}</div>`}
/* Erinnerung an die Datensicherung: gemeinsamer Baustein in ds.js */
const dsRemindHtml=(o,attr)=>DS.remindHtml(o,attr);
function render(mode){
  if(!db)return;
  document.querySelectorAll('nav.tabs button').forEach(b=>b.setAttribute('aria-current',b.dataset.tab===tab?'page':'false'));
  setInd(TABS.indexOf(tab));
  const hasEx=db.devices.some(x=>x.ex)||db.contracts.some(x=>x.ex);
  document.getElementById('banner').innerHTML=hasEx?`<div class="banner slim"><span><b>Beispieldaten</b> zum Ausprobieren</span><button type="button" id="clearEx">Entfernen</button></div>`:'';
  const own=db.devices.some(x=>!x.ex)||db.contracts.some(x=>!x.ex);
  const lb=db.meta&&db.meta.lastBackup?parse(db.meta.lastBackup):null;
  const dirty=db.meta&&db.meta.dirty||0;
  const ghOn=!!ghCfg(),ghOk=ghOn&&!ghStat.err&&ghStat.at;
  const bkO={ghErr:ghOn?(ghStat.err||''):'',ghOk:!!ghOk,own,days:lb?-days(lb):null,dirty};
  const remind=dsRemindHtml(bkO,'id="dsRemind"');DS.lockDot(document.getElementById('lockBtn'),bkO);
  const ce=document.getElementById('clearEx'); if(ce) ce.onclick=()=>{db.devices=db.devices.filter(x=>!x.ex);db.contracts=db.contracts.filter(x=>!x.ex);save();buzz(10);render('rows')};
  main.innerHTML= tab==='home'?remind+viewHome(): tab==='geraete'?viewDevices(): viewContracts();
  const rmd=document.getElementById('dsRemind');if(rmd)rmd.onclick=()=>{menuAcc='gh';openMenu()};
  main.querySelectorAll('[data-open]').forEach(el=>el.onclick=()=>openDetail(el.dataset.kind,el.dataset.open,el));
  main.querySelectorAll('[data-filter]').forEach(el=>el.onclick=()=>{if(filter===el.dataset.filter)return;filter=el.dataset.filter;buzz(5);render('rows')});
  main.querySelectorAll('[data-goto]').forEach(el=>el.onclick=()=>goTab(el.dataset.goto));
  const gb=document.getElementById('gaugeBtn');if(gb)gb.onclick=()=>dsForm('Monatsbudget',[{k:'b',l:'Budget für Fixkosten pro Monat (€)',v:db.meta&&db.meta.budget?String(db.meta.budget).replace('.',','):''}],async(v,fail)=>{
    const t=String(v.b||'').trim().replace(/\./g,'').replace(',','.'),n=t?parseFloat(t):0;if(t&&!(n>0))return fail('Bitte einen Betrag größer 0 eintragen – oder leer lassen.');
    db.meta=Object.assign({},db.meta,{budget:n||0});save();render();buzz(8)},{ok:'Speichern',html:'<p class="ds-dlg-intro">Die Nadel im Tachometer zeigt dann, wie viel deines Budgets die Fixkosten belegen. Leer lassen schaltet die Nadel aus.</p>'});
  if(tab==='home'){bindCheck();const rg=main.querySelector('#revGo');if(rg)rg.onclick=openReview}
  else if(tab==='geraete')bindToolbar(DEV_F,DEV_S,'sortD',db.devices);
  else bindToolbar(CON_F,CON_S,'sortC',db.contracts);
  updBadge();
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
        ${mon>0?gauge(kats,mon):''}
        <div class="bigcost${mon>0?' ongauge':''}"><span class="num" data-count="mon" data-v="${mon}" data-f="eur">${eur(mon)}</span><small><span data-count="jahr" data-v="${mon*12}" data-f="eur">${eur(mon*12)}</span> im Jahr · ${dayTxt(mon*12/365)} am Tag</small></div></div>
      ${kats.length?`<div class="bars">${kats.map(([k,v],i)=>`<div class="bar"><span class="bl"><i class="gdot" style="background:${GCOL[i%GCOL.length]}"></i>${esc(k)}</span><div class="track"><div class="fill" style="width:${Math.max(4,v/max*100)}%;background:${GCOL[i%GCOL.length]}"></div></div><span class="num">${eur(v)}</span></div>`).join('')}</div>`:''}
      <div class="facts">
        <button type="button" class="fact" data-goto="vertraege"><b class="num" data-count="akt" data-v="${act.length}">${act.length}</b><span>Verträge aktiv</span></button>
        <button type="button" class="fact" data-goto="geraete"><b class="num" data-count="ger" data-v="${db.devices.length}">${db.devices.length}</b><span>Geräte<br><small class="num">Wert ${eur(wert).replace(',00','')}</small></span></button>
        <button type="button" class="fact${ohne?' warn':''}" data-goto="geraete"><b class="num" data-count="ohne" data-v="${ohne}">${ohne}</b><span>ohne Beleg</span></button>
      </div>
    </div>
    ${reviewSeason()?`<button type="button" class="revbanner" id="revGo"><span class="label">Jahresrückblick</span><b>Dein MyBelegBox-Jahr ${reviewYear()} ist da</b><span>Ansehen →</span></button>`:''}
    ${checkCard()}
    <div class="sechead"><h2>Demnächst fällig</h2><span class="label">nächste 90 Tage</span></div>
    <div class="list">${ev.length?ev.map(e=>`<button type="button" class="row" data-kind="${e.kind}" data-open="${e.id}">
        ${(()=>{const cd=!e.weiter&&e.n>=0&&e.n<=14&&e.sub==='Letzter Kündigungstag';return `<div class="date${cd?' cdate'+(e.n<=3?' hot':e.n<=7?' warm':''):''}"${cd?` title="Noch ${e.n} ${e.n===1?'Tag':'Tage'} zum Kündigen"`:''}>${cd?`<svg viewBox="0 0 46 46" preserveAspectRatio="none" aria-hidden="true"><rect x="1.5" y="1.5" width="43" height="43" rx="9" pathLength="100" class="cdt"/><rect x="1.5" y="1.5" width="43" height="43" rx="9" pathLength="100" class="cdf" style="stroke-dasharray:${(Math.max(0,Math.min(1,e.n/14))*100).toFixed(1)} 100"/></svg>`:''}<b>${e.date.getDate()}</b><span>${e.date.toLocaleDateString('de-DE',{month:'short'}).replace('.','')}</span></div>`})()}
        <div class="evmain">${evMini(e)}<div style="min-width:0"><div class="t">${esc(e.title)}</div><div class="s">${esc(e.sub)}</div></div></div>
        <span class="pillwrap"><span class="pill ${e.weiter?'p-none':e.n<=14?'p-crit':e.n<=45?'p-warn':'p-ok'}">${e.weiter?'läuft weiter':inDays(e.n)}</span></span></button>`).join('')
      :`<div class="empty">Keine Fristen in den nächsten 90 Tagen.</div>`}</div>
    ${ohne?`<div class="sechead"><h2>Ohne Nachweis</h2><button type="button" class="ghost" data-goto="geraete">Alle Geräte</button></div>
    <div class="list">${db.devices.filter(d=>d.nachweis==='keiner').map(devRow).join('')}</div>
    <details class="tip"><summary>Wo finde ich alte Kaufbelege?</summary><p>Bestellhistorie bei Online-Händlern, alte Bestellmails und Kontoauszüge durchsuchen. Für die Gewährleistung reicht oft jeder plausible Kaufnachweis.</p></details>`:''}
  </section>`;
}
/* Kosten-Tachometer: Halbkreis aus den Kategorien, die Nadel fährt beim Öffnen hoch */
const GCOL=['var(--accent)','var(--gold)','#3B82C4','var(--warn)','#8E5BC9','var(--ok)','#C2477A','var(--muted)'];
function gauge(kats,total){
  const R=80,C=Math.PI*R,cx=100,cy=96;let off=0;
  const segs=kats.map(([k,v],i)=>{const len=v/total*C,seg=`<path d="M${cx-R} ${cy} A${R} ${R} 0 0 1 ${cx+R} ${cy}" pathLength="${C.toFixed(2)}" class="gseg" style="stroke:${GCOL[i%GCOL.length]};stroke-dasharray:${Math.max(0,len-1.5).toFixed(2)} ${C.toFixed(2)};stroke-dashoffset:${(-off).toFixed(2)};--i:${i}"/>`;off+=len;return seg}).join('');
  const ticks=[...Array(11)].map((_,i)=>{const a=Math.PI*(1-i/10),r1=R+12,r2=R+(i%5?16:19);return `<line x1="${(cx+r1*Math.cos(a)).toFixed(1)}" y1="${(cy-r1*Math.sin(a)).toFixed(1)}" x2="${(cx+r2*Math.cos(a)).toFixed(1)}" y2="${(cy-r2*Math.sin(a)).toFixed(1)}"/>`}).join('');
  /* Mit Monatsbudget zeigt die Nadel, wie viel davon die Fixkosten verbrauchen */
  const bud=Number(db.meta&&db.meta.budget)||0,q=bud?total/bud:0,ang=Math.min(1.08,q)*180-90;
  const lbl=bud?`${Math.round(q*100)} % von ${eur(bud).replace(',00','')} Budget`:'Budget festlegen';
  return `<button type="button" class="gauge${bud?' hasbud':''}${q>1?' over':''}" id="gaugeBtn" aria-label="Monatsbudget: ${esc(lbl)}"><svg viewBox="0 0 200 106" aria-hidden="true"><path d="M${cx-R} ${cy} A${R} ${R} 0 0 1 ${cx+R} ${cy}" class="gtrack"/>${segs}<g class="gticks">${ticks}</g>${bud?`<g class="gneedle" style="--a:${ang.toFixed(1)}deg"><line x1="${cx}" y1="${cy}" x2="${cx}" y2="${cy-R+8}"/><circle cx="${cx}" cy="${cy}" r="6"/></g>`:''}</svg><span class="glbl">${esc(lbl)}</span></button>`;
}
/* Kündigungs-Countdown: siehe Datumskachel in „Demnächst fällig“ (schrumpfender Rand in den letzten 14 Tagen) */
/* Garantie-Ampel: farbiger Rand in der Geräteliste */
function gzClass(d){const p=prot(d);if(!p)return '';if(p.left<0)return ' gz-none';if(p.left<=60)return ' gz-crit';return p.f<.5?' gz-warn':' gz-ok'}
/* Garantie-Ring: wie viel vom Schutz noch übrig ist, grün → gelb → rot */
function prot(d){const i=deviceInfo(d);if(!i.best)return null;
  const total=Math.max(1,(i.best.date-i.kauf)/864e5),left=days(i.best.date);
  return {f:clamp(left/total,0,1),left,typ:i.best.typ,months:Math.round(total/30.44)}}
function ringColor(f){return f>=.5?`color-mix(in srgb, var(--ok) ${Math.round((f-.5)*200)}%, var(--gold))`:`color-mix(in srgb, var(--gold) ${Math.round(f*200)}%, var(--crit))`}
function ring(f,size,w){const r=(size-w)/2,c=+(2*Math.PI*r).toFixed(2),h=size/2;
  return `<svg class="ring" viewBox="0 0 ${size} ${size}" style="--c:${c}" aria-hidden="true"><circle class="trk" cx="${h}" cy="${h}" r="${r}" stroke-width="${w}"/>${f==null?'':
    `<circle class="arc" cx="${h}" cy="${h}" r="${r}" stroke-width="${w}" stroke-dasharray="${c}" stroke-dashoffset="${(c*(1-f)).toFixed(2)}" transform="rotate(-90 ${h} ${h})" style="stroke:${ringColor(f)}"/>`}</svg>`}
function tileWrap(d){const p=prot(d);return `<div class="tw">${ring(p?p.f:null,46,3.5)}${tileFor(d)}</div>`}
function devRow(d){const i=deviceInfo(d);return `<button type="button" class="row${gzClass(d)}" data-kind="d" data-open="${d.id}">
  ${tileWrap(d)}<div class="main"><div class="t">${esc(d.name)}${d.notiz?NOTEICON:''}</div><div class="s">${esc([d.hersteller,d.raum].filter(Boolean).concat((d.geschaetzt?'ca. ':'')+i.kauf.getFullYear()).join(' · '))}</div><div class="pl">${devPill(d)}${(r=>r&&r.aktiv?` <span class="pill p-none">Rate ${eur(r.b)} · noch ${r.rest} von ${r.n}</span>`:'')(rateInfo(d))}</div></div>
  ${amtFor(d)}</button>`}
/* Betrag rechts: bei Ratenkauf Endsumme, bisher gezahlt und Fortschritt */
function amtFor(d){const r=rateInfo(d);
  if(!r)return `<span class="amt num">${d.preis?eur(d.preis):'–'}</span>`;
  const bez=r.paid*r.b+Number(d.rate.anzahlung||0);
  return `<span class="amt num ramt" aria-label="Endsumme ${eur(r.total)}, davon bezahlt ${eur(bez)}">${eur(r.total)}
    <small>${r.aktiv?'bezahlt '+eur(bez):'abbezahlt'}</small><span class="mbar"><i style="width:${Math.round(bez/r.total*100)}%"></i></span></span>`}
const DEV_F={alle:['Alle Geräte',()=>true,'Alle'],schutz:['Mit Garantie oder Gewährleistung',d=>!!deviceInfo(d).best,'Geschützt'],bald:['Schutz endet bald',d=>{const b=deviceInfo(d).best;return b&&days(b.date)<=60},'Endet bald'],ohne:['Ohne Kaufbeleg',d=>d.nachweis==='keiner','Ohne Beleg'],raten:['Auf Raten',d=>!!rateInfo(d),'Raten']};
const DEV_S={name:['Name (A–Z)',(a,b)=>a.name.localeCompare(b.name,'de'),'Name'],schutz:['Schutz endet zuerst',(a,b)=>{const x=deviceInfo(a).best,y=deviceInfo(b).best;return (x?x.date:Infinity)-(y?y.date:Infinity)},'Schutzende'],
  kauf:['Neueste zuerst',(a,b)=>parse(b.kauf)-parse(a.kauf),'Neueste'],preis:['Teuerste zuerst',(a,b)=>Number(b.preis||0)-Number(a.preis||0),'Preis']};
const CON_F={alle:['Alle Verträge',()=>true,'Alle'],aktiv:['Aktiv',c=>c.status!=='gekuendigt','Aktiv'],bald:['Frist in 45 Tagen',c=>c.status!=='gekuendigt'&&!weiterOn(c)&&contractInfo(c).by&&days(contractInfo(c).by)<=45,'Frist bald'],gek:['Gekündigt',c=>c.status==='gekuendigt','Gekündigt']};
const CON_S={frist:['Nächste Frist zuerst',(a,b)=>{const x=contractInfo(a),y=contractInfo(b);return (x.by||x.end)-(y.by||y.end)},'Frist'],kosten:['Teuerste zuerst',(a,b)=>monthly(b)-monthly(a),'Kosten'],name:['Name (A–Z)',(a,b)=>a.anbieter.localeCompare(b.anbieter,'de'),'Name']};
const UIK=NS+'belegbox-ui';let ui=(()=>{try{return JSON.parse(localStorage.getItem(UIK))||{}}catch(e){return {}}})();
const setUi=o=>{ui=Object.assign({},ui,o);try{localStorage.setItem(UIK,JSON.stringify(ui))}catch(e){}};
const FUNNEL='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 5h18l-7 8v6l-4-2v-4z"/></svg>';
const SORTI='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 4v16M3 16l4 4 4-4M17 20V4M13 8l4-4 4 4"/></svg>';
const CHEV='<svg class="cv" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>';
function toolbar(F,S,sk,all,total,shown){
  const fl=F[filter]?F[filter][2]:'Alle',on=filter!=='alle';
  return `<div class="tbar"><button type="button" class="tsel${on?' on':''}" data-pop="f" aria-haspopup="menu">${FUNNEL}<span class="tv">${esc(fl)}</span>${on?`<span class="tcnt num">${shown}</span>`:''}${CHEV}</button>
    ${on?`<button type="button" class="tclr" data-clr aria-label="Filter zurücksetzen">✕</button>`:''}
    <button type="button" class="tsel" data-pop="s" aria-haspopup="menu">${SORTI}<span class="tv">${esc(S[sk][2])}</span>${CHEV}</button></div>`}
function bindToolbar(F,S,sKey,items){
  const fb=main.querySelector('[data-pop=f]'),sb=main.querySelector('[data-pop=s]'),cl=main.querySelector('[data-clr]');
  if(fb)fb.onclick=()=>openPop(fb,Object.entries(F).map(([k,v])=>({k,label:v[0],n:items.filter(v[1]).length})),filter,k=>{if(k!==filter){filter=k;render('rows')}});
  if(sb)sb.onclick=()=>openPop(sb,Object.entries(S).map(([k,v])=>({k,label:v[0]})),ui[sKey]||Object.keys(S)[0],k=>{setUi({[sKey]:k});render('rows')});
  if(cl)cl.onclick=()=>{filter='alle';buzz(5);render('rows')}}
/* Aufklappmenü unter einem Knopf */
let popEl=null;
function closePop(){if(!popEl)return;const p=popEl;popEl=null;
  if(motion())p.animate([{opacity:1},{opacity:0}],{duration:120}).onfinish=()=>p.remove();else p.remove();layerClosed()}
function openPop(btn,items,cur,onPick){
  closePop();buzz(5);
  const r=btn.getBoundingClientRect(),W=Math.min(300,innerWidth-24);
  const left=Math.max(12,Math.min(r.left,innerWidth-W-12));
  const p=document.createElement('div');p.className='pop';
  p.innerHTML=`<div class="popscrim"></div><div class="popm" role="menu" style="left:${left}px;top:${r.bottom+6}px;width:${W}px">${items.map(it=>`<button type="button" role="menuitemradio" aria-checked="${it.k===cur}" data-k="${it.k}"><span class="pk">${it.k===cur?'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12l5 5 9-10"/></svg>':''}</span><span class="pl">${esc(it.label)}</span>${it.n!=null?`<span class="pn num">${it.n}</span>`:''}</button>`).join('')}</div>`;
  document.body.appendChild(p);popEl=p;layerOpened();
  const m=p.querySelector('.popm');if(motion())m.animate([{opacity:0,transform:'translateY(-6px) scale(.97)'},{opacity:1,transform:'none'}],{duration:180,easing:'cubic-bezier(.2,.85,.25,1)'});
  p.querySelector('.popscrim').onclick=closePop;
  p.querySelectorAll('[data-k]').forEach(b=>b.onclick=()=>{const k=b.dataset.k;closePop();buzz(6);onPick(k)});
  const first=p.querySelector('[aria-checked=true]')||p.querySelector('[data-k]');if(first)first.focus({preventScroll:true});
}
function viewDevices(){
  const F=DEV_F,sk=DEV_S[ui.sortD]?ui.sortD:'name';
  const list=db.devices.filter(F[filter]?F[filter][1]:()=>true).sort(DEV_S[sk][1]);
  return `<section class="view">
    <div class="sechead"><h2>Geräte</h2><span class="count num">${list.length} von ${db.devices.length}</span></div>
    ${toolbar(F,DEV_S,sk,db.devices,db.devices.length,list.length)}
    <div class="list">${list.length?list.map(devRow).join(''):(db.devices.length?`<div class="empty">Kein Gerät passt zu diesem Filter.</div>`:`<div class="empty">Hier ist noch nichts. Tippe auf „Neu“, um dein erstes Gerät mit Kaufdatum und Beleg anzulegen.</div>`)}</div>
  </section>`;
}
function viewContracts(){
  const F=CON_F,sk=CON_S[ui.sortC]?ui.sortC:'frist';
  const list=db.contracts.filter(F[filter]?F[filter][1]:()=>true).sort(CON_S[sk][1]);
  return `<section class="view">
    <div class="sechead"><h2>Abos & Verträge</h2><span class="count num">${list.length} von ${db.contracts.length}</span></div>
    ${toolbar(F,CON_S,sk,db.contracts,db.contracts.length,list.length)}
    <div class="list">${list.length?list.map(c=>`<button type="button" class="row" data-kind="c" data-open="${c.id}">
      ${conTile(c)}
      <div class="main"><div class="t">${esc(c.anbieter)}${c.notiz?NOTEICON:''}</div><div class="s">${esc(c.kategorie)}${Number(c.intervall)!==1?' · '+eur(price(c))+' '+(INTERVALL[c.intervall]||''):''}</div><div class="pl">${weiterOn(c)?'<span class="pill p-none">Läuft bewusst weiter</span>':conPill(c)}</div></div>
      <span class="amt num">${eur(monthly(c))}<small>/Monat</small><small class="pd">${dayTxt(perDay(c))}/Tag</small></span></button>`).join('')
      :(db.contracts.length?`<div class="empty">Kein Vertrag passt zu diesem Filter.</div>`:`<div class="empty">Noch keine Verträge. Tippe auf „Neu“ und trage Kosten, Laufzeit und Kündigungsfrist ein.</div>`)}</div>
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
  document.body.style.overflow='hidden';layerOpened();
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
  if(anim===false||!motion()){++sheetTok;root.innerHTML='';layerClosed();return}
  if(sc.classList.contains('closing'))return;
  const tok=++sheetTok,sh=sc.firstElementChild;
  const from=sh.style.transform||'translateY(0)';
  sh.getAnimations().forEach(a=>a.cancel());
  sc.classList.add('closing');sc.classList.remove('drag');sc.style.setProperty('--k','0');
  sh.animate([{transform:from},{transform:'translateY(105%)'}],{duration:260,easing:'cubic-bezier(.4,0,.9,.6)',fill:'forwards'});
  layerClosed();setTimeout(()=>{if(tok===sheetTok)root.innerHTML=''},280);
}
document.addEventListener('keydown',e=>{if(e.key!=='Escape')return;if(!document.getElementById('viewer').hidden)closeViewer();else if(fanOpen)setFan(false);else if(root.firstElementChild)closeSheet()});
const head=t=>`<div class="sheethead"><h2>${t}</h2><button type="button" class="icobtn" data-close aria-label="Schließen"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"/></svg></button></div>`;

function openDetail(kind,id,from){
  if(kind==='d'){
    const d=db.devices.find(x=>x.id===id); if(!d)return; const i=deviceInfo(d);
    const p=prot(d);
    openSheet(head(esc(d.name))+`${p?'':`<div class="hero h-none"><span class="hl">Status</span><b>Kein Schutz mehr</b><span class="hs">Gewährleistung endete am ${fmtD(i.gew)}</span></div>`}
      ${p?`<div class="prot tiltme"><div class="rw">${ring(p.f,60,5)}<span class="num">${Math.round(p.f*100)}%</span></div>
        <div><span class="hl">${p.typ} bis</span><b class="num">${fmtD(i.best.date)}</b><span class="hint">noch ${restTxt(p.left)} · ${p.months} Monate Schutz ab Kauf</span></div></div>`:''}
      ${d.foto?`<img class="photo tiltme" src="${d.foto}" alt="Foto von ${esc(d.name)}">`:''}
      <dl class="kv">
        <dt>Hersteller / Modell</dt><dd>${esc([d.hersteller,d.modell].filter(Boolean).join(' ')||'–')}</dd>
        <dt>Seriennummer</dt><dd class="code">${esc(d.sn||'–')}</dd>
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
            ${d.rate.vnr?`<dt>Finanzierungs-Nr.</dt><dd class="code"><span data-rmask>${esc(maskVal(d.rate.vnr))}</span><button type="button" class="reveal" data-rshow>Anzeigen</button></dd>`:''}
          </dl></div>`)(rateInfo(d))}
      ${noteBlock(d)}${extBlock(d)}
      ${docSection(d)}
      <div class="tools"><button type="button" class="tool" id="claim"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4 4 0 0 0 5 5L12 19a2.1 2.1 0 0 1-3-3l7.7-7.7a4 4 0 0 0-2-2z"/></svg>Mangel melden</button></div>
      <div class="actions two"><button type="button" class="btn primary" id="edit">Bearbeiten</button><button type="button" class="btn danger" id="del">Löschen</button></div>`,
      s=>{const pr=s.querySelector('.prot');if(pr&&motion())pr.classList.add('enter');bindDocs(s,d);
          const rs=s.querySelector('[data-rshow]');if(rs){let o=false;rs.onclick=()=>{o=!o;s.querySelector('[data-rmask]').textContent=o?d.rate.vnr:maskVal(d.rate.vnr);rs.textContent=o?'Verbergen':'Anzeigen'}}
          s.querySelector('#claim').onclick=()=>openClaim(d);
          s.querySelector('#edit').onclick=()=>openForm('d',d);armDelete(s,()=>{(d.docs||[]).forEach(x=>fileDel(x.id).catch(()=>{}));db.devices=db.devices.filter(x=>x.id!==id)})},from);
  } else {
    const c=db.contracts.find(x=>x.id===id); if(!c)return; const i=contractInfo(c);
    const cn=i.by?days(i.by):null, verl=i.k>0?` · schon ${i.k}× verlängert`:'';
    const hero=c.status==='gekuendigt'
      ?`<div class="hero h-none"><span class="hl">Gekündigt</span><b class="num">endet ${fmtD(i.end)}</b><span class="hs">${inDays(days(i.end))}${c.gekuendigtAm?' · gekündigt am '+fmtD(parse(c.gekuendigtAm)):''}</span></div>`
      :i.offen?`<div class="hero h-ok"><span class="hl">Jederzeit kündbar</span><b class="num">${FRIST(c.frist)}</b><span class="hs">Bei Kündigung heute endet er am ${fmtD(i.end)}</span></div>`
      :i.by&&weiterOn(c)?`<div class="hero h-none"><span class="hl">Läuft bewusst weiter</span><b class="num">Verlängerung am ${fmtD(i.end)}</b><span class="hs">um ${PER(c.verl)} · für die nächste Laufzeit erinnert dich die App wieder</span></div>`
      :i.by?`<div class="hero ${cn<=14?'h-crit':cn<=45?'h-warn':'h-ok'}"><span class="hl">Spätestens kündigen</span><b class="num">${fmtD(i.by)}</b><span class="hs">${inDays(cn)} · sonst Verlängerung am ${fmtD(i.end)} um ${PER(c.verl)}${verl}</span></div>`
      :`<div style="margin:-6px 0 14px">${conPill(c)}</div>`;
    openSheet(head((c.logo?`<img class="hlogo" src="${c.logo}" alt="">`:'')+esc(c.anbieter))+hero+`
      <dl class="kv">
        <dt>Kategorie</dt><dd>${esc(c.kategorie)}</dd>
        <dt>Kosten</dt><dd><span class="num">${eur(price(c))}</span> ${INTERVALL[c.intervall]||''}${Number(c.intervall)!==1?` <span class="muted">(${eur(monthly(c))} pro Monat)</span>`:''}<br><span class="muted">${dayTxt(perDay(c))} am Tag · ${eur(monthly(c)*12)} im Jahr</span></dd>
        ${(()=>{const p=priceChange(c);if(!p)return '';const past=days(p.date)<=0;
          return `<dt>Preisänderung</dt><dd>${past?`seit ${fmtD(p.date)} ${eur(p.preis)} (vorher ${eur(c.kosten)})`:`ab ${fmtD(p.date)} ${eur(p.preis)} statt ${eur(c.kosten)} <span class="pill ${p.preis>c.kosten?'p-warn':'p-ok'}">${p.preis>c.kosten?'teurer':'günstiger'}</span>`}</dd>`})()}
        ${c.beginn?`<dt>Beginn</dt><dd>${fmtD(parse(c.beginn))}</dd>`:''}
        <dt>Laufzeit</dt><dd>${i.offen?'Unbefristet, jederzeit kündbar':(c.modus==='ende'?`Laufzeitende ${fmtD(parse(c.ende))} eingetragen`:`Mindestens ${PER(c.laufzeit)}`)+`, danach je ${PER(c.verl)}`}</dd>
        <dt>Kündigungsfrist</dt><dd>${Number(c.frist)?c.frist+' Tage':'jederzeit'}</dd>
        ${[['kundennr','Kundennummer'],['vertragsnr','Vertragsnummer']].map(([f,l])=>`<dt>${l}</dt><dd class="code">${c[f]?`<span data-mask="${f}">${esc(maskVal(c[f]))}</span><button type="button" class="reveal" data-show="${f}">Anzeigen</button><button type="button" class="reveal" data-copy="${f}">Kopieren</button>`:'–'}</dd>`).join('')}
      </dl>
      ${noteBlock(c)}${extBlock(c)}
      ${docSection(c)}
      ${c.status!=='gekuendigt'?`<div class="tools">
        <button type="button" class="tool" id="letter"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h16v12H4z"/><path d="M4 7l8 6 8-6"/></svg>Kündigung schreiben</button>
        ${i.by?`<button type="button" class="tool" id="weiter"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${weiterOn(c)?'<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10 21h4"/>':'<path d="M20 12a8 8 0 1 1-2.3-5.7"/><path d="M20 4v4.5h-4.5"/>'}</svg>${weiterOn(c)?'Wieder erinnern':'Weiterlaufen lassen'}</button>`:''}
      </div>`:''}
      <div class="actions two">
        <button type="button" class="btn primary" id="edit">Bearbeiten</button>
        ${c.status!=='gekuendigt'?'<button type="button" class="btn" id="cancel">Gekündigt ✓</button>':'<button type="button" class="btn" id="cancel">Wieder aktiv</button>'}
        <button type="button" class="btn" id="dup">Kopie anlegen</button>
        <button type="button" class="btn danger" id="del">Löschen</button></div>`,
      s=>{bindDocs(s,c);s.querySelectorAll('[data-show]').forEach(b=>{const f=b.dataset.show,sp=s.querySelector(`[data-mask="${f}"]`);let open=false;
            b.onclick=()=>{open=!open;sp.textContent=open?c[f]:maskVal(c[f]);b.textContent=open?'Verbergen':'Anzeigen'}});
          s.querySelectorAll('[data-copy]').forEach(b=>b.onclick=async()=>{const f=b.dataset.copy;
            try{await navigator.clipboard.writeText(c[f]);buzz(8);toast((f==='kundennr'?'Kundennummer':'Vertragsnummer')+' kopiert.')}
            catch(x){toast('Kopieren hat nicht geklappt. Tippe auf „Anzeigen“ und markiere die Nummer.')}});
          s.querySelector('#dup').onclick=()=>openForm('c',null,false,c);
          const lt=s.querySelector('#letter');if(lt)lt.onclick=()=>openLetter(c);
          const wt=s.querySelector('#weiter');if(wt)wt.onclick=()=>{const on=weiterOn(c);if(on)delete c.weiter;else c.weiter=iso(contractInfo(c).end);save();render();openDetail('c',id);
            buzz(8);toast(on?'Die App erinnert dich wieder an die Kündigungsfrist.':`Okay, ${c.anbieter} läuft bis ${fmtD(contractInfo(c).end)} plus ${PER(c.verl)} weiter. Danach erinnere ich dich wieder.`)};
          s.querySelector('#edit').onclick=()=>openForm('c',c);
          s.querySelector('#cancel').onclick=()=>{const was=c.status==='gekuendigt';c.status=was?'aktiv':'gekuendigt';if(was)delete c.gekuendigtAm;else{c.gekuendigtAm=iso(T0);delete c.weiter}save();render();openDetail('c',id);
            if(was){buzz(8);toast('Wieder als aktiv markiert.')}
            else{celebrate('Gekündigt');toast(`Stark! Ab dem ${fmtD(contractInfo(c).end)} sparst du ${eur(monthly(c)*12)} im Jahr.`)}};
          armDelete(s,()=>{(c.docs||[]).forEach(x=>fileDel(x.id).catch(()=>{}));db.contracts=db.contracts.filter(x=>x.id!==id)})},from);
  }
}
function armDelete(s,fn){const b=s.querySelector('#del');
  /* Rückfrage wie in MySmartBox und MyGesundBox */
  b.onclick=()=>{if(!confirm(b.id==='del'&&b.textContent.includes('Alle')?'Wirklich alle Einträge löschen? Das lässt sich nicht rückgängig machen.':'Wirklich löschen?'))return;
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
    <div class="grid2"><label class="field"><span>Kaufdatum *</span><input id="f_kauf" type="date" required value="${iso(T0)}"></label>
      <label class="field"><span>Preis (€)</span><input id="f_preis" type="number" step="0.01" min="0" inputmode="decimal"></label></div>
    <label class="field"><span>Kaufnachweis</span><select id="f_nach">${Object.entries(NACHWEIS).map(([k,v])=>`<option value="${k}">${v}</option>`).join('')}</select></label>
    <div class="field"><span>Foto (Gerät, Beleg oder Typenschild)</span>
      <label class="filepick"><img id="f_prev" alt=""${item&&item.foto?` src="${item.foto}"`:" hidden"}><span class="fp-ic"${item&&item.foto?" hidden":""}>${CAM}</span>
        <span class="fp-t"><b id="f_ftxt">${item&&item.foto?"Foto ersetzen":"Foto aufnehmen oder wählen"}</b><small>Kamera oder Galerie</small></span><input id="f_foto" type="file" accept="image/*" hidden></label></div>
    <div class="ask" id="f_ask" hidden><span>Ist das ein Kaufbeleg (Kassenbon oder Rechnung)?</span>
      <div class="actions"><button type="button" class="btn" id="f_askYes">Ja, als Kaufnachweis</button><button type="button" class="btn" id="f_askNo">Nein</button></div></div>
    ${item&&item.foto?'<label class="check"><input id="f_fotoDel" type="checkbox"> Vorhandenes Foto entfernen</label>':''}
    ${DOCFIELD}
    <details class="more"${(src0&&(src0.sn||src0.haendler||Number(src0.garantieMonate)||src0.rate||src0.notiz||src0.geschaetzt))?' open':''}><summary><span><b>Weitere Angaben</b><small>Seriennummer, Händler, Garantie, Raten, Notizen</small></span></summary><div class="moreb">
    <div class="field"><span><label for="f_sn">Seriennummer</label></span><div class="snrow"><input id="f_sn" placeholder="steht auf dem Typenschild">${canScan()?'<button type="button" class="btn scanbtn" id="f_scan" aria-label="Seriennummer scannen"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3M7 9v6M10 9v6M13 9v6M17 9v6"/></svg>Scannen</button>':''}</div></div>
    <label class="check"><input id="f_ges" type="checkbox"> Kaufdatum nur geschätzt</label>
    <div class="grid2"><label class="field"><span>Händler</span><input id="f_hae"></label>
      <label class="field"><span>Herstellergarantie</span><select id="f_gar"><option value="0">keine</option><option value="12">1 Jahr</option><option value="24">2 Jahre</option><option value="36">3 Jahre</option><option value="60">5 Jahre</option></select></label></div>
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
    <label class="field"><span>Notizen & Hinweise</span><textarea id="x_note" rows="3" placeholder="${kind==='d'?'z. B. Zubehör im Keller, Reparatur 2025, Ersatzteilnummer …':'z. B. Kündigung nur schriftlich, Ansprechpartner, Treuebonus …'}"></textarea></label>
    </div></details>
    <p class="hint">Bei Kontoauszügen vorher alles außer der Buchung schwärzen. Die gesetzliche Gewährleistung von 2 Jahren ab Kauf wird automatisch berechnet.</p>`;
  const con=`
    <label class="field"><span>Anbieter *</span><input id="c_anb" required placeholder="z. B. Spotify"></label>
    <label class="field"><span>Kategorie</span><select id="c_kat">${opt(CON_KAT,'Streaming')}</select></label>
    <div class="grid2"><label class="field"><span>Kosten (€) *</span><input id="c_kost" type="number" step="0.01" min="0" required inputmode="decimal"></label>
      <label class="field"><span>Zahlweise</span><select id="c_int"><option value="1">monatlich</option><option value="3">vierteljährlich</option><option value="6">halbjährlich</option><option value="12">jährlich</option></select></label></div>
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
    ${DOCFIELD}
    <details class="more"${(src0&&(src0.logo||src0.kundennr||src0.vertragsnr||(src0.kostenNach!=null&&src0.kostenNach!=='')||src0.notiz))?' open':''}><summary><span><b>Weitere Angaben</b><small>Logo, Kunden- und Vertragsnummer, Preisänderung, Notizen</small></span></summary><div class="moreb">
    <div class="logofield"><div class="tile logo" id="c_logoPrev"${src0&&src0.logo?'':' hidden'}>${src0&&src0.logo?`<img src="${src0.logo}" alt="">`:''}</div>
      <label class="btn logobtn">${src0&&src0.logo?'Logo ändern':'Logo wählen'}<input id="c_logo" type="file" accept="image/*" hidden></label>
      <button type="button" class="reveal" id="c_logoDel"${src0&&src0.logo?'':' hidden'}>Entfernen</button></div>
    <p class="hint">Tipp: Logo auf der Anbieter-Webseite per langem Druck speichern oder einen Screenshot zuschneiden.</p>
    <div class="grid2"><label class="field"><span>Kundennummer</span><input id="c_kd" autocomplete="off"></label>
      <label class="field"><span>Vertragsnummer</span><input id="c_vnr" autocomplete="off"></label></div>
    <label class="field" data-m="beginn ende"><span id="c_knL">Anderer Preis nach der Mindestlaufzeit (€, optional)</span><input id="c_kn" type="number" step="0.01" min="0" inputmode="decimal" placeholder="leer lassen, wenn der Preis gleich bleibt"></label>
    <label class="field"><span>Notizen & Hinweise</span><textarea id="x_note" rows="3" placeholder="${kind==='d'?'z. B. Zubehör im Keller, Reparatur 2025, Ersatzteilnummer …':'z. B. Kündigung nur schriftlich, Ansprechpartner, Treuebonus …'}"></textarea></label>
    </div></details>`;
  openSheet(head(item?'Bearbeiten':tpl?(tpl._ext?'Aus der '+esc(tpl._ext.src||'MyGesundBox'):'Vertrag kopieren'):'Neuer Eintrag')+`<form id="frm" novalidate>
    ${tpl&&tpl._ext?`<p class="hint" style="margin-bottom:12px">Übernommen aus der <b>${esc(tpl._ext.src||'MyGesundBox')}</b>. Prüf die Angaben und füg den Kaufbeleg als Foto oder PDF hinzu.</p>`:''}${tpl&&!tpl._ext?`<p class="hint">Kopie von <b>${esc(tpl.anbieter)}</b>. Vertragsnummer und Beginn sind leer bzw. auf heute gesetzt, alles andere ist übernommen.</p>`:''}
    <div class="seg"${item||tpl?' hidden':''}><button type="button" data-k="d" aria-pressed="${kind==='d'}">Gerät</button><button type="button" data-k="c" aria-pressed="${kind==='c'}">Abo / Vertrag</button></div>
    ${kind==='d'?dev:con}<p class="hint" id="err" style="color:var(--crit)" hidden></p>
    <div class="actions"><button type="button" class="btn" data-close>Abbrechen</button><button type="submit" class="btn primary">Speichern</button></div></form>`,
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
        err.textContent='Ein Feld sieht nach einer IBAN oder Kartennummer aus. Solche Nummern speichert die MyBelegBox bewusst nicht. Trag höchstens die letzten vier Ziffern ein.';err.hidden=false;return}
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
          garantieMonate:Number(v('f_gar')),nachweis:v('f_nach'),foto,docs:D.docs,cover:D.cover,rate,notiz:v('x_note'),ext:(item&&item.ext)||(tpl&&tpl._ext)||undefined};
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
          intervall:Number(v('c_int')),modus:md,beginn:md==='beginn'?v('c_beg'):(item&&item.beginn||''),ende:md==='ende'?v('c_end'):'',laufzeit:Number(v('c_lz')),verl:Number(v('c_verl')),frist:Number(v('c_fr')),docs:D.docs,notiz:v('x_note'),ext:(item&&item.ext)||(tpl&&tpl._ext)||undefined};
        if(item){Object.assign(item,cc);delete item.ex}else db.contracts.push(Object.assign({id:uid(),status:'aktiv'},cc));
        tab='vertraege';
      }
      filter='alle';db.meta=Object.assign({},db.meta,{dirty:(db.meta&&db.meta.dirty||0)+1});save();D.cleanup();
      /* Haken im Speichern-Knopf, dann schließt das Blatt (wie MySmartBox / MyGesundBox) */
      const sb=s.querySelector('#frm [type=submit]');if(motion()&&sb){DS.savedTick(sb);await new Promise(r=>setTimeout(r,600))}
      closeSheet();render(item?undefined:'rows');
      if(item){buzz(12);toast('Änderungen gespeichert.');openDetail(kind,item.id)}
      else celebrate(first?'Dein erstes Gerät!':'Gespeichert');
    });
    const sb=s.querySelector('#f_scan');if(sb)sb.onclick=()=>openScanner(v=>{const f=s.querySelector('#f_sn');f.value=v;buzz(10);toast('Seriennummer übernommen.')});
    if(kind==='d'){ // Neues Foto: nur auf Nachfrage als Kaufnachweis werten, nie automatisch
      const fi=s.querySelector('#f_foto'),ask=s.querySelector('#f_ask'),na=s.querySelector('#f_nach');
      if(!src)na.value='keiner'; // neues Gerät: erst mit Beleg gilt es als nachgewiesen
      fi.addEventListener('change',()=>{ask.hidden=!(fi.files[0]&&na.value==='keiner');const f=fi.files[0];if(!f)return;
        const p=s.querySelector('#f_prev');if(p._u)URL.revokeObjectURL(p._u);p._u=URL.createObjectURL(f);p.src=p._u;p.hidden=false;
        s.querySelector('.fp-ic').hidden=true;s.querySelector('#f_ftxt').textContent='Anderes Foto wählen';const fd=s.querySelector('#f_fotoDel');if(fd)fd.checked=false;buzz(6)});
      s.querySelector('#docIn').addEventListener('change',()=>{if(na.value==='keiner')ask.hidden=false});
      s.querySelector('#f_askYes').onclick=()=>{na.value='beleg';ask.hidden=true;buzz(6);toast('Kaufnachweis auf „Kassenbon / Rechnung“ gesetzt.')};
      s.querySelector('#f_askNo').onclick=()=>{ask.hidden=true;buzz(5)};
    }
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
      const fi=s.querySelector('#f_foto');fi.setAttribute('capture','environment');allowAway();fi.click();
    }else{const first=s.querySelector('input');if(first)first.focus({preventScroll:true})}
  });
}

let menuAcc=null;
/* ---------- App-Update: Zip-Paket aus der App ins GitHub-Repo laden ----------
   Ein Ablauf im Repo (.github/workflows/paket.yml) entpackt das Paket, prüft Version und Cache,
   übernimmt die Dateien und veröffentlicht. Der Schlüssel liegt verschlüsselt im Tresor (db.meta.upd). */
let UPD='',updBusy=false;
const defaultRepo=()=>{const h=location.hostname;return h.endsWith('.github.io')?h.split('.')[0]+'/'+h:''};
const updCfg=()=>{const u=db&&db.meta&&db.meta.upd;if(!u)return null;const [owner,repo]=u.repo.split('/');return {owner,repo,token:u.token}};
function setUpd(html){UPD=html;const el=document.getElementById('updStatus');if(el){el.innerHTML=html;el.hidden=!html}}
const updErr=e=>e&&e.status===401?'Der Zugangsschlüssel ist ungültig oder abgelaufen.':e&&e.status===403?'Keine Berechtigung. Der Schlüssel braucht „Contents: Read and write“ und „Actions: Read“ für dieses Repo.'
  :e&&e.status===404?'Repo nicht gefunden oder kein Zugriff.':e&&e.status===422?'GitHub hat die Datei abgelehnt (zu groß?).':'Keine Verbindung zu GitHub. Prüfe die Internetverbindung.';
function bindUpd(s){
  const ch=s.querySelector('#up_chg');
  if(ch)ch.onclick=()=>dsForm('App-Update verbinden',[{k:'repo',l:'Repo (Besitzer/Name)',req:true,v:db.meta&&db.meta.upd?db.meta.upd.repo:defaultRepo()},{k:'token',l:'Zugangsschlüssel (github_pat_…)',t:'password',req:true}],async(v,fail)=>{
    const repo=v.repo.trim().replace(/^https:\/\/github\.com\//,'').replace(/\/$/,''),token=v.token.trim();
    if(!/^[\w.-]+\/[\w.-]+$/.test(repo))return fail('Bitte das Repo im Format „Besitzer/Name“ eintragen.');
    try{const [owner,name]=repo.split('/');const info=await ghFetch({owner,repo:name,token},'GET','');
      if(!info)throw Object.assign(new Error(),{status:404});
      if(info.permissions&&info.permissions.push===false)return fail('Der Schlüssel darf in dieses Repo nicht schreiben. Setze „Contents“ auf „Read and write“.');
      const wf=await ghFetch({owner,repo:name,token},'GET','/contents/.github/workflows/paket.yml').catch(()=>null);
      db.meta=Object.assign({},db.meta,{upd:{repo,token}});await save();
      setUpd(wf?'✅ Verbunden. Du kannst jetzt Update-Pakete hochladen.':'⚠️ Verbunden, aber im Repo fehlt <b>.github/workflows/paket.yml</b>. Ohne diesen Ablauf werden Pakete nicht entpackt.');
      buzz(10);toast('GitHub verbunden ✓');openMenu()}
    catch(x){return fail(updErr(x))}},
    {ok:'Prüfen & verbinden',html:'<p class="ds-dlg-intro">Dafür brauchst du einen eigenen Fine-grained-Zugangsschlüssel nur für das App-Repo mit den Rechten <b>Contents: Read and write</b> und <b>Actions: Read</b>. Er wird verschlüsselt im Tresor gespeichert. Der Schlüssel der Datensicherung reicht dafür nicht.</p>'});
  const off=s.querySelector('#up_off');if(off)off.onclick=()=>{if(!confirm('GitHub-Verbindung für Updates entfernen? Den Schlüssel kannst du danach auf GitHub löschen.'))return;
    const m=Object.assign({},db.meta);delete m.upd;db.meta=m;save();setUpd('');openMenu();toast('App-Update getrennt.')};
  const inp=s.querySelector('#up_in');
  if(inp)inp.addEventListener('change',()=>{const f=inp.files[0];inp.value='';if(!f)return;
    if(!/\.zip$/i.test(f.name)){setUpd('❌ Bitte eine .zip-Datei wählen.');return}
    if(f.size>50e6){setUpd('❌ Das Paket ist größer als 50 MB.');return}
    if(confirm(`„${f.name}“ (${fmtSize(f.size)}) ins Repo hochladen und veröffentlichen?`))updUpload(f)});
}
async function updUpload(file){
  const g=updCfg();if(!g||updBusy)return;updBusy=true;
  const name=file.name.replace(/[^\w.\-]/g,'_');
  setUpd('⏳ Lade '+esc(name)+' hoch …');
  try{
    const old=await ghFetch(g,'GET','/contents/'+encodeURIComponent(name));
    const res=await ghFetch(g,'PUT','/contents/'+encodeURIComponent(name),{message:'Paket '+name+' (aus der MyBelegBox)',content:toB64(await file.arrayBuffer()),branch:'main',...(old&&old.sha?{sha:old.sha}:{})});
    setUpd('⚙️ Hochgeladen – GitHub entpackt und prüft das Paket …');buzz(8);
    await updWatch(g,res.commit.sha);
  }catch(e){setUpd('❌ '+esc(updErr(e)))}
  updBusy=false;
}
async function updWatch(g,sha){
  const wait=ms=>new Promise(r=>setTimeout(r,ms));
  const t0=Date.now();let run=null;
  while(Date.now()-t0<5*60e3){
    await wait(5000);
    try{const j=await ghFetch(g,'GET','/actions/runs?head_sha='+sha+'&per_page=5');run=(j&&j.workflow_runs&&j.workflow_runs[0])||run}catch(e){}
    if(run&&run.status==='completed')break;
  }
  const link=run&&/^https:\/\/github\.com\//.test(run.html_url||'')?` <a href="${esc(run.html_url)}" target="_blank" rel="noopener noreferrer">Details</a>`:'';
  if(!run){setUpd('⚠️ Kein Ablauf gefunden. Liegt <b>.github/workflows/paket.yml</b> im Repo, und hat der Schlüssel „Actions: Read“?');return}
  if(run.status!=='completed'){setUpd('⏳ Der Ablauf dauert länger als üblich.'+link);return}
  if(run.conclusion!=='success'){
    let msg='';try{const jobs=await ghFetch(g,'GET','/actions/runs/'+run.id+'/jobs');const id=jobs&&jobs.jobs&&jobs.jobs[0]&&jobs.jobs[0].id;
      if(id){const ann=await ghFetch(g,'GET','/check-runs/'+id+'/annotations')||[];msg=((ann.find(a=>a.annotation_level==='failure')||ann[0])||{}).message||''}}catch(e){}
    setUpd('❌ Paket abgelehnt'+(msg?': '+esc(msg.replace(/^MyBelegBox:?\s*/,'')):'.')+link);buzz([30,50,30]);return;
  }
  setUpd('✅ Paket übernommen – warte auf die Veröffentlichung …'+link);
  const t1=Date.now();
  while(Date.now()-t1<5*60e3){
    await wait(10000);
    try{if(swReg){await swReg.update();if(swReg.waiting||swReg.installing){
      setUpd('🎉 Die neue Version ist online.<div class="ds-acts"><button type="button" class="ds-btn pri" id="up_now">Jetzt neu laden</button></div>');
      const b=document.getElementById('up_now');if(b)b.onclick=()=>{const w=swReg.waiting||swReg.installing;saving.then(()=>w&&w.postMessage('SKIP_WAITING'))};
      celebrate('Update online');return}}}catch(e){}
  }
  setUpd('✅ Paket übernommen. GitHub braucht noch etwas – die App meldet sich mit „Neue Version verfügbar“, sobald sie online ist.'+link);
}
const relTime=t=>{const m=Math.round((Date.now()-t)/6e4);return m<1?'gerade eben':m<60?'vor '+m+' Min.':m<1440?'vor '+Math.round(m/60)+' Std.':'vor '+Math.round(m/1440)+' Tagen'};
/* Ein Bereich im Blatt „Daten & Sicherheit“ – gleicher Aufbau wie in MySmartBox und MyGesundBox */
const MI={sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',lock:'<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',down:'<path d="M12 3v12M7 10l5 5 5-5"/><path d="M5 19h14"/>',
  bell:'<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10 21h4"/>',star:'<path d="M12 3l2.6 5.3 5.9.9-4.3 4.1 1 5.8-5.2-2.7-5.2 2.7 1-5.8L3.5 9.2l5.9-.9z"/>',
  cal:'<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>',pkg:'<path d="M21 8l-9-5-9 5 9 5z"/><path d="M3 8v8l9 5 9-5V8M12 13v8"/>',list:'<path d="M4 6h16M4 12h16M4 18h10"/>'};
const mIco=k=>`<span class="ai"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${MI[k]}</svg></span>`;
const mChev=r=>`<svg class="chev${r?' r':''}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="${r?'M9 6l6 6-6 6':'M6 9l6 6 6-6'}"/></svg>`;
const mAcc=(k,ic,t,sub,body,force)=>`<details class="acc" data-acc="${k}"${menuAcc===k||force?' open':''}><summary>${mIco(ic)}<span class="at"><b>${t}</b><small>${sub}</small></span>${mChev()}</summary><div class="accb">${body}</div></details>`;
function openMenu(){
  const g=ghCfg(),bio=!!(vmeta&&vmeta.bio),lb=db.meta&&db.meta.lastBackup,u=db.meta&&db.meta.upd;
  openSheet(head('Daten & Sicherheit')+`
    <div class="secline"><svg viewBox="0 0 24 24" fill="none" stroke="var(--ok)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>
      Verschlüsselt mit AES-256 · sperrt nach 5 Min. ohne Eingabe oder 1 Min. im Hintergrund</div>`
  +mAcc('sicher','lock','Sicherheit','Passwort · Fingerabdruck '+(bio?'an':'aus'),`
    <p class="ds-hint">Alle Daten liegen verschlüsselt auf diesem Gerät${g?' und als verschlüsselte Sicherung in deinem privaten GitHub-Repo':''}. Sonst wird nichts gesendet. Dein Passwort wird nicht gespeichert.</p>
    ${bioPossible()?`<div class="ds-lbl">Fingerabdruck</div>
    <p class="ds-hint">${bio?'Entsperren per Fingerabdruck ist eingeschaltet. Das Passwort funktioniert weiterhin und bleibt für den Notfall wichtig.':'Entsperre die MyBelegBox mit Fingerabdruck oder Gesichtserkennung statt mit dem Passwort. Dafür wird ein Passkey „MyBelegBox“ in deinem Passwortmanager angelegt.'}</p>
    <div class="ds-acts"><button type="button" class="ds-btn${bio?'':' pri'}" id="bioBtn">${bio?'Ausschalten':'Einschalten'}</button></div>`:''}
    <div class="ds-lbl${bioPossible()?' sep':''}">Passwort</div>
    <p class="ds-hint">Beim Ändern werden alle Daten neu verschlüsselt. Ältere Sicherungsdateien brauchen weiter das Passwort, das beim Sichern galt.</p>
    <div class="ds-acts"><button type="button" class="ds-btn" id="pwBtn">Passwort ändern</button></div>`)
  +mAcc('gh','down','Datensicherung',(g?'GitHub '+(ghStat.err?'⚠️ Problem':'an'):'GitHub aus')+' · '+(lb?'Datei '+fmtD(parse(lb)):'keine Datei'),`
    <div class="ds-lbl">Automatisch in GitHub</div>
    ${g?`<p class="ds-hint">Nach jeder Änderung landet der verschlüsselte Tresor in <b>${esc(g.owner)}/${esc(g.repo)}${g.dir?'/'+esc(g.dir):''}</b>. GitHub sieht nur verschlüsselte Daten.</p>
    <div class="ds-stat" id="ghStatus">${ghStatusText()}</div>
    ${ghStat.conflict?`<div class="ds-box crit">Im Repo liegt ein anderer Tresor (z. B. von einem früheren Gerät). Er bleibt in der Versionsgeschichte von GitHub erhalten, wenn du ihn ersetzt.<div class="ds-acts"><button type="button" class="ds-btn pri" id="ghPull">GitHub-Stand laden</button><button type="button" class="ds-btn dng" id="ghForce">Durch diesen ersetzen</button></div></div>`:''}
    <div class="ds-acts"><button type="button" class="ds-btn pri" id="ghNow">Jetzt sichern</button><button type="button" class="ds-btn" id="ghOff">Trennen</button></div>`
    :`<p class="ds-hint">Sichert den verschlüsselten Tresor und alle Dokumente nach jeder Änderung in ein <b>privates</b> GitHub-Repo – auch wenn Browserdaten gelöscht werden, bleibt alles erhalten.</p>
    <div class="ds-acts"><button type="button" class="ds-btn pri" id="ghSetup">GitHub einrichten</button></div>`}
    <div class="ds-lbl sep">Sicherungsdatei</div>
    <p class="ds-hint">Zusätzlich oder statt GitHub: eine Datei, die du selbst ablegst. Sie ist mit deinem aktuellen Passwort verschlüsselt und enthält auch alle PDFs und Dokumente. ${lb?'Letzte Sicherung: '+fmtD(parse(lb))+'.':'Bisher keine Sicherung.'}</p>
    <div class="ds-acts"><button type="button" class="ds-btn${g?'':' pri'}" id="bkGo">Sicherung erstellen</button><label class="ds-btn">Sicherung laden<input id="bkIn" type="file" accept=".belegbox,application/json" hidden></label></div>
    ${persisted===false?'<p class="ds-hint" style="margin-top:10px">Der Browser hat dauerhaften Speicher nicht zugesagt. Installiere die App auf dem Startbildschirm und sichere regelmäßig.</p>':''}`,!!(g&&(ghStat.conflict||ghStat.err)))
  +mAcc('erin','bell','Erinnerungen',db.meta&&db.meta.remind?'an':'aus',
    'Notification' in window&&'serviceWorker' in navigator?(db.meta&&db.meta.remind?`<p class="ds-hint">An. Läuft in den nächsten 14 Tagen eine Frist ab, meldet sich die MyBelegBox mit einer neutralen Benachrichtigung – auf Android mit einem Punkt am App-Icon. ${db.meta.remindBg?'Android prüft das auch bei geschlossener App, meist etwa einmal am Tag.':'Dein Browser prüft das nur, wenn du die App öffnest.'}</p>
    <div class="ds-acts"><button type="button" class="ds-btn" id="rmTest">Test-Benachrichtigung</button><button type="button" class="ds-btn" id="rmOff">Ausschalten</button></div>`
    :`<p class="ds-hint">Die MyBelegBox meldet sich, wenn in den nächsten 14 Tagen eine Kündigungsfrist oder Garantie abläuft – auch bei geschlossener App. Auf Android erscheint dazu ein Punkt am App-Icon. Dafür liegen nur die <b>Termine ohne Namen und Beträge</b> unverschlüsselt auf dem Handy.</p>
    <div class="ds-acts"><button type="button" class="ds-btn pri" id="rmOn">Einschalten</button></div><p class="ds-err" id="rmMsg" hidden></p>`):'<p class="ds-hint">Dieser Browser kann keine Benachrichtigungen anzeigen.</p>')
  +`<button type="button" class="accrow" id="revM">${mIco('star')}<span class="at"><b>Jahresrückblick ${reviewYear()}</b><small>${T0.getMonth()<11&&reviewYear()===T0.getFullYear()?'bis heute ansehen':'ansehen'}</small></span>${mChev(true)}</button>`
  +mAcc('kal','cal','Kalender','Fristen als Termine exportieren',`
    <p class="ds-hint">Exportiert alle Kündigungsfristen und Garantie-Enden als Termine mit Erinnerung 7 Tage und 1 Tag vorher. Nach neuen Einträgen einfach erneut exportieren, bestehende Termine werden aktualisiert.</p>
    <label class="ds-check"><input id="icsNeutral" type="checkbox" checked> Neutrale Titel (keine Anbieter oder Geräte im Kalender)</label>
    <div class="ds-acts"><button type="button" class="ds-btn" id="icsGo">Fristen in Kalender exportieren</button></div>`)
  +mAcc('upd','pkg','App-Update','Version '+APP_VERSION+' · '+(u?'GitHub verbunden':'nicht verbunden'),`
    ${u?`<p class="ds-hint">Verbunden mit <b>${esc(u.repo)}</b>. Lade hier das Zip-Paket einer neuen Version hoch – GitHub prüft die Versionsnummer und veröffentlicht es in 1–2 Minuten.</p>
    <div class="ds-acts"><label class="ds-btn pri"${updBusy?' aria-disabled="true"':''}>${updBusy?'Update läuft …':'Update-Zip hochladen'}<input id="up_in" type="file" accept=".zip,application/zip" hidden></label><button type="button" class="ds-btn" id="up_chg">Verbindung ändern</button><button type="button" class="ds-btn" id="up_off">Trennen</button></div>`
    :`<p class="ds-hint">Neue Versionen als Zip direkt aus der App veröffentlichen. Dafür brauchst du einen eigenen Zugangsschlüssel nur für das App-Repo.</p>
    <div class="ds-acts"><button type="button" class="ds-btn pri" id="up_chg">GitHub verbinden</button></div>`}
    <div id="updStatus" class="ds-box"${UPD?'':' hidden'}>${UPD}</div>`,!!UPD)
  +mAcc('look','sun','Darstellung',({auto:'Automatisch',light:'Hell',dark:'Dunkel'})[DS.getTheme()]+' · hell oder dunkel',`<div class="ds-lbl">Hell oder dunkel</div>${DS.themeHtml()}`)
  +mAcc('eintr','list','Einträge',db.devices.length+' Geräte · '+db.contracts.length+' Verträge',`
    <p class="ds-hint">${db.devices.length} Geräte · ${db.contracts.length} Verträge. Löscht alle Geräte, Verträge und Dokumente auf diesem Gerät. Das lässt sich nicht rückgängig machen.</p>
    <div class="ds-acts"><button type="button" class="ds-btn dng" id="del">Alle Einträge löschen</button></div>`)
  +`<div class="ds-lbl">Meine Boxen</div>${DS.boxesHtml()}<p class="ds-ver">MyBelegBox · Version ${APP_VERSION}</p>`,
  s=>{s.querySelectorAll('details.acc[data-acc]').forEach(d=>d.addEventListener('toggle',()=>{if(d.open){menuAcc=d.dataset.acc;
       s.querySelectorAll('details.acc[open]').forEach(o=>{if(o!==d)o.open=false});buzz(4)}else if(menuAcc===d.dataset.acc)menuAcc=null}));
     s.querySelector('#pwBtn').onclick=()=>dsForm('Passwort ändern',[{k:'p0',l:'Aktuelles Passwort',t:'password',req:true,ac:'current-password'},{k:'p1',l:'Neues Passwort (mind. 10 Zeichen)',t:'password',req:true,ac:'new-password'},{k:'p2',l:'Neues Passwort wiederholen',t:'password',req:true,ac:'new-password'}],async(v,fail)=>{
       if(v.p1.length<10)return fail('Das neue Passwort braucht mindestens 10 Zeichen.');
       if(v.p1!==v.p2)return fail('Die neuen Passwörter stimmen nicht überein.');
       try{await changePassword(v.p0,v.p1)}catch(x){return fail('Das aktuelle Passwort ist falsch.')}
       closeSheet();celebrate('Neu verschlüsselt');toast('Passwort geändert. Deine Daten sind neu verschlüsselt.')},{ok:'Passwort ändern'});
     const bb=s.querySelector('#bioBtn');
     if(bb)bb.onclick=async()=>{bb.disabled=true;
       try{ if(vmeta.bio){await disableBio();closeSheet();toast('Fingerabdruck ausgeschaltet. Den Passkey „MyBelegBox“ kannst du im Passwortmanager löschen.')}
            else{await enableBio();closeSheet();celebrate('Fingerabdruck an');toast('Fingerabdruck eingeschaltet. Probier es gleich mit „Sperren“ aus.')} }
       catch(x){bb.disabled=false;toast(x&&x.name==='NotAllowedError'?'Abgebrochen.':(x&&x.name==='InvalidStateError'?'Für dieses Gerät gibt es schon einen MyBelegBox-Passkey. Lösche ihn im Passwortmanager und versuch es erneut.':(x&&x.message)||'Das hat nicht geklappt.'))}};
     const ghS=s.querySelector('#ghSetup');
     if(ghS)ghS.onclick=()=>dsForm('GitHub-Sicherung einrichten',[{k:'owner',l:'Konto / Organisation',req:true,v:'jazm-belegbox'},{k:'repo',l:'Privates Repo',req:true,v:'belegbox-daten'},{k:'dir',l:'Ordner im Repo (optional, z. B. belegbox)',v:(ghCfg()&&ghCfg().dir)||''},{k:'token',l:'Zugangsschlüssel (github_pat_…)',t:'password',req:true}],async(v,fail)=>{
       const g={owner:v.owner.trim(),repo:v.repo.trim(),token:v.token.trim()};const dd=bkDir(v.dir);if(dd)g.dir=dd;
       if(!g.owner||!g.repo||!g.token)return fail('Bitte Konto, Repo und Zugangsschlüssel ausfüllen.');
       try{const info=await ghFetch(g,'GET','');
         if(!info)throw Object.assign(new Error(),{status:404});
         if(!info.private)return fail('Dieses Repo ist öffentlich. Aus Sicherheitsgründen sichert die MyBelegBox nur in private Repos.');
         if(info.permissions&&info.permissions.push===false)return fail('Der Schlüssel darf in dieses Repo nicht schreiben. Setze „Contents“ auf „Read and write“.');
       }catch(x){return fail(ghErrText(x))}
       db.meta=Object.assign({},db.meta,{gh:g});setGhStat({err:'',at:0,conflict:false});await save();
       openMenu();ghSync().then(()=>{if(!ghStat.err){celebrate('GitHub verbunden');toast('Automatische Sicherung ist aktiv ✓')}else openMenu()})},
       {ok:'Verbinden & sichern',html:'<p class="ds-dlg-intro">Sichert den verschlüsselten Tresor nach jeder Änderung in ein <b>privates</b> GitHub-Repo. GitHub sieht nur verschlüsselte Daten. Zugangsschlüssel: nur für dieses Repo, mit <b>Contents: Read and write</b>. Tipp: Für alle drei Boxen genügt ein Repo – trag je Box einen eigenen Ordner ein (z. B. smartbox, gesundbox, belegbox) und nutze denselben Zugangsschlüssel.</p>'});
     const ghN=s.querySelector('#ghNow');if(ghN)ghN.onclick=async()=>{await ghSync();if(!ghStat.err){buzz(10);toast('Auf GitHub gesichert ✓')}};
     const ghP=s.querySelector('#ghPull');if(ghP)ghP.onclick=async()=>{
       if(!confirm('Die Daten auf diesem Gerät durch den GitHub-Stand ersetzen?'))return;
       ghP.disabled=true;ghP.textContent='Lade von GitHub …';
       try{const o=await ghRestore(ghCfg());await saving;await restoreVault(o);setGhStat({err:'',conflict:false})}catch(x){ghP.disabled=false;ghP.textContent='GitHub-Stand laden';toast(x&&x.status?ghErrText(x):(x&&x.message||'Das hat nicht geklappt.'))}};
     const ghF=s.querySelector('#ghForce');if(ghF)ghF.onclick=async()=>{if(!confirm('Den Tresor im Repo durch diesen ersetzen? Der alte bleibt in der GitHub-Versionsgeschichte.'))return;await ghSync(true);openMenu();if(!ghStat.err)celebrate('Gesichert')};
     const ghX=s.querySelector('#ghOff');if(ghX)ghX.onclick=()=>{if(!confirm('GitHub-Sicherung trennen? Im Repo bleibt alles liegen.'))return;
       const m=Object.assign({},db.meta);delete m.gh;db.meta=m;setGhStat({err:'',at:0,conflict:false});save();openMenu();toast('GitHub-Sicherung getrennt.')};
     bindUpd(s);
     s.querySelector('#revM').onclick=()=>{closeSheet(false);openReview()};
     const rmOn=s.querySelector('#rmOn');if(rmOn)rmOn.onclick=async()=>{const m=s.querySelector('#rmMsg');rmOn.disabled=true;
       try{const bg=await remindOn();openMenu();celebrate('Erinnerungen an');toast(bg?'Erinnerungen sind an – auch bei geschlossener App.':'Erinnerungen sind an. Dein Browser prüft beim Öffnen der App.')}
       catch(x){rmOn.disabled=false;m.textContent=x.message;m.hidden=false}};
     const rmOff=s.querySelector('#rmOff');if(rmOff)rmOff.onclick=async()=>{await remindOff();openMenu();toast('Erinnerungen ausgeschaltet.')};
     const rmT=s.querySelector('#rmTest');if(rmT)rmT.onclick=async()=>{try{const r=await navigator.serviceWorker.ready;await r.showNotification('MyBelegBox',{body:'So sieht eine Erinnerung aus. Namen und Beträge stehen nie darin.',tag:'belegbox-test',icon:'icons/belegbox-192.png',badge:'icons/belegbox-badge-96.png'});buzz(8)}catch(x){toast('Test hat nicht geklappt.')}};
     s.querySelector('#icsGo').onclick=async()=>{const r=buildIcs(s.querySelector('#icsNeutral').checked);
       if(!r.count){toast('Gerade stehen keine Fristen an.');return}
       if(await deliverFile('belegbox-fristen.ics',r.text,'text/calendar'))toast(r.count+' Termine exportiert. Öffne die Datei mit deinem Kalender.')};
     s.querySelector('#bkGo').onclick=async()=>{await exportBackup();if(root.firstElementChild&&db)openMenu()};
     const bi=s.querySelector('#bkIn');
     bi.addEventListener('change',async()=>{const file=bi.files[0];bi.value='';if(!file)return;
       let pending;try{pending=await readBackupFile(file)}catch(x){toast(x.message);return}
       if(confirm('Die Daten auf diesem Gerät werden durch die Sicherung ersetzt. Fortfahren?'))saving.then(()=>restoreVault(pending))});
     armDelete(s,()=>{db={devices:[],contracts:[]};fileClear().catch(()=>{})})});
}
/* Kleines Fenster für Eingaben (GitHub einrichten, Passwort ändern) – wie in MySmartBox und MyGesundBox */
function dsForm(title,fields,onSave,o={}){
  let d=document.getElementById('dsdlg');
  if(!d){d=document.createElement('dialog');d.id='dsdlg';d.className='dsdlg';d.innerHTML='<form autocomplete="off"></form>';document.body.appendChild(d)}
  const f=d.querySelector('form');
  f.innerHTML=`<h2>${esc(title)}</h2>${o.html||''}${fields.map((x,i)=>`<label for="dsf${i}">${esc(x.l)}</label><input id="dsf${i}" name="${x.k}" type="${x.t||'text'}" value="${esc(x.v||'')}"${x.req?' required':''} autocomplete="${x.ac||'off'}" autocapitalize="off" spellcheck="false">`).join('')}
    <p class="ds-err" hidden></p><div class="dsrow"><button type="button" class="ds-btn" data-x="c">Abbrechen</button><button class="ds-btn pri">${esc(o.ok||'Speichern')}</button></div>`;
  const er=f.querySelector('.ds-err'),ok=f.querySelector('.ds-btn.pri');
  const fail=m=>{er.textContent=m;er.hidden=false;return false};
  f.querySelector('[data-x=c]').onclick=()=>d.close();
  f.onsubmit=async e=>{e.preventDefault();er.hidden=true;const v={};fields.forEach(x=>v[x.k]=f.elements[x.k].value);
    ok.disabled=true;const t=ok.textContent;ok.textContent='Prüfe …';
    try{const r=await onSave(v,fail);if(r!==false)d.close()}catch(x){fail(x&&x.message||'Das hat nicht geklappt.')}finally{ok.disabled=false;ok.textContent=t}};
  if(!d.open)d.showModal();setTimeout(()=>{const i=f.querySelector('input');if(i)i.focus()},50);
}

/* ================= Neue Funktionen (0.7) ================= */

/* ---------- Kosten pro Tag ---------- */
const perDay=c=>monthly(c)*12/365;
const dayTxt=v=>v<1?Math.round(v*100)+' Cent':eur(v);

/* ---------- Vertrag bewusst weiterlaufen lassen (gilt nur für die aktuelle Laufzeit) ---------- */
function weiterOn(c){if(!c.weiter||c.status==='gekuendigt')return false;const i=contractInfo(c);return !i.offen&&c.weiter===iso(i.end)}

/* ---------- Fristen der nächsten 14 Tage: Zähler am Icon und Erinnerungen ---------- */
function dueSoon(){return db?upcoming().filter(e=>!e.weiter&&e.n>=0&&e.n<=14):[]}
function updBadge(){
  if(!db)return;const n=dueSoon().length;
  try{if(navigator.setAppBadge){n?navigator.setAppBadge(n):navigator.clearAppBadge()}}catch(e){}
  writeSched();
}
/* Für Erinnerungen bei geschlossener App: nur Datum und Art, keine Namen, keine Beträge */
const SCHED=NS+'sched-belegbox';
let schedLast='';
async function writeSched(){
  if(!('caches' in window)||!db)return;
  try{const c=await caches.open(SCHED);
    if(!(db.meta&&db.meta.remind)){if(schedLast!=='off'){schedLast='off';await c.delete('./__sched')}return}
    const items=[];
    db.contracts.forEach(k=>{if(k.status==='gekuendigt'||weiterOn(k))return;const i=contractInfo(k);if(i.by&&days(i.by)>=0)items.push({d:iso(i.by),t:'k'});
      const p=priceChange(k);if(p&&days(p.date)>=0)items.push({d:iso(p.date),t:'p'})});
    db.devices.forEach(d=>{const i=deviceInfo(d);[i.gew,i.gar].forEach(x=>{if(x&&days(x)>=0)items.push({d:iso(x),t:'g'})})});
    items.sort((a,b)=>a.d<b.d?-1:1);
    const body=JSON.stringify({items});if(body===schedLast)return;schedLast=body;
    await c.put('./__sched',new Response(body,{headers:{'content-type':'application/json'}}));
  }catch(e){}
}
async function remindPing(force){
  if(!db||!(db.meta&&db.meta.remind)||!('serviceWorker' in navigator))return;
  try{await writeSched();const r=await navigator.serviceWorker.ready;if(r.active)r.active.postMessage({type:'REMIND',force:!!force})}catch(e){}
}
async function remindOn(){
  if(!('Notification' in window)||!('serviceWorker' in navigator))throw new Error('Dieser Browser kann keine Benachrichtigungen anzeigen.');
  const p=await Notification.requestPermission();
  if(p!=='granted')throw new Error('Benachrichtigungen sind für die MyBelegBox blockiert. Erlaube sie in den Android-Einstellungen unter Apps → Chrome bzw. MyBelegBox → Benachrichtigungen.');
  const reg=await navigator.serviceWorker.ready;let bg=false;
  try{if(reg.periodicSync){await reg.periodicSync.register('belegbox-fristen',{minInterval:12*3600e3});bg=true}}catch(e){bg=false}
  db.meta=Object.assign({},db.meta,{remind:true,remindBg:bg});await save();schedLast='';await remindPing(true);return bg;
}
async function remindOff(){
  db.meta=Object.assign({},db.meta,{remind:false});await save();
  try{const reg=await navigator.serviceWorker.ready;if(reg.periodicSync)await reg.periodicSync.unregister('belegbox-fristen');
    (await reg.getNotifications({tag:'belegbox-fristen'})).forEach(n=>n.close())}catch(e){}
  await writeSched();
}

/* ---------- Kleine Helfer ---------- */
async function copyText(t,okMsg){try{await navigator.clipboard.writeText(t);buzz(8);toast(okMsg||'Kopiert.');return true}
  catch(x){toast('Kopieren hat nicht geklappt. Markiere den Text und kopiere ihn von Hand.');return false}}
async function shareText(title,text,files){allowAway();
  if(!navigator.share){return copyText(text,'Teilen geht hier nicht – der Text ist kopiert.')}
  try{if(files&&files.length&&navigator.canShare&&navigator.canShare({files})){await navigator.share({title,text,files});return true}
    await navigator.share({title,text});return true}
  catch(e){if(e&&e.name==='AbortError')return false;return copyText(text,'Teilen ging nicht – der Text ist kopiert.')}}
const fmtLong=d=>d.toLocaleDateString('de-DE',{day:'numeric',month:'long',year:'numeric'});

/* ---------- Kündigungsschreiben ---------- */
function openLetter(c){
  const a=Object.assign({name:'',str:'',ort:''},db.meta&&db.meta.absender);
  const i=contractInfo(c);
  openSheet(head('Kündigung schreiben')+`
    <p class="hint" style="margin:-6px 0 14px">Für <b>${esc(c.anbieter)}</b>. Viele Anbieter haben auf ihrer Webseite einen Knopf „Verträge hier kündigen“ (Pflicht seit Juli 2022) – dort kannst du den Text einfügen. Sonst per E-Mail oder Brief.</p>
    <div class="label" style="margin-bottom:6px">Absender</div>
    <div class="lgrid">
      <label class="field"><span>Name</span><input id="l_name" autocomplete="name" value="${esc(a.name)}"></label>
      <label class="field"><span>Straße und Hausnummer</span><input id="l_str" autocomplete="street-address" value="${esc(a.str)}"></label>
      <label class="field"><span>PLZ und Ort</span><input id="l_ort" autocomplete="off" value="${esc(a.ort)}"></label>
    </div>
    <label class="check" style="margin:10px 0"><input id="l_werb" type="checkbox" checked> Werbung und Rückgewinnungsanrufen widersprechen</label>
    <div class="letter" id="l_txt"></div>
    <div class="actions two" style="margin-top:14px">
      <button type="button" class="btn primary" id="l_share">Teilen</button>
      <button type="button" class="btn" id="l_copy">Text kopieren</button>
      ${c.status!=='gekuendigt'?'<button type="button" class="btn wide2" id="l_done">Abgeschickt – als gekündigt markieren</button>':''}
    </div>`,
  s=>{
    const val=id=>s.querySelector('#'+id).value.trim();
    const build=()=>{const n=val('l_name'),st=val('l_str'),o=val('l_ort');const ort=o.replace(/^\d{4,5}\s*/,'');
      const L=[];if(n)L.push(n);if(st)L.push(st);if(o)L.push(o);if(L.length)L.push('');
      L.push('An: '+c.anbieter,'');
      L.push((ort?ort+', ':'')+fmtLong(T0),'');
      L.push('Kündigung meines Vertrags');
      if(c.kundennr)L.push('Kundennummer: '+c.kundennr);
      if(c.vertragsnr)L.push('Vertragsnummer: '+c.vertragsnr);
      L.push('','Sehr geehrte Damen und Herren,','',
        `hiermit kündige ich meinen Vertrag fristgerecht zum nächstmöglichen Zeitpunkt. Nach meinen Unterlagen ist das der ${fmtD(i.end)}.`,'',
        'Bitte bestätigen Sie mir die Kündigung und das Vertragsende schriftlich.');
      if(s.querySelector('#l_werb').checked)L.push('','Der Nutzung meiner Daten für Werbezwecke widerspreche ich. Von Anrufen zur Rückgewinnung bitte ich abzusehen.');
      L.push('','Mit freundlichen Grüßen',n||'');
      return L.join('\n').replace(/\n+$/,'')};
    const out=s.querySelector('#l_txt');const upd=()=>{out.textContent=build()};
    s.addEventListener('input',upd);s.addEventListener('change',upd);upd();
    const keep=()=>{const na={name:val('l_name'),str:val('l_str'),ort:val('l_ort')};
      const old=db.meta&&db.meta.absender||{};if(na.name!==old.name||na.str!==old.str||na.ort!==old.ort){db.meta=Object.assign({},db.meta,{absender:na});save()}};
    s.querySelector('#l_copy').onclick=()=>{keep();copyText(build(),'Kündigung kopiert.')};
    s.querySelector('#l_share').onclick=()=>{keep();shareText('Kündigung '+c.anbieter,build())};
    const dn=s.querySelector('#l_done');
    if(dn)dn.onclick=()=>{keep();c.status='gekuendigt';c.gekuendigtAm=iso(T0);delete c.weiter;save();render();openDetail('c',c.id);
      celebrate('Gekündigt');toast(`Stark! Ab dem ${fmtD(contractInfo(c).end)} sparst du ${eur(monthly(c)*12)} im Jahr.`)};
  });
}

/* ---------- Garantiefall: alles für die Reklamation in einem Paket ---------- */
function openClaim(d){
  const i=deviceInfo(d),gewOk=days(i.gew)>=0,garOk=i.gar&&days(i.gar)>=0,docs=d.docs||[];
  const an=gewOk?{wer:d.haendler||'den Händler',warum:'gesetzliche Gewährleistung',hint:`Die Gewährleistung läuft bis ${fmtD(i.gew)}. Ansprechpartner ist der Händler, bei dem du gekauft hast.`}
    :garOk?{wer:d.hersteller||'den Hersteller',warum:'Herstellergarantie',hint:`Die Gewährleistung ist abgelaufen, aber die Herstellergarantie läuft noch bis ${fmtD(i.gar)}. Wende dich an den Hersteller.`}
    :{wer:d.haendler||d.hersteller||'den Händler',warum:'Kulanz',hint:'Gewährleistung und Garantie sind abgelaufen. Fragen kostet trotzdem nichts – viele Hersteller helfen aus Kulanz.'};
  openSheet(head('Mangel melden')+`
    <div class="hero ${gewOk||garOk?'h-ok':'h-none'}"><span class="hl">An ${esc(an.wer)}</span><b>${an.warum}</b><span class="hs">${an.hint}</span></div>
    <label class="field"><span>Was ist kaputt?</span><textarea id="m_was" rows="3" placeholder="z. B. Display flackert, Gerät schaltet sich nach wenigen Minuten ab"></textarea></label>
    <label class="field" style="margin-top:10px"><span>Seit wann?</span><input id="m_seit" type="date" value="${iso(T0)}"></label>
    ${docs.length?`<label class="check" style="margin:10px 0 0"><input id="m_docs" type="checkbox" checked> ${docs.length===1?'Beleg':docs.length+' Belege'} beim Teilen anhängen</label>`
      :`<p class="hint" style="margin-top:10px">Zu diesem Gerät ist kein Beleg gespeichert. ${d.nachweis&&d.nachweis!=='keiner'?'Häng deinen Nachweis ('+NACHWEIS[d.nachweis]+') selbst an.':'Such vorher nach Bestellmail oder Kontoauszug.'}</p>`}
    <div class="letter" id="m_txt" style="margin-top:12px"></div>
    <div class="actions two" style="margin-top:14px"><button type="button" class="btn primary" id="m_share">${docs.length?'Mit Belegen teilen':'Teilen'}</button><button type="button" class="btn" id="m_copy">Text kopieren</button></div>
    <p class="hint" id="m_msg" hidden></p>`,
  s=>{
    const build=()=>{const was=s.querySelector('#m_was').value.trim(),seit=s.querySelector('#m_seit').value;
      const L=['Reklamation – '+an.warum,'',
        'Gerät: '+[d.hersteller,d.modell].filter(Boolean).join(' ')+(d.name&&!(d.modell||'').includes(d.name)?' ('+d.name+')':'')];
      if(d.sn)L.push('Seriennummer: '+d.sn);
      L.push('Kaufdatum: '+(d.geschaetzt?'ca. ':'')+fmtD(i.kauf)+(d.haendler?' bei '+d.haendler:'')+(d.preis?', Preis '+eur(d.preis):''));
      L.push('','Mangel: '+(was||'…'));
      if(seit)L.push('Aufgetreten seit: '+fmtD(parse(seit)));
      L.push('');
      if(gewOk){L.push('Ich bitte im Rahmen der gesetzlichen Gewährleistung um Nachbesserung oder Ersatzlieferung.');
        if(seit&&(parse(seit)-i.kauf)/864e5<=365)L.push('Der Mangel ist innerhalb eines Jahres nach dem Kauf aufgetreten. Nach § 477 BGB wird daher vermutet, dass er schon bei Übergabe vorlag.')}
      else if(garOk)L.push(`Ich bitte um Reparatur oder Austausch im Rahmen Ihrer Herstellergarantie (gültig bis ${fmtD(i.gar)}).`);
      else L.push('Ich bitte um eine Lösung auf Kulanz.');
      L.push('Der Kaufbeleg liegt bei. Bitte teilen Sie mir das weitere Vorgehen mit.','','Mit freundlichen Grüßen');
      const n=db.meta&&db.meta.absender&&db.meta.absender.name;if(n)L.push(n);
      return L.join('\n')};
    const out=s.querySelector('#m_txt');const upd=()=>{out.textContent=build()};s.addEventListener('input',upd);s.addEventListener('change',upd);upd();
    s.querySelector('#m_copy').onclick=()=>copyText(build(),'Reklamation kopiert.');
    s.querySelector('#m_share').onclick=async()=>{const b=s.querySelector('#m_share'),m=s.querySelector('#m_msg');
      const want=s.querySelector('#m_docs')&&s.querySelector('#m_docs').checked;let files=[];
      if(want){b.disabled=true;b.textContent='Belege werden vorbereitet …';
        for(const x of docs){try{files.push(new File([await openDoc(x.id)],x.name,{type:x.type}))}catch(e){}}
        b.disabled=false;b.textContent='Mit Belegen teilen';
        if(files.length<docs.length){m.textContent='Nicht alle Belege konnten geöffnet werden.';m.hidden=false}}
      shareText('Reklamation '+(d.name||''),build(),files)};
    s.querySelector('#m_was').focus({preventScroll:true});
  });
}

/* ---------- Seriennummer per Kamera scannen (Barcode / QR) ---------- */
const canScan=()=>'BarcodeDetector' in window&&!!(navigator.mediaDevices&&navigator.mediaDevices.getUserMedia);
async function openScanner(onPick){
  const ov=document.createElement('div');ov.className='scanov';ov.setAttribute('role','dialog');ov.setAttribute('aria-modal','true');
  ov.innerHTML=`<div class="scanhead"><b>Seriennummer scannen</b><button type="button" class="x" aria-label="Schließen">✕</button></div>
    <div class="scanbox"><video playsinline muted autoplay></video><div class="scanframe"></div></div>
    <p class="scanmsg">Halte die Kamera auf den Barcode oder QR-Code am Typenschild.</p><div class="scanhits"></div>`;
  document.body.appendChild(ov);
  const video=ov.querySelector('video'),msg=ov.querySelector('.scanmsg'),hits=ov.querySelector('.scanhits');
  let stream=null,alive=true,timer=0;const seen=new Map();
  const close=()=>{alive=false;clearTimeout(timer);if(stream)stream.getTracks().forEach(t=>t.stop());ov.remove();layerClosed()};
  layerOpened();
  ov.querySelector('.x').onclick=close;
  try{
    const fm=await BarcodeDetector.getSupportedFormats().catch(()=>[]);
    const det=new BarcodeDetector(fm.length?{formats:fm}:undefined);
    stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:'environment'},width:{ideal:1920},height:{ideal:1080}},audio:false});
    if(!alive){stream.getTracks().forEach(t=>t.stop());return}
    video.srcObject=stream;await video.play().catch(()=>{});
    const tick=async()=>{if(!alive)return;
      try{if(video.readyState>=2){const r=await det.detect(video);
        r.forEach(b=>{const v=String(b.rawValue||'').trim();if(!v||v.length>80||seen.has(v))return;seen.set(v,b.format);buzz(8);
          const btn=document.createElement('button');btn.type='button';btn.className='btn';btn.innerHTML=`<span class="code">${esc(v)}</span><small>${esc(String(b.format).replace(/_/g,' '))} · übernehmen</small>`;
          btn.onclick=()=>{onPick(v);close()};hits.appendChild(btn);
          msg.textContent=seen.size>1?'Mehrere Codes gefunden – tippe die Seriennummer an.':'Gefunden. Tippe zum Übernehmen – oder warte auf weitere Codes.'})}}catch(e){}
      timer=setTimeout(tick,250)};
    tick();
  }catch(e){msg.textContent=e&&e.name==='NotAllowedError'?'Die Kamera ist blockiert. Erlaube den Kamerazugriff für die MyBelegBox und versuch es erneut.':'Die Kamera konnte nicht gestartet werden.';msg.classList.add('err')}
}

/* ---------- Suche über alles ---------- */
function openSearch(){
  openSheet(head('Suchen')+`<label class="ds-srch"><span class="sr">Suchbegriff</span><input id="q" type="search" placeholder="Name, Seriennummer, Notiz, Kundennummer …" autocomplete="off" enterkeyhint="search"></label>
    <div id="qres" class="ds-qres"></div>`,
  s=>{const q=s.querySelector('#q'),R=s.querySelector('#qres');
    const fieldsD=d=>[['',d.name],['',d.hersteller],['',d.modell],['Seriennr.',d.sn],['',d.raum],['',d.haendler],['',d.kategorie],['Notiz',d.notiz],['',(d.docs||[]).map(x=>x.name).join(' ')]];
    const fieldsC=c=>[['',c.anbieter],['',c.kategorie],['Kundennr.',c.kundennr],['Vertragsnr.',c.vertragsnr],['Notiz',c.notiz],['',(c.docs||[]).map(x=>x.name).join(' ')]];
    const hitIn=(fs,terms)=>{const all=fs.map(f=>String(f[1]||'').toLowerCase()).join(' \u0001 ');if(!terms.every(t=>all.includes(t)))return null;
      const f=fs.find(f=>f[0]&&terms.some(t=>String(f[1]||'').toLowerCase().includes(t)));return f?f:true};
    const snip=(f,terms)=>{if(f===true)return '';const v=String(f[1]);const p=v.toLowerCase().indexOf(terms.find(t=>v.toLowerCase().includes(t)));
      const a=Math.max(0,p-24),txt=(a?'…':'')+v.slice(a,p+40)+(p+40<v.length?'…':'');
      return `<span class="qs">${esc(f[0])}: ${f[0]==='Kundennr.'||f[0]==='Vertragsnr.'?esc(maskVal(v)):esc(txt)}</span>`};
    const draw=()=>{const terms=q.value.toLowerCase().split(/\s+/).filter(Boolean);
      if(!terms.length){R.innerHTML=`<p class="ds-qhint">${db.devices.length} Geräte und ${db.contracts.length} Verträge durchsuchbar – auch Seriennummern, Notizen, Kunden­nummern und Dateinamen von Belegen.</p>`;return}
      const D=[],C=[];
      db.devices.forEach(d=>{const h=hitIn(fieldsD(d),terms);if(h)D.push([d,h])});
      db.contracts.forEach(c=>{const h=hitIn(fieldsC(c),terms);if(h)C.push([c,h])});
      if(!D.length&&!C.length){R.innerHTML='<p class="ds-qhint">Nichts gefunden.</p>';return}
      R.innerHTML=(D.length?`<div class="ds-lbl">Geräte</div><div class="ds-qlist">${D.slice(0,30).map(([d,h])=>`<button type="button" class="row" data-qk="d" data-qi="${d.id}">${tileFor(d)}<div class="main"><div class="t">${esc(d.name)}</div><div class="s">${esc([d.hersteller,d.raum].filter(Boolean).join(' · '))}</div>${snip(h,terms)}</div><span></span></button>`).join('')}</div>`:'')
        +(C.length?`<div class="ds-lbl">Verträge</div><div class="ds-qlist">${C.slice(0,30).map(([c,h])=>`<button type="button" class="row" data-qk="c" data-qi="${c.id}">${conTile(c)}<div class="main"><div class="t">${esc(c.anbieter)}</div><div class="s">${esc(c.kategorie)}</div>${snip(h,terms)}</div><span class="amt num">${eur(monthly(c))}<small>/Monat</small></span></button>`).join('')}</div>`:'');
      R.querySelectorAll('[data-qi]').forEach(b=>b.onclick=()=>openDetail(b.dataset.qk,b.dataset.qi))};
    q.addEventListener('input',draw);draw();setTimeout(()=>q.focus(),motion()?320:0);
  });
}

/* ---------- Abo-Check alle 3 Monate ---------- */
const CHECK_KAT=['Streaming','Software','Fitness','Sonstiges'];
function checkDue(){
  return db.contracts.filter(c=>{if(c.status==='gekuendigt'||!CHECK_KAT.includes(c.kategorie))return false;
    if(c.checkSnooze&&days(parse(c.checkSnooze))>0)return false;
    const base=c.check||c.beginn;return !base||days(parse(base))<=-90})
    .sort((a,b)=>monthly(b)-monthly(a))[0]||null}
function checkCard(){const c=checkDue();if(!c)return '';
  return `<div class="chk" data-chk="${c.id}">
    <div class="chkhead">${conTile(c)}<div class="chkt"><span class="label">Abo-Check</span><b>Nutzt du ${esc(c.anbieter)} noch?</b><small class="num">${eur(monthly(c)*12)} im Jahr · ${dayTxt(perDay(c))} am Tag</small></div></div>
    <div class="chkbtns"><button type="button" class="btn primary" data-a="ja">Behalten</button><button type="button" class="btn" data-a="nein">Kündigen</button><button type="button" class="btn ghostbtn" data-a="spaeter">Später</button></div></div>`}
function bindCheck(){const el=main.querySelector('[data-chk]');if(!el)return;const c=db.contracts.find(x=>x.id===el.dataset.chk);if(!c)return;
  el.querySelectorAll('[data-a]').forEach(b=>b.onclick=()=>{const a=b.dataset.a;delete c.checkSnooze;
    if(a==='ja'){c.check=iso(T0);buzz(8);toast(`Alles klar. In 3 Monaten frag ich wieder nach ${c.anbieter}.`)}
    else if(a==='spaeter'){c.checkSnooze=iso(addDays(T0,7));buzz(5);toast('Ich frag in einer Woche nochmal.')}
    else{c.check=iso(T0);save();render();openLetter(c);return}
    save();if(motion())el.animate([{opacity:1,transform:'none'},{opacity:0,transform:'translateX(30px)'}],{duration:220,easing:'ease-in'}).onfinish=()=>render();else render()})}

/* ---------- Jahresrückblick ---------- */
function reviewYear(){const m=T0.getMonth();return m===0?T0.getFullYear()-1:T0.getFullYear()}
function reviewSeason(){const m=T0.getMonth(),d=T0.getDate();return m===11||(m===0&&d<=15)}
function reviewStats(Y){
  const inY=s=>s&&String(s).slice(0,4)===String(Y);
  const act=db.contracts.filter(c=>c.status!=='gekuendigt');
  const mon=act.reduce((s,c)=>s+monthly(c),0);
  const top=act.slice().sort((a,b)=>monthly(b)-monthly(a))[0]||null;
  const gek=db.contracts.filter(c=>inY(c.gekuendigtAm));const spar=gek.reduce((s,c)=>s+monthly(c)*12,0);
  const neu=db.devices.filter(d=>inY(d.kauf));const neuW=neu.reduce((s,d)=>s+Number(d.preis||0),0);
  const neuTop=neu.slice().sort((a,b)=>Number(b.preis||0)-Number(a.preis||0))[0]||null;
  const ab=db.devices.filter(d=>{const r=rateInfo(d);return r&&!r.aktiv&&inY(iso(r.last))});
  const belege=[...db.devices,...db.contracts].reduce((s,x)=>s+(x.docs||[]).filter(d=>inY(d.added)).length,0);
  const byKat={};act.forEach(c=>byKat[c.kategorie]=(byKat[c.kategorie]||0)+monthly(c));
  const kat=Object.entries(byKat).sort((a,b)=>b[1]-a[1])[0]||null;
  const wert=db.devices.reduce((s,d)=>s+Number(d.preis||0),0);
  return {mon,top,gek,spar,neu,neuW,neuTop,ab,belege,kat,wert,nAct:act.length,nDev:db.devices.length}}
function openReview(){
  const Y=reviewYear(),st=reviewStats(Y),bisher=T0.getMonth()<11&&Y===T0.getFullYear();
  const S=[];
  S.push({k:'MyBelegBox',big:String(Y),sub:bisher?'Dein Jahr bis heute – tipp dich durch.':'Dein Jahr in Zahlen – tipp dich durch.',bg:'g1'});
  S.push({k:'Deine Fixkosten',big:eur(st.mon*12),sub:`im Jahr für ${st.nAct} Verträge${st.mon?` – das sind ${dayTxt(st.mon*12/365)} an jedem einzelnen Tag.`:'.'}`,bg:'g2'});
  if(st.top)S.push({k:'Dein teuerstes Abo',big:esc(st.top.anbieter),sub:`${eur(monthly(st.top))} im Monat · ${eur(monthly(st.top)*12)} im Jahr`,bg:'g3'});
  if(st.kat)S.push({k:'Hier geht das meiste Geld hin',big:esc(st.kat[0]),sub:`${eur(st.kat[1])} im Monat`,bg:'g4'});
  S.push(st.gek.length?{k:`${Y} gekündigt`,big:String(st.gek.length),sub:`${st.gek.map(c=>esc(c.anbieter)).slice(0,4).join(', ')}${st.gek.length>4?' …':''} – das spart ${eur(st.spar)} im Jahr.`,bg:'g5'}
    :{k:`${Y} gekündigt`,big:'0',sub:'Kein einziges Abo gekündigt. Vielleicht hilft dir der Abo-Check im neuen Jahr?',bg:'g5'});
  if(st.neu.length)S.push({k:'Neu dazugekommen',big:`${st.neu.length} Gerät${st.neu.length>1?'e':''}`,sub:`zusammen ${eur(st.neuW)}${st.neuTop&&st.neuTop.preis?` – am teuersten: ${esc(st.neuTop.name)}`:''}`,bg:'g6'});
  if(st.ab.length)S.push({k:'Abbezahlt',big:String(st.ab.length),sub:`${st.ab.map(d=>esc(d.name)).join(', ')} – keine Raten mehr!`,bg:'g3'});
  S.push({k:'Gut aufgehoben',big:String(st.belege),sub:`Beleg${st.belege===1?'':'e'} ${Y} gespeichert · ${st.nDev} Geräte im Wert von ${eur(st.wert)}`,bg:'g2'});
  S.push({k:'Das war '+Y,big:Y===T0.getFullYear()&&T0.getMonth()<11?'Weiter so!':'Auf '+(Y+1)+'!',sub:'Danke, dass du deine Verträge im Blick behältst.',bg:'g1',end:true});
  const ov=document.createElement('div');ov.className='story';ov.setAttribute('role','dialog');ov.setAttribute('aria-modal','true');
  ov.innerHTML=`<div class="sbars">${S.map(()=>'<i><b></b></i>').join('')}</div><button type="button" class="x sx" aria-label="Schließen">✕</button><div class="sslide"></div>
    <div class="snav"><button type="button" class="sprev" aria-label="Zurück"></button><button type="button" class="snext" aria-label="Weiter"></button></div>`;
  document.body.appendChild(ov);document.body.style.overflow='hidden';
  let n=0,timer=0;const bars=[...ov.querySelectorAll('.sbars i')],sl=ov.querySelector('.sslide');
  const close=()=>{clearTimeout(timer);ov.remove();if(!root.firstElementChild)document.body.style.overflow='';layerClosed()};
  layerOpened();
  const show=k=>{n=Math.max(0,Math.min(S.length-1,k));const s=S[n];clearTimeout(timer);
    ov.className='story '+s.bg;bars.forEach((b,j)=>{b.className=j<n?'done':j===n?'now':''});
    sl.innerHTML=`<div class="sk">${s.k}</div><div class="sbig">${s.big}</div><div class="ssub">${s.sub}</div>${s.end?'<button type="button" class="btn sdone">Schließen</button>':''}`;
    if(motion())sl.animate([{opacity:0,transform:'translateY(18px) scale(.98)'},{opacity:1,transform:'none'}],{duration:420,easing:'cubic-bezier(.2,.85,.25,1)'});
    const d=sl.querySelector('.sdone');if(d)d.onclick=close;
    if(s.end){buzz([12,50,24]);return}
    if(motion())timer=setTimeout(()=>show(n+1),5200)};
  ov.querySelector('.sx').onclick=close;ov.querySelector('.snext').onclick=()=>{buzz(4);n===S.length-1?close():show(n+1)};ov.querySelector('.sprev').onclick=()=>{buzz(4);show(n-1)};
  show(0);
}

/* ---------- Aus anderen Apps geteilte Dateien (Share Target) ---------- */
const INBOX=NS+'inbox-belegbox';
async function inboxFiles(){if(!('caches' in window))return [];
  const c=await caches.open(INBOX),ks=await c.keys(),out=[];
  for(const k of ks){const r=await c.match(k);if(!r)continue;const b=await r.blob();
    out.push({key:k,file:new File([b],decodeURIComponent(r.headers.get('x-name')||'Datei'),{type:r.headers.get('content-type')||b.type})})}
  return out}
async function inboxClear(items){try{const c=await caches.open(INBOX);for(const it of items)await c.delete(it.key)}catch(e){}}
async function attachFiles(it,files){
  const docs=it.docs?it.docs.slice():[];let ok=0;
  for(const f of files){const isPdf=f.type==='application/pdf'||/\.pdf$/i.test(f.name);if(!isPdf&&!/^image\//.test(f.type))continue;
    try{const r=await prepDoc(f,isPdf);await filePut(r.meta.id,await sealFile(r.meta.id,r.buf));docs.push(r.meta);ok++}catch(e){}}
  it.docs=docs;db.meta=Object.assign({},db.meta,{dirty:(db.meta&&db.meta.dirty||0)+1});await save();return ok}
const SHARE_T='application/x-belegbox-share';
async function openInbox(items){
  const fileItems=items.filter(x=>x.file.type!==SHARE_T),notes=items.filter(x=>x.file.type===SHARE_T);
  if(!fileItems.length){ // keine Datei angekommen: zeigen, was stattdessen kam
    let info={};try{info=JSON.parse(await notes[notes.length-1].file.text())}catch(e){}
    return openShareText(items,info)}
  if(notes.length)inboxClear(notes);
  items=fileItems;
  const files=items.map(x=>x.file),names=files.map(f=>esc(f.name)).join(', ');
  const all=[...db.devices.map(d=>({k:'d',it:d,t:d.name,s:[d.hersteller,d.raum].filter(Boolean).join(' · ')})),...db.contracts.map(c=>({k:'c',it:c,t:c.anbieter,s:c.kategorie}))];
  openSheet(head(files.length>1?files.length+' Dateien empfangen':'Datei empfangen')+`
    <p class="hint" style="margin:-6px 0 14px">${names}</p>
    <div class="actions two"><button type="button" class="btn primary" id="i_d">Neues Gerät</button><button type="button" class="btn primary" id="i_c">Neuer Vertrag</button></div>
    <div class="label" style="margin:18px 0 8px">Oder zu einem vorhandenen Eintrag</div>
    <label class="field srchf"><span class="sr">Eintrag suchen</span><input id="i_q" type="search" placeholder="Eintrag suchen …" autocomplete="off"></label>
    <div class="list" id="i_list" style="margin-top:10px"></div>
    <div class="actions" style="margin-top:16px"><button type="button" class="btn danger" id="i_x">Verwerfen</button></div>`,
  s=>{const L=s.querySelector('#i_list'),q=s.querySelector('#i_q');
    const draw=()=>{const t=q.value.toLowerCase().trim();const hit=all.filter(x=>!t||(x.t+' '+x.s).toLowerCase().includes(t)).slice(0,25);
      L.innerHTML=hit.length?hit.map(x=>`<button type="button" class="row" data-ik="${x.k}" data-ii="${x.it.id}">${x.k==='d'?tileFor(x.it):conTile(x.it)}<div class="main"><div class="t">${esc(x.t)}</div><div class="s">${esc(x.s||'')}</div></div><span class="pill p-none">${x.k==='d'?'Gerät':'Vertrag'}</span></button>`).join(''):'<div class="empty">Nichts gefunden.</div>';
      L.querySelectorAll('[data-ii]').forEach(b=>b.onclick=async()=>{const it=(b.dataset.ik==='d'?db.devices:db.contracts).find(x=>x.id===b.dataset.ii);if(!it)return;
        b.disabled=true;b.querySelector('.pill').textContent='Wird verschlüsselt …';
        const n=await attachFiles(it,files);await inboxClear(items);render();openDetail(b.dataset.ik,it.id);
        if(n){celebrate('Gespeichert');toast(`${n===1?'Datei':n+' Dateien'} bei ${b.dataset.ik==='d'?it.name:it.anbieter} gespeichert.`)}else toast('Die Datei konnte nicht gelesen werden. Erlaubt sind PDF und Bilder.')})};
    q.addEventListener('input',draw);draw();
    const newWith=k=>{openForm(k);const inp=root.querySelector('#docIn');
      if(inp&&window.DataTransfer){const dt=new DataTransfer();files.forEach(f=>dt.items.add(f));inp.files=dt.files;inp.dispatchEvent(new Event('change'))}
      inboxClear(items)};
    s.querySelector('#i_d').onclick=()=>newWith('d');s.querySelector('#i_c').onclick=()=>newWith('c');
    s.querySelector('#i_x').onclick=async()=>{await inboxClear(items);closeSheet();toast('Verworfen.')};
  });
}

/* Geteilt wurde nur ein Link oder Text – oder es ging etwas schief */
function openShareText(items,info){
  const txt=String(info.text||'').trim();
  const all=[...db.devices.map(d=>({k:'d',it:d,t:d.name,s:[d.hersteller,d.raum].filter(Boolean).join(' · ')})),...db.contracts.map(c=>({k:'c',it:c,t:c.anbieter,s:c.kategorie}))];
  const why=info.error?`Beim Empfangen ist ein Fehler aufgetreten (${esc(info.error)}). Versuch es bitte noch einmal.`
    :info.big?'Die Datei ist größer als 25 MB und wurde nicht übernommen.'
    :'Es kam keine Datei an, sondern nur ein Link oder Text. In <b>Adobe Acrobat</b> unter „Teilen“ die Option <b>„Kopie senden“</b> bzw. <b>„Datei teilen“</b> wählen – nicht „Link teilen“. In Gmail den PDF-Anhang öffnen und von dort teilen.';
  openSheet(head(txt?'Link oder Text empfangen':'Nichts empfangen')+`
    <div class="note" style="margin:-4px 0 14px">${why}</div>
    ${txt?`<div class="letter">${esc(txt)}</div>
      <div class="label" style="margin:16px 0 8px">Als Notiz zu einem Eintrag speichern</div>
      <label class="field srchf"><span class="sr">Eintrag suchen</span><input id="t_q" type="search" placeholder="Eintrag suchen …" autocomplete="off"></label>
      <div class="list" id="t_list" style="margin-top:10px"></div>`:''}
    <div class="actions" style="margin-top:16px"><button type="button" class="btn" id="t_x">${txt?'Verwerfen':'Schließen'}</button></div>`,
  s=>{s.querySelector('#t_x').onclick=async()=>{await inboxClear(items);closeSheet()};
    if(!txt){inboxClear(items);return}
    const L=s.querySelector('#t_list'),q=s.querySelector('#t_q');
    const draw=()=>{const t=q.value.toLowerCase().trim();const hit=all.filter(x=>!t||(x.t+' '+x.s).toLowerCase().includes(t)).slice(0,25);
      L.innerHTML=hit.length?hit.map(x=>`<button type="button" class="row" data-ik="${x.k}" data-ii="${x.it.id}">${x.k==='d'?tileFor(x.it):conTile(x.it)}<div class="main"><div class="t">${esc(x.t)}</div><div class="s">${esc(x.s||'')}</div></div><span class="pill p-none">${x.k==='d'?'Gerät':'Vertrag'}</span></button>`).join(''):'<div class="empty">Nichts gefunden.</div>';
      L.querySelectorAll('[data-ii]').forEach(b=>b.onclick=async()=>{const it=(b.dataset.ik==='d'?db.devices:db.contracts).find(x=>x.id===b.dataset.ii);if(!it)return;
        if(textBanky(txt)){toast('Der Text enthält eine IBAN oder Kartennummer und wird deshalb nicht gespeichert.');return}
        it.notiz=(it.notiz?it.notiz.replace(/\s+$/,'')+'\n\n':'')+fmtD(T0)+': '+txt;
        db.meta=Object.assign({},db.meta,{dirty:(db.meta&&db.meta.dirty||0)+1});await save();await inboxClear(items);render();openDetail(b.dataset.ik,it.id);
        buzz(10);toast('Als Notiz gespeichert.')})};
    q.addEventListener('input',draw);draw()});
}

/* ---------- Schnellaktionen am App-Icon und Start nach dem Entsperren ---------- */
const QS=new URLSearchParams(location.search);
{const H=new URLSearchParams(location.hash.slice(1));for(const k of ['neu','ref'])if(H.get(k)&&!QS.get(k))QS.set(k,H.get(k))}
let pendingAct=QS.get('aktion'),pendingShare=QS.has('geteilt'),pendingNeu=QS.get('neu'),pendingRef=QS.get('ref');
if(location.search||/^#(neu|ref)=/.test(location.hash)){try{history.replaceState(null,'',location.pathname)}catch(e){}}
function afterUnlock(){
  setTimeout(async()=>{if(!db)return;
    let items=[];try{items=await inboxFiles()}catch(e){}
    if(items.length){pendingAct=null;pendingShare=false;openInbox(items);return}
    if(pendingShare){pendingShare=false;openShareText([],{})}
    if(pendingNeu||pendingRef){const n=pendingNeu,rf=pendingRef;pendingNeu=pendingRef=null;openExternal(n,rf);remindPing(false);return}
    const a=pendingAct;pendingAct=null;
    if(a==='foto')openForm('d',null,true);else if(a==='geraet')openForm('d');else if(a==='vertrag')openForm('c');else if(a==='suche')openSearch();
    remindPing(false);
  },motion()?950:60);
}

/* ---------- Zurück-Geste (Android): oberstes Fenster schließen statt die App ---------- */
let histPushed=false,ignorePop=false;
function topLayer(){
  const V=document.getElementById('viewer');if(V&&!V.hidden)return 'viewer';
  if(document.querySelector('.scanov'))return 'scan';
  if(document.querySelector('.story'))return 'story';
  if(document.querySelector('.pop'))return 'pop';
  const sc=root.firstElementChild;if(sc&&!sc.classList.contains('closing'))return 'sheet';
  if(fanOpen)return 'fan';return null}
function layerOpened(){if(!histPushed&&key){try{history.pushState({belegbox:1},'');histPushed=true}catch(e){}}}
function layerClosed(){setTimeout(()=>{if(histPushed&&!topLayer()){histPushed=false;ignorePop=true;try{history.back()}catch(e){ignorePop=false}}},0)}
addEventListener('popstate',()=>{
  if(ignorePop){ignorePop=false;return}
  histPushed=false;const t=topLayer();
  if(t==='viewer')closeViewer();
  else if(t==='scan'||t==='story'){const el=document.querySelector(t==='scan'?'.scanov .x':'.story .sx');if(el)el.click()}
  else if(t==='pop')closePop();
  else if(t==='sheet')closeSheet();
  else if(t==='fan')setFan(false);
  setTimeout(()=>{if(topLayer())layerOpened()},300);
});

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
  if(open){fan.hidden=false;void fan.offsetWidth;fan.classList.add('show');buzz(6);layerOpened()}
  else{fan.classList.remove('show');layerClosed();setTimeout(()=>{if(!fanOpen)fan.hidden=true},motion()?260:0)}
}
fab.onclick=()=>setFan(!fanOpen);
let lastY=0;addEventListener('scroll',()=>{const y=window.scrollY;if(Math.abs(y-lastY)<8)return;
  fab.classList.toggle('shrunk',y>lastY&&y>120);lastY=y},{passive:true});
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
  render('rise');
  /* Neue Version: gleiche Rückfrage wie in MySmartBox und MyGesundBox */
  if(upd){if(confirm('Eine neue Version der MyBelegBox ist da. Jetzt neu laden?')){const w=swReg.waiting||swReg.installing;
      const go=()=>saving.then(()=>w.postMessage('SKIP_WAITING'));if(w){if(w.state==='installed')go();else w.addEventListener('statechange',()=>{if(w.state==='installed')go()})}}}
  else toast('Alles aktuell. Fristen sind neu berechnet.');
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
if(IS_TEST){document.title='MyBelegBox TEST';const h=document.querySelector('.brand h1');if(h)h.insertAdjacentHTML('beforeend',' <span class="testtag">TEST</span>')}
document.getElementById('searchBtn').onclick=()=>{if(!db)return;setFan(false);openSearch()};
document.getElementById('lockBtn').onclick=()=>lock(true);
boot();

/* Service Worker: offline nutzbar, Hinweis bei neuer Version */
if('serviceWorker' in navigator){
  let reloading=false;const hadController=!!navigator.serviceWorker.controller;
  // Nur neu laden, wenn eine bestehende Version abgelöst wird – nicht beim allerersten Installieren
  navigator.serviceWorker.addEventListener('controllerchange',()=>{if(reloading||!hadController)return;reloading=true;location.reload()});
  navigator.serviceWorker.register('sw.js',{updateViaCache:'none'}).then(reg=>{swReg=reg;
    const offer=w=>{const r=document.getElementById('updRoot');
      r.innerHTML='<div class="ds-updbar" role="status"><span>Neue Version der MyBelegBox ist da.</span><button type="button" class="ds-btn pri" id="updGo">Aktualisieren</button><button type="button" class="ds-x" id="updX" aria-label="Später">✕</button></div>';
      document.getElementById('updGo').onclick=()=>saving.then(()=>w.postMessage('SKIP_WAITING'));
      document.getElementById('updX').onclick=()=>{r.innerHTML=''}};
    if(reg.waiting&&navigator.serviceWorker.controller)offer(reg.waiting);
    reg.addEventListener('updatefound',()=>{const w=reg.installing;if(!w)return;
      w.addEventListener('statechange',()=>{if(w.state==='installed'&&navigator.serviceWorker.controller)offer(w)})});
    setInterval(()=>reg.update().catch(()=>{}),60*60e3);
  }).catch(()=>{});
}

/* ================= Verbindung zur MyGesundBox (0.9.1) =================
   Die MyGesundBox schickt einen Eintrag als Link (?neu=…). Gespeichert wird nur die Verknüpfung (ext),
   die Daten bleiben in der jeweiligen App. ?ref=… öffnet einen bereits übernommenen Eintrag. */
const GB_URL=/^https:\/\/jazm-gesundbox\.github\.io\//;
const SB_URL=/^https:\/\/jazm-smartbox\.github\.io\//;
/* Partner-Apps: Erkennung über die Adresse, Kennungen mit festem Präfix */
const EXT_APPS=[
  {src:'MyGesundBox',re:GB_URL,pre:/^mygesundbox:/,what:'Sehstärke, Gläser und Pflege',cls:'gb',ico:'<path d="M12 21s-7-4.4-9.5-9A5.5 5.5 0 0 1 12 6a5.5 5.5 0 0 1 9.5 6c-2.5 4.6-9.5 9-9.5 9z"/>'},
  {src:'MySmartBox',re:SB_URL,pre:/^mysmartbox:/,what:'Raum, Grundriss und Bedienung',cls:'sb',ico:'<path d="M3 11l9-7 9 7"/><path d="M5 10v10h14V10"/><path d="M10 20v-5h4v5"/>'}];
const extApp=x=>x&&x.ext&&EXT_APPS.find(a=>a.re.test(x.ext.url||''));
function b64urlDecode(t){t=String(t||'').replace(/-/g,'+').replace(/_/g,'/');while(t.length%4)t+='=';return td.decode(fromB64(t))}
function findExt(ref){if(!db||!ref)return null;const d=db.devices.find(x=>x.ext&&x.ext.ref===ref);if(d)return['d',d];const c=db.contracts.find(x=>x.ext&&x.ext.ref===ref);return c?['c',c]:null}
function extBlock(x){const a=extApp(x);if(!a)return '';
  return `<a class="extlink ${a.cls}" href="${esc(x.ext.url)}" target="_blank" rel="noopener"><span class="ai"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${a.ico}</svg></span><span class="at"><b>In der ${a.src} öffnen</b><small>${esc(x.ext.what||a.what)}</small></span><svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 6l6 6-6 6"/></svg></a>`}
/* Ähnliche vorhandene Geräte finden (z. B. „TV“ ↔ „Fernseher Wohnzimmer“) */
const SYN=[['tv','fernseher','fernseh','television'],['kühlschrank','kuehlschrank'],['waschmaschine','wama'],['trockner','wäschetrockner'],['saugroboter','saug','robot','staubsauger'],['lautsprecher','speaker','sonos','echo','alexa'],['router','fritzbox','fritz!box'],['kamera','cam','arlo']];
const nrm=t=>String(t||'').toLowerCase().replace(/[^a-z0-9äöüß ]/g,' ').replace(/\s+/g,' ').trim();
function likeScore(d,o){const a=nrm(o.name),b=nrm(d.name);if(!a||!b)return 0;let sc=0;
  if(a===b)sc+=10;else if(b.includes(a)||a.includes(b))sc+=6;
  const wa=a.split(' '),wb=b.split(' ');sc+=wa.filter(w=>w.length>2&&wb.includes(w)).length*3;
  for(const g of SYN)if(g.some(w=>a.includes(w))&&g.some(w=>b.includes(w)))sc+=5;
  if(o.raum&&d.raum&&nrm(o.raum)===nrm(d.raum))sc+=2;
  return sc}
function openExternal(neu,ref){
  try{
    if(ref){const f=findExt(ref);if(f){tab=f[0]==='d'?'geraete':'vertraege';render();openDetail(f[0],f[1].id)}else toast('Dieser Eintrag ist noch nicht in der MyBelegBox.');return}
    const o=JSON.parse(b64urlDecode(neu));const app=o&&o.ref&&EXT_APPS.find(a=>a.pre.test(o.ref));if(!app)throw new Error('format');
    const f=findExt(o.ref);if(f){tab=f[0]==='d'?'geraete':'vertraege';render();openDetail(f[0],f[1].id);toast('Ist schon mit der MyBelegBox verknüpft.');return}
    const ext={src:app.src,ref:String(o.ref),url:app.re.test(o.url||'')?String(o.url):'',what:String(o.what||'')};
    const str=v=>v==null?'':String(v).slice(0,300),num=v=>{const n=parseFloat(v);return isFinite(n)&&n>=0?n:0};
    if(o.k==='c'){
      openForm('c',null,false,{_ext:ext,anbieter:str(o.anbieter),kategorie:'Gesundheit',kosten:num(o.kosten),intervall:Number(o.intervall)||1,modus:['beginn','ende','offen'].includes(o.modus)?o.modus:'offen',
        laufzeit:Number(o.laufzeit)||1,verl:Number(o.verl)||1,frist:Number(o.frist)||0,notiz:str(o.notiz),logo:''});
      return;
    }
    const tpl={_ext:ext,name:str(o.name)||(app.src==='MyGesundBox'?'Brille':'Gerät'),kategorie:DEV_KAT.includes(o.kategorie)?o.kategorie:(app.src==='MyGesundBox'?'Gesundheit':'Technik'),raum:str(o.raum),hersteller:str(o.hersteller),modell:str(o.modell),
      kauf:/^\d{4}-\d{2}-\d{2}$/.test(o.kauf||'')?o.kauf:iso(T0),preis:num(o.preis),haendler:str(o.haendler),garantieMonate:Number(o.garantieMonate)||0,nachweis:'keiner',notiz:str(o.notiz)};
    const free=db.devices.filter(d=>!d.ext);
    const cand=free.map(d=>[likeScore(d,o),d]).filter(x=>x[0]>=5).sort((a,b)=>b[0]-a[0]).map(x=>x[1]).slice(0,4);
    if(app.src==='MySmartBox'&&free.length)return openLinkChooser(o,ext,tpl,cand,free);
    openForm('d',null,false,tpl);
  }catch(e){toast('Der Link aus der anderen App ließ sich nicht lesen.')}
}
/* Gerät aus der MySmartBox: mit vorhandenem Gerät verknüpfen oder neu anlegen */
function openLinkChooser(o,ext,tpl,cand,free){
  const row=d=>`<button type="button" class="row" data-li="${d.id}">${tileFor(d)}<div class="main"><div class="t">${esc(d.name)}</div><div class="s">${esc([d.hersteller,d.raum].filter(Boolean).join(' · '))}</div></div><span class="pill p-none">Verknüpfen</span></button>`;
  openSheet(head('Aus der MySmartBox')+`
    <p class="hint" style="margin-bottom:14px"><b>${esc(o.name||'Gerät')}</b>${o.raum?' · '+esc(o.raum):''}. Gibt es dieses Gerät hier schon? Dann verknüpfe es – Beleg und Garantie bleiben hier, Raum und Bedienung in der MySmartBox.</p>
    ${cand.length?`<div class="label" style="margin-bottom:8px">Passt wahrscheinlich</div><div class="list">${cand.map(row).join('')}</div>`:''}
    <div class="label" style="margin:16px 0 8px">${cand.length?'Oder anderes Gerät':'Vorhandenes Gerät wählen'}</div>
    <label class="field srchf"><span class="sr">Gerät suchen</span><input id="l_q" type="search" placeholder="Gerät suchen …" autocomplete="off"></label>
    <div class="list" id="l_list" style="margin-top:10px"></div>
    <div class="actions" style="margin-top:16px"><button type="button" class="btn primary" id="l_new">Als neues Gerät anlegen</button></div>`,
  s=>{const L=s.querySelector('#l_list'),q=s.querySelector('#l_q');
    const bind=root=>root.querySelectorAll('[data-li]').forEach(b=>b.onclick=async()=>{const d=db.devices.find(x=>x.id===b.dataset.li);if(!d)return;
      d.ext=ext;db.meta=Object.assign({},db.meta,{dirty:(db.meta&&db.meta.dirty||0)+1});await save();closeSheet();tab='geraete';render();openDetail('d',d.id);buzz([10,40,10]);toast('Verknüpft mit der MySmartBox.')});
    const draw=()=>{const t=nrm(q.value);const hit=t?free.filter(d=>nrm(d.name+' '+(d.hersteller||'')+' '+(d.raum||'')).includes(t)).slice(0,25):[];
      L.innerHTML=t?(hit.length?hit.map(row).join(''):'<div class="empty">Nichts gefunden.</div>'):'';bind(L)};
    bind(s);q.addEventListener('input',draw);
    s.querySelector('#l_new').onclick=()=>{closeSheet();setTimeout(()=>openForm('d',null,false,tpl),motion()?320:0)}});
}
/* Verknüpfung lösen (im Bearbeiten-Formular nicht nötig: über die Detailansicht) */
})();
