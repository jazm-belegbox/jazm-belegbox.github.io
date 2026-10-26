(function(){
const APP_VERSION='0.1.0.1';
const KEY='belegbox-v1';
const T0=sod(new Date());
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

/* Verschlüsselter Tresor: PBKDF2 (SHA-256) leitet aus dem Passwort einen AES-256-GCM-Schlüssel ab.
   Gespeichert werden nur Salt, IV und Chiffretext. Schlüssel und Klartext existieren nur im Arbeitsspeicher. */
const VKEY='belegbox-vault-v1', ITER=600000, IDLE_MS=5*60e3, BG_MS=60e3;
let db=null, key=null, curSalt=null, tab='home', filter='alle';
const te=new TextEncoder(), td=new TextDecoder();
function toB64(buf){const u=new Uint8Array(buf);let s='';for(let i=0;i<u.length;i+=0x8000)s+=String.fromCharCode.apply(null,u.subarray(i,i+0x8000));return btoa(s)}
function fromB64(s){const b=atob(s);const u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u}
async function deriveKey(pw,salt,iter){
  const base=await crypto.subtle.importKey('raw',te.encode(pw),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:iter,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
function readVault(){try{const r=localStorage.getItem(VKEY);return r?JSON.parse(r):null}catch(e){return null}}
async function persist(){
  if(!key||!db)return;
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,te.encode(JSON.stringify(db)));
  localStorage.setItem(VKEY,JSON.stringify({v:1,iter:ITER,salt:toB64(curSalt),iv:toB64(iv),ct:toB64(ct)}));
}
let saving=Promise.resolve();
function save(){saving=saving.then(persist).catch(()=>toast('Speichern fehlgeschlagen. Der Speicher ist vermutlich voll: Entferne ein paar Fotos.'));return saving}
async function unlock(pw){
  const v=readVault();const salt=fromB64(v.salt);
  const k=await deriveKey(pw,salt,v.iter||ITER);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:fromB64(v.iv)},k,fromB64(v.ct)); // wirft bei falschem Passwort
  db=JSON.parse(td.decode(pt));key=k;curSalt=salt;
}
async function createVault(pw,withEx){
  curSalt=crypto.getRandomValues(new Uint8Array(16));key=await deriveKey(pw,curSalt,ITER);
  let old=null;try{old=JSON.parse(localStorage.getItem(KEY))}catch(e){}
  db=old&&Array.isArray(old.devices)?old:withEx?samples():{devices:[],contracts:[]};
  await persist();
  try{localStorage.removeItem(KEY)}catch(e){} // alte unverschlüsselte Daten entfernen
}
async function changePassword(oldPw,newPw){
  const v=readVault();const k=await deriveKey(oldPw,fromB64(v.salt),v.iter||ITER);
  await crypto.subtle.decrypt({name:'AES-GCM',iv:fromB64(v.iv)},k,fromB64(v.ct));
  curSalt=crypto.getRandomValues(new Uint8Array(16));key=await deriveKey(newPw,curSalt,ITER);await save();
}
function lock(){saving.then(()=>{key=null;db=null;closeSheet();main.innerHTML='';showLock()})}

/* Bankdaten gar nicht erst speichern */
function looksBanky(s){const x=String(s||'').replace(/[\s-]/g,'').toUpperCase();
  if(/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(x))return true;
  if(/^\d{13,19}$/.test(x)){let sum=0,alt=false;for(let i=x.length-1;i>=0;i--){let n=+x[i];if(alt){n*=2;if(n>9)n-=9}sum+=n;alt=!alt}return sum%10===0}
  return false}
const maskVal=s=>{s=String(s||'');return s.length<=4?s:'•••• '+s.slice(-4)};

function toast(msg){const r=document.getElementById('toastRoot');r.innerHTML=`<div class="toast" role="status">${esc(msg)}</div>`;clearTimeout(toast.t);toast.t=setTimeout(()=>r.innerHTML='',4000)}

const SHIELD='<svg viewBox="0 0 24 24" fill="none" stroke="var(--accent-ink)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>';
function showLock(){
  document.body.classList.add('locked');
  const L=document.getElementById('lock');
  const setup=!readVault();
  L.innerHTML=`<div class="lock"><form class="lockcard" id="lf" novalidate>
    <div class="shield">${SHIELD}</div>
    ${setup?`<h2>Tresor einrichten</h2>
      <p>Alle Einträge und Fotos werden mit deinem Passwort verschlüsselt, bevor sie gespeichert werden. Ohne Passwort sind sie nicht lesbar.</p>
      <label class="field"><span>Passwort (mind. 10 Zeichen)</span><input id="lp1" type="password" autocomplete="new-password" minlength="10"></label>
      <label class="field"><span>Passwort wiederholen</span><input id="lp2" type="password" autocomplete="new-password"></label>
      <label class="check"><input id="lex" type="checkbox" checked> Mit Beispieleinträgen starten</label>
      <div class="note">Es gibt keine Wiederherstellung. Wer das Passwort vergisst, verliert die Daten. Notier es dir an einem sicheren Ort, z. B. im Passwortmanager.</div>`
    :`<h2>Belegbox ist gesperrt</h2><p>Gib dein Passwort ein, um deine Daten zu entschlüsseln.</p>
      <label class="field"><span>Passwort</span><input id="lp1" type="password" autocomplete="current-password"></label>`}
    <p class="hint" id="lerr" style="color:var(--crit)" hidden></p>
    <button type="submit" class="btn primary" id="lgo">${setup?'Tresor anlegen':'Entsperren'}</button>
    ${setup?'<label class="linkbtn" style="cursor:pointer">Neues Handy? Sicherung wiederherstellen<input id="lrestore" type="file" accept=".belegbox,application/json" hidden></label>'
      :'<button type="button" class="linkbtn" id="lreset">Passwort vergessen? Tresor zurücksetzen</button>'}
    <p class="hint" style="text-align:center">Version ${APP_VERSION}</p>
  </form></div>`;
  const f=L.querySelector('#lf'),err=L.querySelector('#lerr'),go=L.querySelector('#lgo');
  const fail=m=>{err.textContent=m;err.hidden=false;go.disabled=false;go.textContent=setup?'Tresor anlegen':'Entsperren'};
  f.addEventListener('submit',async e=>{e.preventDefault();err.hidden=true;
    const p1=L.querySelector('#lp1').value;
    if(!window.crypto||!crypto.subtle)return fail('Dieser Browser unterstützt keine Verschlüsselung. Öffne die Seite in einem aktuellen Browser.');
    if(setup){const p2=L.querySelector('#lp2').value;
      if(p1.length<10)return fail('Das Passwort braucht mindestens 10 Zeichen.');
      if(p1!==p2)return fail('Die beiden Passwörter stimmen nicht überein.');}
    go.disabled=true;go.textContent=setup?'Wird verschlüsselt …':'Wird entschlüsselt …';
    try{ setup?await createVault(p1,L.querySelector('#lex').checked):await unlock(p1) }
    catch(x){return fail(setup?'Der Tresor konnte nicht angelegt werden. Prüfe, ob der Browser Speicher erlaubt.':'Das Passwort ist falsch.')}
    L.innerHTML='';document.body.classList.remove('locked');lastAct=Date.now();tab='home';filter='alle';render();askPersist();
  });
  const rf=L.querySelector('#lrestore');
  if(rf)rf.addEventListener('change',async()=>{const file=rf.files[0];if(!file)return;
    try{restoreVault(await readBackupFile(file))}catch(x){fail(x.message)}});
  const rs=L.querySelector('#lreset');
  if(rs){let armed=false;rs.onclick=()=>{if(!armed){armed=true;rs.classList.add('sure');rs.textContent='Wirklich alles löschen? Nochmal tippen';return}
    try{localStorage.removeItem(VKEY)}catch(e){}showLock()}}
  const first=L.querySelector('input');if(first)first.focus({preventScroll:true});
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

/* Verschlüsselte Sicherung: enthält nur den bereits verschlüsselten Tresor */
async function exportBackup(){
  db.meta=Object.assign({},db.meta,{lastBackup:iso(T0)});
  await save();
  const v=readVault();if(!v){toast('Es gibt noch nichts zu sichern.');return}
  const payload=JSON.stringify({app:'belegbox',format:1,exported:new Date().toISOString(),version:APP_VERSION,vault:v});
  const ok=await deliverFile('belegbox-sicherung-'+iso(T0)+'.belegbox',payload,'application/json');
  if(ok){toast('Sicherung erstellt. Leg die Datei an einem zweiten Ort ab, z. B. in deiner Cloud.');render()}
}
function readBackupFile(file){return new Promise((res,rej)=>{const r=new FileReader();
  r.onload=()=>{try{const o=JSON.parse(r.result);const v=o&&o.app==='belegbox'&&o.vault;
      if(!v||typeof v.salt!=='string'||typeof v.iv!=='string'||typeof v.ct!=='string')throw new Error('format');res(v)}
    catch(e){rej(new Error('Das ist keine gültige Belegbox-Sicherung.'))}};
  r.onerror=()=>rej(new Error('Die Datei konnte nicht gelesen werden.'));
  if(file.size>40e6)return rej(new Error('Die Datei ist zu groß für eine Belegbox-Sicherung.'));
  r.readAsText(file)})}
function restoreVault(v){localStorage.setItem(VKEY,JSON.stringify(v));key=null;db=null;closeSheet();main.innerHTML='';showLock();
  toast('Sicherung geladen. Entsperre sie mit dem Passwort, das beim Sichern galt.')}

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
function contractInfo(c){
  const start=parse(c.beginn);
  for(let k=0;k<600;k++){
    const end=addMonths(start,Number(c.laufzeit||1)+k*Number(c.verl||1));
    const by=addDays(end,-Number(c.frist||0));
    if(c.status==='gekuendigt'){ if(days(end)>=0||k>500) return {end,by:null}; continue }
    if(days(by)>=0) return {end,by};
  }
  return {end:start,by:null};
}
function monthly(c){return Number(c.kosten||0)/Number(c.intervall||1)}
function deviceInfo(d){
  const kauf=parse(d.kauf);
  const gew=addMonths(kauf,24);
  const gar=Number(d.garantieMonate)>0?addMonths(kauf,Number(d.garantieMonate)):null;
  const ends=[{typ:'Gewährleistung',date:gew},gar&&{typ:'Herstellergarantie',date:gar}].filter(Boolean).filter(x=>days(x.date)>=0).sort((a,b)=>b.date-a.date);
  return {kauf,gew,gar,best:ends[0]||null};
}
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
  const n=days(i.by);
  const cls=n<=14?'p-crit':n<=45?'p-warn':'p-ok';
  return `<span class="pill ${cls}">Kündigen bis ${fmtD(i.by)}</span>`;
}
function upcoming(){
  const ev=[];
  db.contracts.filter(c=>c.status!=='gekuendigt').forEach(c=>{const i=contractInfo(c);const n=days(i.by);
    if(n<=60) ev.push({date:i.by,n,title:c.anbieter,sub:`Kündigungsfrist · sonst Verlängerung um ${c.verl==12?'1 Jahr':c.verl+' Monat'+(c.verl>1?'e':'')}`,kind:'c',id:c.id})});
  db.devices.forEach(d=>{const i=deviceInfo(d);
    [['Gewährleistung',i.gew],['Herstellergarantie',i.gar]].forEach(([t,dt])=>{if(!dt)return;const n=days(dt);
      if(n>=0&&n<=90) ev.push({date:dt,n,title:d.name,sub:t+' läuft ab',kind:'d',id:d.id})})});
  return ev.sort((a,b)=>a.n-b.n);
}

/* Render */
const main=document.getElementById('main');
function tileFor(d){return d.foto?`<div class="tile"><img src="${d.foto}" alt=""></div>`:`<div class="tile">${esc((d.hersteller||d.name||'?').charAt(0).toUpperCase())}</div>`}
function render(){
  if(!db)return;
  document.querySelectorAll('nav.tabs button').forEach(b=>b.setAttribute('aria-current',b.dataset.tab===tab?'page':'false'));
  const hasEx=db.devices.some(x=>x.ex)||db.contracts.some(x=>x.ex);
  document.getElementById('banner').innerHTML=hasEx?`<div class="banner"><span>Du siehst Beispieleinträge, damit du die App ausprobieren kannst.</span><button type="button" id="clearEx">Beispiele entfernen</button></div>`:'';
  const own=db.devices.some(x=>!x.ex)||db.contracts.some(x=>!x.ex);
  const lb=db.meta&&db.meta.lastBackup?parse(db.meta.lastBackup):null;
  if(own&&(!lb||days(lb)<-30)){
    document.getElementById('banner').insertAdjacentHTML('beforeend',`<div class="banner" style="background:var(--warn-soft)"><span>${lb?'Letzte Sicherung vor '+(-days(lb))+' Tagen.':'Du hast noch keine Sicherung.'} Ohne Sicherung sind bei Handyverlust alle Daten weg.</span><button type="button" id="bkNow" style="color:var(--warn)">Jetzt sichern</button></div>`);
    document.getElementById('bkNow').onclick=exportBackup;
  }
  const ce=document.getElementById('clearEx'); if(ce) ce.onclick=()=>{db.devices=db.devices.filter(x=>!x.ex);db.contracts=db.contracts.filter(x=>!x.ex);save();render()};
  main.innerHTML= tab==='home'?viewHome(): tab==='geraete'?viewDevices(): viewContracts();
  main.querySelectorAll('[data-open]').forEach(el=>el.onclick=()=>openDetail(el.dataset.kind,el.dataset.open));
  main.querySelectorAll('[data-filter]').forEach(el=>el.onclick=()=>{filter=el.dataset.filter;render()});
  main.querySelectorAll('[data-goto]').forEach(el=>el.onclick=()=>{tab=el.dataset.goto;filter='alle';render();window.scrollTo(0,0)});
}

function viewHome(){
  const act=db.contracts.filter(c=>c.status!=='gekuendigt');
  const mon=act.reduce((s,c)=>s+monthly(c),0);
  const wert=db.devices.reduce((s,d)=>s+Number(d.preis||0),0);
  const ohne=db.devices.filter(d=>d.nachweis==='keiner').length;
  const byKat={};act.forEach(c=>byKat[c.kategorie]=(byKat[c.kategorie]||0)+monthly(c));
  const kats=Object.entries(byKat).sort((a,b)=>b[1]-a[1]);const max=kats[0]?kats[0][1]:1;
  const ev=upcoming();
  return `<section class="view">
    <div class="summary">
      <div><div class="label">Fixkosten pro Monat</div>
        <div class="bigcost"><span class="num">${eur(mon)}</span><small>${eur(mon*12)} im Jahr</small></div></div>
      ${kats.length?`<div class="bars">${kats.map(([k,v])=>`<div class="bar"><span>${esc(k)}</span><div class="track"><div class="fill" style="width:${Math.max(4,v/max*100)}%"></div></div><span class="num">${eur(v)}</span></div>`).join('')}</div>`:''}
      <div class="facts">
        <div><b>${act.length}</b><span>aktive Verträge</span></div>
        <div><b>${db.devices.length}</b><span>Geräte · ${eur(wert)}</span></div>
        <div><b>${ohne}</b><span>ohne Kaufnachweis</span></div>
      </div>
    </div>
    <div class="sechead"><h2>Demnächst fällig</h2><span class="label">nächste 90 Tage</span></div>
    <div class="list">${ev.length?ev.map(e=>`<button type="button" class="row" data-kind="${e.kind}" data-open="${e.id}">
        <div class="date"><b>${e.date.getDate()}</b><span>${e.date.toLocaleDateString('de-DE',{month:'short'}).replace('.','')}</span></div>
        <div style="min-width:0"><div class="t">${esc(e.title)}</div><div class="s">${esc(e.sub)}</div></div>
        <span class="pill ${e.n<=14?'p-crit':e.n<=45?'p-warn':'p-ok'}">${inDays(e.n)}</span></button>`).join('')
      :`<div class="empty">Keine Fristen in den nächsten 90 Tagen.</div>`}</div>
    ${ohne?`<div class="sechead"><h2>Ohne Nachweis</h2><button type="button" class="ghost" data-goto="geraete">Alle Geräte</button></div>
    <div class="list">${db.devices.filter(d=>d.nachweis==='keiner').map(devRow).join('')}</div>
    <p class="hint">Tipp: Bestellhistorie bei Online-Händlern, alte Bestellmails und Kontoauszüge durchsuchen. Für die Gewährleistung reicht oft jeder plausible Kaufnachweis.</p>`:''}
  </section>`;
}
function devRow(d){const i=deviceInfo(d);return `<button type="button" class="row" data-kind="d" data-open="${d.id}">
  ${tileFor(d)}<div style="min-width:0"><div class="t">${esc(d.name)}</div><div class="s">${esc([d.hersteller,d.raum].filter(Boolean).join(' · '))} · gekauft ${d.geschaetzt?'ca. ':''}${i.kauf.getFullYear()}</div></div>
  <div class="right"><span class="num">${d.preis?eur(d.preis):'–'}</span>${devPill(d)}</div></button>`}
function viewDevices(){
  const F={alle:['Alle',()=>true],schutz:['Schutz aktiv',d=>!!deviceInfo(d).best],bald:['Läuft bald ab',d=>{const b=deviceInfo(d).best;return b&&days(b.date)<=60}],ohne:['Ohne Nachweis',d=>d.nachweis==='keiner']};
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
      <div class="tile">${esc(c.anbieter.charAt(0).toUpperCase())}</div>
      <div style="min-width:0"><div class="t">${esc(c.anbieter)}</div><div class="s">${esc(c.kategorie)} · ${eur(c.kosten)} ${INTERVALL[c.intervall]||''}</div></div>
      <div class="right"><span class="num">${eur(monthly(c))}/M</span>${conPill(c)}</div></button>`).join('')
      :`<div class="empty">Noch keine Verträge. Tippe auf „Neu“ und trage Kosten, Laufzeit und Kündigungsfrist ein.</div>`}</div>
  </section>`;
}

/* Sheet */
const root=document.getElementById('sheetRoot');
function openSheet(html,onMount){
  root.innerHTML=`<div class="scrim" id="scrim"><div class="sheet" role="dialog" aria-modal="true"><div class="grab"></div>${html}</div></div>`;
  document.getElementById('scrim').addEventListener('click',e=>{if(e.target.id==='scrim')closeSheet()});
  root.querySelectorAll('[data-close]').forEach(b=>b.onclick=closeSheet);
  document.body.style.overflow='hidden';
  if(onMount)onMount(root.querySelector('.sheet'));
}
function closeSheet(){root.innerHTML='';document.body.style.overflow=''}
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&root.innerHTML)closeSheet()});
const head=t=>`<div class="sheethead"><h2>${t}</h2><button type="button" class="x" data-close aria-label="Schließen">✕</button></div>`;

function openDetail(kind,id){
  if(kind==='d'){
    const d=db.devices.find(x=>x.id===id); if(!d)return; const i=deviceInfo(d);
    openSheet(head(esc(d.name))+`<div style="margin:-6px 0 14px">${devPill(d)}</div>
      ${d.foto?`<img class="photo" src="${d.foto}" alt="Foto von ${esc(d.name)}">`:''}
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
      <div class="actions"><button type="button" class="btn danger" id="del">Gerät löschen</button><button type="button" class="btn" data-close>Schließen</button></div>`,
      s=>armDelete(s,()=>{db.devices=db.devices.filter(x=>x.id!==id)}));
  } else {
    const c=db.contracts.find(x=>x.id===id); if(!c)return; const i=contractInfo(c);
    openSheet(head(esc(c.anbieter))+`<div style="margin:-6px 0 14px">${conPill(c)}</div>
      <dl class="kv">
        <dt>Kategorie</dt><dd>${esc(c.kategorie)}</dd>
        <dt>Kosten</dt><dd>${eur(c.kosten)} ${INTERVALL[c.intervall]||''} · <span class="num">${eur(monthly(c))}</span>/Monat</dd>
        <dt>Beginn</dt><dd>${fmtD(parse(c.beginn))}</dd>
        <dt>Mindestlaufzeit</dt><dd>${c.laufzeit} Monat${c.laufzeit>1?'e':''}, danach je ${c.verl==12?'12 Monate':c.verl+' Monat'+(c.verl>1?'e':'')}</dd>
        <dt>Kündigungsfrist</dt><dd>${Number(c.frist)?c.frist+' Tage':'jederzeit'}</dd>
        <dt>${c.status==='gekuendigt'?'Endet am':'Nächstes Laufzeitende'}</dt><dd>${fmtD(i.end)}</dd>
        ${i.by?`<dt>Spätestens kündigen</dt><dd><b>${fmtD(i.by)}</b> (${inDays(days(i.by))})</dd>`:''}
        <dt>Kundennummer</dt><dd class="num">${c.kundennr?`<span id="kd">${esc(maskVal(c.kundennr))}</span><button type="button" class="reveal" id="kdBtn">Anzeigen</button>`:'–'}</dd>
      </dl>
      <div class="actions">
        ${c.status!=='gekuendigt'?'<button type="button" class="btn primary" id="cancel">Als gekündigt markieren</button>':'<button type="button" class="btn" id="cancel">Wieder aktiv</button>'}
        <button type="button" class="btn danger" id="del">Löschen</button></div>`,
      s=>{const kb=s.querySelector('#kdBtn');if(kb){let open=false;kb.onclick=()=>{open=!open;s.querySelector('#kd').textContent=open?c.kundennr:maskVal(c.kundennr);kb.textContent=open?'Verbergen':'Anzeigen'}}
          s.querySelector('#cancel').onclick=()=>{c.status=c.status==='gekuendigt'?'aktiv':'gekuendigt';save();render();openDetail('c',id)};
          armDelete(s,()=>{db.contracts=db.contracts.filter(x=>x.id!==id)})});
  }
}
function armDelete(s,fn){const b=s.querySelector('#del');let armed=false;
  b.onclick=()=>{if(!armed){armed=true;b.classList.add('sure');b.textContent='Wirklich löschen?';setTimeout(()=>{if(b.isConnected){armed=false;b.classList.remove('sure');b.textContent='Löschen'}},4000);return}
    fn();save();closeSheet();render()}}

function shrink(file){return new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>{const img=new Image();
  img.onload=()=>{const k=Math.min(1,520/Math.max(img.width,img.height));const cv=document.createElement('canvas');
    cv.width=Math.round(img.width*k);cv.height=Math.round(img.height*k);cv.getContext('2d').drawImage(img,0,0,cv.width,cv.height);res(cv.toDataURL('image/jpeg',.72))};
  img.onerror=rej;img.src=r.result};r.onerror=rej;r.readAsDataURL(file)})}

function openForm(kind){
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
    <div class="grid2"><label class="field"><span>Händler</span><input id="f_hae"></label>
      <label class="field"><span>Herstellergarantie</span><select id="f_gar"><option value="0">keine</option><option value="12">1 Jahr</option><option value="24">2 Jahre</option><option value="36">3 Jahre</option><option value="60">5 Jahre</option></select></label></div>
    <label class="field"><span>Kaufnachweis</span><select id="f_nach">${Object.entries(NACHWEIS).map(([k,v])=>`<option value="${k}">${v}</option>`).join('')}</select></label>
    <label class="field"><span>Foto von Beleg oder Typenschild</span><input id="f_foto" type="file" accept="image/*"></label>
    <p class="hint">Bei Kontoauszügen vorher alles außer der Buchung schwärzen. Die gesetzliche Gewährleistung von 2 Jahren ab Kauf wird automatisch berechnet.</p>`;
  const con=`
    <label class="field"><span>Anbieter *</span><input id="c_anb" required placeholder="z. B. Spotify"></label>
    <div class="grid2"><label class="field"><span>Kategorie</span><select id="c_kat">${opt(CON_KAT,'Streaming')}</select></label>
      <label class="field"><span>Kundennummer</span><input id="c_kd"></label></div>
    <div class="grid2"><label class="field"><span>Kosten (€) *</span><input id="c_kost" type="number" step="0.01" min="0" required inputmode="decimal"></label>
      <label class="field"><span>Zahlweise</span><select id="c_int"><option value="1">monatlich</option><option value="3">vierteljährlich</option><option value="12">jährlich</option></select></label></div>
    <div class="grid2"><label class="field"><span>Vertragsbeginn *</span><input id="c_beg" type="date" required value="${iso(T0)}"></label>
      <label class="field"><span>Mindestlaufzeit</span><select id="c_lz"><option value="1">1 Monat</option><option value="6">6 Monate</option><option value="12" selected>12 Monate</option><option value="24">24 Monate</option></select></label></div>
    <div class="grid2"><label class="field"><span>Verlängert sich um</span><select id="c_verl"><option value="1">1 Monat</option><option value="12">12 Monate</option></select></label>
      <label class="field"><span>Kündigungsfrist</span><select id="c_fr"><option value="0">jederzeit</option><option value="14">14 Tage</option><option value="30" selected>1 Monat</option><option value="90">3 Monate</option></select></label></div>
    <p class="hint">Aus Beginn, Laufzeit und Frist berechnet die App, bis wann du spätestens kündigen musst.</p>`;
  openSheet(head('Neuer Eintrag')+`<form id="frm" novalidate>
    <div class="seg"><button type="button" data-k="d" aria-pressed="${kind==='d'}">Gerät</button><button type="button" data-k="c" aria-pressed="${kind==='c'}">Abo / Vertrag</button></div>
    ${kind==='d'?dev:con}<p class="hint" id="err" style="color:var(--crit)" hidden></p>
    <div class="actions"><button type="submit" class="btn primary">Speichern</button><button type="button" class="btn" data-close>Abbrechen</button></div></form>`,
  s=>{
    s.querySelectorAll('.seg button').forEach(b=>b.onclick=()=>openForm(b.dataset.k));
    const v=id=>s.querySelector('#'+id).value.trim();
    s.querySelector('#frm').addEventListener('submit',async e=>{e.preventDefault();const err=s.querySelector('#err');
      if([...s.querySelectorAll('input:not([type])')].some(i=>looksBanky(i.value))){
        err.textContent='Ein Feld sieht nach einer IBAN oder Kartennummer aus. Solche Nummern speichert die Belegbox bewusst nicht. Trag höchstens die letzten vier Ziffern ein.';err.hidden=false;return}
      if(kind==='d'){
        if(!v('f_name')||!v('f_kauf')){err.textContent='Bitte Bezeichnung und Kaufdatum ausfüllen.';err.hidden=false;return}
        let foto='';const f=s.querySelector('#f_foto').files[0];
        if(f){try{foto=await shrink(f)}catch(x){err.textContent='Das Foto konnte nicht gelesen werden. Versuch es mit einem JPG oder PNG.';err.hidden=false;return}}
        db.devices.push({id:uid(),name:v('f_name'),kategorie:v('f_kat'),raum:v('f_raum'),hersteller:v('f_her'),modell:v('f_mod'),sn:v('f_sn'),
          kauf:v('f_kauf'),geschaetzt:s.querySelector('#f_ges').checked,preis:parseFloat(v('f_preis'))||0,haendler:v('f_hae'),
          garantieMonate:Number(v('f_gar')),nachweis:v('f_nach'),foto});
        tab='geraete';
      } else {
        if(!v('c_anb')||!v('c_kost')||!v('c_beg')){err.textContent='Bitte Anbieter, Kosten und Vertragsbeginn ausfüllen.';err.hidden=false;return}
        db.contracts.push({id:uid(),anbieter:v('c_anb'),kategorie:v('c_kat'),kundennr:v('c_kd'),kosten:parseFloat(v('c_kost'))||0,
          intervall:Number(v('c_int')),beginn:v('c_beg'),laufzeit:Number(v('c_lz')),verl:Number(v('c_verl')),frist:Number(v('c_fr')),status:'aktiv'});
        tab='vertraege';
      }
      filter='alle';save();closeSheet();render();
    });
    const first=s.querySelector('input');if(first)first.focus({preventScroll:true});
  });
}

function openMenu(){
  openSheet(head('Daten & Sicherheit')+`
    <div class="secline"><svg viewBox="0 0 24 24" fill="none" stroke="var(--ok)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>
      Verschlüsselt mit AES-256 · sperrt nach 5 Min. ohne Eingabe oder 1 Min. im Hintergrund</div>
    <p class="hint" style="margin-bottom:14px">Deine Daten liegen nur verschlüsselt in diesem Browser und werden nirgendwohin gesendet. Dein Passwort wird nicht gespeichert.</p>
    <form id="pwf" novalidate style="margin-bottom:18px">
      <div class="label">Passwort ändern</div>
      <label class="field"><span>Aktuelles Passwort</span><input id="pw0" type="password" autocomplete="current-password"></label>
      <div class="grid2"><label class="field"><span>Neues Passwort</span><input id="pw1" type="password" autocomplete="new-password"></label>
        <label class="field"><span>Wiederholen</span><input id="pw2" type="password" autocomplete="new-password"></label></div>
      <p class="hint" id="pwerr" style="color:var(--crit)" hidden></p>
      <div class="actions"><button type="submit" class="btn" id="pwgo">Passwort ändern</button></div>
    </form>
    <div class="label" style="margin-bottom:8px">Kalender</div>
    <p class="hint" style="margin-bottom:10px">Exportiert alle Kündigungsfristen und Garantie-Enden als Termine mit Erinnerung 7 Tage und 1 Tag vorher. Nach neuen Einträgen einfach erneut exportieren, bestehende Termine werden aktualisiert.</p>
    <label class="check" style="margin-bottom:10px"><input id="icsNeutral" type="checkbox" checked> Neutrale Titel (keine Anbieter oder Geräte im Kalender)</label>
    <div class="actions" style="margin-bottom:18px"><button type="button" class="btn" id="icsGo">Fristen in Kalender exportieren</button></div>
    <div class="label" style="margin-bottom:8px">Sicherung</div>
    <p class="hint" style="margin-bottom:10px">Die Sicherung ist mit deinem aktuellen Passwort verschlüsselt. ${db.meta&&db.meta.lastBackup?'Letzte Sicherung: '+fmtD(parse(db.meta.lastBackup))+'.':'Bisher keine Sicherung.'}</p>
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
       closeSheet();toast('Passwort geändert. Deine Daten sind neu verschlüsselt.')});
     s.querySelector('#icsGo').onclick=async()=>{const r=buildIcs(s.querySelector('#icsNeutral').checked);
       if(!r.count){toast('Gerade stehen keine Fristen an.');return}
       if(await deliverFile('belegbox-fristen.ics',r.text,'text/calendar'))toast(r.count+' Termine exportiert. Öffne die Datei mit deinem Kalender.')};
     s.querySelector('#bkGo').onclick=exportBackup;
     let pending=null;const msg=s.querySelector('#bkMsg'),cf=s.querySelector('#bkConfirm'),bi=s.querySelector('#bkIn');
     bi.addEventListener('change',async()=>{const file=bi.files[0];if(!file)return;msg.hidden=true;
       try{pending=await readBackupFile(file);cf.hidden=false}catch(x){msg.textContent=x.message;msg.style.color='var(--crit)';msg.hidden=false}bi.value=''});
     s.querySelector('#bkNo').onclick=()=>{pending=null;cf.hidden=true};
     s.querySelector('#bkYes').onclick=()=>{if(pending)saving.then(()=>restoreVault(pending))};
     s.querySelector('#m_ex').onclick=()=>{const sm=samples();db.devices=db.devices.filter(x=>!x.ex).concat(sm.devices);db.contracts=db.contracts.filter(x=>!x.ex).concat(sm.contracts);save();closeSheet();render()};
     armDelete(s,()=>{db={devices:[],contracts:[]}})});
}

document.querySelectorAll('nav.tabs button').forEach(b=>b.onclick=()=>{tab=b.dataset.tab;filter='alle';render();window.scrollTo(0,0)});
document.getElementById('fab').onclick=()=>openForm();
document.getElementById('menuBtn').onclick=openMenu;
document.getElementById('lockBtn').onclick=lock;
showLock();

/* Service Worker: offline nutzbar, Hinweis bei neuer Version */
if('serviceWorker' in navigator){
  let reloading=false;
  navigator.serviceWorker.addEventListener('controllerchange',()=>{if(reloading)return;reloading=true;location.reload()});
  navigator.serviceWorker.register('sw.js').then(reg=>{
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
