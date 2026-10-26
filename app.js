(function(){
const APP_VERSION='0.4.1.0';
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
  localStorage.setItem(VKEY,JSON.stringify(Object.assign({},vmeta,{v:2,iv:box.iv,ct:box.ct})));
}
let saving=Promise.resolve();
function save(){saving=saving.then(persist).catch(()=>toast('Speichern fehlgeschlagen. Der Speicher ist vermutlich voll: Entferne ein paar Fotos.'));return saving}
async function openWithDek(raw,v){
  const k=await importDek(raw);
  const pt=await open_(k,v);
  db=JSON.parse(td.decode(pt));key=k;dekRaw=raw;
  vmeta={iter:v.iter,salt:v.salt,wrapPw:v.wrapPw,bio:v.bio||null};
}
async function unlock(pw){
  const v=readVault();const salt=fromB64(v.salt);
  const kek=await deriveKey(pw,salt,v.iter||ITER);
  if(v.v===2){await openWithDek(await open_(kek,v.wrapPw),v);return} // wirft bei falschem Passwort
  // Format 1 (bis 0.2.0.2): direkt mit dem Passwortschlüssel verschlüsselt → auf Format 2 umstellen
  const pt=await open_(kek,v);db=JSON.parse(td.decode(pt));
  dekRaw=rnd(32);key=await importDek(dekRaw);
  vmeta={iter:v.iter||ITER,salt:v.salt,wrapPw:await seal(kek,dekRaw),bio:null};
  await save();
}
async function createVault(pw,withEx){
  const salt=rnd(16);const kek=await deriveKey(pw,salt,ITER);
  dekRaw=rnd(32);key=await importDek(dekRaw);
  vmeta={iter:ITER,salt:toB64(salt),wrapPw:await seal(kek,dekRaw),bio:null};
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
function lock(anim){saving.then(()=>{key=null;db=null;if(dekRaw)dekRaw.fill(0);dekRaw=null;vmeta=null;closeSheet(false);setFan(false);main.innerHTML='';shown={};showLock(anim===true)})}

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
      <div class="note">Es gibt keine Wiederherstellung. Wer das Passwort vergisst, verliert die Daten. Notier es dir an einem sicheren Ort, z. B. im Passwortmanager.</div>`
    :`<h2>Belegbox ist gesperrt</h2><p>${bio?'Entsperre mit deinem Fingerabdruck oder deinem Passwort.':'Gib dein Passwort ein, um deine Daten zu entschlüsseln.'}</p>
      ${bio?`<button type="button" class="btn primary bio" id="lbio">${FINGER}Mit Fingerabdruck entsperren</button><div class="or"><span>oder mit Passwort</span></div>`:''}
      <label class="field"><span>Passwort</span><input id="lp1" type="password" autocomplete="current-password"></label>`}
    <p class="hint" id="lerr" style="color:var(--crit)" hidden></p>
    <button type="submit" class="btn${bio?'':' primary'}" id="lgo">${setup?'Tresor anlegen':'Entsperren'}</button>
    ${setup?'<label class="linkbtn" style="cursor:pointer">Neues Handy? Sicherung wiederherstellen<input id="lrestore" type="file" accept=".belegbox,application/json" hidden></label>'
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
    if(setup){const p2=L.querySelector('#lp2').value;
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
    document.body.classList.remove('locked');lastAct=Date.now();tab='home';filter='alle';shown={};askPersist();buzz([10,40,18]);
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
  const rf=L.querySelector('#lrestore');
  if(rf)rf.addEventListener('change',async()=>{const file=rf.files[0];if(!file)return;
    try{restoreVault(await readBackupFile(file))}catch(x){fail(x.message)}});
  const rs=L.querySelector('#lreset');
  if(rs){let armed=false;rs.onclick=()=>{if(!armed){armed=true;buzz(10);rs.classList.add('sure');rs.textContent='Wirklich alles löschen? Nochmal tippen';return}
    try{localStorage.removeItem(VKEY)}catch(e){}showLock()}}
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

/* Verschlüsselte Sicherung: enthält nur den bereits verschlüsselten Tresor */
async function exportBackup(){
  db.meta=Object.assign({},db.meta,{lastBackup:iso(T0)});
  await save();
  const v=readVault();if(!v){toast('Es gibt noch nichts zu sichern.');return}
  const payload=JSON.stringify({app:'belegbox',format:1,exported:new Date().toISOString(),version:APP_VERSION,vault:v});
  const ok=await deliverFile('belegbox-sicherung-'+iso(T0)+'.belegbox',payload,'application/json');
  if(ok){celebrate('Gesichert');toast('Sicherung erstellt. Leg die Datei an einem zweiten Ort ab, z. B. in deiner Cloud.');render()}
}
function readBackupFile(file){return new Promise((res,rej)=>{const r=new FileReader();
  r.onload=()=>{try{const o=JSON.parse(r.result);const v=o&&o.app==='belegbox'&&o.vault;
      if(!v||typeof v.salt!=='string'||typeof v.iv!=='string'||typeof v.ct!=='string')throw new Error('format');res(v)}
    catch(e){rej(new Error('Das ist keine gültige Belegbox-Sicherung.'))}};
  r.onerror=()=>rej(new Error('Die Datei konnte nicht gelesen werden.'));
  if(file.size>40e6)return rej(new Error('Die Datei ist zu groß für eine Belegbox-Sicherung.'));
  r.readAsText(file)})}
function restoreVault(v){localStorage.setItem(VKEY,JSON.stringify(v));key=null;db=null;closeSheet(false);main.innerHTML='';showLock();
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
    if(c.status==='gekuendigt'){ if(days(end)>=0||k>500) return {end,by:null,k}; continue }
    if(days(by)>=0) return {end,by,k};
  }
  return {end:start,by:null,k:0};
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
function render(mode){
  if(!db)return;
  document.querySelectorAll('nav.tabs button').forEach(b=>b.setAttribute('aria-current',b.dataset.tab===tab?'page':'false'));
  setInd(TABS.indexOf(tab));
  const hasEx=db.devices.some(x=>x.ex)||db.contracts.some(x=>x.ex);
  document.getElementById('banner').innerHTML=hasEx?`<div class="banner"><span>Du siehst Beispieleinträge, damit du die App ausprobieren kannst.</span><button type="button" id="clearEx">Beispiele entfernen</button></div>`:'';
  const own=db.devices.some(x=>!x.ex)||db.contracts.some(x=>!x.ex);
  const lb=db.meta&&db.meta.lastBackup?parse(db.meta.lastBackup):null;
  if(own&&(!lb||days(lb)<-30)){
    document.getElementById('banner').insertAdjacentHTML('beforeend',`<div class="banner" style="background:var(--warn-soft)"><span>${lb?'Letzte Sicherung vor '+(-days(lb))+' Tagen.':'Du hast noch keine Sicherung.'} Ohne Sicherung sind bei Handyverlust alle Daten weg.</span><button type="button" id="bkNow" style="color:var(--warn)">Jetzt sichern</button></div>`);
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
  const mon=act.reduce((s,c)=>s+monthly(c),0);
  const wert=db.devices.reduce((s,d)=>s+Number(d.preis||0),0);
  const ohne=db.devices.filter(d=>d.nachweis==='keiner').length;
  const byKat={};act.forEach(c=>byKat[c.kategorie]=(byKat[c.kategorie]||0)+monthly(c));
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
        <div style="min-width:0"><div class="t">${esc(e.title)}</div><div class="s">${esc(e.sub)}</div></div>
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
  ${tileWrap(d)}<div class="main"><div class="t">${esc(d.name)}</div><div class="s">${esc([d.hersteller,d.raum].filter(Boolean).join(' · '))}${d.hersteller||d.raum?' · ':''}gekauft ${d.geschaetzt?'ca. ':''}${i.kauf.getFullYear()}</div><div class="pl">${devPill(d)}</div></div>
  <span class="amt num">${d.preis?eur(d.preis):'–'}</span></button>`}
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
      <div class="main"><div class="t">${esc(c.anbieter)}</div><div class="s">${esc(c.kategorie)} · ${eur(c.kosten)} ${INTERVALL[c.intervall]||''}</div><div class="pl">${conPill(c)}</div></div>
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
document.addEventListener('keydown',e=>{if(e.key!=='Escape')return;if(fanOpen)setFan(false);else if(root.firstElementChild)closeSheet()});
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
      <div class="actions"><button type="button" class="btn primary" id="edit">Bearbeiten</button><button type="button" class="btn danger" id="del">Löschen</button></div>`,
      s=>{const pr=s.querySelector('.prot');if(pr&&motion())pr.classList.add('enter');
          s.querySelector('#edit').onclick=()=>openForm('d',d);armDelete(s,()=>{db.devices=db.devices.filter(x=>x.id!==id)})},from);
  } else {
    const c=db.contracts.find(x=>x.id===id); if(!c)return; const i=contractInfo(c);
    openSheet(head(esc(c.anbieter))+`<div style="margin:-6px 0 14px">${conPill(c)}</div>
      <dl class="kv">
        <dt>Kategorie</dt><dd>${esc(c.kategorie)}</dd>
        <dt>Kosten</dt><dd>${eur(c.kosten)} ${INTERVALL[c.intervall]||''} · <span class="num">${eur(monthly(c))}</span>/Monat</dd>
        <dt>Beginn</dt><dd>${fmtD(parse(c.beginn))}</dd>
        <dt>Mindestlaufzeit</dt><dd>${c.laufzeit} Monat${c.laufzeit>1?'e':''}, danach je ${c.verl==12?'12 Monate':c.verl+' Monat'+(c.verl>1?'e':'')}</dd>
        <dt>Kündigungsfrist</dt><dd>${Number(c.frist)?c.frist+' Tage':'jederzeit'}</dd>
        <dt>${c.status==='gekuendigt'?'Endet am':'Nächstes Laufzeitende'}</dt><dd>${fmtD(i.end)}${c.status!=='gekuendigt'&&i.k>0?` <span class="pill p-none">schon ${i.k}× verlängert</span>`:''}</dd>
        ${i.by?`<dt>Spätestens kündigen</dt><dd><b>${fmtD(i.by)}</b> (${inDays(days(i.by))})</dd>`:''}
        ${[['kundennr','Kundennummer'],['vertragsnr','Vertragsnummer']].map(([f,l])=>`<dt>${l}</dt><dd class="num">${c[f]?`<span data-mask="${f}">${esc(maskVal(c[f]))}</span><button type="button" class="reveal" data-show="${f}">Anzeigen</button><button type="button" class="reveal" data-copy="${f}">Kopieren</button>`:'–'}</dd>`).join('')}
      </dl>
      <div class="actions">
        <button type="button" class="btn primary" id="edit">Bearbeiten</button>
        ${c.status!=='gekuendigt'?'<button type="button" class="btn" id="cancel">Als gekündigt markieren</button>':'<button type="button" class="btn" id="cancel">Wieder aktiv</button>'}
        <button type="button" class="btn" id="dup">Kopie anlegen</button>
        <button type="button" class="btn danger" id="del">Löschen</button></div>`,
      s=>{s.querySelectorAll('[data-show]').forEach(b=>{const f=b.dataset.show,sp=s.querySelector(`[data-mask="${f}"]`);let open=false;
            b.onclick=()=>{open=!open;sp.textContent=open?c[f]:maskVal(c[f]);b.textContent=open?'Verbergen':'Anzeigen'}});
          s.querySelectorAll('[data-copy]').forEach(b=>b.onclick=async()=>{const f=b.dataset.copy;
            try{await navigator.clipboard.writeText(c[f]);buzz(8);toast((f==='kundennr'?'Kundennummer':'Vertragsnummer')+' kopiert.')}
            catch(x){toast('Kopieren hat nicht geklappt. Tippe auf „Anzeigen“ und markiere die Nummer.')}});
          s.querySelector('#dup').onclick=()=>openForm('c',null,false,c);
          s.querySelector('#edit').onclick=()=>openForm('c',c);
          s.querySelector('#cancel').onclick=()=>{const was=c.status==='gekuendigt';c.status=was?'aktiv':'gekuendigt';save();render();openDetail('c',id);
            if(was){buzz(8);toast('Wieder als aktiv markiert.')}
            else{celebrate('Gekündigt');toast(`Stark! Ab dem ${fmtD(contractInfo(c).end)} sparst du ${eur(monthly(c)*12)} im Jahr.`)}};
          armDelete(s,()=>{db.contracts=db.contracts.filter(x=>x.id!==id)})},from);
  }
}
function armDelete(s,fn){const b=s.querySelector('#del');let armed=false;
  b.onclick=()=>{if(!armed){armed=true;buzz(10);b.classList.add('sure');b.textContent='Wirklich löschen?';setTimeout(()=>{if(b.isConnected){armed=false;b.classList.remove('sure');b.textContent='Löschen'}},4000);return}
    buzz([10,40,30]);fn();save();closeSheet();render('rows')}}

function shrink(file){return new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>{const img=new Image();
  img.onload=()=>{const k=Math.min(1,520/Math.max(img.width,img.height));const cv=document.createElement('canvas');
    cv.width=Math.round(img.width*k);cv.height=Math.round(img.height*k);cv.getContext('2d').drawImage(img,0,0,cv.width,cv.height);res(cv.toDataURL('image/jpeg',.72))};
  img.onerror=rej;img.src=r.result};r.onerror=rej;r.readAsDataURL(file)})}

function openForm(kind,item,camera,tpl){
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
    <label class="field"><span>${item&&item.foto?'Foto ersetzen':'Foto von Beleg oder Typenschild'}</span><input id="f_foto" type="file" accept="image/*"></label>
    ${item&&item.foto?'<label class="check"><input id="f_fotoDel" type="checkbox"> Vorhandenes Foto entfernen</label>':''}
    <p class="hint">Bei Kontoauszügen vorher alles außer der Buchung schwärzen. Die gesetzliche Gewährleistung von 2 Jahren ab Kauf wird automatisch berechnet.</p>`;
  const con=`
    <label class="field"><span>Anbieter *</span><input id="c_anb" required placeholder="z. B. Spotify"></label>
    <label class="field"><span>Kategorie</span><select id="c_kat">${opt(CON_KAT,'Streaming')}</select></label>
    <div class="grid2"><label class="field"><span>Kundennummer</span><input id="c_kd" autocomplete="off"></label>
      <label class="field"><span>Vertragsnummer</span><input id="c_vnr" autocomplete="off"></label></div>
    <div class="grid2"><label class="field"><span>Kosten (€) *</span><input id="c_kost" type="number" step="0.01" min="0" required inputmode="decimal"></label>
      <label class="field"><span>Zahlweise</span><select id="c_int"><option value="1">monatlich</option><option value="3">vierteljährlich</option><option value="12">jährlich</option></select></label></div>
    <div class="grid2"><label class="field"><span>Vertragsbeginn *</span><input id="c_beg" type="date" required value="${iso(T0)}"></label>
      <label class="field"><span>Mindestlaufzeit</span><select id="c_lz"><option value="1">1 Monat</option><option value="3">3 Monate</option><option value="6">6 Monate</option><option value="12" selected>12 Monate</option><option value="24">24 Monate</option><option value="36">36 Monate</option></select></label></div>
    <div class="grid2"><label class="field"><span>Verlängert sich um</span><select id="c_verl"><option value="1">1 Monat</option><option value="3">3 Monate</option><option value="6">6 Monate</option><option value="12">12 Monate</option><option value="24">24 Monate</option></select></label>
      <label class="field"><span>Kündigungsfrist</span><select id="c_fr"><option value="0">jederzeit</option><option value="7">7 Tage</option><option value="14">14 Tage</option><option value="30" selected>1 Monat</option><option value="60">2 Monate</option><option value="90">3 Monate</option></select></label></div>
    <p class="hint">Trag immer den <b>ursprünglichen</b> Vertragsbeginn ein, auch wenn der Vertrag schon verlängert wurde. Die App rechnet die Verlängerungen selbst weiter.</p>
    <div class="prev" id="c_prev" aria-live="polite"></div>
    <div class="note" id="c_law" hidden>Verträge, die ab dem 1. März 2022 geschlossen wurden, verlängern sich nach der Mindestlaufzeit meist nur noch auf unbestimmte Zeit und sind dann monatlich kündbar (1 Monat Frist). Prüf kurz deine Unterlagen.
      <button type="button" class="linkbtn" id="c_lawGo" style="display:block;padding-top:6px;color:var(--warn)">Monatlich kündbar übernehmen</button></div>`;
  openSheet(head(item?'Bearbeiten':tpl?'Vertrag kopieren':'Neuer Eintrag')+`<form id="frm" novalidate>
    ${tpl?`<p class="hint">Kopie von <b>${esc(tpl.anbieter)}</b>. Vertragsnummer und Beginn sind leer bzw. auf heute gesetzt, alles andere ist übernommen.</p>`:''}
    <div class="seg"${item||tpl?' hidden':''}><button type="button" data-k="d" aria-pressed="${kind==='d'}">Gerät</button><button type="button" data-k="c" aria-pressed="${kind==='c'}">Abo / Vertrag</button></div>
    ${kind==='d'?dev:con}<p class="hint" id="err" style="color:var(--crit)" hidden></p>
    <div class="actions"><button type="submit" class="btn primary">Speichern</button><button type="button" class="btn" data-close>Abbrechen</button></div></form>`,
  s=>{
    s.querySelectorAll('.seg button').forEach(b=>b.onclick=()=>openForm(b.dataset.k));
    const v=id=>s.querySelector('#'+id).value.trim();
    const src=item||tpl;
    if(src){ // Felder vorbelegen; fehlende Auswahlwerte ergänzen
      const set=(id,val)=>{const el=s.querySelector('#'+id);if(!el||val==null)return;
        if(el.tagName==='SELECT'&&![...el.options].some(o=>o.value===String(val))){const o=document.createElement('option');o.value=String(val);o.textContent=String(val);el.appendChild(o)}
        el.value=String(val)};
      if(kind==='d'){set('f_name',src.name);set('f_kat',src.kategorie);set('f_raum',src.raum);set('f_her',src.hersteller);set('f_mod',src.modell);
        set('f_sn',src.sn);set('f_kauf',src.kauf);set('f_preis',src.preis||'');set('f_hae',src.haendler);set('f_gar',src.garantieMonate||0);set('f_nach',src.nachweis);
        s.querySelector('#f_ges').checked=!!src.geschaetzt}
      else{set('c_anb',src.anbieter);set('c_kat',src.kategorie);set('c_kd',src.kundennr);set('c_kost',src.kosten);set('c_int',src.intervall);
        set('c_lz',src.laufzeit);set('c_verl',src.verl);set('c_fr',src.frist);
        if(item){set('c_beg',item.beginn);set('c_vnr',item.vertragsnr||'')}}
    }
    s.querySelector('#frm').addEventListener('submit',async e=>{e.preventDefault();const err=s.querySelector('#err');let first=false;
      if([...s.querySelectorAll('input:not([type])')].some(i=>looksBanky(i.value))){
        err.textContent='Ein Feld sieht nach einer IBAN oder Kartennummer aus. Solche Nummern speichert die Belegbox bewusst nicht. Trag höchstens die letzten vier Ziffern ein.';err.hidden=false;return}
      if(kind==='d'){
        if(!v('f_name')||!v('f_kauf')){err.textContent='Bitte Bezeichnung und Kaufdatum ausfüllen.';err.hidden=false;return}
        let foto=item&&item.foto||'';const f=s.querySelector('#f_foto').files[0];
        const fd=s.querySelector('#f_fotoDel');if(fd&&fd.checked)foto='';
        if(f){try{foto=await shrink(f)}catch(x){err.textContent='Das Foto konnte nicht gelesen werden. Versuch es mit einem JPG oder PNG.';err.hidden=false;return}}
        const dd={name:v('f_name'),kategorie:v('f_kat'),raum:v('f_raum'),hersteller:v('f_her'),modell:v('f_mod'),sn:v('f_sn'),
          kauf:v('f_kauf'),geschaetzt:s.querySelector('#f_ges').checked,preis:parseFloat(v('f_preis'))||0,haendler:v('f_hae'),
          garantieMonate:Number(v('f_gar')),nachweis:v('f_nach'),foto};
        if(item){Object.assign(item,dd);delete item.ex}else{first=!db.devices.some(x=>!x.ex);db.devices.push(Object.assign({id:uid()},dd))}
        tab='geraete';
      } else {
        if(!v('c_anb')||!v('c_kost')||!v('c_beg')){err.textContent='Bitte Anbieter, Kosten und Vertragsbeginn ausfüllen.';err.hidden=false;return}
        const cc={anbieter:v('c_anb'),kategorie:v('c_kat'),kundennr:v('c_kd'),vertragsnr:v('c_vnr'),kosten:parseFloat(v('c_kost'))||0,
          intervall:Number(v('c_int')),beginn:v('c_beg'),laufzeit:Number(v('c_lz')),verl:Number(v('c_verl')),frist:Number(v('c_fr'))};
        if(item){Object.assign(item,cc);delete item.ex}else db.contracts.push(Object.assign({id:uid(),status:'aktiv'},cc));
        tab='vertraege';
      }
      filter='alle';save();closeSheet();render(item?undefined:'rows');
      if(item){buzz(12);toast('Änderungen gespeichert.');openDetail(kind,item.id)}
      else celebrate(first?'Dein erstes Gerät!':'Gespeichert');
    });
    if(kind==='c'){ // Vorschau: was die App aus den Angaben ausrechnet
      const pv=s.querySelector('#c_prev'),law=s.querySelector('#c_law');
      const upd=()=>{const beg=v('c_beg');if(!beg){pv.innerHTML='';law.hidden=true;return}
        const t={beginn:beg,laufzeit:Number(v('c_lz')),verl:Number(v('c_verl')),frist:Number(v('c_fr')),status:'aktiv'};
        const i=contractInfo(t);
        pv.innerHTML=`<div class="label">So rechnet die App</div>
          <div>Nächstes Laufzeitende <b>${fmtD(i.end)}</b>${i.k>0?` · schon <b>${i.k}×</b> verlängert`:''}</div>
          <div>Spätestens kündigen <b>${i.by?fmtD(i.by):'–'}</b>${i.by?` (${inDays(days(i.by))})`:''}</div>`;
        law.hidden=!(beg>='2022-03-01'&&t.verl>1)};
      s.querySelector('#frm').addEventListener('input',upd);s.querySelector('#frm').addEventListener('change',upd);
      s.querySelector('#c_lawGo').onclick=()=>{s.querySelector('#c_verl').value='1';s.querySelector('#c_fr').value='30';buzz(6);upd()};
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
    <p class="hint" style="margin-bottom:14px">Deine Daten liegen nur verschlüsselt in diesem Browser und werden nirgendwohin gesendet. Dein Passwort wird nicht gespeichert.</p>
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
       closeSheet();celebrate('Neu verschlüsselt');toast('Passwort geändert. Deine Daten sind neu verschlüsselt.')});
     const bb=s.querySelector('#bioBtn');
     if(bb)bb.onclick=async()=>{const m=s.querySelector('#bioMsg');m.hidden=true;bb.disabled=true;
       try{ if(vmeta.bio){await disableBio();closeSheet();toast('Fingerabdruck ausgeschaltet. Den Passkey „Belegbox“ kannst du im Passwortmanager löschen.')}
            else{await enableBio();closeSheet();celebrate('Fingerabdruck an');toast('Fingerabdruck eingeschaltet. Probier es gleich mit „Sperren“ aus.')} }
       catch(x){bb.disabled=false;m.textContent=x&&x.name==='NotAllowedError'?'Abgebrochen.':(x&&x.name==='InvalidStateError'?'Für dieses Gerät gibt es schon einen Belegbox-Passkey. Lösche ihn im Passwortmanager und versuch es erneut.':(x&&x.message)||'Das hat nicht geklappt.');
         m.style.color='var(--crit)';m.hidden=false}};
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
     armDelete(s,()=>{db={devices:[],contracts:[]}})});
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
showLock();

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
