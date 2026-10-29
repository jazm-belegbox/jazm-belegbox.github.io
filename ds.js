/* Gemeinsamer Baustein – identisch in MySmartBox, MyGesundBox und MyBelegBox.
   Darstellung (Hell/Dunkel/Automatisch), Feier-Effekt, Entsperr-Animation, Sicherungs-Status,
   Erinnerung an die Datensicherung, Haken beim Speichern, Wechsel zwischen den Boxen. */
'use strict';
(function(){
const reduced=()=>{try{return matchMedia('(prefers-reduced-motion: reduce)').matches}catch(e){return false}};
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const buzz=p=>{try{navigator.vibrate&&!document.hidden&&navigator.vibrate(p)}catch(e){}};
const BOXES=[
  {id:'smartbox',name:'MySmartBox',url:'https://jazm-smartbox.github.io/',sub:'Geräte, Räume, Grundriss',c:'#2456E0'},
  {id:'gesundbox',name:'MyGesundBox',url:'https://jazm-gesundbox.github.io/',sub:'Termine, Werte, Dokumente',c:'#8C2F45'},
  {id:'belegbox',name:'MyBelegBox',url:'https://jazm-belegbox.github.io/',sub:'Verträge, Geräte, Belege',c:'#0E6A5B'}];
let APP='box';

/* ---------- Darstellung: Automatisch / Hell / Dunkel ----------
   Schaltet die vorhandenen Dunkel-Regeln der App ein oder aus, ohne das CSS zu ändern. */
const THEME_KEY=()=>APP+'-darstellung';
let darkRules=null,metaOrig=null;
function collect(){
  if(darkRules)return;darkRules=[];
  for(const sh of Array.from(document.styleSheets)){let rs;try{rs=sh.cssRules}catch(e){continue}
    (function walk(list){for(const r of Array.from(list||[])){
      if(r.media&&/prefers-color-scheme\s*:\s*dark/i.test(r.media.mediaText)){darkRules.push({r,orig:r.media.mediaText})}
      else if(r.cssRules&&!(r.media))walk(r.cssRules)}})(rs)}
  metaOrig=Array.from(document.querySelectorAll('meta[name="theme-color"]')).map(m=>({m,media:m.getAttribute('media'),c:m.getAttribute('content')}));
}
function setMedia(r,orig,v){const t=v==='auto'?orig:orig.replace(/\(\s*prefers-color-scheme\s*:\s*dark\s*\)/ig,v==='dark'?'(min-width: 0px)':'(max-width: 0px)');
  try{r.media.mediaText=t}catch(e){}}
function getTheme(){try{const v=localStorage.getItem(THEME_KEY());return v==='light'||v==='dark'?v:'auto'}catch(e){return 'auto'}}
function applyTheme(v){
  collect();v=v||getTheme();
  for(const d of darkRules)setMedia(d.r,d.orig,v);
  const root=document.documentElement;
  if(v==='auto'){delete root.dataset.theme;root.style.colorScheme=''}else{root.dataset.theme=v;root.style.colorScheme=v}
  /* Statusleiste: passende Farbe aus den vorhandenen meta-Tags */
  if(metaOrig&&metaOrig.length>1){const dark=v==='dark'||(v==='auto'&&matchMedia('(prefers-color-scheme: dark)').matches);
    const want=metaOrig.find(x=>(x.media||'').includes(dark?'dark':'light'));
    metaOrig.forEach(x=>{if(v==='auto'){x.media!=null?x.m.setAttribute('media',x.media):x.m.removeAttribute('media')}else{if(x===want)x.m.removeAttribute('media');else x.m.setAttribute('media','not all')}})}
}
function setTheme(v){try{v==='auto'?localStorage.removeItem(THEME_KEY()):localStorage.setItem(THEME_KEY(),v)}catch(e){}applyTheme(v);buzz(6)}
function themeHtml(){const v=getTheme();
  return `<div class="ds-seg" role="radiogroup" aria-label="Darstellung">${[['auto','Automatisch'],['light','Hell'],['dark','Dunkel']].map(([k,l])=>`<button type="button" role="radio" aria-checked="${v===k}" data-ds-theme="${k}">${l}</button>`).join('')}</div>
    <p class="ds-hint" style="margin-top:8px">„Automatisch“ folgt der Einstellung des Handys. Gilt nur auf diesem Gerät.</p>`}
document.addEventListener('click',e=>{const b=e.target.closest('[data-ds-theme]');if(!b)return;setTheme(b.dataset.dsTheme);
  b.parentElement.querySelectorAll('[data-ds-theme]').forEach(x=>x.setAttribute('aria-checked',x===b))});

/* ---------- Feier-Effekt mit Konfetti ---------- */
function yay(text,big){buzz([12,50,24]);
  if(reduced()){return}
  const cols=['var(--ds-accent)','var(--ds-ok)','#E8B931','var(--ds-warn)','#E25B8A'];
  const el=document.createElement('div');el.className='ds-yay';el.setAttribute('aria-hidden','true');
  let conf='';if(big)for(let i=0;i<26;i++){const x=(Math.random()*100).toFixed(1),d=(Math.random()*.5).toFixed(2),r=Math.round(Math.random()*720-360),s=(.8+Math.random()*.7).toFixed(2);
    conf+=`<em style="--x:${x}vw;--d:${d}s;--r:${r}deg;--s:${s};--c:${cols[i%cols.length]}"></em>`}
  el.innerHTML=`${conf}<div class="ds-yay-card"><svg viewBox="0 0 52 52"><circle class="yc" cx="26" cy="26" r="23"/><path class="yk" d="M15 27l7 7 15-16"/></svg>${
    Array.from({length:10},(_,i)=>`<i style="--a:${i*36}deg;--c:${cols[i%cols.length]}"></i>`).join('')}${text?`<b>${esc(text)}</b>`:''}</div>`;
  document.body.appendChild(el);setTimeout(()=>el.remove(),big?2600:1600);
}

/* ---------- Entsperr-Animation (MySmartBox: Licht geht an, MyGesundBox: Herzschlag) ---------- */
function unlockAnim(lock,ico,kind,done){
  if(reduced()||!lock||!ico||lock.hidden){done();return}
  const r=ico.getBoundingClientRect(),fx=document.createElement('div');
  fx.className='ds-unl ds-unl-'+kind;fx.setAttribute('aria-hidden','true');
  fx.style.cssText=`left:${r.left+r.width/2}px;top:${r.top+r.height/2}px`;
  fx.innerHTML=kind==='light'?'<span class="ray"></span><span class="glow"></span>':'<span class="ring"></span><span class="ring r2"></span>';
  document.body.appendChild(fx);ico.classList.add('ds-unl-ico','ds-unl-'+kind+'-ico');buzz(kind==='heart'?[14,90,14]:[10,40,18]);
  setTimeout(()=>{const a=lock.animate([{opacity:1,transform:'none'},{opacity:0,transform:'scale(1.05)'}],{duration:320,easing:'ease-in',fill:'forwards'});
    const fin=()=>{fx.remove();ico.classList.remove('ds-unl-ico','ds-unl-'+kind+'-ico');done();requestAnimationFrame(()=>a.cancel())};
    a.onfinish=fin;a.oncancel=null;
    fx.animate([{opacity:1},{opacity:0}],{duration:320,fill:'forwards'})},kind==='heart'?760:680);
}

/* ---------- Sicherungs-Status: Punkt am Schloss oben ---------- */
function bkState(o){
  if(o.ghErr)return 'crit';
  if(!o.own)return '';
  if(o.ghOk)return 'ok';
  const d=o.days,dirty=o.dirty||0;
  return d!=null&&d<=14&&dirty<5?'ok':'warn';
}
function lockDot(btn,o){if(!btn)return;const s=bkState(o);btn.classList.add('ds-lockbtn');btn.dataset.bk=s;
  const t={ok:'Gesichert',warn:'Sicherung fällig',crit:'Problem mit der Sicherung'}[s];
  btn.title=t?'Sperren · '+t:'Sperren'}

/* ---------- Erinnerung an die Datensicherung oben in der Übersicht ---------- */
const ICO_DOWN='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v12M7 10l5 5 5-5"/><path d="M5 19h14"/></svg>';
const ICO_WARN='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.3 3.9L2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>';
function remindHtml(o,attr){
  const card=(cls,ico,t,s,go)=>`<button type="button" class="ds-remind${cls}" ${attr}><span class="ds-remind-i">${ico}</span><span class="ds-remind-t"><b>${esc(t)}</b><small>${esc(s)}</small></span><span class="ds-remind-go">${go}</span></button>`;
  const st=bkState(o);
  if(st==='crit')return card(' crit',ICO_WARN,'GitHub-Sicherung: Problem',o.ghErr,'Ansehen');
  if(st!=='warn')return '';
  const d=o.days,dirty=o.dirty||0;
  return card('',ICO_DOWN,d==null?'Noch keine Datensicherung':dirty>=5?dirty+' Änderungen seit der letzten Datensicherung':'Letzte Datensicherung vor '+d+' Tagen',
    'Ohne Sicherung sind bei Handyverlust oder gelöschten Browserdaten alle Daten weg.','Sichern');
}

/* ---------- Haken im Speichern-Knopf ---------- */
function savedTick(btn){
  if(!btn||!btn.isConnected)return;const w=btn.getBoundingClientRect().width;if(btn._dsT)clearTimeout(btn._dsT);
  if(!btn._dsH)btn._dsH=btn.innerHTML;btn.style.width=w+'px';btn.classList.add('ds-saved');btn.setAttribute('aria-label','Gespeichert');
  btn.innerHTML='<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path class="tk" d="M5 12.5l4.5 4.5L19 7.5"/></svg>';
  btn._dsT=setTimeout(()=>{btn.innerHTML=btn._dsH;btn._dsH=null;btn.classList.remove('ds-saved');btn.style.width='';btn.removeAttribute('aria-label')},1100);
}

/* ---------- Wechsel zwischen den Boxen ---------- */
function boxesHtml(){
  return `<div class="ds-boxes">${BOXES.filter(b=>b.id!==APP).map(b=>`<a class="ds-boxlink" href="${b.url}" rel="noopener"><img class="ds-boxico" src="boxen/${b.id}.png" alt="" width="36" height="36"><span class="ds-qt"><b>${b.name}</b><small>${b.sub}</small></span><svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg></a>`).join('')}</div>`}

/* ---------- Tabs: sanftes Einblenden des Inhalts ---------- */
function tabIn(el,dir){if(reduced()||!el||!el.animate)return;
  el.animate([{opacity:0,transform:`translateX(${dir<0?-18:dir>0?18:0}px)`},{opacity:1,transform:'none'}],{duration:260,easing:'cubic-bezier(.2,.85,.25,1)'})}

function init(app){APP=app;applyTheme();
  try{matchMedia('(prefers-color-scheme: dark)').addEventListener('change',()=>{if(getTheme()==='auto')applyTheme('auto')})}catch(e){}}
/* Start: App-Name kommt aus data-app am Script-Tag */
const me=document.currentScript;init((me&&me.dataset.app)||'box');
window.DS={init,applyTheme,setTheme,getTheme,themeHtml,yay,unlockAnim,bkState,lockDot,remindHtml,savedTick,boxesHtml,tabIn,BOXES};
})();
