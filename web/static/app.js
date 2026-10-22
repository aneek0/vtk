/* ── helpers ── */
function esc(s){return(''+(s||'')).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}

async function apiGet(url){
  var r=await fetch(url),d=await r.json();
  if(!d.ok) throw new Error(d.error||'request failed');
  return d;
}
async function apiPost(url,body){
  var r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  var d=await r.json();
  if(!d.ok) throw new Error(d.error||'request failed');
  return d;
}

/* ── copy ── */
function copyText(text,btn){
  (async function(){
    try{
      if(navigator.clipboard) await navigator.clipboard.writeText(text);
      else{
        var ta=document.createElement('textarea');
        ta.value=text;ta.style.position='fixed';ta.style.left='-9999px';
        document.body.appendChild(ta);ta.select();
        document.execCommand('copy');document.body.removeChild(ta);
      }
      if(btn){var orig=btn.textContent;btn.textContent='\u2713';setTimeout(function(){btn.textContent=orig},1200)}
    }catch(e){
      if(btn){var orig2=btn.textContent;btn.textContent='\u2717';setTimeout(function(){btn.textContent=orig2},1200)}
    }
  })();
}
function copyResult(id){
  var text=document.getElementById(id).textContent;
  var container=document.getElementById(id);
  var btn=container&&container.parentElement?container.parentElement.querySelector('.copy-btn'):null;
  copyText(text,btn);
}

/* ── showResult ── */
function showResult(id,content,success,isHtml){
  var box=document.getElementById(id);
  var el=document.getElementById(id+'Content');
  if(!el) return;
  if(isHtml) el.innerHTML=content;
  else el.textContent=content;
  el.className='result-content '+(success?'success':'error');
  box.classList.add('visible','fade-in');
}

/* ── busy state on the triggering button ── */
function setBusy(btn,on){
  if(!btn) return;
  if(on){btn.setAttribute('aria-busy','true')}
  else btn.removeAttribute('aria-busy');
}

/* ── theme ── */
(function initTheme(){
  var t=localStorage.getItem('vtk-theme')
    ||(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');
  document.documentElement.setAttribute('data-theme',t);
  document.addEventListener('DOMContentLoaded',function(){
    var btn=document.getElementById('themeToggle');
    if(!btn) return;
    btn.textContent=t==='light'?'\u263E':'\u2600';
    btn.addEventListener('click',function(){
      var cur=document.documentElement.getAttribute('data-theme');
      var next=cur==='light'?'dark':'light';
      document.documentElement.setAttribute('data-theme',next);
      localStorage.setItem('vtk-theme',next);
      btn.textContent=next==='light'?'\u263E':'\u2600';
    });
  });
})();

/* ── topbar dock ── */
(function initChrome(){
  document.addEventListener('DOMContentLoaded',function(){
    document.documentElement.classList.remove('preload');
    var bar=document.getElementById('topbar');
    if(!bar) return;
    var docked=false;
    function sync(){
      var next=window.scrollY>8;
      if(next===docked) return;
      docked=next;
      bar.classList.toggle('docked',docked);
    }
    window.addEventListener('scroll',sync,{passive:true});
    sync();
  });
})();

/* ── pickers: native <select> → akres-style list ── */
(function initPickers(){
  function setup(sel){
    var label=sel.id&&document.querySelector('label[for="'+sel.id+'"]');
    var wrap=document.createElement('div');wrap.className='picker';
    sel.parentNode.insertBefore(wrap,sel);wrap.appendChild(sel);
    sel.hidden=true;

    var btn=document.createElement('button');
    btn.type='button';btn.className='picker-btn';
    btn.setAttribute('aria-haspopup','listbox');btn.setAttribute('aria-expanded','false');
    if(label&&!label.id) label.id=sel.id+'-label';
    if(label) btn.setAttribute('aria-labelledby',label.id);
    else btn.setAttribute('aria-label',sel.id||'Options');
    btn.innerHTML='<span class="picker-tx"></span>'
      +'<svg class="mi chev" aria-hidden="true" role="presentation"><use href="#i-arrow_drop_down"/></svg>';
    var tx=btn.querySelector('.picker-tx');

    var menu=document.createElement('div');
    menu.className='menu';menu.hidden=true;
    menu.setAttribute('role','listbox');
    if(label) menu.setAttribute('aria-labelledby',label.id);

    var items=Array.from(sel.options).map(function(opt,i){
      var it=document.createElement('button');
      it.type='button';it.className='menu-item';
      it.setAttribute('role','option');it.dataset.index=i;
      it.innerHTML='<svg class="mi tick" aria-hidden="true" role="presentation"><use href="#i-check"/></svg>'
        +'<span class="menu-tx"></span>';
      it.querySelector('.menu-tx').textContent=opt.textContent;
      it.addEventListener('click',function(){pick(i)});
      menu.appendChild(it);
      return it;
    });
    wrap.appendChild(btn);wrap.appendChild(menu);

    function sync(){
      var cur=sel.selectedIndex;
      tx.textContent=sel.options[cur]?sel.options[cur].textContent:'';
      items.forEach(function(it,i){
        it.setAttribute('aria-selected',i===cur?'true':'false');
        it.tabIndex=i===cur?0:-1;
      });
    }
    var hideTimer=0;
    function open(focusIdx){
      clearTimeout(hideTimer);
      menu.hidden=false;
      void menu.offsetWidth;               // let display flip settle before animating
      wrap.classList.add('open');
      btn.setAttribute('aria-expanded','true');
      var it=items[focusIdx==null?sel.selectedIndex:focusIdx];
      if(it) it.focus();
    }
    function close(refocus){
      if(!wrap.classList.contains('open')) return;
      wrap.classList.remove('open');
      btn.setAttribute('aria-expanded','false');
      hideTimer=setTimeout(function(){menu.hidden=true},260);
      if(refocus) btn.focus();
    }
    function pick(i){
      sel.selectedIndex=i;
      sel.dispatchEvent(new Event('change',{bubbles:true}));
      sync();close(true);
    }

    btn.addEventListener('click',function(){
      if(wrap.classList.contains('open')) close(false); else open();
    });
    btn.addEventListener('keydown',function(e){
      if(e.key==='ArrowDown'||e.key==='ArrowUp'){
        e.preventDefault();open(e.key==='ArrowUp'?items.length-1:undefined);
      }
    });
    menu.addEventListener('keydown',function(e){
      var i=items.indexOf(document.activeElement);
      if(e.key==='ArrowDown'){e.preventDefault();items[Math.min(i+1,items.length-1)].focus()}
      else if(e.key==='ArrowUp'){e.preventDefault();items[Math.max(i-1,0)].focus()}
      else if(e.key==='Home'){e.preventDefault();items[0].focus()}
      else if(e.key==='End'){e.preventDefault();items[items.length-1].focus()}
      else if(e.key==='Escape'){e.preventDefault();close(true)}
      else if(e.key==='Tab') close(false);
    });
    document.addEventListener('pointerdown',function(e){
      if(!wrap.contains(e.target)) close(false);
    });
    sel.addEventListener('change',sync);   // programmatic .value = ... + change
    sync();
  }
  document.addEventListener('DOMContentLoaded',function(){
    document.querySelectorAll('select').forEach(setup);
  });
})();

/* ── tab SPA ── */
(function(){
  var tabs=['convert','proxy','decrypt','api'];
  function switchTab(name){
    document.getElementById('rb-convert').checked=name==='convert';
    document.getElementById('rb-proxy').checked=name==='proxy';
    document.getElementById('rb-decrypt').checked=name==='decrypt';
    document.getElementById('rb-api').checked=name==='api';
    tabs.forEach(function(t){
      var btn=document.getElementById('tab-'+t);
      if(btn) btn.classList.toggle('active',t===name);
    });
    // fade in main content
    var main=document.getElementById('main');
    main.classList.remove('fade-enter');
    void main.offsetWidth;
    main.classList.add('fade-enter');
  }
  function tabFromPath(){
    var p=window.location.pathname.replace(/^\/|\/$/g,'');
    return tabs.indexOf(p)>=0?p:'convert';
  }
  switchTab(tabFromPath());
  document.querySelectorAll('.tab-btn').forEach(function(a){
    a.addEventListener('click',function(e){
      e.preventDefault();
      var name=this.getAttribute('href').replace(/^\//,'');
      if(tabs.indexOf(name)<0) name='convert';
      switchTab(name);
      history.pushState({tab:name},'', '/'+name);
    });
  });
  window.addEventListener('popstate',function(){switchTab(tabFromPath())});
})();

/* ── drag & drop ── */
(function initDragDrop(){
  document.addEventListener('DOMContentLoaded',function(){
    var areas=document.querySelectorAll('textarea');
    areas.forEach(function(ta){
      ta.addEventListener('dragover',function(e){e.preventDefault();this.classList.add('drag-over')});
      ta.addEventListener('dragleave',function(e){e.preventDefault();this.classList.remove('drag-over')});
      ta.addEventListener('drop',function(e){
        e.preventDefault();
        this.classList.remove('drag-over');
        var file=e.dataTransfer.files[0];
        if(!file) return;
        var reader=new FileReader();
        reader.onload=function(ev){ta.value=ev.target.result};
        reader.readAsText(file);
      });
    });
  });
})();

/* ── CONVERT tab ── */
function showServerError(msg){
  var titleEl=document.getElementById('serversTitle');
  titleEl.textContent=msg;
  var section=document.getElementById('convertServersSection');
  section.style.display='block';
  document.getElementById('convertServers').innerHTML='';
  document.getElementById('serverFilters').style.display='none';
}

async function convertLinks(){
  var input=document.getElementById('convertInput').value.trim();
  if(!input){showServerError('Enter links');return}
  var format=document.getElementById('convertFormat').value;
  var prefix=document.getElementById('tagPrefix').value;
  var deviceOn=document.getElementById('convertDeviceOn').checked;
  var device={
    os:document.getElementById('convertOs').value.trim(),
    ua:document.getElementById('convertUa').value.trim(),
    ver:document.getElementById('convertVer').value.trim(),
    model:document.getElementById('convertModel').value.trim(),
    locale:document.getElementById('convertLocale').value.trim(),
    hwid:document.getElementById('convertHwidOn').checked?document.getElementById('convertHwid').value.trim():''
  };
  var btn=document.getElementById('convertBtn');
  setBusy(btn,true);
  try{
    var d=await apiPost('/api/convert',{input:input,format:format,tag_prefix:prefix,device_on:deviceOn,device:device});
  }catch(e){showServerError('Error: '+e.message);return}
  finally{setBusy(btn,false)}

  // subscription headers
  var headers=d.sub_headers||[];
  var headersSection=document.getElementById('convertHeadersSection');
  var headersEl=document.getElementById('convertHeaders');
  if(headers.length){
    headersEl.innerHTML='';
    headers.forEach(function(h){
      var k=document.createElement('div');k.className='sub-header-key';k.textContent=h[0];
      var v=document.createElement('div');v.className='sub-header-val';v.textContent=h[1];
      headersEl.appendChild(k);headersEl.appendChild(v);
    });
    headersSection.style.display='block';
  }else headersSection.style.display='none';

  // body spoiler
  var bodySection=document.getElementById('convertBodySection');
  var bodyContent=document.getElementById('convertBodyContent');
  if(d.result&&d.result.trim()){
    bodyContent.textContent=d.result.trim();
    bodySection.style.display='block';
  }else bodySection.style.display='none';

  // servers list
  var serversSection=document.getElementById('convertServersSection');
  var serversEl=document.getElementById('convertServers');
  var servers=d.servers||[];
  var titleEl=document.getElementById('serversTitle');
  window._vtkServers=servers; window._vtkFormat=format;
  window._vtkLastInput=input; window._vtkTagPrefix=prefix;
  window._vtkDeviceOn=deviceOn; window._vtkDevice=device;
  serversEl.innerHTML='';
  renderServers('all');
  renderServerFilters(d.protocols||{}, d.total_nodes||servers.length);
  if(servers.length) serversSection.style.display='block';
  else serversSection.style.display='none';

  document.getElementById('serversTitle').textContent='servers ('+d.nodes+')';
}

async function refetchProtocol(proto){
  var btn=document.getElementById('convertBtn');
  setBusy(btn,true);
  try{
    var d=await apiPost('/api/convert',{input:window._vtkLastInput,format:window._vtkFormat,
      tag_prefix:window._vtkTagPrefix,device_on:window._vtkDeviceOn,device:window._vtkDevice,
      protocol:proto==='all'?'':proto});
  }catch(e){showServerError('Error: '+e.message);return}
  finally{setBusy(btn,false)}
  window._vtkServers=d.servers||[];
  document.getElementById('convertServers').innerHTML='';
  renderServers(proto);
  renderServerFilters(d.protocols||{}, d.total_nodes||d.servers.length, proto);
  var titleEl=document.getElementById('serversTitle');
  titleEl.textContent='servers ('+(d.nodes)+')';
  var sec=document.getElementById('convertHeadersSection');
  if(d.sub_headers&&d.sub_headers.length){sec.style.display='block'}else{sec.style.display='none'}
}

function renderServerFilters(protocols,total,active){
  var bar=document.getElementById('serverFilters');
  bar.innerHTML='';
  var protos=Object.keys(protocols);
  var mk=function(id,label,n){
    var b=document.createElement('button');
    b.className='proto-chip';
    b.textContent=label+' ('+n+')';
    b.setAttribute('aria-pressed', id===(active||'all')?'true':'false');
    b.dataset.proto=id;
    b.onclick=function(){
      bar.querySelectorAll('.proto-chip').forEach(function(c){c.setAttribute('aria-pressed',c.dataset.proto===id?'true':'false')});
      refetchProtocol(id);
    };
    return b;
  };
  bar.appendChild(mk('all','all',total));
  protos.forEach(function(p){bar.appendChild(mk(p,p,protocols[p]))});
  bar.style.display=protos.length>1?'flex':'none';
}
function renderServers(filter){
  var servers=window._vtkServers||[];
  var serversEl=document.getElementById('convertServers');
  var format=window._vtkFormat||'singbox';
  serversEl.innerHTML='';
  if(!servers.length) return;
  var protoLabels={vless:'VLESS',vmess:'VMESS',trojan:'TROJAN',ss:'SS',ssr:'SSR',hysteria2:'HYSTERIA2',socks:'SOCKS'};
  var commonRows=[['Address','address'],['Port','port'],['Type','type'],['Encryption','encryption'],['Security','security']];
  var protoRows={
    vless:commonRows.concat([['UUID','uuid'],['Flow','flow'],['SNI','sni'],['ALPN','alpn'],['FP','fp'],['Path','path'],['Host','host'],['PBK','pbk'],['SID','sid']]),
    vmess:commonRows.concat([['UUID','uuid'],['AID','aid'],['Path','path'],['Host','host'],['SNI','sni'],['ALPN','alpn'],['FP','fp']]),
    trojan:commonRows.concat([['Password','password'],['SNI','sni'],['Path','path'],['Host','host'],['FP','fp']]),
    hysteria2:commonRows.concat([['Password','password'],['Obfs','obfs'],['SNI','sni'],['ALPN','alpn'],['Path','path'],['Host','host']]),
    ss:commonRows.concat([['Method','method'],['Password','password']]),
    ssr:commonRows.concat([['Method','method'],['Password','password'],['Protocol','ssr_protocol'],['Obfs','ssr_obfs']]),
    socks:commonRows.concat([['Username','socks_user'],['Password','socks_pass']])
  };
  servers.forEach(function(s){
    if(filter!=='all'&&s.protocol!==filter) return;
    var card=document.createElement('details');
    card.className='server-card';
    if(s.link) card.setAttribute('data-link',s.link);
    card.dataset.proto=s.protocol;
    var prot=protoLabels[s.protocol]||s.net.toUpperCase();
      var protoStr=s.reality?'REALITY':prot;
      var summary=document.createElement('summary');
      summary.className='server-summary';
      summary.innerHTML='<span class="server-name">'+esc(s.name)+'</span><span class="server-proto">'+protoStr+'</span>';
      card.setAttribute('data-addr',s.address+':'+s.port);
      var details=document.createElement('div');
      details.className='server-details';
      var rowDefs=protoRows[s.protocol]||[['UUID','uuid'],['Flow','flow'],['Path','path'],['SNI','sni'],['Host','host']];
      if(s.reality&&rowDefs.indexOf('PBK')<0) rowDefs=rowDefs.concat([['PBK','pbk'],['SID','sid']]);
      rowDefs.forEach(function(def){
        var key=def[0],field=def[1],val=s[field]||'';
        if(val) details.innerHTML+='<div class="detail-key">'+esc(key)+'</div>'
          +'<div class="detail-val">'+esc(val)+'</div>';
      });
      // copy buttons
      var btnRow=document.createElement('div');
      btnRow.style.cssText='display:flex;gap:0.4rem;margin-top:0.4rem;flex-wrap:wrap;grid-column:1/-1';
      var linkToCopy=s.link||(s.protocol+'://'+s.address+':'+s.port);
      var copyLinkBtn=document.createElement('button');
      copyLinkBtn.className='copy-btn';
      copyLinkBtn.textContent='Copy link';
      copyLinkBtn.onclick=function(t,b){return function(){copyText(t,b)}}(linkToCopy,copyLinkBtn);
      btnRow.appendChild(copyLinkBtn);
      var copyFmtBtn=document.createElement('button');
      copyFmtBtn.className='copy-btn';
      copyFmtBtn.textContent='Copy as '+format.toUpperCase();
      copyFmtBtn.onclick=function(link,fmt,btn){
        return async function(){
          btn.textContent='\u23F3';
          try{
            var d=await apiPost('/api/convert',{input:link,format:fmt});
            copyText(d.result||'',btn);
          }catch(e){
            btn.textContent='\u2717';
            setTimeout(function(){btn.textContent='Copy as '+fmt.toUpperCase()},1500);
          }
        };
      }(linkToCopy,format,copyFmtBtn);
      btnRow.appendChild(copyFmtBtn);
      details.appendChild(btnRow);
      card.appendChild(summary);
      card.appendChild(details);
    serversEl.appendChild(card);
  });
}


function copyAllServers(){
  var servers=document.querySelectorAll('#convertServers .server-card');
  var lines=[];
  servers.forEach(function(card){
    var link=card.getAttribute('data-link');
    if(link){lines.push(link);return}
    var name=card.querySelector('.server-name').textContent;
    var addr=card.getAttribute('data-addr')||'';
    var proto=card.querySelector('.server-proto').textContent;
    lines.push(proto+' '+name+' '+addr);
  });
  var btn=document.querySelector('#convertServersSection .copy-btn');
  copyText(lines.join('\n'),btn);
}

/* ── DECRYPT tab ── */
async function decryptLink(){
  var input=document.getElementById('decryptInput').value.trim();
  if(!input){showResult('decryptResult','Enter link',false);return}
  try{
    var d=await apiPost('/api/happ/decrypt',{url:input});
    showResult('decryptResult',d.decryptedUrl,true);
  }catch(e){showResult('decryptResult','Error: '+e.message,false)}
}
async function decryptText(){
  var input=document.getElementById('decryptInput').value.trim();
  if(!input){showResult('decryptResult','Enter text',false);return}
  try{
    var d=await apiPost('/api/happ/decrypt-text',{text:input});
    showResult('decryptResult',d.text,d.decrypted);
  }catch(e){showResult('decryptResult','Error: '+e.message,false)}
}
function clearDecrypt(){
  document.getElementById('decryptInput').value='';
  document.getElementById('decryptResult').classList.remove('visible');
}

/* ── PROXY tab ── */
async function proxyFetch(){
  var url=document.getElementById('proxyUrl').value.trim();
  if(!url){showResult('proxyResult','Enter subscription URL',false);return}
  var parts=[];
  var fields=['proxyVer','proxyModel','proxyUa','proxyLocale','proxyHwid'];
  var vals=['ver=','model=','ua=','locale=','hwid='];
  for(var i=0;i<fields.length;i++){
    var v=document.getElementById(fields[i]).value.trim();
    if(v) parts.push(vals[i]+v);
  }
  var os_val=document.getElementById('proxyOs').value.trim();
  if(parts.length===0) parts.push(os_val||'android');
  else parts.unshift(os_val||'android');
  var format=document.getElementById('proxyFormat').value;
  var host=window.location.origin;
  var paramsStr=parts.join(',');
  var fullUrl=host+'/p/'+paramsStr+'/'+url;
  if(format!=='as_is') fullUrl+='?format='+format;
  var urlHtml='<label>URL for app</label><div class="url-box"><a href="'+fullUrl+'" target="_blank">'+fullUrl+'</a></div>';
  urlHtml+='<button class="copy-btn" onclick="copyText(\''+fullUrl+'\',this)">COPY</button> ';
  urlHtml+='<a href="'+fullUrl+'" target="_blank"><button class="copy-btn">OPEN</button></a>';
  urlHtml+=' <button class="copy-btn" onclick="proxyQR()">QR</button>';
  urlHtml+=' <div id="proxyQRCode" style="margin-top:0.5rem"></div>';
  showResult('proxyResult',urlHtml,true,true);
  try{
    var r=await fetch('/p/'+paramsStr+'/'+url+(format!=='as_is'?'?format='+format:''));
    var text=await r.text();
    if(text.length>0){
      var preview='<div class="preview"><strong>Preview:</strong><br>'+text.substring(0,800)+(text.length>800?'... ('+text.length+' bytes)':'')+'</div>';
      document.getElementById('proxyResultContent').insertAdjacentHTML('beforeend', preview);
    }
  }catch(e){/* ignore */}
}

function proxyQR(){
  var url=document.querySelector('#proxyResultContent .url-box a');
  if(!url) return;
  var container=document.getElementById('proxyQRCode');
  if(container.classList.contains('visible')){container.classList.remove('visible');return}
  container.classList.add('visible');
  container.innerHTML='';
  if(typeof QRCode==='undefined'){
    var s=document.createElement('script');
    s.src='https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js';
    s.onload=function(){new QRCode(container,{text:url.href,width:180,height:180})};
    document.head.appendChild(s);
  }else new QRCode(container,{text:url.href,width:180,height:180});
}

async function _applyRandom(prefix){
  try{
    var d=await (await fetch('/api/device/random')).json();
    var os=document.getElementById(prefix+'Os');
    os.value=d.os||'android';
    os.dispatchEvent(new Event('change'));
    document.getElementById(prefix+'Ua').value=d.ua||'';
    document.getElementById(prefix+'Ver').value=d.ver||'';
    document.getElementById(prefix+'Model').value=d.model||'';
    document.getElementById(prefix+'Locale').value=d.locale||'';
    document.getElementById(prefix+'Hwid').value=d.hwid||'';
  }catch(e){/* ignore */}
}
function randomizeProxy(){ _applyRandom('proxy'); }
function randomizeConvert(){ _applyRandom('convert'); }

