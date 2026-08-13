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

/* ── spinner ── */
function showSpinner(id){showResult(id,'<span class="spinner"></span> loading…',true,true)}
function hideSpinner(id){
  var box=document.getElementById(id);
  if(box) box.classList.remove('visible');
}

/* ── theme ── */
(function initTheme(){
  var t=localStorage.getItem('vtk-theme')||'dark';
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

/* ── custom <select> ── */
(function initSelects(){
  document.addEventListener('DOMContentLoaded',function(){
    document.querySelectorAll('select').forEach(function(sel){
      var wrap=document.createElement('div');wrap.className='cs-wrap';
      sel.parentNode.insertBefore(wrap,sel);wrap.appendChild(sel);
      sel.style.display='none';
      var details=document.createElement('details');details.className='cs-details';
      var summary=document.createElement('summary');summary.className='cs-summary';
      summary.textContent=sel.options[sel.selectedIndex].textContent;
      details.appendChild(summary);
      var menu=document.createElement('div');menu.className='cs-menu';
      Array.from(sel.options).forEach(function(opt,i){
        var d=document.createElement('div');d.className='cs-opt'+(opt.selected?' selected':'');
        d.textContent=opt.textContent;d.dataset.value=opt.value;d.dataset.index=i;
        d.addEventListener('click',function(e){
          // sync hidden select
          sel.selectedIndex=parseInt(this.dataset.index);
          sel.dispatchEvent(new Event('change',{bubbles:true}));
          // update summary
          summary.textContent=this.textContent;
          // highlight
          menu.querySelectorAll('.cs-opt').forEach(function(o){o.classList.remove('selected')});
          this.classList.add('selected');
          // close
          details.removeAttribute('open');
        });
        menu.appendChild(d);
      });
      // sync custom display when hidden select changes programmatically
      sel.addEventListener('_sync', function(){
        summary.textContent = sel.options[sel.selectedIndex].textContent;
        menu.querySelectorAll('.cs-opt').forEach(function(o){o.classList.toggle('selected', o.dataset.index == sel.selectedIndex)});
      });
      details.appendChild(menu);
      wrap.appendChild(details);
    });
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
async function convertLinks(){
  var input=document.getElementById('convertInput').value.trim();
  if(!input){showResult('convertResult','Enter links',false);return}
  var format=document.getElementById('convertFormat').value;
  var prefix=document.getElementById('tagPrefix').value;
  var deviceOn=document.getElementById('convertDeviceOn').checked;
  var device={
    os:document.getElementById('convertOs').value.trim(),
    ua:document.getElementById('convertUa').value.trim(),
    ver:document.getElementById('convertVer').value.trim(),
    model:document.getElementById('convertModel').value.trim(),
    locale:document.getElementById('convertLocale').value.trim(),
    hwid:document.getElementById('convertHwid').value.trim()
  };
  showSpinner('convertResult');
  try{
    var d=await apiPost('/api/convert',{input:input,format:format,tag_prefix:prefix,device_on:deviceOn,device:device});
  }catch(e){showResult('convertResult','Error: '+e.message,false);return}
  hideSpinner('convertResult');

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
  var vlessCount=servers.filter(function(s){return s.protocol==='vless'}).length;
  var titleEl=document.getElementById('serversTitle');
  if(vlessCount>0) titleEl.textContent='vless servers ('+vlessCount+')';
  else titleEl.textContent='servers ('+servers.length+')';

  serversEl.innerHTML='';
  if(servers.length){
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
      var card=document.createElement('details');
      card.className='server-card';
      if(s.link) card.setAttribute('data-link',s.link);
      var prot=protoLabels[s.protocol]||s.net.toUpperCase();
      var protoStr=s.reality?'REALITY':prot;
      var summary=document.createElement('summary');
      summary.className='server-summary';
      summary.innerHTML='<span class="server-name">'+esc(s.name)+'</span><span class="server-addr">'+esc(s.address)+':'+s.port+'</span><span class="server-proto">'+protoStr+'</span>';
      var details=document.createElement('div');
      details.className='server-details';
      var rowDefs=protoRows[s.protocol]||[['UUID','uuid'],['Flow','flow'],['Path','path'],['SNI','sni'],['Host','host']];
      if(s.reality&&rowDefs.indexOf('PBK')<0) rowDefs=rowDefs.concat([['PBK','pbk'],['SID','sid']]);
      rowDefs.forEach(function(def){
        var key=def[0],field=def[1],val=s[field]||'';
        if(val) details.innerHTML+='<div><span class="detail-key">'+key+'</span><span class="detail-val">'+esc(val)+'</span></div>';
      });
      // copy buttons
      var btnRow=document.createElement('div');
      btnRow.style.cssText='display:flex;gap:0.4rem;margin-top:0.4rem;flex-wrap:wrap';
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
    serversSection.style.display='block';
  }else serversSection.style.display='none';

  showResult('convertResult','\u2713 '+d.nodes+' converted',true);
}

function copyAllServers(){
  var servers=document.querySelectorAll('#convertServers .server-card');
  var lines=[];
  servers.forEach(function(card){
    var link=card.getAttribute('data-link');
    if(link){lines.push(link);return}
    var name=card.querySelector('.server-name').textContent;
    var addr=card.querySelector('.server-addr').textContent;
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
    document.getElementById(prefix+'Os').value=d.os||'android';
    document.getElementById(prefix+'Ua').value=d.ua||'';
    document.getElementById(prefix+'Ver').value=d.ver||'';
    document.getElementById(prefix+'Model').value=d.model||'';
    document.getElementById(prefix+'Locale').value=d.locale||'';
    document.getElementById(prefix+'Hwid').value=d.hwid||'';
  }catch(e){/* ignore */}
}
function randomizeProxy(){ _applyRandom('proxy'); }
function randomizeConvert(){ _applyRandom('convert'); }

