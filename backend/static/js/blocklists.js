(() => {
  "use strict";
  const rows = document.getElementById("blocklistRows");
  const stats = document.getElementById("blocklistStats");
  const dialog = document.getElementById("blocklistDialog");
  const form = document.getElementById("blocklistForm");
  const nameInput = document.getElementById("blocklistName");
  const contentInput = document.getElementById("blocklistContent");
  const sourceInput = document.getElementById("blocklistSourceUrl");
  const message = document.getElementById("blocklistMessage");
  let editing = null;
  const esc = v => String(v ?? "");
  const button = (label, action, value) => { const b=document.createElement("button"); b.type="button"; b.className="manage-button row-action"; b.textContent=label; b.addEventListener("click",()=>action(value)); return b; };
  const cell = (value) => { const td=document.createElement("td"); td.textContent=esc(value); return td; };
  async function api(url, options={}) { const r=await fetch(url,{credentials:"same-origin",cache:"no-store",...options,headers:{Accept:"application/json",...(options.headers||{})}}); let data={}; try{data=await r.json();}catch{} if(!r.ok) throw new Error(data.detail||`Request failed (${r.status})`); return data; }
  async function load(){
    try{
      const data=await api("/api/blocklists"); rows.replaceChildren(); let total=0;
      const records=Array.isArray(data.blocklists)?data.blocklists:[];
      records.forEach(item=>{ total+=Number(item.domains)||0; const tr=document.createElement("tr"); tr.append(cell(item.filename)); tr.append(cell(item.domains)); const type=cell(item.custom === true?"CUSTOM":"BUILT-IN"); tr.append(type); const actions=document.createElement("td"); actions.className="row-actions"; if(item.custom === true){actions.append(button("Edit",openEdit,item.filename)); actions.append(button("Delete",remove,item.filename));} actions.append(button("Reload",reload,item.filename)); tr.append(actions); rows.append(tr); });
      if(!records.length){const tr=document.createElement("tr"); const td=cell("No blocklists found."); td.colSpan=4; tr.append(td); rows.append(tr);}
      stats.replaceChildren(stat("LISTS",records.length),stat("DOMAINS",total),stat("CUSTOM",records.filter(x=>String(x.filename).startsWith("custom_")).length));
    }catch(e){rows.replaceChildren();const tr=document.createElement("tr");const td=cell(e.message);td.colSpan=4;tr.append(td);rows.append(tr);}
  }
  function stat(label,value){const a=document.createElement("article");a.className="manage-stat";const s=document.createElement("span");s.textContent=label;const b=document.createElement("strong");b.textContent=String(value);a.append(s,b);return a;}
  function openAdd(){editing=null;document.getElementById("blocklistDialogTitle").textContent="Add blocklist";nameInput.disabled=false;nameInput.value="";contentInput.value="";sourceInput.value="";message.textContent="";dialog.showModal();}
  async function openEdit(filename){editing=filename;document.getElementById("blocklistDialogTitle").textContent="Edit blocklist";nameInput.disabled=true;nameInput.value=filename.replace(/^custom_/i,"").replace(/\.txt$/i,"");sourceInput.value="";message.textContent="Loading…";try{const r=await api(`/api/blocklists/${encodeURIComponent(filename)}`);contentInput.value=Array.isArray(r.domains)?r.domains.join("\n"):"";message.textContent="";dialog.showModal();}catch(e){message.textContent=e.message;}}
  async function save(){message.textContent="Saving…";try{if(editing){await api(`/api/blocklists/${encodeURIComponent(editing)}`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify({content:contentInput.value})});}else{await api("/api/blocklists",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:nameInput.value,content:contentInput.value,source_url:sourceInput.value.trim()||null})});}dialog.close();await load();}catch(e){message.textContent=e.message;}}
  async function remove(filename){if(!confirm(`Delete ${filename}?`))return;try{await api(`/api/blocklists/${encodeURIComponent(filename)}`,{method:"DELETE"});await load();}catch(e){alert(e.message);}}
  async function reload(filename){try{await api(`/blocklists/${encodeURIComponent(filename)}/reload`,{method:"POST"});await load();}catch(e){alert(e.message);}}
  document.getElementById("newBlocklist").addEventListener("click",openAdd);document.getElementById("reloadAll").addEventListener("click",async()=>{try{await api("/blocklists/reload-all",{method:"POST"});await load();}catch(e){alert(e.message);}});
  form.addEventListener("submit",e=>{if(e.submitter&&e.submitter.value==="save"){e.preventDefault();save();}});
  document.getElementById("closeBlocklistDialog").addEventListener("click",()=>dialog.close());
  document.querySelectorAll("#blocklistDialog .dialog-cancel").forEach(b=>b.addEventListener("click",()=>dialog.close()));
  // Detail endpoint for edit is added by the server below.
  load();
})();
