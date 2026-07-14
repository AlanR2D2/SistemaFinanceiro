// Valida a lógica "aplicaModalOrdemVisibilidade" adicionada em
// _mandados_table.html / _acordos_table.html:
//   Bug 1: coluna oculta (ex.: TIPO) deve sumir também do modal de criar/editar.
//   Bug 2: campo personalizado (ex.: DATA REPASSE, posição 13) deve aparecer na
//          posição configurada, não sempre no fim da grade.
// Usa um mini-DOM (mesmo estilo de test_frontend_headers.js) — sem browser.

let PASS = 0, FAIL = 0;
function assert(c, m){ if(c){PASS++;console.log("  ok -",m);} else {FAIL++;console.log("  FAIL -",m);} }

// ------------------------- mini-DOM -------------------------
const registry = {};
class El {
  constructor(tag){ this.tag=tag; this.parent=null; this.children=[]; this.className=""; this.dataset={}; this.id=null; this.style={}; }
  appendChild(c){ this._detach(c); c.parent=this; this.children.push(c); return c; }
  prepend(c){ this._detach(c); c.parent=this; this.children.unshift(c); return c; }
  _detach(c){ if(c.parent){ const i=c.parent.children.indexOf(c); if(i>=0) c.parent.children.splice(i,1); } c.parent=null; }
  after(node){
    const p=this.parent; if(!p) return;
    p._detach(node); node.parent=p;
    const i=p.children.indexOf(this);
    p.children.splice(i+1,0,node);
  }
  _hasClass(c){ return this.className.split(/\s+/).filter(Boolean).includes(c); }
  matches(sel){
    // Suporta ".cls" e ".cls[data-attr=\"val\"]"
    const m = sel.match(/^\.([A-Za-z0-9_-]+)(?:\[([A-Za-z0-9_-]+)="([^"]*)"\])?$/);
    if(!m) return false;
    if(!this._hasClass(m[1])) return false;
    if(m[2]){ const key = m[2].replace(/^data-/, "").replace(/-([a-z])/g,(_,c)=>c.toUpperCase());
      return String(this.dataset[key]) === m[3]; }
    return true;
  }
  closest(sel){ let n=this; while(n){ if(n.matches && n.matches(sel)) return n; n=n.parent; } return null; }
  querySelector(sel){
    const walk=(el)=>{ for(const ch of el.children){ if(ch.matches&&ch.matches(sel)) return ch; const d=walk(ch); if(d) return d; } return null; };
    return walk(this);
  }
}
const document = {
  getElementById:(id)=>registry[id]||null,
  querySelector:(sel)=>{
    const parts = sel.trim().split(/\s+/);
    if(parts[0].startsWith("#")){
      const root = registry[parts[0].slice(1)] || null;
      if(parts.length===1) return root;
      return root ? root.querySelector(parts.slice(1).join(" ")) : null;
    }
    return null;
  }
};
const window = {}; // sem CSS.escape -> usa fallback

function makeField(containerClass, inputId, dataAttrs){
  const div = new El("div"); div.className = "md-field " + containerClass;
  if(dataAttrs) Object.assign(div.dataset, dataAttrs);
  const inp = new El("input"); inp.id = inputId; registry[inputId] = inp;
  div.appendChild(inp);
  return div;
}

// ------------------- monta o modal (ordem real do modal) -------------------
const overlay = new El("div"); overlay.className="md-modal-overlay"; overlay.id="mdModalOverlay"; registry["mdModalOverlay"]=overlay;
const grid = new El("div"); grid.className="md-grid"; overlay.appendChild(grid);

const modalLabelMap = {
  tipo_reu:"mdTipoReu", data_quitacao:"mdDataQuitacao", uf:"mdUfSelect",
  numero_processo:"mdNumeroProcesso", reu:"mdReuSelect", autor:"mdAutor",
  local:"mdLocalSelect", tipo:"mdTipo", observacoes:"mdObservacoes",
};
// Ordem do DOM do modal (fixos), personalizado SEMPRE no fim (como o Jinja renderiza).
["tipo_reu","data_quitacao","uf","numero_processo","reu","autor","local","tipo","observacoes"]
  .forEach(ch => grid.appendChild(makeField("", modalLabelMap[ch])));
const cfDiv = makeField("md-custom-field", "mdCf_data_repasse", { cfChave:"data_repasse" });
grid.appendChild(cfDiv);

// ------------------- MD_ORDEM (config do tenant) -------------------
// local=12, DATA REPASSE=13 (custom), TIPO=14 (oculto). Demais na ordem natural.
window.MD_ORDEM = [
  {chave:"data_quitacao",  origem:"fixa", ordem:1,  visivel:1},
  {chave:"numero_processo",origem:"fixa", ordem:2,  visivel:1},
  {chave:"uf",             origem:"fixa", ordem:3,  visivel:1},
  {chave:"reu",            origem:"fixa", ordem:4,  visivel:1},
  {chave:"autor",          origem:"fixa", ordem:5,  visivel:1},
  {chave:"local",          origem:"fixa", ordem:12, visivel:1},
  {chave:"data_repasse",   origem:"custom",ordem:13,visivel:1},
  {chave:"tipo",           origem:"fixa", ordem:14, visivel:0}, // OCULTO
  {chave:"tipo_reu",       origem:"fixa", ordem:15, visivel:1},
  {chave:"observacoes",    origem:"fixa", ordem:23, visivel:1},
];

// ------------------- função sob teste (cópia fiel dos partials) -------------------
(function aplicaModalOrdemVisibilidade() {
  const ordem = Array.isArray(window.MD_ORDEM) ? window.MD_ORDEM : [];
  if (!ordem.length) return;
  const grid = document.querySelector("#mdModalOverlay .md-grid");
  if (!grid) return;
  const escapeSel = (s) => (window.CSS && window.CSS.escape) ? window.CSS.escape(s) : String(s).replace(/"/g, '\\"');
  function fieldEl(item) {
    if (!item || !item.chave) return null;
    if (item.origem === "custom") {
      return grid.querySelector(`.md-custom-field[data-cf-chave="${escapeSel(item.chave)}"]`);
    }
    const inputId = modalLabelMap[item.chave];
    if (!inputId) return null;
    const inp = document.getElementById(inputId);
    return inp ? inp.closest(".md-field") : null;
  }
  ordem.forEach((item, i) => {
    if (item.origem !== "custom") return;
    const el = fieldEl(item);
    if (!el) return;
    let anchor = null;
    for (let j = i - 1; j >= 0; j--) { const prev = fieldEl(ordem[j]); if (prev) { anchor = prev; break; } }
    if (anchor) anchor.after(el); else grid.prepend(el);
  });
  ordem.forEach(item => {
    if (Number(item.visivel) === 0) { const el = fieldEl(item); if (el) el.style.display = "none"; }
  });
})();

// ------------------- asserts -------------------
console.log("\n[Bug 2] posição do campo personalizado no modal");
const idxLocal = grid.children.indexOf(registry["mdLocalSelect"].closest(".md-field"));
const idxCf    = grid.children.indexOf(cfDiv);
const idxTipo  = grid.children.indexOf(registry["mdTipo"].closest(".md-field"));
assert(idxCf === idxLocal + 1, "DATA REPASSE fica logo após LOCAL (posição configurada)");
assert(idxCf !== grid.children.length - 1, "DATA REPASSE deixou de ser o último campo do modal");
assert(idxTipo === idxCf + 1, "TIPO (posição 14) vem logo depois de DATA REPASSE na ordem");

console.log("\n[Bug 1] visibilidade dos campos no modal");
assert(registry["mdTipo"].closest(".md-field").style.display === "none", "TIPO oculto some do modal");
assert(cfDiv.style.display !== "none", "DATA REPASSE (visível) permanece no modal");
assert(registry["mdLocalSelect"].closest(".md-field").style.display !== "none", "LOCAL (visível) permanece no modal");

console.log(`\n=== ${PASS} passaram, ${FAIL} falharam ===`);
process.exit(FAIL?1:0);
