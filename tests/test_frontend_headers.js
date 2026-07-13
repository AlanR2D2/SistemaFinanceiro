// Garante que aplicar rótulo customizado NÃO destrói o botão de filtro (▾)
// injetado pelo buildHeaderUI em _acordos_table.html / _mandados_table.html.
// (Regressão que quebrou os filtros ao renomear colunas.)
let PASS = 0, FAIL = 0;
function assert(c, m){ if(c){PASS++;console.log("  ok -",m);} else {FAIL++;console.log("  FAIL -",m);} }

class El {
  constructor(t){ this.tag=t; this.children=[]; this._text=null; this.className=""; this.dataset={}; }
  get classList(){ const s=this; return {
    contains:(c)=>s.className.split(/\s+/).includes(c),
    add:(c)=>{ if(!s.classList.contains(c)) s.className=(s.className+" "+c).trim(); } }; }
  appendChild(c){ this.children.push(c); return c; }
  set textContent(v){ this.children=[]; this._text=String(v); }
  get textContent(){ return this._text!==null?this._text:this.children.map(c=>c.textContent).join(""); }
  matchesSel(sel){
    if(sel.startsWith("[data-act=")){ const m=sel.match(/\[data-act="?([^"\]]+)"?\]/); return this.dataset.act===m[1]; }
    if(sel.startsWith(".")) return this.classList.contains(sel.slice(1));
    return this.tag===sel;
  }
  querySelector(sel){
    if(sel.includes(">")){
      const [p,c]=sel.split(">").map(s=>s.trim());
      const findP=(el)=>{ for(const ch of el.children){
        if(ch.matchesSel&&ch.matchesSel(p)){ const h=ch.children.find(g=>g.matchesSel&&g.matchesSel(c)); if(h) return h; }
        const d=findP(ch); if(d) return d; } return null; };
      return findP(this);
    }
    const walk=(el)=>{ for(const ch of el.children){ if(ch.matchesSel&&ch.matchesSel(sel)) return ch; const d=walk(ch); if(d) return d; } return null; };
    return walk(this);
  }
}
function makeFilterableTh(text, prefix){
  const th=new El("th"), inner=new El("span"); inner.className=`${prefix}-th-inner`;
  const lbl=new El("span"); lbl.textContent=text;
  const tools=new El("span"); tools.className=`${prefix}-th-tools`;
  const dot=new El("span"); dot.className=`${prefix}-dot`;
  const open=new El("span"); open.className=`${prefix}-th-btn`; open.dataset.act="open"; open.textContent="▾";
  tools.appendChild(dot); tools.appendChild(open); inner.appendChild(lbl); inner.appendChild(tools); th.appendChild(inner);
  return th;
}
function makeNoFilterTh(text){ const th=new El("th"); th.textContent=text; return th; }
// função sob teste (cópia fiel da corrigida nos partials)
function setHeaderLabel(th, label, prefix){
  if(!th) return;
  const inner=th.querySelector(`.${prefix}-th-inner > span`);
  if(inner) inner.textContent=label; else th.textContent=label;
}
function setHeaderLabelOld(th,label){ if(th) th.textContent=label; }

for(const prefix of ["ac","md"]){
  console.log(`\n[${prefix}] coluna filtrável`);
  const th=makeFilterableTh("STATUS",prefix); setHeaderLabel(th,"SITUAÇÃO",prefix);
  assert(th.querySelector('[data-act="open"]')!==null, "botão de filtro ▾ preservado ao renomear");
  assert(th.querySelector(`.${prefix}-th-inner > span`).textContent==="SITUAÇÃO", "rótulo atualizado");
  console.log(`[${prefix}] regressão do comportamento antigo`);
  const old=makeFilterableTh("STATUS",prefix); setHeaderLabelOld(old,"SITUAÇÃO");
  assert(old.querySelector('[data-act="open"]')===null, "th.textContent= removia o botão (bug original)");
  console.log(`[${prefix}] coluna no-filter`);
  const nf=makeNoFilterTh("EXTRA 1"); setHeaderLabel(nf,"PROTOCOLO",prefix);
  assert(nf.textContent==="PROTOCOLO", "coluna no-filter renomeada");
}
console.log(`\n=== ${PASS} passaram, ${FAIL} falharam ===`);
process.exit(FAIL?1:0);
