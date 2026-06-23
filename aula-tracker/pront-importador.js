// importador.mjs — converte a planilha longitudinal antiga (linha=analito,
// coluna=data) em coletas no mesmo formato do histórico. Determinístico;
// o resultado ainda passa por revisão humana antes de salvar.
//
// Recebe a aba como matriz 2D (linhas de células). No navegador, gerar com
// SheetJS: XLSX.utils.sheet_to_json(ws,{header:1,raw:false,defval:null}).
// No servidor, idem (Node + xlsx) — o parsing de layout vive aqui.

import { CANONICOS, norm, parseValue, parseRef, flagStatus } from "./pront-normalizador.js";

// abreviações do Dr. (curtas demais p/ o índice geral; só usadas na importação)
const APELIDOS_IMPORT = {
  "cd4":"cd4","ratio":"cd4_ratio","cv":"cv_hiv",
  "hb":"hemoglobina","ht":"hematocrito","vcm":"vcm","hcm":"hcm","chcm":"chcm","rdw":"rdw",
  "leuco total":"leucocitos","leuco":"leucocitos","leucocitos":"leucocitos",
  "seg":"segmentados","bast":"bastonetes","linf":"linfocitos","mono":"monocitos",
  "eos":"eosinofilos","bas":"basofilos","plq":"plaquetas","plaq":"plaquetas",
  "retc":"reticulocitos","ferritina":"ferritina","sat transf":"saturacao_transf",
  "b12":"vitamina_b12","af":"acido_folico","efhb":"eletroforese_hb",
  "gli":"glicose","hbgli":"hba1c","hba1c":"hba1c","frutos":"frutosamina",
  "insul":"insulina","homa":"homa_ir","col":"colesterol_total","ldl":"ldl","hdl":"hdl","trig":"triglicerides",
  "cr":"creatinina","ur":"ureia","protcrea":"relacao_prot_creat","microalb":"microalbuminuria",
  "pth":"pth","ca":"calcio","pi":"fosforo","mg":"magnesio","pi urinario":"fosforo_urinario",
  "na":"sodio","k":"potassio","urac":"acido_urico","cpk":"cpk","ldh":"ldh",
  "ast":"ast","alt":"alt","falc":"fosfatase_alc","ggt":"ggt",
  "bi":"bilirrubina_total","d/i":"bilirrubina_di","(d/i)":"bilirrubina_di","albumina":"albumina",
  "tpap":"tap","ttpa":"ttpa","tsh":"tsh","t4l":"t4_livre","t4 livre":"t4_livre",
  "vitd":"vitamina_d","fta":"fta_sifilis","sarampo igg":"sarampo_igg",
};
function canonImport(label){
  const n=norm(label);
  if(APELIDOS_IMPORT[n]) return APELIDOS_IMPORT[n];
  // tenta o índice geral do normalizador como reforço
  for(const[c,d]of Object.entries(CANONICOS)) if(d.sin.some(s=>norm(s)===n)) return c;
  return null;
}

function ehData(v){
  if(v==null) return null;
  if(v instanceof Date) return iso(v);
  const s=String(v).trim();
  let m=s.match(/^(\d{4})-(\d{2})-(\d{2})/);                 if(m) return `${m[1]}-${m[2]}-${m[3]}`;
  m=s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{2,4})$/);            // dd/mm/aaaa
  if(m){const y=m[3].length===2?"20"+m[3]:m[3];return `${y}-${p2(m[2])}-${p2(m[1])}`;}
  return null;
}
const p2=x=>String(x).padStart(2,"0");
const iso=d=>`${d.getFullYear()}-${p2(d.getMonth()+1)}-${p2(d.getDate())}`;
const blank=v=>v==null||String(v).trim()===""||String(v).trim()==="-";

// separa um valor combinado: "238 / 0,09", "23 e 11", "1,31 / 51"
function dividir(cell){
  return String(cell).split(/\s*\/\s*|\s+e\s+/).map(s=>s.trim()).filter(s=>s!=="");
}

export function importarPlanilha(rows){
  const avisos=[];
  // 1) paciente / DN
  let paciente=null, dn=null;
  for(const r of rows){
    const c0=norm(r[0]);
    if(c0.startsWith("paciente") && !paciente){const v=r.slice(1).find(x=>!blank(x)); if(v)paciente=String(v).trim();}
    if(c0==="dn" && !dn){const d=ehData(r[1]); if(d)dn=d;}
  }
  // 2) linha de datas = a que tem mais células-data
  let dateRow=-1, dateCols={}, best=0;
  rows.forEach((r,ri)=>{
    const cols={}; let n=0;
    r.forEach((c,ci)=>{const d=ci>0?ehData(c):null; if(d){cols[ci]=d;n++;}});
    if(n>best){best=n;dateRow=ri;dateCols=cols;}
  });
  if(dateRow<0){avisos.push("Não encontrei a linha de datas."); return{paciente,dn,coletas:[],avisos};}

  // 3) coletas (uma por coluna de data)
  const colets={}; // colIndex -> {data, analitos:[], tarv}
  for(const[ci,data]of Object.entries(dateCols)) colets[ci]={data,analitos:[],tarv:null};

  for(let ri=dateRow+1; ri<rows.length; ri++){
    const r=rows[ri]; const rotulo=r[0]; if(blank(rotulo)) continue;
    const partes=String(rotulo).split("/").map(s=>s.trim());
    const ehTarv=norm(rotulo)==="tarv";
    for(const ci of Object.keys(dateCols)){
      const cell=r[ci]; if(blank(cell)) continue;
      if(ehTarv){ colets[ci].tarv=String(cell).trim(); continue; }
      const vals = partes.length>1 ? dividir(cell) : [String(cell).trim()];
      partes.forEach((lab,i)=>{
        if(i>=vals.length) return;                 // só o 1º analito veio nesta data
        const canon=canonImport(lab);
        const v=parseValue(vals[i]);
        colets[ci].analitos.push({
          nome_original:lab, canonico:canon,
          rotulo:canon?CANONICOS[canon].rotulo:lab, ...v, ref:null, status:null,
        });
      });
    }
  }

  // 4) coletas não-vazias, ordenadas; avisos de escala inconsistente
  const coletas=Object.values(colets)
    .filter(c=>c.analitos.length||c.tarv)
    .sort((a,b)=>a.data<b.data?-1:1);

  // aviso: mesmo analito com escalas muito diferentes entre coletas (ex.: Plaquetas 242000 vs 262)
  const porCanon={};
  coletas.forEach(c=>c.analitos.forEach(a=>{if(a.canonico&&a.tipo_valor==="numerico"){(porCanon[a.canonico]=porCanon[a.canonico]||[]).push(a.valor);}}));
  for(const[canon,vs]of Object.entries(porCanon)){
    const mx=Math.max(...vs),mn=Math.min(...vs.filter(v=>v>0));
    if(mn>0&&mx/mn>=100) avisos.push(`Escalas divergentes em ${CANONICOS[canon].rotulo} (de ${mn} a ${mx}) — revisar unidade.`);
  }
  const naoMapeados=new Set();
  coletas.forEach(c=>c.analitos.forEach(a=>{if(!a.canonico)naoMapeados.add(a.nome_original);}));

  return {paciente,dn,coletas,naoMapeados:[...naoMapeados],avisos};
}
