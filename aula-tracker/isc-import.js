// isc-import.js
// ──────────────────────────────────────────────────────────────────────────
// Núcleo do importador de MAPA CIRÚRGICO — puro, sem banco/Express/HTML.
//
// PRINCÍPIO: não fixar o formato. Nenhum layout de mapa cirúrgico é estável
// (muda de hospital, de sistema, e de versão do sistema). Em vez de acoplar a
// um cabeçalho específico, o importador lê QUALQUER tabela e o operador mapeia
// coluna → campo na tela. adivinhaMapeamento() só chuta o palpite inicial.
//
// O importador NUNCA grava direto: sempre passa por prévia (dry-run) que
// classifica cada linha em nova/duplicada/erro. Mapa cirúrgico é dado sujo —
// linha de cabeçalho repetida no meio, "SUSPENSA", nome vazio, data em 3
// formatos. Gravar sem prévia é como o programa de vigilância morre.
// ──────────────────────────────────────────────────────────────────────────

import { normalizaTelefone, toISODate } from './isc-core.js';
import { triar } from './isc-triagem.js';

// Campos da ficha que podem receber coluna do mapa.
// obrigatorio: sem ele a linha é erro. chave: participa da dedup.
export const CAMPOS_IMPORTAVEIS = [
  { key: 'paciente_nome',  label: 'Nome do paciente',      obrigatorio: true },
  { key: 'cirurgia_id',    label: 'Nº da cirurgia (Tasy)' },
  { key: 'data_cirurgia',  label: 'Data da cirurgia',      obrigatorio: true, chave: true, tipo: 'data' },
  // ATENDIMENTO APOSENTADO. O relatório do Tasy trocou a coluna Atend por Pront.,
  // e o sistema passou a identificar a cirurgia por nº de cirurgia + prontuário.
  // Deixar o campo mapeável foi o que permitiu o erro que motivou a mudança: a
  // coluna "Unid atend" (unidade + leito, ex.: "10 01") foi mapeada como
  // atendimento, e a chave de deduplicação virou `at:10 01|data`. Removendo o
  // campo, essa classe de erro deixa de existir. A COLUNA continua no banco e
  // continua valendo como chave para as fichas antigas (ver chavesDedup).
  { key: 'prontuario',     label: 'Prontuário' },
  { key: 'paciente_dn',    label: 'Data de nascimento',    tipo: 'data' },
  { key: 'telefone',       label: 'Telefone / WhatsApp',   tipo: 'telefone' },
  { key: 'procedimento',   label: 'Procedimento' },
  { key: 'cirurgiao',      label: 'Cirurgião' },
  { key: 'equipe',         label: 'Equipe / especialidade', tipo: 'equipe' },
  { key: 'data_alta',      label: 'Data da alta',          tipo: 'data' },
  { key: 'implante',       label: 'Implante / prótese',    tipo: 'bool' },
  { key: 'potencial_contaminacao', label: 'Potencial de contaminação', tipo: 'potencial' },
  { key: 'duracao_min',    label: 'Duração (min)',         tipo: 'int' },
  { key: 'asa',            label: 'ASA',                   tipo: 'asa' },
  { key: 'antibioticoprofilaxia', label: 'Antibioticoprofilaxia' },
  { key: 'paciente_iniciais', label: 'Iniciais' },
  { key: 'contato_alternativo', label: 'Contato alternativo' },
  { key: 'observacao',     label: 'Observação' },
  // Coluna "endereço + Fone: + Celular:" do Tasy_Rel, num blob só.
  { key: 'contato_blob',   label: 'Endereço + Fone (bloco do Tasy)', tipo: 'contato' },
  // Auxiliares: alimentam a triagem, não viram coluna da ficha.
  { key: 'tipo_anestesia', label: 'Tipo de anestesia (só p/ triagem)', tipo: 'auxiliar' },
];

// ── Parsing tabular ───────────────────────────────────────────────────────
// Detecta o separador olhando qual gera mais colunas de forma CONSISTENTE
// entre as primeiras linhas (não só na primeira — cabeçalho pode ter vírgula
// no texto e enganar a contagem).
export function detectaDelimitador(texto) {
  const linhas = String(texto ?? '').split(/\r?\n/).filter(l => l.trim()).slice(0, 10);
  if (!linhas.length) return '\t';
  let melhor = '\t', melhorScore = -1;
  for (const d of ['\t', ';', ',', '|']) {
    const contagens = linhas.map(l => partirLinha(l, d).length);
    const max = Math.max(...contagens);
    if (max < 2) continue;
    // consistência: quantas linhas têm exatamente o nº modal de colunas
    const modal = contagens.sort((a, b) => contagens.filter(x => x === b).length - contagens.filter(x => x === a).length)[0];
    const consist = contagens.filter(c => c === modal).length / contagens.length;
    const score = modal * consist;
    if (score > melhorScore) { melhorScore = score; melhor = d; }
  }
  return melhor;
}

// Split respeitando aspas duplas (CSV real: "SILVA, MARIA" é uma célula só).
export function partirLinha(linha, delim) {
  const out = [];
  let atual = '', dentro = false;
  const s = String(linha ?? '');
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '"') {
      if (dentro && s[i + 1] === '"') { atual += '"'; i++; }   // "" escapado
      else dentro = !dentro;
    } else if (ch === delim && !dentro) { out.push(atual); atual = ''; }
    else atual += ch;
  }
  out.push(atual);
  return out.map(x => x.trim());
}

// texto → { header:[], linhas:[[]] }. Ignora linhas totalmente vazias.
export function parseTabular(texto, delim) {
  const d = delim || detectaDelimitador(texto);
  const brutas = String(texto ?? '').split(/\r?\n/).filter(l => l.trim() !== '');
  if (!brutas.length) return { header: [], linhas: [], delim: d };
  const header = partirLinha(brutas[0], d);
  const linhas = brutas.slice(1)
    .map(l => partirLinha(l, d))
    .filter(cs => cs.some(c => c !== ''));
  return { header, linhas, delim: d };
}

// ── Normalização de valores ───────────────────────────────────────────────
const norm = s => String(s ?? '')
  .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
  .toLowerCase().replace(/[^a-z0-9]/g, '');

// Datas de mapa cirúrgico vêm em tudo quanto é formato, inclusive serial do
// Excel (nº de dias desde 1899-12-30) quando a célula é copiada como número.
export function parseDataFlexivel(v) {
  if (v == null || v === '') return null;
  const s = String(v).trim();

  // Serial do Excel: número puro entre 20000 (1954) e 60000 (2064).
  if (/^\d{5}(\.\d+)?$/.test(s)) {
    const n = parseFloat(s);
    if (n > 20000 && n < 60000) {
      const ms = Math.round((n - 25569) * 86400000);   // 25569 = 1970-01-01
      return new Date(ms).toISOString().slice(0, 10);
    }
  }
  // ISO / yyyy-mm-dd (aceita hora junto)
  let m = s.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (m) return `${m[1]}-${m[2]}-${m[3]}`;
  // dd/mm/yyyy · dd-mm-yyyy · dd.mm.yyyy (+ hora opcional)
  m = s.match(/^(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{2,4})/);
  if (m) {
    let [, d, mo, y] = m;
    if (y.length === 2) y = (Number(y) > 50 ? '19' : '20') + y;
    const dd = d.padStart(2, '0'), mm = mo.padStart(2, '0');
    if (Number(mm) > 12 || Number(dd) > 31 || Number(mm) < 1 || Number(dd) < 1) return null;
    const iso = `${y}-${mm}-${dd}`;
    // valida de verdade (31/02 não existe)
    const dt = new Date(iso + 'T12:00:00Z');
    if (Number.isNaN(dt.getTime()) || dt.toISOString().slice(0, 10) !== iso) return null;
    return iso;
  }
  return null;
}

const SIM = new Set(['sim', 's', 'yes', 'y', '1', 'true', 'x', 'verdadeiro']);
const NAO = new Set(['nao', 'n', 'no', '0', 'false', '', 'falso']);
export function parseBoolFlexivel(v) {
  const s = norm(v);
  if (SIM.has(s)) return true;
  if (NAO.has(s)) return false;
  return null;
}

export function parsePotencial(v) {
  const s = norm(v);
  if (!s) return null;
  if (s.includes('potencialmente') || s.includes('potencial')) return 'potencialmente_contaminada';
  if (s.includes('infectad')) return 'infectada';
  if (s.includes('contaminad')) return 'contaminada';
  if (s.includes('limpa')) return 'limpa';
  return null;
}

export function parseAsa(v) {
  const s = String(v ?? '').toUpperCase().replace(/[^IVX0-9]/g, '');
  if (!s) return null;
  const mapa = { '1': 'I', '2': 'II', '3': 'III', '4': 'IV', '5': 'V' };
  if (mapa[s]) return mapa[s];
  return ['I', 'II', 'III', 'IV', 'V'].includes(s) ? s : null;
}

export function parseIntFlexivel(v) {
  const s = String(v ?? '').replace(/[^\d]/g, '');
  if (!s) return null;
  const n = parseInt(s, 10);
  return Number.isInteger(n) ? n : null;
}

// ── Contato (bloco do Tasy) ───────────────────────────────────────────────
// Formato observado:
//   "Rua X,123 Bairro Cidade UF 12345678 Fone: 950948572 Celular: 968650910"
//
// PROBLEMA: no HUSF, NENHUM dos 67 telefones vinha com DDD. Um WhatsApp para o
// número errado revela a um estranho que alguém foi operado — então o DDD NUNCA
// é presumido em silêncio. Ele só é aplicado quando a CIDADE do endereço está
// na tabela abaixo, e a ficha fica marcada como telefone presumido, para a
// agenda pedir confirmação antes do primeiro envio. Cidade fora da tabela →
// ficha entra SEM telefone e com aviso. Melhor sem telefone que com o errado.
//
// ⚠️ TABELA A CONFIRMAR pelo SCIH: são as cidades da região do HUSF. Errar aqui
// manda mensagem para outra pessoa.
export const DDD_CIDADES = {
  // DDD 11
  'saopaulo': '11', 'bragancapaulista': '11', 'atibaia': '11', 'itatiba': '11',
  'jarinu': '11', 'piracaia': '11', 'nazarepaulista': '11', 'joanopolis': '11',
  'bomjesusdosperdoes': '11', 'vargem': '11', 'pinhalzinho': '11', 'pedrabela': '11',
  'tuiuti': '11',
  // DDD 19
  'campinas': '19', 'morungaba': '19', 'socorro': '19', 'amparo': '19',
  // DDD 35 (MG)
  'extrema': '35', 'camanducaia': '35', 'itapeva': '35',
};

const chaveCidade = s => String(s ?? '')
  .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
  .toLowerCase().replace(/[^a-z]/g, '');

// Extrai as partes do bloco. Não decide nada — só separa.
export function parseContato(blob) {
  const s = String(blob ?? '').replace(/\s+/g, ' ').trim();
  if (!s) return {};
  const dig = v => String(v ?? '').replace(/\D/g, '');
  const fone = dig((s.match(/Fone:\s*([\d\s-]*)/i) || [])[1]);
  const celular = dig((s.match(/Celular:\s*([\d\s-]*)/i) || [])[1]);
  // "... Bairro Cidade UF 12345678 Fone:" → cidade é o que antecede UF+CEP
  const m = s.match(/([A-Za-zÀ-ÿ'.\- ]+?)\s+([A-Z]{2})\s+(\d{8})\s*(?:Fone:|Celular:|$)/);
  let cidade = null, uf = null, cep = null;
  if (m) {
    uf = m[2]; cep = m[3];
    // O trecho antes do UF é "bairro cidade": a cidade é o sufixo que casa
    // com a tabela. Testa do fim para o começo.
    const toks = m[1].trim().split(/\s+/);
    for (let i = 0; i < toks.length; i++) {
      const cand = toks.slice(i).join(' ');
      if (DDD_CIDADES[chaveCidade(cand)]) { cidade = cand; break; }
    }
    if (!cidade) cidade = toks.slice(-2).join(' ');   // palpite p/ exibir no aviso
  }
  const endereco = s.replace(/\s*(Fone|Celular):.*$/i, '').trim();
  return { fone, celular, cidade, uf, cep, endereco };
}

// Escolhe o número e resolve o DDD. Devolve { e164, presumido, aviso }.
// Celular tem prioridade: o fluxo é WhatsApp.
export function resolveTelefone({ fone, celular, cidade }, ddds = DDD_CIDADES) {
  const cands = [celular, fone].filter(n => n && n.length >= 8);   // celular primeiro
  if (!cands.length) return { e164: null, aviso: 'Sem telefone aproveitável no mapa' };

  const movelComDDD = n => n.length === 11 && n[2] === '9';
  const movelSemDDD = n => n.length === 9 && n[0] === '9';
  const fixoComDDD  = n => n.length === 10;
  const ddd = cidade ? ddds[chaveCidade(cidade)] : null;

  // Prioridade pelo FLUXO, não pela completude: o canal é WhatsApp, então um
  // celular sem DDD (que a cidade resolve) vale mais que um fixo com DDD — em
  // fixo, WhatsApp não chega. Ordem: móvel c/ DDD > móvel s/ DDD + cidade >
  // fixo c/ DDD (a colaboradora liga) > nada.
  const m1 = cands.find(movelComDDD);
  if (m1) return { e164: '55' + m1, presumido: false };

  const m2 = cands.find(movelSemDDD);
  if (m2 && ddd) return { e164: '55' + ddd + m2, presumido: true, aviso: `DDD ${ddd} presumido pela cidade (${cidade}) — confirmar antes do 1º envio` };

  const f1 = cands.find(fixoComDDD);
  if (f1) return { e164: '55' + f1, presumido: false, aviso: 'Só telefone fixo — WhatsApp não chega, contato por ligação' };

  if (m2 && !ddd) {
    return { e164: null, aviso: `Celular sem DDD e cidade ${cidade ? `"${cidade}" fora da tabela` : 'não identificada'} — ficha entra sem WhatsApp` };
  }
  // 8 dígitos: fixo antigo ou celular sem o 9 — não dá para reconstruir com
  // segurança. Número errado = revelar a cirurgia a um estranho. Não inventa.
  return { e164: null, aviso: `Número com ${cands[0].length} dígitos e sem DDD — ambíguo, ficha entra sem WhatsApp` };
}

// ── Palpite de mapeamento ─────────────────────────────────────────────────
// Sinônimos vistos em mapa cirúrgico brasileiro. É só o CHUTE INICIAL — o
// operador confirma na tela. Errar aqui não quebra nada.
const SINONIMOS = {
  paciente_nome:  ['paciente', 'nome', 'nomepaciente', 'nomedopaciente', 'pacientenome'],
  data_cirurgia:  ['datacirurgia', 'datadacirurgia', 'data', 'datacir', 'dtcirurgia', 'dataprocedimento', 'datadoprocedimento', 'dtcir', 'datahora', 'datahorario'],
  cirurgia_id:    ['cirurgia', 'nrcirurgia', 'ncirurgia', 'numerocirurgia', 'codcirurgia', 'codigocirurgia', 'idcirurgia'],
  prontuario:     ['prontuario', 'pront', 'nrprontuario', 'numeroprontuario', 'registro', 'matricula'],
  paciente_dn:    ['datanascimento', 'dtnascimento', 'nascimento', 'dn', 'datadenascimento'],
  telefone:       ['telefone', 'fone', 'celular', 'whatsapp', 'zap', 'contato', 'tel'],
  procedimento:   ['procedimento', 'proc', 'descricao', 'procedimentorealizado', 'descricaoprocedimento', 'procedimentoprincipal'],
  cirurgiao:      ['cirurgiao', 'medico', 'responsavel', 'medicoresponsavel', 'profissional', 'executante'],
  equipe:         ['equipe', 'especialidade', 'clinica', 'setor', 'servico'],
  data_alta:      ['dataalta', 'dtalta', 'alta', 'datadealta'],
  implante:       ['implante', 'protese', 'opme', 'material'],
  potencial_contaminacao: ['potencial', 'potencialcontaminacao', 'classificacao', 'contaminacao', 'potencialdecontaminacao'],
  duracao_min:    ['duracao', 'tempo', 'duracaomin', 'tempocirurgico', 'minutos', 'min'],
  asa:            ['asa', 'classificacaoasa', 'riscoasa'],
  antibioticoprofilaxia: ['antibiotico', 'profilaxia', 'atb', 'antibioticoprofilaxia', 'atbprofilaxia'],
  paciente_iniciais: ['iniciais'],
  contato_alternativo: ['contatoalternativo', 'telefone2', 'recado', 'contatorecado'],
  observacao:     ['observacao', 'obs', 'observacoes'],
  contato_blob:   ['endereco', 'contato', 'fone', 'endereçofone'],
  tipo_anestesia: ['tipo', 'anestesia', 'tipoanestesia'],
};

// Devolve { indiceDaColuna: 'campo' }. Cada campo é usado no máximo 1x:
// vence o match exato; parcial só entra se o campo ainda estiver livre.
//
// PARCIAL É ESTRITO DE PROPÓSITO, e ficou mais estrito depois de um erro caro:
// a coluna "Unid atend" (unidade + leito, ex.: "10 01") foi mapeada como
// ATENDIMENTO, porque "unidatend".includes("atend") é verdadeiro. Com isso a
// chave de deduplicação virou `at:10 01|data` — dois pacientes em leitos iguais
// em dias diferentes colidiriam, e o atendimento real nunca era gravado.
//
// Agora o casamento parcial exige PREFIXO dos dois lados: o nome da coluna
// começa com o sinônimo, ou o sinônimo começa com o nome da coluna.
//   "atendimento".startsWith("atend")  → casa   ✓
//   "unidatend".startsWith("atend")    → NÃO casa ✓ (é o que queremos)
// Substring no meio da palavra é a mesma doença de `raque` em TRAQUEOSTOMIA.
export function adivinhaMapeamento(header, linhas = null) {
  const mapa = {};
  const usados = new Set();
  const cols = (header || []).map(norm);

  for (const [campo, syns] of Object.entries(SINONIMOS)) {
    const i = cols.findIndex((c, idx) => c && syns.includes(c) && !(idx in mapa));
    if (i >= 0) { mapa[i] = campo; usados.add(campo); }
  }
  for (const [campo, syns] of Object.entries(SINONIMOS)) {
    if (usados.has(campo)) continue;
    const i = cols.findIndex((c, idx) => c && c.length >= 4 && !(idx in mapa) &&
      syns.some(s => s.length >= 4 && (c.startsWith(s) || s.startsWith(c))));
    if (i >= 0) { mapa[i] = campo; usados.add(campo); }
  }
  if (linhas && linhas.length) refinaPorValor(mapa, usados, linhas);
  return mapa;
}

// Em relatório de impressão o rótulo mente (fica na coluna errada), mas o VALOR
// não. Quando o campo obrigatório não foi encontrado pelo nome, procura pela
// cara do dado. É isto que salva a data: o rótulo mais próximo da coluna da data
// no Tasy_Rel é "CID".
export function refinaPorValor(mapa, usados, linhas) {
  const amostra = linhas.slice(0, 40);
  const fracao = (col, teste) => {
    const vals = amostra.map(l => String(l[col] ?? '').trim()).filter(Boolean);
    if (vals.length < 3) return 0;
    return vals.filter(teste).length / vals.length;
  };
  const largura = Math.max(...amostra.map(l => l.length));
  const livre = c => !(c in mapa);

  // data_cirurgia: ≥80% das células parseáveis como data.
  if (!usados.has('data_cirurgia')) {
    for (let c = 0; c < largura; c++) {
      if (!livre(c)) continue;
      if (fracao(c, v => !!parseDataFlexivel(v)) >= 0.8) { mapa[c] = 'data_cirurgia'; usados.add('data_cirurgia'); break; }
    }
  }
  // contato_blob: o bloco do Tasy é inconfundível ("Fone:" / "Celular:").
  if (!usados.has('contato_blob')) {
    for (let c = 0; c < largura; c++) {
      if (!livre(c)) continue;
      if (fracao(c, v => /Fone:|Celular:/i.test(v)) >= 0.8) { mapa[c] = 'contato_blob'; usados.add('contato_blob'); break; }
    }
  }
  // paciente_nome: texto com ≥2 palavras, sem dígito.
  if (!usados.has('paciente_nome')) {
    for (let c = 0; c < largura; c++) {
      if (!livre(c)) continue;
      if (fracao(c, v => !/\d/.test(v) && v.split(/\s+/).length >= 2 && v.length >= 8) >= 0.8) {
        mapa[c] = 'paciente_nome'; usados.add('paciente_nome'); break;
      }
    }
  }
  return mapa;
}

// ── Normalização de linha ─────────────────────────────────────────────────
// mapa: { indiceColuna: 'campo' }. equipes: [{id,nome,sigla,implante_default}]
// Devolve { ficha, erros:[], avisos:[] }.
export function normalizaLinha(colunas, mapa, equipes = []) {
  const ficha = {};
  const erros = [], avisos = [];
  const bruto = {};

  for (const [idx, campo] of Object.entries(mapa)) {
    if (!campo) continue;
    const v = colunas[Number(idx)];
    if (v == null || String(v).trim() === '') continue;
    bruto[campo] = String(v).trim();
  }

  const def = CAMPOS_IMPORTAVEIS.reduce((a, c) => (a[c.key] = c, a), {});

  for (const [campo, v] of Object.entries(bruto)) {
    const d = def[campo];
    if (!d) continue;
    switch (d.tipo) {
      case 'data': {
        const iso = parseDataFlexivel(v);
        if (!iso) { erros.push(`${d.label}: data não reconhecida ("${v}")`); }
        else ficha[campo] = iso;
        break;
      }
      case 'telefone': {
        const tel = normalizaTelefone(v);
        if (!tel) avisos.push(`Telefone não reconhecido ("${v}") — ficha entra sem WhatsApp`);
        else { ficha.telefone = tel; ficha.telefone_raw = v; }
        break;
      }
      case 'bool': {
        const b = parseBoolFlexivel(v);
        if (b === null) avisos.push(`${d.label}: valor não reconhecido ("${v}") — assumido Não`);
        ficha[campo] = b === true;
        break;
      }
      case 'int': {
        const n = parseIntFlexivel(v);
        if (n === null) avisos.push(`${d.label}: número não reconhecido ("${v}")`);
        else ficha[campo] = n;
        break;
      }
      case 'asa': {
        const a = parseAsa(v);
        if (!a) avisos.push(`ASA não reconhecido ("${v}")`);
        else ficha.asa = a;
        break;
      }
      case 'potencial': {
        const pc = parsePotencial(v);
        if (!pc) avisos.push(`Potencial de contaminação não reconhecido ("${v}")`);
        else ficha.potencial_contaminacao = pc;
        break;
      }
      case 'equipe': {
        const alvo = norm(v);
        const eq = equipes.find(e => norm(e.nome) === alvo || norm(e.sigla) === alvo)
                || equipes.find(e => alvo && (norm(e.nome).includes(alvo) || alvo.includes(norm(e.nome))));
        if (eq) {
          ficha.equipe_id = eq.id;
          // Equipe de implante por padrão só marca se o mapa não disse nada.
          if (eq.implante_default && bruto.implante == null) ficha.implante = true;
        } else {
          avisos.push(`Equipe "${v}" não cadastrada — ficha entra sem equipe`);
          ficha.especialidade = v;   // preserva o texto: não perder o dado
        }
        break;
      }
      case 'contato': {
        const partes = parseContato(v);
        const r = resolveTelefone(partes);
        if (r.e164) { ficha.telefone = r.e164; ficha.telefone_raw = partes.celular || partes.fone; }
        if (r.presumido) ficha.telefone_presumido = true;
        if (r.aviso) avisos.push(r.aviso);
        // Nunca perder o dado: o número cru e o endereço ficam no contato
        // alternativo, para a colaboradora completar à mão se preciso.
        const alt = [partes.celular && `Cel: ${partes.celular}`, partes.fone && `Fone: ${partes.fone}`,
                     partes.cidade && `(${partes.cidade}${partes.uf ? '/' + partes.uf : ''})`]
                    .filter(Boolean).join(' · ');
        if (alt) ficha.contato_alternativo = alt.slice(0, 500);
        if (partes.endereco) ficha.observacao = [ficha.observacao, partes.endereco].filter(Boolean).join(' | ').slice(0, 2000);
        break;
      }
      case 'auxiliar':
        break;   // já está em `bruto`, que é o que a triagem lê
      default:
        ficha[campo] = String(v).slice(0, 500);
    }
  }

  for (const c of CAMPOS_IMPORTAVEIS) {
    if (c.obrigatorio && !ficha[c.key]) erros.push(`${c.label} é obrigatório`);
  }
  if (!ficha.cirurgia_id && !ficha.prontuario) {
    avisos.push('Sem nº de cirurgia e sem prontuário — a ficha só será reconhecida por nome + data');
  }
  return { ficha, erros, avisos, bruto };
}

// ── Complementação ────────────────────────────────────────────────────────
// Caso real: importa-se o mapa sem contato e, depois, o MESMO recorte com a
// coluna de endereço+fone. Sem isto, a 2ª importação dá "67 duplicadas, nada a
// fazer" e 61 telefones se perdem calados.
//
// REGRA: PREENCHER LACUNA, NUNCA SOBRESCREVER. Só entra em campo que está vazio
// na ficha. Se a colaboradora corrigiu um telefone na mão, reimportar o mapa não
// pode atropelar — o dado dela vale mais que o do Tasy. É a mesma disciplina do
// motor de monitoramento do ATB, que protege entrada manual.
//
// Fora desta lista de propósito:
//   • classificação/tipo/patógeno → ato médico, importação nunca toca;
//   • data_cirurgia → é chave de janela; mudar reescreveria toda a vigilância;
//   • implante/janelas → vêm da regra de triagem, que é determinística;
//   • booleano em geral → não dá para distinguir "false" de "não preenchido".
export const CAMPOS_COMPLEMENTAVEIS = [
  'cirurgia_id', 'atendimento', 'prontuario', 'paciente_nome', 'paciente_iniciais',
  'paciente_dn', 'telefone', 'contato_alternativo',
  'equipe_id', 'especialidade', 'procedimento', 'cirurgiao', 'data_alta',
  'potencial_contaminacao', 'duracao_min', 'asa', 'antibioticoprofilaxia', 'observacao',
];

// Campos que só entram JUNTO com outro — sozinhos, mentem. Ex.: telefone_raw é
// "o que estava escrito no telefone"; se o telefone é o que a colaboradora
// corrigiu, o raw do Tasy ao lado só confunde quem for conferir.
const ACOPLADOS = { telefone: ['telefone_raw', 'telefone_presumido'] };

const vazio = v => v == null || String(v).trim() === '';

// Devolve só o que a ficha existente NÃO tem e a importação traz.
export function camposComplementaveis(atual, novo) {
  const out = {};
  if (!atual || !novo) return out;
  for (const k of CAMPOS_COMPLEMENTAVEIS) {
    if (vazio(atual[k]) && !vazio(novo[k])) out[k] = novo[k];
  }
  // Acoplados entram só na carona do campo principal.
  for (const [principal, juntos] of Object.entries(ACOPLADOS)) {
    if (!(principal in out)) continue;
    for (const k of juntos) {
      // telefone_presumido é booleano: acompanha sempre (inclusive como false).
      if (k === 'telefone_presumido') out[k] = novo.telefone_presumido === true;
      else if (!vazio(novo[k])) out[k] = novo[k];
    }
  }
  return out;
}

// ── Prévia (dry-run) ──────────────────────────────────────────────────────
// existentes: Set de chaves "atendimento|data_cirurgia" já no banco.
// Classifica cada linha e detecta duplicata DENTRO do próprio arquivo também
// (mapa cirúrgico repete linha quando a cirurgia é remarcada).
// ── Deduplicação ──────────────────────────────────────────────────────────
// O relatório do Tasy tem largura fixa: cada coluna nova entra no lugar de
// outra. Já circularam três combinações — (nº cirurgia + atendimento),
// (prontuário + atendimento) e (nº cirurgia + prontuário) — e uma ficha antiga
// pode ter sido criada por qualquer uma delas.
//
// Por isso a dedup trabalha com uma LISTA ordenada de chaves, não uma só: a
// linha nova tenta todas as suas chaves contra todas as chaves registradas da
// ficha existente. Sem isso, trocar o layout do relatório recriaria do zero as
// fichas já em vigilância — com o paciente recebendo tudo de novo.
//
// Ordem = confiabilidade: o nº da cirurgia identifica O ATO (não muda nem se a
// cirurgia for remarcada); atendimento+data identifica a internação; e
// prontuário+data, o paciente naquele dia — o mais frouxo, porque dois
// procedimentos no mesmo paciente e no mesmo dia colidiriam.
const chaveNome = s => String(s ?? '')
  .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
  .toUpperCase().replace(/[^A-Z0-9 ]/g, '').replace(/\s+/g, ' ').trim();

export function chavesDedup(ficha) {
  const chaves = [];
  const cir = String(ficha?.cirurgia_id ?? '').trim();
  const at = String(ficha?.atendimento ?? '').trim();
  const pr = String(ficha?.prontuario ?? '').trim();
  const nm = chaveNome(ficha?.paciente_nome);
  const dt = toISODate(ficha?.data_cirurgia);
  if (cir) chaves.push(`cir:${cir}`);
  // `at:` só aparece em ficha ANTIGA (o campo saiu da importação). Fica aqui
  // porque é a chave que essas fichas têm — e é o que permite reconhecê-las.
  if (at && dt) chaves.push(`at:${at}|${dt}`);
  if (pr && dt) chaves.push(`pront:${pr}|${dt}`);
  // Último recurso: paciente + dia. Existe para atravessar mudança de layout —
  // quando a ficha antiga só tem atendimento e a linha nova só tem nº de
  // cirurgia + prontuário, o nome e a data são a única ponte. Na primeira
  // importação depois da virada isto reconcilia e preenche os IDs que faltavam;
  // a partir daí a chave forte (nº da cirurgia) assume sozinha.
  if (nm && dt) chaves.push(`nome:${nm}|${dt}`);
  return chaves;
}

// Encontra a ficha existente correspondente, testando as chaves em ordem de
// confiabilidade — com uma TRAVA indispensável:
//
// no mapa de julho há 3 casos reais de mesmo paciente operado DUAS VEZES no
// mesmo dia (cirurgias 286355 e 286333, por exemplo). Para esses, prontuário+dia
// e nome+dia apontam para a mesma ficha, mas são cirurgias diferentes. Quando os
// dois lados têm nº de cirurgia e eles DIVERGEM, a chave fraca é descartada:
// coincidir paciente e dia não faz duas cirurgias virarem uma.
export function acharExistente(ficha, existentes) {
  if (!existentes || typeof existentes.get !== 'function') {
    const k = chavesDedup(ficha).find(x => existentes?.has?.(x));
    return k ? { chave: k, atual: null } : null;
  }
  const cirNovo = String(ficha?.cirurgia_id ?? '').trim();
  for (const k of chavesDedup(ficha)) {
    const atual = existentes.get(k);
    if (!atual) continue;
    const cirAtual = String(atual?.cirurgia_id ?? '').trim();
    if (cirNovo && cirAtual && cirNovo !== cirAtual) continue;   // cirurgias distintas
    return { chave: k, atual };
  }
  return null;
}

// Chave principal (a mais confiável disponível). Mantida para quem só precisa
// de uma identidade estável da linha.
export function chaveDedup(ficha) {
  return chavesDedup(ficha)[0] || null;
}

// regras: quando fornecidas, filtram o que entra na vigilância. Sem regras
// (colar um CSV próprio, por ex.), tudo é candidato — o comportamento antigo.
//
// existentes: Set de chaves (só detecta duplicata) OU Map chave→ficha (detecta
// duplicata E o que dá para complementar). Aceitar os dois mantém compatível
// quem só quer saber se já existe.
export function montarPrevia(linhas, mapa, equipes, existentes = new Set(), regras = null) {
  const vistas = new Map();   // chave → ficha, para a trava de nº de cirurgia
  const usarTriagem = Array.isArray(regras) && regras.length > 0;

  const itens = linhas.map((colunas, i) => {
    const { ficha, erros, avisos, bruto } = normalizaLinha(colunas, mapa, equipes);

    // Triagem primeiro: não faz sentido apontar erro de campo numa cirurgia
    // que nem entra no recorte (uma Bera sem telefone não é problema de nada).
    let triagem = null;
    if (usarTriagem) {
      triagem = triar({
        procedimento: ficha.procedimento || bruto.procedimento || '',
        cirurgiao: ficha.cirurgiao || bruto.cirurgiao || '',
        tipo_anestesia: bruto.tipo_anestesia || '',
      }, regras);
      if (!triagem || !triagem.vigiar) {
        // `chaves` também aqui: sem isso a linha fora do recorte entrava no
        // diagnóstico como "sem chave de deduplicação" e disparava um alarme
        // vermelho falso — 425 linhas fora do recorte viravam 425 "sem chave".
        return {
          linha: i + 2, status: 'fora_recorte', ficha, erros: [], avisos: [],
          bruto, chaves: chavesDedup(ficha),
          motivo: triagem ? triagem.motivo : 'Nenhuma regra de vigilância casou',
        };
      }
      // A regra manda na equipe/implante — o mapa do Tasy não traz nem um nem outro.
      if (triagem.equipe_id) ficha.equipe_id = triagem.equipe_id;
      if (triagem.implante != null && ficha.implante == null) ficha.implante = triagem.implante;
      if (triagem.codigo_cve) ficha.codigo_cve = triagem.codigo_cve;
    }

    const chaves = chavesDedup(ficha);
    const chave = chaves[0] || null;
    const achado = erros.length ? null : acharExistente(ficha, existentes);
    let status = 'nova';
    let complemento = null;
    let casouPor = null;
    if (erros.length) status = 'erro';
    else if (achado) {
      casouPor = achado.chave;
      const atual = achado.atual;
      const faltando = atual ? camposComplementaveis(atual, ficha) : {};
      if (Object.keys(faltando).length) {
        status = 'complementa';
        complemento = { id: atual.id, campos: faltando, chave: achado.chave };
      } else {
        status = 'duplicada';
      }
    } else if (acharExistente(ficha, vistas)) {
      status = 'duplicada'; avisos.push('Linha repetida dentro do próprio arquivo');
    }
    if (status === 'nova') for (const k of chaves) if (!vistas.has(k)) vistas.set(k, ficha);
    return { linha: i + 2, status, ficha, erros, avisos, bruto, complemento, chaves, casouPor,
             motivo: triagem?.motivo || null };
  });

  // Diagnóstico da deduplicação. Existe porque "110 fichas novas" numa
  // reimportação é ambíguo: pode ser período novo (correto) ou chave que não
  // casou (bug). Sem mostrar as chaves dos dois lados, não há como saber qual.
  const tipos = k => k.split(':')[0];
  const contarTipos = (lista) => lista.reduce((acc, k) => { acc[tipos(k)] = (acc[tipos(k)] || 0) + 1; return acc; }, {});
  const chavesArquivo = itens.flatMap(i => i.chaves || []);
  const chavesBanco = typeof existentes.keys === 'function' ? [...existentes.keys()] : [];
  const dedup = {
    fichasNoSistema: typeof existentes.get === 'function'
      ? new Set([...existentes.values()].map(v => v?.id).filter(Boolean)).size
      : existentes.size,
    chavesIndexadas: chavesBanco.length,
    porTipoNoSistema: contarTipos(chavesBanco),
    porTipoNoArquivo: contarTipos(chavesArquivo),
    // Só conta quem VAI virar ficha: linha fora do recorte não é gravada, então
    // não ter chave nela é irrelevante — contá-la só gera alarme falso.
    semChave: itens.filter(i => i.status === 'nova' && !(i.chaves || []).length).length,
    casaram: itens.filter(i => i.status === 'complementa' || i.status === 'duplicada').length,
  };

  return {
    itens,
    dedup,
    resumo: {
      total: itens.length,
      novas: itens.filter(x => x.status === 'nova').length,
      complementa: itens.filter(x => x.status === 'complementa').length,
      duplicadas: itens.filter(x => x.status === 'duplicada').length,
      erros: itens.filter(x => x.status === 'erro').length,
      fora_recorte: itens.filter(x => x.status === 'fora_recorte').length,
      avisos: itens.filter(x => x.status !== 'erro' && x.avisos.length).length,
    },
  };
}
