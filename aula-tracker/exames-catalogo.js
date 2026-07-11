// ============================================================
//  exames-catalogo.js — FONTE ÚNICA do catálogo de exames
//  Lê o arquivo público diagnostico/exams-data.js (window.EXAMS)
//  e adiciona o overlay operacional de VR (valor de referência),
//  derivado do método + 6 Marcadores curados.
//
//  Consumido pelo emissor de laudos (lab-emissor-routes.js).
//  NÃO edite o catálogo aqui: edite no diagnostico/admin.html e
//  exporte o exams-data.js. Este módulo só o carrega e enriquece.
// ============================================================
import { readFileSync } from 'node:fs';

// ── Carrega window.EXAMS do arquivo público (é um array JSON puro
//    após "window.EXAMS = ") ────────────────────────────────────
let EXAMS = [];
try {
  const raw = readFileSync(new URL('../diagnostico/exams-data.js', import.meta.url), 'utf8');
  const marker = raw.indexOf('window.EXAMS');       // pula o comentário de cabeçalho
  const a = raw.indexOf('[', marker === -1 ? 0 : marker);
  const b = raw.lastIndexOf(']');
  if (a === -1 || b === -1) throw new Error('array não encontrado');
  EXAMS = JSON.parse(raw.slice(a, b + 1));
} catch (err) {
  console.error('[exames-catalogo] falha ao carregar diagnostico/exams-data.js:', err.message);
  EXAMS = [];
}

// ── norm() no mesmo padrão do restante do codebase ──────────────
export function norm(s) {
  return (s || '')
    .toString().toLowerCase().normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, ' ')
    .replace(/\s+/g, ' ').trim();
}

// ── Overlay de VR ───────────────────────────────────────────────
// Regra determinística por método (confirmada com o médico):
const VR_METODO = {
  'Sorologia':    'NÃO REAGENTE',
  'Antígeno':     'NÃO DETECTADO',
  'Microscopia':  '—',
  'Fenotípico':   '—',
  'Antibiograma': '—',
  'Marcador':     '',        // quantitativo → faixa curada abaixo
};

// Faixas curadas dos 6 Marcadores (dependem do kit — confirmadas com o médico).
// Chave = norm(nome).
const VR_CURADO = {
  [norm('Proteína C reativa (PCR)')]:      '< 5 mg/L',
  [norm('Procalcitonina')]:                '< 0,25 ng/mL',
  [norm('Dímero-D')]:                      '< 500 ng/mL',
  [norm('Hemoglobina glicada (HbA1c)')]:   '< 5,7%',
  [norm('Cistatina C')]:                   '0,53–0,95 mg/L',
  [norm('Calprotectina fecal')]:           '< 50 µg/g',
};

// VR para um exame do catálogo (por nome ou objeto {nome, metodo})
export function vrFor(exam) {
  const nome   = typeof exam === 'string' ? exam : exam?.nome;
  const metodo = typeof exam === 'string' ? undefined : exam?.metodo;
  const curado = VR_CURADO[norm(nome)];
  if (curado != null) return curado;
  if (metodo && VR_METODO[metodo] != null) return VR_METODO[metodo];
  return '—';
}

// Tipo de campo de resultado sugerido pelo método (o cliente decide o widget)
export function resultKind(metodo) {
  if (metodo === 'Sorologia')  return 'reagente';   // Reagente / Não reagente / Indeterminado
  if (metodo === 'Antígeno')   return 'detectado';  // Detectado / Não detectado / Indeterminado
  if (metodo === 'Marcador')   return 'dosagem';    // número + unidade
  return 'texto';                                    // microscopia / fenotípico / antibiograma
}

// ── Índice por nome normalizado ─────────────────────────────────
const BY_NORM = new Map(EXAMS.map(e => [norm(e.nome), e]));
export function findExam(nome) {
  return BY_NORM.get(norm(nome)) || null;
}

// ── Lista enriquecida para o endpoint /api/exames-catalogo ──────
// Devolve o mínimo que o emissor precisa (sem o bloco clínico "sm",
// que é grande e só interessa ao site público).
export function catalogoParaEmissor() {
  return EXAMS.map(e => ({
    nome:    e.nome,
    grupo:   e.grupo,
    metodo:  e.metodo,
    amostra: e.amostra,
    vr:      vrFor(e),
    kind:    resultKind(e.metodo),
    triagem: !!e.triagem,
  })).sort((a, b) => a.nome.localeCompare(b.nome, 'pt-BR', { sensitivity: 'base' }));
}

export function totalExames() { return EXAMS.length; }
export { EXAMS };
