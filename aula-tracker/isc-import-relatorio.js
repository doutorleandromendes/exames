// isc-import-relatorio.js
// ──────────────────────────────────────────────────────────────────────────
// Normaliza RELATÓRIO EM LAYOUT DE IMPRESSÃO → tabela de dados.
//
// POR QUE ISTO EXISTE
// O Tasy_Rel não exporta dados: exporta uma PÁGINA IMPRESSA despejada em
// células. O "Relação das Cirurgias" do HUSF quebra três premissas que todo
// importador de planilha assume:
//
//   1. Cabeçalho na 1ª linha        → está na linha 2 (0 e 1 são título/período)
//   2. 1 linha = 1 registro         → 185 linhas = 66 registros; o texto longo
//                                     quebra em 2-4 linhas de continuação
//   3. Coluna do rótulo = coluna do → "Atend" está na col 4, o número na col 3;
//      dado                           "Data Inicio" na col 10, a data na col 7.
//                                     O deslocamento é arbitrário (é layout de
//                                     impressão: o rótulo é posicionado por
//                                     pixel, não por coluna de dados).
//
// Rodar o importador comum nesse arquivo dá 182 linhas / 182 erros / 0 fichas.
//
// ESTRATÉGIA
// Reconstruir os registros usando a COLUNA ÂNCORA: no layout de impressão, a
// linha que inicia um registro tem a 1ª coluna preenchida (o ID), e as linhas
// de continuação não têm. Isso dá os limites de cada registro sem depender dos
// rótulos. As continuações são concatenadas por coluna — e é aqui que o XLS
// ganha do RTF: a grade de células mantém "Pugas" na mesma coluna de "Leonardo
// Soares de", enquanto o RTF (tab-stops relativos) perde o alinhamento.
//
// Os rótulos viram só DICA de mapeamento: quem manda é o índice REAL da coluna,
// que é estável entre exportações do mesmo relatório — então o perfil salvo
// continua valendo mês que vem.
// ──────────────────────────────────────────────────────────────────────────

const txt = v => String(v ?? '').trim();
const vazio = v => txt(v) === '';

// ── Detecção da coluna âncora ─────────────────────────────────────────────
// A âncora é a coluna mais à esquerda que aparece de forma recorrente e que,
// quando usada como limite, produz registros plausíveis. minOcorr evita eleger
// uma coluna que só tem 1 valor solto (um título perdido, por exemplo).
export function detectaAncora(aoa, minOcorr = 3) {
  if (!Array.isArray(aoa) || !aoa.length) return null;
  const largura = Math.max(...aoa.map(l => (l ? l.length : 0)));
  for (let c = 0; c < largura; c++) {
    const n = aoa.filter(l => l && !vazio(l[c])).length;
    if (n >= minOcorr) return c;
  }
  return null;
}

// ── Detecção do layout ────────────────────────────────────────────────────
// Devolve { relatorio: bool, motivo } — auto-detecção que o operador pode
// sobrescrever na tela. Nunca decidir escondido: a prévia mostra o que foi
// detectado.
export function detectaLayout(aoa) {
  const ancora = detectaAncora(aoa);
  if (ancora == null) return { relatorio: false, motivo: 'sem coluna âncora' };
  const linhasComDado = aoa.filter(l => l && l.some(v => !vazio(v))).length;
  const inicios = aoa.filter(l => l && !vazio(l[ancora])).length;
  if (linhasComDado === 0) return { relatorio: false, motivo: 'vazio' };

  const primeiroInicio = aoa.findIndex(l => l && !vazio(l[ancora]));
  const razao = inicios / linhasComDado;

  if (primeiroInicio > 1) return { relatorio: true, motivo: `cabeçalho fora da 1ª linha (registros começam na linha ${primeiroInicio + 1})` };
  if (razao < 0.85) return { relatorio: true, motivo: `${inicios} registros em ${linhasComDado} linhas — há linhas de continuação` };
  return { relatorio: false, motivo: 'tabela plana (1 linha = 1 registro)' };
}

// ── Rótulo mais próximo ───────────────────────────────────────────────────
// No layout de impressão o rótulo raramente cai na coluna do dado. Procura o
// mais próximo, preferindo o exato, depois esquerda, depois direita.
// É DICA: o operador confirma na tela vendo as amostras.
function rotuloProximo(rotulos, col, janela = 4) {
  if (!vazio(rotulos[col])) return txt(rotulos[col]);
  for (let d = 1; d <= janela; d++) {
    if (col - d >= 0 && !vazio(rotulos[col - d])) return txt(rotulos[col - d]);
    if (col + d < rotulos.length && !vazio(rotulos[col + d])) return txt(rotulos[col + d]);
  }
  return '';
}

// ── Normalização ──────────────────────────────────────────────────────────
// aoa → { rotulos, linhas, colunasUteis, diagnostico }
//
// IMPORTANTE: `linhas` sai com a LARGURA ORIGINAL, indexada pela coluna real da
// planilha. Assim o mapeamento { "7": "data_cirurgia" } e o perfil salvo
// continuam válidos, e normalizaLinha() do isc-import.js funciona sem alteração.
// `colunasUteis` diz à tela quais colunas mostrar.
export function normalizaRelatorio(aoa, opts = {}) {
  const linhasBrutas = (aoa || []).map(l => Array.isArray(l) ? l : []);
  const largura = Math.max(1, ...linhasBrutas.map(l => l.length));
  const ancora = opts.ancora != null ? Number(opts.ancora) : detectaAncora(linhasBrutas);

  if (ancora == null) {
    return { rotulos: [], linhas: [], colunasUteis: [], diagnostico: { erro: 'Não consegui identificar onde cada registro começa.' } };
  }

  // 1. Onde começa cada registro
  const inicios = [];
  linhasBrutas.forEach((l, i) => { if (!vazio(l[ancora])) inicios.push(i); });
  if (!inicios.length) {
    return { rotulos: [], linhas: [], colunasUteis: [], diagnostico: { erro: 'Nenhum registro encontrado.' } };
  }

  // 2. Cabeçalho = última linha com conteúdo ANTES do 1º registro.
  //    O que estiver acima (título, período) é descarte.
  let linhaCabecalho = -1;
  for (let i = inicios[0] - 1; i >= 0; i--) {
    if (linhasBrutas[i].some(v => !vazio(v))) { linhaCabecalho = i; break; }
  }
  const rotulos = linhaCabecalho >= 0 ? linhasBrutas[linhaCabecalho].map(txt) : [];

  // 3. Agrupar: registro i vai do seu início até o início do próximo.
  //    As linhas do meio são continuação do texto que quebrou.
  const gruposIdx = inicios.map((ini, k) => ({
    inicio: ini,
    fim: k + 1 < inicios.length ? inicios[k + 1] : linhasBrutas.length,
  }));

  // 4. Colunas úteis. Duas formas de uma coluna se qualificar:
  //    (a) tem dado numa linha de INÍCIO de registro → coluna normal; ou
  //    (b) aparece em ≥2 registros diferentes, ainda que só em linhas de
  //        continuação.
  //
  //    (b) existe porque a variante do relatório com contato põe o bloco
  //    "endereço + Fone + Celular" numa linha SEPARADA — nunca na linha de
  //    início. Só a regra (a) descartava o telefone inteiro, calado.
  //
  //    O limiar de 2 registros é o que continua matando o rodapé
  //    ("Total minutos: 8889"): ele vive em colunas que aparecem num único
  //    grupo (o último) e nunca num início.
  const minGrupos = 2;
  const colunasUteis = [];
  for (let c = 0; c < largura; c++) {
    if (inicios.some(i => !vazio(linhasBrutas[i][c]))) { colunasUteis.push(c); continue; }
    let grupos = 0;
    for (const g of gruposIdx) {
      for (let i = g.inicio; i < g.fim; i++) {
        if (!vazio(linhasBrutas[i][c])) { grupos++; break; }
      }
      if (grupos >= minGrupos) break;
    }
    if (grupos >= minGrupos) colunasUteis.push(c);
  }

  // 5. Concatenar as continuações, coluna a coluna.
  const linhas = gruposIdx.map(g => {
    const rec = new Array(largura).fill('');
    for (const c of colunasUteis) {
      const partes = [];
      for (let i = g.inicio; i < g.fim; i++) {
        const v = linhasBrutas[i][c];
        if (!vazio(v)) partes.push(txt(v));
      }
      // Junta com espaço e colapsa: aguenta tanto "TRATAMENTO " (com espaço à
      // direita) quanto "TRATAMENTO" (sem), sem colar as palavras.
      rec[c] = partes.join(' ').replace(/\s+/g, ' ').trim();
    }
    return rec;
  });

  // 6. Rótulos-dica reposicionados para a coluna do DADO.
  const rotulosDica = new Array(largura).fill('');
  for (const c of colunasUteis) rotulosDica[c] = rotuloProximo(rotulos, c);

  return {
    rotulos: rotulosDica,
    rotulosOriginais: rotulos,
    linhas,
    colunasUteis,
    diagnostico: {
      linhaCabecalho: linhaCabecalho >= 0 ? linhaCabecalho + 1 : null,
      colunaAncora: ancora,
      registros: linhas.length,
      linhasLidas: linhasBrutas.length,
      linhasDescartadas: linhasBrutas.length - linhas.length,
      colunasUteis: colunasUteis.length,
      colunasDescartadas: largura - colunasUteis.length,
    },
  };
}

// ── Tabela plana ──────────────────────────────────────────────────────────
// Mesmo formato de saída, para o caminho comum (CSV/colar) não precisar de
// dois códigos diferentes lá na frente.
export function normalizaPlano(aoa) {
  const linhasBrutas = (aoa || []).map(l => Array.isArray(l) ? l : []).filter(l => l.some(v => !vazio(v)));
  if (!linhasBrutas.length) return { rotulos: [], linhas: [], colunasUteis: [], diagnostico: { registros: 0 } };
  const largura = Math.max(1, ...linhasBrutas.map(l => l.length));
  const rotulos = linhasBrutas[0].map(txt);
  const linhas = linhasBrutas.slice(1).map(l => {
    const r = new Array(largura).fill('');
    for (let c = 0; c < largura; c++) r[c] = txt(l[c]);
    return r;
  });
  const colunasUteis = [];
  for (let c = 0; c < largura; c++) {
    if (!vazio(rotulos[c]) || linhas.some(l => !vazio(l[c]))) colunasUteis.push(c);
  }
  return {
    rotulos, rotulosOriginais: rotulos, linhas, colunasUteis,
    diagnostico: { linhaCabecalho: 1, colunaAncora: null, registros: linhas.length, linhasLidas: linhasBrutas.length, linhasDescartadas: 0, colunasUteis: colunasUteis.length, colunasDescartadas: largura - colunasUteis.length },
  };
}

// ── Ponto de entrada ──────────────────────────────────────────────────────
// modo: 'auto' | 'plano' | 'relatorio'
export function normalizaAoA(aoa, modo = 'auto') {
  const det = detectaLayout(aoa);
  const usar = modo === 'auto' ? (det.relatorio ? 'relatorio' : 'plano') : modo;
  const out = usar === 'relatorio' ? normalizaRelatorio(aoa) : normalizaPlano(aoa);
  out.diagnostico = { ...out.diagnostico, modo: usar, deteccao: det };
  return out;
}
