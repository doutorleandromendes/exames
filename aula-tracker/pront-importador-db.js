// pront-importador-db.js — ponte entre o motor importarPlanilha() e o banco.
// Decisão do Dr.: resultados LIMPOS gravam direto em pront_coletas/resultados;
// os MARCADOS (sem canônico, escala suspeita, rótulo≠valor) vão para conferência.
// Reimportar a mesma data atualiza (UNIQUE paciente+data+laboratorio), não duplica.

import { importarPlanilha } from "./pront-importador.js";

const LAB_EXTERNO = "Externo (importado)";

// mapeia um analito do motor -> linha de pront_resultados
function paraResultado(a) {
  return {
    canonico:      a.canonico || null,
    rotulo:        a.rotulo || a.nome_original || null,
    nome_original: a.nome_original || null,
    tipo_valor:    a.tipo_valor || null,
    valor_num:     (a.tipo_valor === "numerico" || a.tipo_valor === "censurado") ? (a.valor ?? null) : null,
    operador:      a.operador || null,
    unidade:       a.unidade || null,
    resultado_txt: a.resultado || a.texto || null,
    status_flag:   a.status || null,
  };
}

// decide se um analito é "limpo" (grava direto) ou "marcado" (vai p/ conferência)
// motivos de marca: sem canônico (não reconhecido), escala suspeita (vem do conjunto), tipo texto cru
function avaliaAnalito(a, canonicosSuspeitos) {
  const motivos = [];
  if (!a.canonico) motivos.push("analito não reconhecido");
  if (a.canonico && canonicosSuspeitos.has(a.canonico)) motivos.push("escala destoa entre datas");
  if (a.tipo_valor === "texto") motivos.push("valor não interpretado");
  return motivos;
}

// Analisa a matriz e devolve uma PRÉVIA (sem gravar): { paciente, dn, datas, limpos, marcados, avisos }
export function preverImportacao(rows) {
  const parsed = importarPlanilha(rows);
  // canônicos com escala suspeita: derivado dos avisos do motor (que cita o rótulo)
  const suspeitos = new Set();
  for (const c of parsed.coletas)
    for (const a of c.analitos)
      if (a.canonico && parsed.avisos.some(av => av.includes(a.rotulo))) suspeitos.add(a.canonico);

  const limpos = [], marcados = [];
  for (const col of parsed.coletas) {
    for (const a of col.analitos) {
      const motivos = avaliaAnalito(a, suspeitos);
      const item = { data: col.data, laboratorio: LAB_EXTERNO, tarv: col.tarv || null, ...paraResultado(a) };
      if (motivos.length) marcados.push({ ...item, motivos });
      else limpos.push(item);
    }
  }
  return {
    paciente: parsed.paciente, dn: parsed.dn,
    datas: parsed.coletas.map(c => c.data),
    coletas: parsed.coletas,
    limpos, marcados,
    naoMapeados: parsed.naoMapeados || [],
    avisos: parsed.avisos || [],
  };
}

// Grava os LIMPOS direto; devolve {coletasCriadas, resultadosGravados}. (marcados são tratados à parte)
export async function gravarLimpos(pool, pacienteId, limpos, criadoPor) {
  // agrupa por data (uma coleta por data)
  const porData = {};
  for (const it of limpos) (porData[it.data] ||= { tarv: it.tarv, itens: [] }).itens.push(it);

  let coletasCriadas = 0, resultadosGravados = 0;
  for (const [data, grupo] of Object.entries(porData)) {
    // upsert da coleta (reimportar mesma data atualiza a mesma coleta)
    const { rows: [col] } = await pool.query(
      `INSERT INTO pront_coletas (paciente_id, data_coleta, laboratorio, fonte, tarv, criado_por)
       VALUES ($1,$2,$3,'xlsx',$4,$5)
       ON CONFLICT (paciente_id, data_coleta)
       DO UPDATE SET tarv = COALESCE(EXCLUDED.tarv, pront_coletas.tarv)
       RETURNING id`,
      [pacienteId, data, LAB_EXTERNO, grupo.tarv, criadoPor]);
    coletasCriadas++;
    // substitui resultados dessa coleta para os canônicos que estão sendo reimportados (evita duplicar analito)
    for (const it of grupo.itens) {
      if (it.canonico) {
        await pool.query(`DELETE FROM pront_resultados WHERE coleta_id=$1 AND canonico=$2`, [col.id, it.canonico]);
      }
      await pool.query(
        `INSERT INTO pront_resultados
          (coleta_id, canonico, rotulo, nome_original, tipo_valor, valor_num, operador, unidade, resultado_txt, status_flag, laboratorio)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [col.id, it.canonico, it.rotulo, it.nome_original, it.tipo_valor, it.valor_num, it.operador, it.unidade, it.resultado_txt, it.status_flag, LAB_EXTERNO]);
      resultadosGravados++;
    }
  }
  return { coletasCriadas, resultadosGravados };
}

// Grava LIMPOS (normais) + MARCADOS (com status_flag='revisar'), tudo no grid, numa só passada.
export async function gravarTudo(pool, pacienteId, prev, criadoPor) {
  // marca os "marcados" com a flag de revisão e funde com os limpos
  const marcadosFlag = (prev.marcados || []).map(m => ({ ...m, status_flag: "revisar" }));
  const todos = [...(prev.limpos || []), ...marcadosFlag];
  const r = await gravarLimpos(pool, pacienteId, todos, criadoPor);
  return { ...r, limpos: (prev.limpos || []).length, marcados: marcadosFlag.length };
}
