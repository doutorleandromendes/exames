// atb-nlq-glossario.js
// ════════════════════════════════════════════════════════════════════════════
// GLOSSÁRIO SEMÂNTICO — o "moat" do NL→SQL do módulo ATB.
//
// Este é o contexto injetado no system prompt do modelo (Ollama local ou API).
// O modelo NÃO conhece a semântica do teu schema: que "UTIAB" = setor 'UTI', que
// "dias de ATB" = tempo_previsto, que metade dos campos vive em payload_raw, que
// a data canônica é um COALESCE, que tempo_previsto é por-ficha e não por-droga.
// Tudo isso está aqui. O modelo é substituível; este arquivo é o que dá acerto.
//
// IMPORTANTE (privacidade): no v0 o modelo recebe SÓ a pergunta + este glossário.
// Ele gera o SQL; os RESULTADOS (linhas de paciente) são formatados no servidor e
// NUNCA voltam para o modelo. Nenhum PHI atravessa o LLM.
// ════════════════════════════════════════════════════════════════════════════

export const ENUMS_ATB = {
  setor: ['PS','EPM','Cuidados Intermediários','Psiquiatria','Apartamento','Oncologia',
          'Clínica Cirúrgica','Semi','Hemodiálise','Pediatria','UTI','UTI Neo / Infantil',
          'UTI C','Ginecologia/Obstetrícia','Clínica Médica'],
  tipo_terapia: ['Empírica','Guiada por cultura','Profilaxia cirúrgica'],
  foco_infeccao: ['Corrente sanguínea (bacteremia)','Pneumonia','Infecção do trato urinário',
                  'Infecção do sítio cirúrgico','Meningite/Encefalite','Abdominal',
                  'Osteoarticular','Pele/Partes moles','Neutropenia Febril'],
  atb_solicitado: ['Cefepime','Ceftriaxone','Fosfomicina','Anfotericina B','Daptomicina',
                   'Tigeciclina','Micafungina','Meropenem','Piperacilina/Tazobactam',
                   'Vancomicina','Teicoplanina','Polimixina B','Polimixina E (colestimetato)',
                   'Amicacina','Gentamicina','NÃO PADRONIZADO'],
  dispositivos_invasivos: ['AVP','CVC','IOT','SVD','CDL (Shilley)','PAi'],
  status: ['pendente','em_avaliacao','avaliado','arquivado'],
};

export const GLOSSARIO_ATB = `
Você converte perguntas em português sobre stewardship de antimicrobianos em UMA query PostgreSQL (apenas SELECT/WITH). Responda SOMENTE com o SQL, sem explicação, sem crases.

# REGRAS INVIOLÁVEIS
- Apenas SELECT/WITH. Nunca INSERT/UPDATE/DELETE/DDL. Um único statement, sem ";" extra.
- SEMPRE filtre por instituição: JOIN atb_instituicoes i ON i.id = f.instituicao_id, e filtre i.sigla ('HUSF' ou 'SCMI'). Se a pergunta não disser, use 'HUSF'.
- SEMPRE exclua removidas: f.deletado_em IS NULL.
- Data da ficha = SEMPRE a expressão canônica: COALESCE(f.data_referencia, f.jotform_created_at, f.created_at). (data_referencia só é preenchida em ficha retrospectiva.) Use-a em qualquer filtro/ordenação por data.
- Arrays JSONB: teste pertinência com @> jsonb_build_array('Valor'). Nunca use IN para arrays.
- Sempre inclua LIMIT quando a pergunta pedir linhas (não agregados).

# TABELAS
atb_fichas f — a ficha de solicitação de ATB (uma por solicitação). Tabela central.
atb_instituicoes i — id, sigla ('HUSF','SCMI'), nome. Junte por f.instituicao_id = i.id.
atb_avaliacoes av — avaliação SCIH: av.ficha_id → f.id (1:1). Campos: iras, etiol_iras, micro, desfecho_iras, desfecho_data, saps3.
atb_evolutivos ev — dados evolutivos: ev.ficha_id → f.id (1:1). labs/hemodinamica/ventilatorio (JSONB).

# COLUNAS DE atb_fichas (as que importam pra análise)
- setor (TEXT, enum). MAPA DE LINGUAGEM: "UTIAB" = 'UTI'; "UTIC" = 'UTI C' (com espaço). "as UTIs adulto" = ('UTI','UTI C'). Existe também 'UTI Neo / Infantil'.
- leito (TEXT), equipe_responsavel (TEXT).
- data_internacao (DATE), data_admissao_uti (DATE), paciente_dn (DATE).
- tipo_terapia (TEXT, enum). foco_infeccao (TEXT, enum) — só é preenchido quando tipo_terapia <> 'Profilaxia cirúrgica'. "suspeita de pneumonia" = foco_infeccao = 'Pneumonia'.
- sepse (BOOL), gestante (BOOL), lactante (BOOL), obito (BOOL), data_obito (DATE).
- comorbidades (JSONB array), atb_previos (JSONB), culturas_colhidas (JSONB), culturas_previas (JSONB).
- dispositivos_invasivos (JSONB array, enum). "sob ventilação mecânica invasiva / intubado" = @> '["IOT"]'.
- atb_solicitado (JSONB array, ATÉ 3 drogas por ficha, enum). Uma droga presente = @> jsonb_build_array('Meropenem').
- tempo_previsto (INTEGER) = "dias de ATB solicitados / previstos" = dias de tratamento planejados. É POR FICHA, não por droga (ver ARMADILHAS).
- sofa (INT), sofa_renal (INT) — escores já computados.
- status (TEXT, enum). retrospectiva (BOOL). recomendacao_scih (JSONB) = veredito SCIH.
- payload_raw (JSONB) = "extras" que ainda não viraram coluna. Acesso: payload_raw->>'chave'. Ex.: o suporte respiratório do SOFA é payload_raw->>'sofa_suporte' (valores incluem 'VNI ou Ventilação Mecânica (VM)'). ATENÇÃO: essa chave pode não existir em fichas antigas migradas do JotForm — só confie após sondar.

# DERIVADOS COMPUTADOS (não são colunas — calcule com aritmética de data)
Seja ref = COALESCE(f.data_referencia, f.jotform_created_at, f.created_at)::date.
- dias_uti        = ref - f.data_admissao_uti
- dias_internacao = ref - f.data_internacao
- idade (anos)    = date_part('year', age(ref, f.paciente_dn))

# ARMADILHAS (obrigatório respeitar)
- "sob VM" é AMBÍGUO. Padrão = IOT (invasiva), coluna dispositivos_invasivos @> '["IOT"]'. A leitura do SOFA (payload_raw->>'sofa_suporte' = 'VNI ou Ventilação Mecânica (VM)') INCLUI VNI (não-invasiva) e só existe no payload_raw. Se a pergunta não distinguir, use IOT e não invente.
- tempo_previsto é UM valor por ficha, não por droga. Ao estratificar por droga, a MESMA ficha entra em até 3 linhas → somar dias entre drogas dá dupla contagem. Isso é esperado; nunca trate como aditivo entre drogas.
- foco_infeccao é NULL em profilaxia cirúrgica — filtrar foco já exclui profilaxia.
`;

// Few-shots: exemplos reais validados (âncoras de acerto). O endpoint pode
// anexar 1–3 destes ao prompt conforme a pergunta.
export const FEWSHOTS_ATB = [
  {
    pergunta: 'Quantos dias de ATB foram solicitados para pacientes com suspeita de pneumonia, sob VM, nas UTIs adulto (UTIAB e UTIC) do HUSF nos últimos 6 meses?',
    sql: `SELECT COUNT(*) AS n_fichas,
       COALESCE(SUM(f.tempo_previsto),0) AS dias_atb_total,
       ROUND(AVG(f.tempo_previsto)::numeric,1) AS dias_atb_media
FROM atb_fichas f
JOIN atb_instituicoes i ON i.id = f.instituicao_id
WHERE i.sigla = 'HUSF' AND f.deletado_em IS NULL
  AND f.setor IN ('UTI','UTI C')
  AND f.foco_infeccao = 'Pneumonia'
  AND f.dispositivos_invasivos @> '["IOT"]'::jsonb
  AND COALESCE(f.data_referencia, f.jotform_created_at, f.created_at) >= now() - interval '6 months'`,
  },
  {
    pergunta: 'Estratifique esses dias por Piperacilina/Tazobactam, Meropenem, Vancomicina, Teicoplanina e Polimixina B.',
    sql: `WITH coorte AS (
  SELECT f.id, f.atb_solicitado, f.tempo_previsto
  FROM atb_fichas f
  JOIN atb_instituicoes i ON i.id = f.instituicao_id
  WHERE i.sigla = 'HUSF' AND f.deletado_em IS NULL
    AND f.setor IN ('UTI','UTI C')
    AND f.foco_infeccao = 'Pneumonia'
    AND f.dispositivos_invasivos @> '["IOT"]'::jsonb
    AND COALESCE(f.data_referencia, f.jotform_created_at, f.created_at) >= now() - interval '6 months'
),
drogas(droga) AS (VALUES ('Piperacilina/Tazobactam'),('Meropenem'),('Vancomicina'),('Teicoplanina'),('Polimixina B'))
SELECT d.droga, COUNT(c.id) AS n_fichas,
       COALESCE(SUM(c.tempo_previsto),0) AS dias_atb_total
FROM drogas d
LEFT JOIN coorte c ON c.atb_solicitado @> jsonb_build_array(d.droga)
GROUP BY d.droga ORDER BY dias_atb_total DESC`,
  },
];
