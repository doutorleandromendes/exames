// atb-form-schema.js
// ════════════════════════════════════════════════════════════════════════════
// Sistema de formulário orientado a schema (form vivo).
// A definição do formulário (campos, opções, condicionais) vive no banco,
// não no código. Esta é a base que torna o formulário editável sem deploy.
//
// Exporta:
//   - ensureFormSchemaTable(pool)   → cria tabela + semeia HUSF/H2 se vazio
//   - getFormSchema(pool, sigla)    → lê a definição ativa de uma instituição
//   - saveFormSchema(pool, sigla, def, autor) → grava nova versão
//   - SEMENTE_HUSF                  → definição inicial (todos os campos atuais)
// ════════════════════════════════════════════════════════════════════════════

// ── Tipos de campo suportados pelo motor de renderização ──────────────────────
// 'text'      → input texto
// 'textarea'  → texto multilinha
// 'number'    → input numérico
// 'date'      → data
// 'select'    → dropdown (1 escolha)
// 'radio'     → botões de rádio (1 escolha)
// 'checkbox'  → múltipla escolha (array)
// 'matrix'    → tabela de linhas × colunas (redesenhada como cartões)
// 'crm'       → campo especial de validação de CRM
// 'sofa'      → bloco especial de cálculo SOFA
// 'computed'  → campo calculado/oculto (idade, sofa_renal)

// ── A SEMENTE: definição inicial do formulário HUSF ───────────────────────────
// Cada campo tem: key (estável, casa com o parser/banco), type, label, e o que
// for pertinente (options, required, hint, cond). `cond` descreve condicional:
//   { campo: 'setor', op: 'in', valor: ['UTI','UTI C'] }  → mostra se setor∈...
// Na Fase 1 as condicionais são DADOS aqui, e o motor as interpreta. O editor
// visual de condicionais é a Fase 2 — mas como já são dados, o motor não muda.

export const SEMENTE_HUSF = {
  titulo: 'Ficha de solicitação de ATB de uso restrito',
  instituicao: 'HUSF',
  versao: 1,
  secoes: [
    {
      id: 'identificacao', titulo: 'Identificação do Paciente',
      campos: [
        { key:'pac_nome', type:'text', label:'Nome completo do paciente', required:true,
          hint:'Não abreviar. Preencher todos os nomes para desambiguação.',
          transform:'upper', validate:'nome_completo', placeholder:'Ex.: MARIA SILVA SOUZA' },
        { key:'pac_dn', type:'date', label:'Data de nascimento', required:true, showAge:true },
        { key:'prontuario', type:'text', label:'Prontuário', required:true },
        { key:'atendimento', type:'text', label:'Número de atendimento', required:true },
      ]
    },
    {
      id: 'internacao', titulo: 'Dados de Internação',
      campos: [
        { key:'setor', type:'select', label:'Setor de internação', required:true,
          options:['PS','EPM','Cuidados Intermediários','Psiquiatria','Apartamento','Oncologia','Clínica Cirúrgica','Semi','Hemodiálise','Pediatria','UTI','UTI Neo / Infantil','UTI C','Ginecologia/Obstetrícia','Clínica Médica'] },
        { key:'leito', type:'text', label:'Leito' },
        { key:'equipe', type:'select', label:'Equipe responsável', required:true,
          options:['Cx Geral','Proctologia','Urologia','Ortopedia','Ginecologia / Obstetricia','Otorrino','NCR','Clínica Médica','Nefrologia','Cardiologia','Pediatria'] },
        { key:'data_internacao', type:'date', label:'Data de internação', required:true },
        { key:'data_uti', type:'date', label:'Data de admissão na UTI', required:true,
          cond:{ campo:'setor', op:'in', valor:['UTI','UTI C'] } },
        { key:'gestante', type:'radio', label:'Gestante', options:['Sim','Não'], required:true,
          cond:{ any:[ { campo:'setor', op:'eq', valor:'Ginecologia/Obstetrícia' }, { campo:'equipe', op:'eq', valor:'Ginecologia / Obstetricia' } ] } },
        { key:'lactante', type:'radio', label:'Lactante', options:['Sim','Não'], required:true,
          cond:{ any:[ { campo:'setor', op:'eq', valor:'Ginecologia/Obstetrícia' }, { campo:'equipe', op:'eq', valor:'Ginecologia / Obstetricia' } ] } },
      ]
    },
    {
      id: 'terapia', titulo: 'Tipo de Terapia',
      campos: [
        { key:'tipo_terapia', type:'radio', label:'Tipo de uso', required:true,
          options:['Empírica','Guiada por cultura','Profilaxia cirúrgica'] },
      ]
    },
    {
      id: 'clinica', titulo: 'Contexto Clínico',
      cond:{ campo:'tipo_terapia', op:'neq', valor:'Profilaxia cirúrgica' },
      campos: [
        { key:'historia_clinica', type:'textarea', label:'História clínica da infecção', required:true,
          hint:'Descrever detalhadamente a justificativa de uso do antimicrobiano. Se paciente veio de casa, informar.' },
        { key:'foco_infeccao', type:'select', label:'Foco de infecção',
          options:['Corrente sanguínea (bacteremia)','Pneumonia','Infecção do trato urinário','Infecção do sítio cirúrgico','Meningite/Encefalite','Abdominal','Osteoarticular','Pele/Partes moles','Neutropenia Febril'] },
        { key:'sepse', type:'radio', label:'Sepse?', options:['Sim','Não'], required:true,
          autodetect:'historia_clinica' },
      ]
    },
    {
      id: 'cirurgia', titulo: 'Cirurgia',
      cond:{ campo:'tipo_terapia', op:'eq', valor:'Profilaxia cirúrgica' },
      campos: [
        { key:'cirurgia', type:'textarea', label:'Cirurgia a ser realizada', required:true },
      ]
    },
    {
      id: 'sofa', titulo: 'Avaliação de Gravidade (SOFA)',
      cond:{ all:[
        { campo:'tipo_terapia', op:'neq', valor:'Profilaxia cirúrgica' },
        { any:[
          { campo:'sepse', op:'eq', valor:'Sim' },
          { campo:'setor', op:'in', valor:['UTI','UTI C','Semi','Cuidados Intermediários','PS'] },
          { campo:'foco_infeccao', op:'in', valor:['Corrente sanguínea (bacteremia)','Pneumonia','Meningite/Encefalite','Abdominal'] },
          { campo:'atb_solicitado', op:'contains_any', valor:['Ceftriaxone','Cefepime','Meropenem','Piperacilina/Tazobactam','Vancomicina','Teicoplanina','Polimixina B','Polimixina E (colestimetato)','Amicacina','Tigeciclina','Daptomicina','Anfotericina B','Micafungina'] },
          { campo:'historia_clinica', op:'text_contains_any', valor:['sepse','septico','séptico','choque','hipotens','lactato','vasopressor','vasoativa','noradrenalina','dva'] }
        ] }
      ] },
      campos: [
        { key:'_sofa_bloco', type:'sofa', label:'SOFA', required:true },
      ]
    },
    {
      id: 'comorbidades', titulo: 'Comorbidades / Antecedentes',
      cond:{ campo:'tipo_terapia', op:'neq', valor:'Profilaxia cirúrgica' },
      campos: [
        { key:'comorbidades', type:'checkbox', label:'Comorbidades relevantes',
          options:['DM','Cancer','IRC','Insuficiência cardíaca','DPOC','Cirrose','Institucionalizado','Uso crônico de imunossupressor (corticosteróides, por ex)','HIV/AIDS'] },
        { key:'faz_quimio', type:'radio', label:'Paciente faz quimioterapia na instituição?', options:['Sim','Não'],
          cond:{ any:[
            { campo:'comorbidades', op:'contains', valor:'Cancer' },
            { campo:'historia_clinica', op:'text_contains_any',
              valor:['qt','qtx','quimio','quimioterapia','ca','cancer','câncer','neoplasia','neutropenia','onco','oncolog'] }
          ] } },
        { key:'cateter_quimio', type:'radio', label:'Possui cateter de longa permanência?', options:['Sim','Não'],
          cond:{ campo:'faz_quimio', op:'eq', valor:'Sim' } },
        { key:'acesso_quimio', type:'select', label:'Tipo de acesso', options:['PICC','Portocath','Permcath/Hickman'],
          cond:{ campo:'cateter_quimio', op:'eq', valor:'Sim' } },
      ]
    },
    {
      id: 'atb_previos', titulo: 'Antimicrobianos Prévios',
      cond:{ campo:'tipo_terapia', op:'neq', valor:'Profilaxia cirúrgica' },
      campos: [
        { key:'uso_atb_7d', type:'radio', label:'Uso de antimicrobianos nos últimos 7 dias?', options:['Sim','Não'], required:true },
        { key:'atb_previos', type:'matrix', label:'Antimicrobianos usados',
          cond:{ campo:'uso_atb_7d', op:'eq', valor:'Sim' },
          maxLinhas:4, linhaLabel:'ATB',
          colunas:[
            { key:'qual', label:'Qual?', type:'text' },
            { key:'inicio', label:'Início', type:'date' },
            { key:'termino', label:'Término', type:'date' },
            { key:'motivo', label:'Motivo da suspensão', type:'select',
              options:['Fim de tratamento','Mudança guiada por cultura','Reação adversa','Falha de tratamento'] },
          ] },
      ]
    },
    {
      id: 'culturas', titulo: 'Culturas',
      cond:{ campo:'tipo_terapia', op:'neq', valor:'Profilaxia cirúrgica' },
      campos: [
        { key:'culturas_colhidas', type:'matrix', label:'Culturas colhidas',
          linhasFixas:['Hemocultura','Secreção','Urocultura'], linhaLabel:'Cultura',
          colunas:[
            { key:'colhido', label:'Colhido?', type:'check' },
            { key:'data', label:'Data', type:'date' },
          ] },
        { key:'culturas_previas', type:'matrix', label:'Culturas prévias (pertinentes à escolha atual)',
          cond:{ campo:'tipo_terapia', op:'eq', valor:'Guiada por cultura' },
          maxLinhas:3, linhaLabel:'Cultura',
          colunas:[
            { key:'material', label:'Material', type:'text' },
            { key:'data', label:'Data', type:'date' },
            { key:'micro', label:'Microrganismo', type:'text' },
            { key:'resist', label:'Resistências', type:'text' },
          ] },
      ]
    },
    {
      id: 'dispositivos', titulo: 'Dispositivos Invasivos',
      campos: [
        { key:'dispositivos_invasivos', type:'checkbox', label:'Dispositivos presentes',
          options:['AVP','CVC','IOT','SVD','CDL (Shilley)','PAi'],
          requiredCond:{ campo:'setor', op:'in', valor:['UTI','UTI C'] } },
        { key:'data_insercao_cateter', type:'date', label:'Data de inserção do cateter',
          cond:{ any:[
            { campo:'dispositivos_invasivos', op:'contains', valor:'CVC' },
            { campo:'acesso_vascular_neo', op:'contains', valor:'PICC' },
            { campo:'acesso_vascular_neo', op:'contains', valor:'Cateter umbilical' }
          ] } },
        { key:'sitio_cvc', type:'checkbox', label:'Sítio de inserção do CVC', options:['Jugular','Subclávio','Femoral'],
          cond:{ campo:'dispositivos_invasivos', op:'contains', valor:'CVC' } },
        { key:'sitio_cdl', type:'checkbox', label:'Sítio de inserção do CDL (Shilley)', options:['Jugular','Subclávio','Femoral'],
          cond:{ campo:'dispositivos_invasivos', op:'contains', valor:'CDL (Shilley)' } },
        { key:'sitio_pai', type:'checkbox', label:'Sítio de inserção da PAi', options:['Periférico','Femoral'],
          cond:{ campo:'dispositivos_invasivos', op:'contains', valor:'PAi' } },
        { key:'peso_nascimento', type:'number', label:'Peso ao nascimento (g)', required:true,
          cond:{ campo:'setor', op:'eq', valor:'UTI Neo / Infantil' } },
        { key:'acesso_vascular_neo', type:'checkbox', label:'Acesso vascular (Neo)',
          options:['Cateter umbilical','PICC','Periférico','Flebotomia'], required:true,
          cond:{ campo:'setor', op:'eq', valor:'UTI Neo / Infantil' } },
        { key:'acesso_dialise', type:'select', label:'Acesso para diálise', options:['FAV','CDL (Shilley)','Perm-cath','PTFE'], required:true,
          cond:{ campo:'setor', op:'eq', valor:'Hemodiálise' } },
        { key:'sinais_dialise', type:'radio', label:'Sinais de infecção local no acesso?', options:['Sim','Não'], required:true,
          cond:{ campo:'setor', op:'eq', valor:'Hemodiálise' } },
      ]
    },
    {
      id: 'renal', titulo: 'Função Renal',
      cond:{ campo:'tipo_terapia', op:'neq', valor:'Profilaxia cirúrgica' },
      campos: [
        { key:'insuficiencia_renal', type:'checkbox', label:'Insuficiência renal?',
          options:['Não','Sim (aguda)','Sim (crônica-agudizada)','Sim (crônica)'], exclusivo:'Não', required:true },
        { key:'dialise', type:'radio', label:'Em diálise?', options:['Sim','Não'],
          cond:{ campo:'insuficiencia_renal', op:'contains_any', valor:['Sim (aguda)','Sim (crônica-agudizada)','Sim (crônica)'] } },
        { key:'clcr', type:'number', label:'Clearance de creatinina (ml/min)',
          cond:{ campo:'insuficiencia_renal', op:'contains_any', valor:['Sim (aguda)','Sim (crônica-agudizada)','Sim (crônica)'] } },
      ]
    },
    {
      id: 'atb_solicitado', titulo: 'Antimicrobiano Solicitado',
      campos: [
        { key:'atb_solicitado', type:'checkbox', label:'ATB solicitado', required:true, max:3,
          hint:'Selecione até 3 drogas.',
          options:['Cefepime','Ceftriaxone','Fosfomicina','Anfotericina B','Daptomicina','Tigeciclina','Micafungina','Meropenem','Piperacilina/Tazobactam','Vancomicina','Teicoplanina','Polimixina B','Polimixina E (colestimetato)','Amicacina','Gentamicina','NÃO PADRONIZADO'] },
        { key:'peso', type:'number', label:'Peso (kg)', required:true,
          cond:{ campo:'atb_solicitado', op:'contains', valor:'Polimixina E (colestimetato)' } },
        { key:'altura', type:'number', label:'Altura (cm)', required:true,
          cond:{ campo:'atb_solicitado', op:'contains', valor:'Polimixina E (colestimetato)' } },
        { key:'posologia', type:'matrix', label:'Posologia', required:true,
          sincronizaCom:'atb_solicitado', maxLinhas:3, linhaLabel:'ATB',
          colunas:[
            { key:'droga', label:'Droga', type:'text', readonly:true },
            { key:'dose', label:'Dose', type:'text', placeholder:'Ex.: 4,5g' },
            { key:'intervalo', label:'Intervalo', type:'text', placeholder:'Ex.: 6/6h' },
          ] },
        { key:'tempo_previsto', type:'number', label:'Tempo previsto de tratamento (dias)', required:true },
        { key:'oxacilina_associacao', type:'radio', label:'Será prescrita Oxacilina em associação?', options:['Sim','Não'],
          cond:{ any:[
            { campo:'setor', op:'eq', valor:'UTI Neo / Infantil' },
            { campo:'setor', op:'eq', valor:'Pediatria' },
            { campo:'equipe', op:'eq', valor:'Pediatria' }
          ] } },
        { key:'classificacao_fratura', type:'radio', label:'Classificação de fratura exposta (Gustillo-Anderson)',
          options:['I','II','IIIa','IIIb','IIIc'],
          cond:{ all:[
            { campo:'equipe', op:'eq', valor:'Ortopedia' },
            { campo:'atb_solicitado', op:'contains', valor:'Gentamicina' }
          ] } },
      ]
    },
    {
      id: 'prescritor', titulo: 'Identificação do Prescritor',
      campos: [
        { key:'crm', type:'crm', label:'CRM', required:true },
        { key:'prescritor_nome', type:'text', label:'Nome do prescritor', readonly:true,
          hint:'Preenchido automaticamente após validação do CRM' },
      ]
    },
  ]
};

// ── Tabela + persistência ─────────────────────────────────────────────────────
export async function ensureFormSchemaTable(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_form_schema (
      id          SERIAL PRIMARY KEY,
      instituicao TEXT NOT NULL,
      versao      INTEGER NOT NULL DEFAULT 1,
      definicao   JSONB NOT NULL,
      ativo       BOOLEAN NOT NULL DEFAULT true,
      criado_por  INTEGER,
      created_at  TIMESTAMPTZ DEFAULT now()
    )
  `);
  await pool.query(`CREATE INDEX IF NOT EXISTS atb_form_schema_inst_idx ON atb_form_schema(instituicao, ativo)`);

  // Semeia HUSF e H2 se ainda não houver definição
  const { rows:[{ n }] } = await pool.query(`SELECT COUNT(*) n FROM atb_form_schema`);
  if (parseInt(n,10) === 0) {
    await pool.query(
      `INSERT INTO atb_form_schema (instituicao, versao, definicao, ativo) VALUES ($1,$2,$3,true)`,
      ['HUSF', 1, JSON.stringify(SEMENTE_HUSF)]
    );
    // H2 começa como cópia derivada do HUSF (forms independentes, mas H2 deriva do HUSF)
    const defH2 = { ...SEMENTE_HUSF, instituicao:'H2' };
    await pool.query(
      `INSERT INTO atb_form_schema (instituicao, versao, definicao, ativo) VALUES ($1,$2,$3,true)`,
      ['H2', 1, JSON.stringify(defH2)]
    );
    console.log('[atb-form-schema] semeado: HUSF + H2 (v1)');
  }
}

export async function getFormSchema(pool, sigla) {
  const { rows } = await pool.query(
    `SELECT definicao, versao FROM atb_form_schema WHERE instituicao=$1 AND ativo=true ORDER BY versao DESC LIMIT 1`,
    [sigla]
  );
  return rows[0] ? { ...rows[0].definicao, versao: rows[0].versao } : null;
}

// Grava nova versão (mantém histórico: desativa a anterior, insere nova)
export async function saveFormSchema(pool, sigla, definicao, autorId) {
  const { rows:[{ v }] } = await pool.query(
    `SELECT COALESCE(MAX(versao),0)+1 v FROM atb_form_schema WHERE instituicao=$1`, [sigla]
  );
  await pool.query(`UPDATE atb_form_schema SET ativo=false WHERE instituicao=$1`, [sigla]);
  await pool.query(
    `INSERT INTO atb_form_schema (instituicao, versao, definicao, ativo, criado_por) VALUES ($1,$2,$3,true,$4)`,
    [sigla, v, JSON.stringify({ ...definicao, versao:v }), autorId || null]
  );
  return v;
}
