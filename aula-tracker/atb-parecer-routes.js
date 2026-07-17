// ════════════════════════════════════════════════════════════════════════════
//  Rotas que alimentam o visualizador de pareceres (Google Apps Script).
//
//  O Apps Script hoje lê do JotForm. Estas rotas devolvem JSON no MESMO formato
//  que o `extractFields` do script já produz — então a única mudança no Apps
//  Script é trocar as duas URLs (ver instruções no fim deste arquivo).
//
//  COLAR dentro de registerAtbRoutes(app, pool, ...) em atb-routes.js.
//  São rotas PÚBLICAS de leitura (sem auth) — o Apps Script não envia cookie.
//  Não expõem dados sensíveis além do que o parecer já mostra no EMR.
//  Filtram por instituição HUSF por padrão (?inst=H2 para o outro hospital).
// ════════════════════════════════════════════════════════════════════════════

// — helper: monta a tabela HTML de posologia no formato que buildParecer espera —
function _posologiaHtml(posologia) {
  let arr = posologia;
  if (typeof arr === 'string') { try { arr = JSON.parse(arr); } catch { arr = []; } }
  if (!Array.isArray(arr) || !arr.length) return '—';
  let rows = '';
  arr.forEach((row, i) => {
    if (!row || typeof row !== 'object') return;   // linha vazia/removida vem como null no jsonb
    const droga     = row.droga     || row.Droga     || '';
    const dose      = row.dose      || row.Dose      || '';
    const intervalo = row.intervalo || row.Intervalo || '';
    if (!droga && !dose && !intervalo) return;
    rows += `<tr>
      <td style="padding:4px 6px;border:1px solid #ddd;font-weight:bold;background:#f3f3f3;">${i + 1}</td>
      <td style="padding:4px 6px;border:1px solid #ddd;">${droga}</td>
      <td style="padding:4px 6px;border:1px solid #ddd;">${dose}</td>
      <td style="padding:4px 6px;border:1px solid #ddd;">${intervalo}</td>
    </tr>`;
  });
  if (!rows) return '—';
  return `<table style="border-collapse:collapse;font-size:13px;">
    <thead><tr style="background:#eee;">
      <th style="padding:4px 6px;border:1px solid #ddd;"></th>
      <th style="padding:4px 6px;border:1px solid #ddd;">Droga</th>
      <th style="padding:4px 6px;border:1px solid #ddd;">Dose</th>
      <th style="padding:4px 6px;border:1px solid #ddd;">Intervalo</th>
    </tr></thead><tbody>${rows}</tbody></table>`;
}

// — helper: converte uma ficha do banco no objeto de campos que o script espera —
function _fichaParaCampos(f) {
  const arr = v => Array.isArray(v) ? v : (typeof v === 'string' ? (() => { try { return JSON.parse(v); } catch { return []; } })() : []);
  const atb = arr(f.atb_solicitado).join(', ');
  const rec = arr(f.recomendacao_scih);
  // data no formato que o JotForm devolvia (texto + ISO), usando a referência da ficha
  const dt = f.jotform_created_at || f.data_referencia || f.created_at;
  const dataFmt = dt ? new Date(dt).toISOString().replace('T', ' ').slice(0, 19) : '';

  return {
    // chaves IDÊNTICAS às que o extractFields do JotForm produzia:
    nome:                f.paciente_nome || f.paciente_nome_raw || '',
    insiraUma155:        '',
    data:                dataFmt,
    atendimento:         f.atendimento || '',
    prontuario:          f.prontuario || '',
    sepse:               f.sepse === true ? 'Sim' : f.sepse === false ? 'Não' : '',
    setorDe:             f.setor || '',
    leito:               f.leito || '',
    equipeResponsavel:   f.equipe_responsavel || '',
    atbSolicitado:       atb,
    tempoPrevisto:       f.tempo_previsto != null ? String(f.tempo_previsto) : '',
    posologia:           '',                                   // não usado p/ render
    _posologia_raw:      _posologiaHtml(f.posologia),          // tabela HTML pronta
    nomeCompleto:        f.prescritor_nome || '',
    responsavelPelo34:   f.crm || '',
    recomendacaoScih30:  rec[0] || '',                         // veredito principal
    recomendacoesDo:     f.recomendacoes_especificacao || f.recomendacoes_adicionais || '',
    // metadados úteis para a lista:
    _id:                 f.id,
    _created_at:         dataFmt,
  };
}

export function registerParecerApiRoutes(app, pool) {

  // ── Lista (substitui api.jotform.com/form/.../submissions) ────────────────
  // GET /atb/api/pareceres?inst=HUSF&q=busca&limit=100
  app.get('/atb/api/pareceres', async (req, res) => {
    try {
      const inst  = (req.query.inst || 'HUSF');
      const limit = Math.min(parseInt(req.query.limit || '100', 10), 500);
      const { rows } = await pool.query(`
        SELECT f.id, f.paciente_nome, f.paciente_nome_raw, f.prontuario, f.atendimento,
               f.setor, f.leito, f.equipe_responsavel, f.sepse,
               f.atb_solicitado, f.posologia, f.tempo_previsto,
               f.crm, f.prescritor_nome,
               f.recomendacao_scih, f.recomendacoes_especificacao, f.recomendacoes_adicionais,
               f.jotform_created_at, f.data_referencia, f.created_at
        FROM atb_fichas f
        LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
        WHERE ($1::text IS NULL OR i.sigla = $1)
        ORDER BY COALESCE(f.data_referencia, f.jotform_created_at, f.created_at) DESC
        LIMIT $2
      `, [inst || null, limit]);

      res.json({ ok: true, content: rows.map(_fichaParaCampos) });
    } catch (e) {
      console.error('[atb] /api/pareceres error:', e);
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // ── Parecer individual (substitui api.jotform.com/submission/{id}) ────────
  // GET /atb/api/parecer/:id   (id = id da ficha no nosso sistema)
  app.get('/atb/api/parecer/:id', async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { rows: [f] } = await pool.query(`
        SELECT f.id, f.paciente_nome, f.paciente_nome_raw, f.prontuario, f.atendimento,
               f.setor, f.leito, f.equipe_responsavel, f.sepse,
               f.atb_solicitado, f.posologia, f.tempo_previsto,
               f.crm, f.prescritor_nome,
               f.recomendacao_scih, f.recomendacoes_especificacao, f.recomendacoes_adicionais,
               f.jotform_created_at, f.data_referencia, f.created_at
        FROM atb_fichas f
        WHERE f.id = $1
      `, [id]);
      if (!f) return res.status(404).json({ ok: false, error: 'Ficha não encontrada' });
      res.json({ ok: true, fields: _fichaParaCampos(f) });
    } catch (e) {
      console.error('[atb] /api/parecer/:id error:', e);
      res.status(500).json({ ok: false, error: e.message });
    }
  });
}
