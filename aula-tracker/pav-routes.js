// pav-routes.js
// ════════════════════════════════════════════════════════════════════════════
//  Rotas do módulo PAV (bundle de prevenção de PAV).
//
//  /pav/m               → FORM DO PLANTÃO (mobile-first, também serve desktop).
//                         Cada leito em VM vira um card; o profissional preenche
//                         o turno vigente da sua categoria. SSR no molde do /atb/m.
//  POST /pav/api/check/:fichaId → grava o registro do turno (fato, não julgamento).
//
//  Reuso / disciplina:
//   • turnoVigente / podeEscrever / itensDaCategoria / leitosVisiveis / saloesDoContexto
//     e extraiRegistro vêm do pav-core.js — a regra vive lá, testada. Aqui é só
//     I/O: query da população ativa, render, e persistência.
//   • tenant-lock por domínio (req.atbTenant) já restringe a instituição, como no
//     ATB. O recorte NOVO é o de SALÃO (leitosVisiveis), empilhado sobre o tenant.
//   • O grid do SCIH (/pav/admin/grid) e o painel entram DEPOIS, neste mesmo arquivo.
//
//  Assinatura (registrada no app.js):
//    registerPavRoutes(app, pool, pavRequired, renderShell);
// ════════════════════════════════════════════════════════════════════════════

import {
  turnoVigente, podeEscrever, itensDaCategoria, leitosVisiveis, saloesDoContexto,
  extraiRegistro, relacaoPF, efeitoEncerramento, coberturaDoDia, estadoTurnosDoDia,
  REGISTRO, SALOES, SECRECAO_QUANTIDADE,
  SECRECAO_ASPECTO, SUBGLOTICA_VIA, SUBGLOTICA_VIA_DEFAULT, CATEGORIAS_PAV, DESFECHOS, TURNOS, hojeISO,
} from './pav-core.js';

function safe(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const SALAO_LABEL = Object.fromEntries(SALOES);
const TURNO_LABEL = { M: 'Manhã', T: 'Tarde', N: 'Noite', E: 'Madrugada' };

// Categoria de trabalho do req.user. super_admin sem categoria assume 'fisio'
// (só para poder ver/testar a tela — a escrita dele é sempre retroativa/livre).
function categoriaDe(user, adm) {
  if (user?.categoria_pav) return user.categoria_pav;
  if (user?.super_admin || adm) return 'fisio';
  return null;
}

// Contexto de escopo (turno × salão) a partir do req.user + sessão.
// O salão da enf vem do cookie de sessão pav_salao (seleção por sessão); a fisio
// alcança os dois. super_admin alcança tudo.
function contextoDe(req, adm) {
  return {
    super_admin: !!(req.user?.super_admin) || adm,
    categoria_pav: categoriaDe(req.user, adm),
    salao_sessao: req.cookies?.pav_salao || null,
  };
}

export function registerPavRoutes(app, pool, pavRequired, renderShell, scihRequired) {

  // Dias de VM (D+n) de um episódio até hoje — só para exibição no card.
  const dPlus = (intub) => {
    if (!intub) return '';
    const ini = new Date(intub); ini.setHours(0,0,0,0);
    const hoje = new Date(); hoje.setHours(0,0,0,0);
    const n = Math.floor((hoje - ini) / 86400000);
    return n >= 0 ? `D+${n}` : '';
  };

  // ── FORM DO PLANTÃO ───────────────────────────────────────────────────────
  // ══════════════════════════════════════════════════════════════════════════
  //  GRID DE VIGILÂNCIA DO SCIH  (/pav/admin/grid) — scihRequired
  // ══════════════════════════════════════════════════════════════════════════
  // Visão de vigilância: TODOS os episódios ativos dos dois salões (SCIH cruza
  // tudo, sem recorte de salão). Mostra cobertura do dia por turno, pendências
  // de extubação (com confirmação do lado do SCIH) e contadores de topo.
  // FILTRA dado de treino (treino=false) — trial não polui a vigilância real.
  // NÃO gera indicador de VM-dia/PAV (isso é do ATB); só adesão/cobertura.
  const gridGuard = scihRequired || pavRequired;
  app.get('/pav/admin/grid', gridGuard, async (req, res) => {
    try {
      const sigla = req.atbTenant || '';
      const hoje = hojeISO();

      const params = [];
      let where = `f.estado IN ('ativo','extubacao_pendente') AND COALESCE(f.treino,false) = false`;
      if (sigla) { params.push(sigla); where += ` AND i.sigla = $${params.length}`; }

      const { rows: fichas } = await pool.query(`
        SELECT f.id, f.paciente_nome, f.paciente_nome_raw, f.prontuario, f.leito, f.salao,
               f.data_intubacao, f.estado, f.data_extubacao, f.desfecho,
               f.extub_registrada_por_nome, f.extub_registrada_em,
               i.sigla AS instituicao
          FROM pav_fichas f
          LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
         WHERE ${where}
         ORDER BY f.salao, f.leito NULLS LAST, f.id`, params);

      // Checks de HOJE de todas as fichas, para a cobertura por turno.
      let checksHoje = {};
      if (fichas.length) {
        const ids = fichas.map(f => f.id);
        const { rows } = await pool.query(
          `SELECT ficha_id, turno, itens FROM pav_checks
            WHERE ficha_id = ANY($1::int[]) AND data = $2 AND COALESCE(treino,false) = false`,
          [ids, hoje]);
        for (const r of rows) {
          (checksHoje[r.ficha_id] = checksHoje[r.ficha_id] || []).push({ turno: r.turno, itens: r.itens });
        }
      }

      res.send(renderGrid({ sigla, fichas, checksHoje, hoje, dPlus }));
    } catch (e) {
      console.error('ERRO /pav/admin/grid', e);
      res.status(500).send(renderShell('Erro', `<div class="card"><h1>Erro</h1><p>${safe(e.message)}</p></div>`));
    }
  });

  app.get('/pav/m', pavRequired, async (req, res) => {
    try {
      const adm = req.cookies?.adm === '1';
      const ctx = contextoDe(req, adm);
      const vig = turnoVigente(new Date());
      const sigla = req.atbTenant || '';

      // A enfermagem precisa ter escolhido o salão da sessão. Se não escolheu
      // (e não é fisio/super), mostra o seletor de salão antes de tudo.
      const precisaEscolherSalao = ctx.categoria_pav === 'enf' && !ctx.salao_sessao && !ctx.super_admin;
      if (precisaEscolherSalao) {
        return res.send(renderSalaoPicker(sigla));
      }

      const saloesAlcance = saloesDoContexto(ctx);

      // População ativa: episódios em VM, no tenant, nos salões do contexto.
      const params = [];
      let where = 'f.ativo = true';
      if (sigla) { params.push(sigla); where += ` AND i.sigla = $${params.length}`; }
      if (saloesAlcance.length) {
        params.push(saloesAlcance);
        where += ` AND f.salao = ANY($${params.length}::text[])`;
      } else {
        where += ' AND false'; // sem alcance de salão → nada visível
      }

      const { rows: fichas } = await pool.query(`
        SELECT f.id, f.paciente_nome, f.paciente_nome_raw, f.prontuario, f.leito, f.salao,
               f.data_intubacao, f.numero_tubo, f.rima_labial, f.estado,
               f.data_extubacao, f.desfecho, f.extub_registrada_por_nome,
               i.sigla AS instituicao
          FROM pav_fichas f
          LEFT JOIN atb_instituicoes i ON i.id = f.instituicao_id
         WHERE ${where}
         ORDER BY f.salao, f.leito NULLS LAST, f.id`, params);

      // Já preenchidos neste turno vigente (para marcar o card como "feito").
      let feitos = new Set();
      // Último registro conhecido de cada ficha, para mostrar como REFERÊNCIA
      // passiva ao lado dos campos (Opção A: contexto sem carry-forward — o campo
      // começa vazio, isto é só o "anterior: X" ao lado). Pega o check mais recente
      // ANTERIOR ao turno vigente, de qualquer categoria (último valor conhecido).
      let anteriores = {};
      if (fichas.length) {
        const ids = fichas.map(f => f.id);
        if (vig) {
          const { rows } = await pool.query(
            `SELECT ficha_id FROM pav_checks WHERE ficha_id = ANY($1::int[]) AND data = $2 AND turno = $3`,
            [ids, vig.data, vig.turno]);
          feitos = new Set(rows.map(r => r.ficha_id));
        }
        // Último check por ficha: a linha com maior created_at entre as de maior
        // data, excluindo o turno vigente. Subquery de MAX (ANSI, não DISTINCT ON)
        // para ficar testável e alinhado ao resto do repo.
        const { rows: ult } = await pool.query(`
          SELECT c.ficha_id, c.data, c.turno, c.categoria, c.itens, c.vent, c.secrecao,
                 c.preenchido_por_nome, c.identificacao_manual
            FROM pav_checks c
            JOIN (
              SELECT ficha_id, MAX(created_at) AS mx
                FROM pav_checks
               WHERE ficha_id = ANY($1::int[])
                 ${vig ? 'AND NOT (data = $2 AND turno = $3)' : ''}
               GROUP BY ficha_id
            ) m ON m.ficha_id = c.ficha_id AND m.mx = c.created_at`,
          vig ? [ids, vig.data, vig.turno] : [ids]);
        for (const r of ult) anteriores[r.ficha_id] = r;
      }

      res.send(renderForm({ sigla, ctx, vig, fichas, feitos, anteriores, dPlus }));
    } catch (e) {
      console.error('ERRO /pav/m', e);
      res.status(500).send(renderShell('Erro', `<div class="card"><h1>Erro</h1><p class="mut">${safe(e.message)}</p></div>`));
    }
  });

  // Seleção de salão da enfermagem (grava cookie de sessão).
  app.post('/pav/salao', pavRequired, (req, res) => {
    const salao = SALAO_LABEL[req.body?.salao] ? req.body.salao : null;
    if (salao) res.cookie('pav_salao', salao, { httpOnly: true, sameSite: 'lax', maxAge: 16 * 3600 * 1000 });
    res.redirect('/pav/m');
  });
  app.get('/pav/trocar-salao', pavRequired, (req, res) => {
    res.clearCookie('pav_salao'); res.redirect('/pav/m');
  });

  // ── ABERTURA DE EPISÓDIO ──────────────────────────────────────────────────
  // Qualquer profissional PAV abre, a QUALQUER hora (paciente vai a VM em
  // qualquer horário) — SEM trava de turno. Alcance de salão respeitado. A data
  // de intubação é FATO digitado (pode ser algumas horas atrás); o cadastro pode
  // cair no turno seguinte. Só o salão precisa estar no alcance do contexto.
  app.post('/pav/api/abrir', pavRequired, async (req, res) => {
    try {
      const adm = req.cookies?.adm === '1';
      const ctx = contextoDe(req, adm);
      const b = req.body || {};

      const salao = String(b.salao || '').trim();
      if (!SALAO_LABEL[salao]) return res.status(400).json({ erro: 'salão inválido' });
      if (!saloesDoContexto(ctx).includes(salao))
        return res.status(403).json({ erro: 'salão fora do seu alcance' });

      const nome = String(b.paciente_nome || '').trim();
      if (!nome) return res.status(400).json({ erro: 'nome do paciente é obrigatório' });
      const dataIntub = String(b.data_intubacao || '').trim();
      if (!/^\d{4}-\d{2}-\d{2}$/.test(dataIntub)) return res.status(400).json({ erro: 'data de intubação inválida' });

      // Instituição: pelo tenant do portal (ou a única, se não travado).
      let instId = null;
      if (req.atbTenant) {
        const { rows } = await pool.query(`SELECT id FROM atb_instituicoes WHERE sigla=$1`, [req.atbTenant]);
        instId = rows[0]?.id || null;
      } else {
        const { rows } = await pool.query(`SELECT id FROM atb_instituicoes ORDER BY id LIMIT 1`);
        instId = rows[0]?.id || null;
      }

      const { rows } = await pool.query(`
        INSERT INTO pav_fichas
          (instituicao_id, paciente_nome, prontuario, salao, leito,
           data_intubacao, numero_tubo, rima_labial, ativo, estado,
           aberta_por, aberta_por_nome, treino)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true,'ativo',$9,$10,$11)
        RETURNING id`,
        [instId, nome.slice(0,200), String(b.prontuario||'').trim().slice(0,60) || null,
         salao, String(b.leito||'').trim().slice(0,20) || null, dataIntub,
         String(b.numero_tubo||'').trim().slice(0,20) || null,
         String(b.rima_labial||'').trim().slice(0,20) || null,
         req.user?.id || null, req.user?.full_name || null, !!req.user?.treino]);

      res.json({ ok: true, id: rows[0].id });
    } catch (e) {
      console.error('ERRO POST /pav/api/abrir', e);
      res.status(500).json({ erro: e.message });
    }
  });

  // ── ENCERRAMENTO (dois níveis) ────────────────────────────────────────────
  // acao 'registrar': marca a extubação (data + desfecho). Fisio/SCIH/super →
  //   encerra direto. Enf → vira 'extubacao_pendente' (fica na lista, aguarda revisão).
  // acao 'confirmar': fisio/SCIH confirmam uma pendência da enf → 'encerrado'
  //   (herda data/desfecho já preenchidos, podendo corrigir).
  app.post('/pav/api/encerrar/:fichaId', pavRequired, async (req, res) => {
    try {
      const adm = req.cookies?.adm === '1';
      const ctx = { ...contextoDe(req, adm), scih: !!(req.user?.scih) };
      const b = req.body || {};
      const fichaId = parseInt(req.params.fichaId, 10);
      if (!Number.isFinite(fichaId)) return res.status(400).json({ erro: 'ficha inválida' });

      const { rows } = await pool.query(
        `SELECT f.id, f.salao, f.estado, f.data_extubacao, f.desfecho, i.sigla
           FROM pav_fichas f LEFT JOIN atb_instituicoes i ON i.id=f.instituicao_id
          WHERE f.id=$1`, [fichaId]);
      const ficha = rows[0];
      if (!ficha) return res.status(404).json({ erro: 'episódio não encontrado' });
      if (req.atbTenant && ficha.sigla && ficha.sigla !== req.atbTenant && !ctx.super_admin)
        return res.status(403).json({ erro: 'episódio de outra unidade' });
      if (!saloesDoContexto(ctx).includes(ficha.salao) && !ctx.super_admin)
        return res.status(403).json({ erro: 'salão fora do seu alcance' });
      if (ficha.estado === 'encerrado') return res.status(409).json({ erro: 'episódio já encerrado' });

      const acao = (b.acao === 'confirmar') ? 'confirmar' : 'registrar';
      const ef = efeitoEncerramento(ctx, acao);
      if (!ef.estado_novo) return res.status(403).json({ erro: ef.motivo || 'sem permissão' });

      const nome = req.user?.full_name || null;

      if (acao === 'confirmar') {
        // Herda data/desfecho da pendência; permite correção se vier no corpo.
        const dataExtub = /^\d{4}-\d{2}-\d{2}$/.test(String(b.data_extubacao||'')) ? b.data_extubacao : ficha.data_extubacao;
        const desfecho = DESFECHOS.some(d => d[0] === b.desfecho) ? b.desfecho : ficha.desfecho;
        await pool.query(`
          UPDATE pav_fichas SET estado='encerrado', ativo=false,
            data_extubacao=$2, desfecho=$3,
            extub_confirmada_por=$4, extub_confirmada_por_nome=$5, extub_confirmada_em=now(),
            updated_at=now()
          WHERE id=$1`, [ficha.id, dataExtub, desfecho, req.user?.id || null, nome]);
        return res.json({ ok: true, estado: 'encerrado' });
      }

      // acao 'registrar': exige data + desfecho.
      const dataExtub = String(b.data_extubacao||'').trim();
      if (!/^\d{4}-\d{2}-\d{2}$/.test(dataExtub)) return res.status(400).json({ erro: 'data de extubação inválida' });
      const desfecho = DESFECHOS.some(d => d[0] === b.desfecho) ? b.desfecho : null;
      if (!desfecho) return res.status(400).json({ erro: 'desfecho inválido' });

      if (ef.encerra) {
        // Fisio/SCIH/super: encerra direto.
        await pool.query(`
          UPDATE pav_fichas SET estado='encerrado', ativo=false,
            data_extubacao=$2, desfecho=$3,
            extub_registrada_por=$4, extub_registrada_por_nome=$5, extub_registrada_em=now(),
            extub_confirmada_por=$4, extub_confirmada_por_nome=$5, extub_confirmada_em=now(),
            updated_at=now()
          WHERE id=$1`, [ficha.id, dataExtub, desfecho, req.user?.id || null, nome]);
        return res.json({ ok: true, estado: 'encerrado' });
      }

      // Enf: registra extubação, vira pendente (continua na lista).
      await pool.query(`
        UPDATE pav_fichas SET estado='extubacao_pendente',
          data_extubacao=$2, desfecho=$3,
          extub_registrada_por=$4, extub_registrada_por_nome=$5, extub_registrada_em=now(),
          updated_at=now()
        WHERE id=$1`, [ficha.id, dataExtub, desfecho, req.user?.id || null,
          (contextoDe(req, adm).categoria_pav === 'enf') ? (String(b.identificacao||'').trim().slice(0,200) || nome) : nome]);
      res.json({ ok: true, estado: 'extubacao_pendente' });
    } catch (e) {
      console.error('ERRO POST /pav/api/encerrar', e);
      res.status(500).json({ erro: e.message });
    }
  });

  // ── GRAVAÇÃO DO REGISTRO DO TURNO ─────────────────────────────────────────
  app.post('/pav/api/check/:fichaId', pavRequired, async (req, res) => {
    try {
      const adm = req.cookies?.adm === '1';
      const ctx = contextoDe(req, adm);
      const fichaId = parseInt(req.params.fichaId, 10);
      if (!Number.isFinite(fichaId)) return res.status(400).json({ erro: 'ficha inválida' });

      const { rows } = await pool.query(
        `SELECT f.id, f.salao, f.instituicao_id, i.sigla
           FROM pav_fichas f LEFT JOIN atb_instituicoes i ON i.id=f.instituicao_id
          WHERE f.id=$1 AND f.ativo=true`, [fichaId]);
      const ficha = rows[0];
      if (!ficha) return res.status(404).json({ erro: 'episódio não encontrado ou já encerrado' });

      // Tenant: não deixa gravar em ficha de outra unidade quando o portal é travado.
      if (req.atbTenant && ficha.sigla && ficha.sigla !== req.atbTenant && !ctx.super_admin)
        return res.status(403).json({ erro: 'episódio de outra unidade' });

      const vig = turnoVigente(new Date());
      const alvo = vig
        ? { data: vig.data, turno: vig.turno, salao: ficha.salao }
        : { data: null, turno: null, salao: ficha.salao };

      const perm = podeEscrever(alvo, ctx, new Date());
      if (!perm.permitido) return res.status(403).json({ erro: perm.motivo || 'sem permissão para este turno/salão' });

      // Registro factual (pav-core sanitiza e valida; motivos = rejeições factuais).
      const reg = extraiRegistro(req.body);
      if (reg.motivos.length) return res.status(400).json({ erro: reg.motivos[0], motivos: reg.motivos });

      const categoria = vig ? vig.categoria : ctx.categoria_pav;
      const nome = req.user?.full_name || null;
      // enf compartilhada: identificação digitada no ato (nome + COREN).
      const identificacao = (categoria === 'enf')
        ? String(req.body?.identificacao || '').trim().slice(0, 200) || null
        : null;

      // Upsert por (ficha, data, turno, categoria). Correção dentro do turno
      // vigente acumula histórico (mesma disciplina de atb_evolutivos). O
      // timestamp do histórico vem como parâmetro ($14) — evita depender de
      // função de formatação do banco e mantém o SQL portável.
      await pool.query(`
        INSERT INTO pav_checks
          (ficha_id, instituicao_id, data, turno, categoria, salao,
           itens, vent, secrecao, preenchido_por, preenchido_por_nome,
           identificacao_manual, retroativo, treino)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$15)
        ON CONFLICT (ficha_id, data, turno, categoria) DO UPDATE SET
          itens = EXCLUDED.itens, vent = EXCLUDED.vent, secrecao = EXCLUDED.secrecao,
          preenchido_por = EXCLUDED.preenchido_por, preenchido_por_nome = EXCLUDED.preenchido_por_nome,
          identificacao_manual = EXCLUDED.identificacao_manual, retroativo = EXCLUDED.retroativo,
          treino = EXCLUDED.treino,
          historico = pav_checks.historico || jsonb_build_object(
            'em', $14::text,
            'por', pav_checks.preenchido_por_nome,
            'itens', pav_checks.itens),
          updated_at = now()`,
        [ficha.id, ficha.instituicao_id, alvo.data, alvo.turno, categoria, ficha.salao,
         JSON.stringify(reg.itens), JSON.stringify(reg.vent),
         reg.secrecao ? JSON.stringify(reg.secrecao) : null,
         req.user?.id || null, nome, identificacao, !!perm.retroativo,
         new Date().toISOString(), !!req.user?.treino]);

      await pool.query(`UPDATE pav_fichas SET ultimo_check_em = now(), updated_at = now() WHERE id=$1`, [ficha.id]);

      res.json({ ok: true, retroativo: !!perm.retroativo });
    } catch (e) {
      console.error('ERRO POST /pav/api/check', e);
      res.status(500).json({ erro: e.message });
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  //  RENDER
  // ══════════════════════════════════════════════════════════════════════════
  // ── Render do grid de vigilância do SCIH (desktop) ────────────────────────
  function renderGrid({ sigla, fichas, checksHoje, hoje, dPlus }) {
    const emVM = fichas.length;
    const pendentes = fichas.filter(f => f.estado === 'extubacao_pendente');
    // "incompletos hoje": ativos com menos de 1 turno preenchido no dia
    let incompletos = 0;
    for (const f of fichas) {
      if (f.estado !== 'ativo') continue;
      const cob = coberturaDoDia(checksHoje[f.id] || []);
      if (cob.preenchidos === 0) incompletos++;
    }

    const hojeBr = hoje.split('-').reverse().join('/');

    // Bloco de pendências (se houver) — ação de confirmar do lado do SCIH.
    let blocoPend = '';
    if (pendentes.length) {
      const linhas = pendentes.map(f => {
        const dtx = f.data_extubacao ? String(f.data_extubacao).slice(0,10).split('-').reverse().join('/') : '';
        const desf = (DESFECHOS.find(d => d[0] === f.desfecho) || [null, f.desfecho || ''])[1];
        return `<div class="pend-row">
          <div class="pend-info">
            <b>${safe(f.paciente_nome || 'Paciente')}</b>
            <span class="mut">${safe(SALAO_LABEL[f.salao]||f.salao)} · Leito ${safe(f.leito||'—')}</span>
            <span class="pend-meta">Extubação ${safe(dtx)}${desf ? ' · ' + safe(desf) : ''}${f.extub_registrada_por_nome ? ' · registrada por ' + safe(f.extub_registrada_por_nome) : ''}</span>
          </div>
          <button class="confirmar" onclick="confirmarPend(${f.id})">Confirmar encerramento</button>
        </div>`;
      }).join('');
      blocoPend = `<div class="pend-box">
        <div class="pend-box-tit">⏳ Extubações aguardando confirmação (${pendentes.length})</div>
        ${linhas}
      </div>`;
    }

    // Linhas da grade.
    const linhas = fichas.map(f => {
      const cob = coberturaDoDia(checksHoje[f.id] || []);
      const dp = dPlus(f.data_intubacao) || '';
      const circulos = TURNOS.map(def => {
        const st = cob.estados[def.turno];
        const cls = st === 'conforme' ? 'c-ok' : (st === 'nc' ? 'c-nc' : 'c-vazio');
        const tit = `${def.label}: ${st === 'conforme' ? 'conforme' : (st === 'nc' ? 'com não-conformidade' : 'sem registro')}`;
        return `<span class="circ ${cls}" title="${tit}">${def.turno}</span>`;
      }).join('');
      const pend = f.estado === 'extubacao_pendente';
      return `<tr class="${pend ? 'row-pend' : ''}">
        <td class="td-leito">${safe(f.leito || '—')}</td>
        <td class="mut">${safe(SALAO_LABEL[f.salao] || f.salao || '')}</td>
        <td>${safe(f.paciente_nome || f.paciente_nome_raw || 'Paciente')}${pend ? ' <span class="tag-pend">extubação pendente</span>' : ''}</td>
        <td class="td-dp">${dp}</td>
        <td class="td-circ">${circulos}</td>
        <td class="td-cob mut">${cob.preenchidos}/${cob.total_turnos}${cob.preenchidos ? ` · ${cob.conformes} conf.` : ''}</td>
      </tr>`;
    }).join('');

    const corpo = fichas.length
      ? `<table class="grid">
          <thead><tr>
            <th>Leito</th><th>Salão</th><th>Paciente</th><th>VM</th>
            <th>Turnos hoje (${TURNOS.map(t=>t.turno).join('·')})</th><th>Cobertura</th>
          </tr></thead>
          <tbody>${linhas}</tbody>
        </table>`
      : `<div class="vazio">Nenhum paciente em ventilação mecânica no momento.</div>`;

    return `${HEAD_ADMIN(sigla)}
<div class="top">
  <div class="l1"><h1>Vigilância PAV${sigla ? ' · ' + safe(sigla) : ''}</h1><span class="data">${hojeBr}</span></div>
</div>
<div class="wrap">
  <div class="cards">
    <div class="stat"><div class="stat-n">${emVM}</div><div class="stat-l">em ventilação</div></div>
    <div class="stat"><div class="stat-n">${incompletos}</div><div class="stat-l">sem registro hoje</div></div>
    <div class="stat"><div class="stat-n">${pendentes.length}</div><div class="stat-l">extubações pendentes</div></div>
  </div>
  ${blocoPend}
  ${corpo}
  <div class="legenda">
    <span><span class="circ c-ok">M</span> conforme</span>
    <span><span class="circ c-nc">T</span> com não-conformidade</span>
    <span><span class="circ c-vazio">N</span> sem registro</span>
    <span class="mut">Classificação de PAV: módulo ATB</span>
  </div>
</div>
${GRID_SCRIPT()}
${FOOT()}`;
  }

  function HEAD_ADMIN(sigla) {
    return `<!doctype html><html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vigilância PAV${sigla ? ' · ' + safe(sigla) : ''}</title>
<style>
  :root{--pri:#0e6b52;--bg:#f1f5f4;--card:#fff;--ink:#1e293b;--mut:#64748b;--line:#e2e8f0;
    --ok:#0e7a4b;--ok-bg:#dff2e8;--nc:#c0392b;--nc-bg:#fdecea;--warn:#b45309;--warn-bg:#fef3e2;--vazio:#cbd5e1}
  *{box-sizing:border-box}
  body{margin:0;font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--ink)}
  .mut{color:var(--mut)}
  .top{background:var(--pri);color:#fff;padding:14px 22px}
  .top .l1{display:flex;align-items:center;gap:12px;max-width:1100px;margin:0 auto}
  .top h1{font-size:17px;font-weight:700;margin:0;flex:1}
  .top .data{font-size:13px;opacity:.9}
  .wrap{max-width:1100px;margin:0 auto;padding:20px 22px}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:18px}
  .stat{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px}
  .stat-n{font-size:28px;font-weight:600;line-height:1}
  .stat-l{font-size:13px;color:var(--mut);margin-top:4px}
  .pend-box{background:var(--warn-bg);border:1px solid #f0d8b0;border-radius:12px;padding:14px 16px;margin-bottom:18px}
  .pend-box-tit{font-size:14px;font-weight:600;color:var(--warn);margin-bottom:10px}
  .pend-row{display:flex;align-items:center;gap:12px;padding:8px 0;border-top:1px solid #f0d8b0}
  .pend-row:first-of-type{border-top:0}
  .pend-info{flex:1;display:flex;flex-direction:column;gap:2px}
  .pend-info b{font-size:14px}
  .pend-info .mut{font-size:12px}
  .pend-meta{font-size:12px;color:var(--warn)}
  .confirmar{font:inherit;font-size:13px;font-weight:600;padding:8px 14px;border:0;border-radius:9px;background:var(--pri);color:#fff;cursor:pointer;white-space:nowrap}
  table.grid{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
  table.grid th{text-align:left;font-size:12px;font-weight:600;color:var(--mut);padding:11px 14px;background:#f8fafc;border-bottom:1px solid var(--line)}
  table.grid td{padding:11px 14px;border-bottom:1px solid var(--line)}
  table.grid tr:last-child td{border-bottom:0}
  .row-pend{background:var(--warn-bg)}
  .td-leito{font-weight:600}
  .td-dp{font-weight:600;color:var(--pri)}
  .td-circ{white-space:nowrap}
  .circ{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:50%;font-size:11px;font-weight:700;margin-right:3px;color:#fff}
  .c-ok{background:var(--ok)} .c-nc{background:var(--nc)} .c-vazio{background:var(--vazio);color:#fff}
  .tag-pend{font-size:11px;background:var(--warn-bg);color:var(--warn);border:1px solid #f0d8b0;border-radius:5px;padding:1px 6px;margin-left:6px}
  .vazio{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:30px;text-align:center;color:var(--mut)}
  .legenda{display:flex;gap:18px;flex-wrap:wrap;align-items:center;margin-top:14px;font-size:12px;color:var(--mut)}
  .legenda .circ{width:18px;height:18px;font-size:9px;margin-right:5px}
</style></head><body>`;
  }

  function GRID_SCRIPT() {
    return `<script>
function confirmarPend(id){
  if(!confirm('Confirmar o encerramento deste episódio? A ficha sairá da vigilância e o VM-dia será fechado.')) return;
  fetch('/pav/api/encerrar/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({acao:'confirmar'})})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j}})})
    .then(function(x){ if(!x.ok){ alert(x.j.erro||'Erro'); return; } location.reload(); })
    .catch(function(){ alert('Falha de conexão'); });
}
</script>`;
  }

  function renderSalaoPicker(sigla) {
    const botoes = SALOES.map(([k, label]) =>
      `<form method="post" action="/pav/salao"><input type="hidden" name="salao" value="${safe(k)}">
       <button class="salao-btn" type="submit">${safe(label)}<span>${safe(k)}</span></button></form>`).join('');
    return `${HEAD(sigla, 'Selecionar salão')}
<div class="top"><div class="l1"><h1>Bundle PAV${sigla ? ' · ' + safe(sigla) : ''}</h1></div></div>
<div class="wrap">
  <p class="mut" style="margin:16px 4px">Selecione o salão em que você está neste plantão. Você só verá e registrará os leitos deste salão.</p>
  <div class="salao-grid">${botoes}</div>
</div>${FOOT()}`;
  }

  function renderForm({ sigla, ctx, vig, fichas, feitos, anteriores, dPlus }) {
    const cat = ctx.categoria_pav;
    const catLabel = (CATEGORIAS_PAV.find(c => c[0] === cat) || [null, cat])[1] || '—';
    const itens = itensDaCategoria(cat);
    const semTurno = !vig;
    const turnoTxt = vig ? `${TURNO_LABEL[vig.turno]} · ${vig.data.split('-').reverse().join('/')}` : 'Fora de turno';

    // Aviso quando a categoria do usuário não bate com o turno vigente.
    const turnoDaOutra = vig && ctx.categoria_pav && vig.categoria !== ctx.categoria_pav && !ctx.super_admin;
    // Pode PREENCHER check? (só no turno vigente da própria categoria, ou super)
    const podeCheck = ctx.super_admin || (vig && (!ctx.categoria_pav || vig.categoria === ctx.categoria_pav));

    const salaoInfo = cat === 'enf' && ctx.salao_sessao
      ? `<a class="full" href="/pav/trocar-salao">${safe(SALAO_LABEL[ctx.salao_sessao] || ctx.salao_sessao)} ⇄</a>` : '';

    // Aviso de contexto (não bloqueia a lista nem o botão de abrir).
    let aviso = '';
    if (semTurno) aviso = `<div class="aviso">Fora de turno: você pode abrir/encerrar fichas, mas o preenchimento do bundle só é possível no turno cronológico da sua categoria.</div>`;
    else if (turnoDaOutra) aviso = `<div class="aviso">O turno vigente é da ${safe(vig.categoria)}. Você pode abrir/encerrar fichas; o preenchimento do bundle é da categoria vigente.</div>`;

    // Salões que o usuário pode escolher ao abrir uma ficha.
    const saloesUsuario = saloesDoContexto(ctx);

    let lista;
    if (!fichas.length) {
      lista = `<div class="aviso">Nenhum paciente em ventilação mecânica ${cat === 'enf' && ctx.salao_sessao ? 'neste salão' : 'nos seus salões'} no momento. Use “+ paciente em VM” para abrir uma ficha.</div>`;
    } else {
      lista = fichas.map(f => card(f, itens, feitos.has(f.id), cat, dPlus, podeCheck, ctx, (anteriores||{})[f.id])).join('');
    }

    return `${HEAD(sigla, 'Plantão')}
<div class="top">
  <div class="l1">
    <h1>Bundle PAV${sigla ? ' · ' + safe(sigla) : ''}</h1>
    ${salaoInfo}
  </div>
  <div class="l2"><span class="turno">${safe(turnoTxt)}</span><span class="cat">${safe(catLabel)}</span></div>
</div>
<div class="wrap">
  <button class="novo" type="button" onclick="abrirNovo()">+ paciente em VM</button>
  ${aviso}
  ${lista}
</div>
${SHEET(itens, cat)}
${SHEET_NOVO(saloesUsuario)}
${SHEET_ENCERRAR()}
${FOOT()}
${SCRIPT()}`;
  }

  // Card de um leito.
  // Monta o "anterior" (Opção A): mapa key→texto curto do último valor conhecido,
  // + um rótulo de quando/quem. Não é default de campo; é referência ao lado.
  function resumoAnterior(anterior) {
    if (!anterior) return null;
    const out = {};
    const it = anterior.itens || {};
    for (const c of REGISTRO) {
      const v = it[c.key];
      if (!v) continue;
      if (c.tipo === 'valor' && v.valor != null) out[c.key] = String(v.valor);
      else if (v.resp === 'sim') out[c.key] = 'sim';
      else if (v.resp === 'nao') out[c.key] = 'não';
    }
    const vt = anterior.vent || {};
    if (vt.fio2 != null) out.fio2 = String(vt.fio2);
    if (vt.peep != null) out.peep = String(vt.peep);
    if (vt.pao2 != null) out.pao2 = String(vt.pao2);
    const s = anterior.secrecao;
    if (s && s.aspecto) out.secrecao = s.aspecto + (s.quantidade ? ', ' + s.quantidade : '');
    const dataBr = anterior.data ? String(anterior.data).slice(0,10).split('-').reverse().join('/') : '';
    const quem = anterior.preenchido_por_nome || anterior.identificacao_manual || '';
    out.__rot = `${TURNO_LABEL[anterior.turno] || anterior.turno || ''} ${dataBr}`.trim() + (quem ? ' · ' + quem : '');
    return out;
  }

  function card(f, itens, feito, cat, dPlus, podeCheck, ctx, anterior) {
    const nome = safe(f.paciente_nome || f.paciente_nome_raw || 'Paciente');
    const dp = dPlus(f.data_intubacao);
    const sub = [
      f.leito ? 'Leito ' + safe(f.leito) : '',
      SALAO_LABEL[f.salao] ? safe(SALAO_LABEL[f.salao]) : safe(f.salao || ''),
      f.numero_tubo ? 'TOT ' + safe(f.numero_tubo) : '',
      f.rima_labial ? 'rima ' + safe(f.rima_labial) : '',
    ].filter(Boolean).join(' · ');

    const ant = resumoAnterior(anterior);
    const antAttr = ant ? ` data-ant='${safe(JSON.stringify(ant))}'` : '';

    const pendente = f.estado === 'extubacao_pendente';
    // Quem pode CONFIRMAR uma pendência: fisio, SCIH, super-admin.
    const podeConfirmar = ctx.super_admin || ctx.categoria_pav === 'fisio' || ctx.scih;

    // Botão de bundle só quando pode preencher check (turno vigente da categoria).
    const btnBundle = podeCheck && !pendente
      ? `<button class="abrir" type="button" onclick="abrir(${f.id})">${feito ? 'Revisar turno' : 'Registrar turno'}</button>`
      : '';

    let bloco = '';
    if (pendente) {
      const dtx = f.data_extubacao ? String(f.data_extubacao).slice(0,10).split('-').reverse().join('/') : '';
      const desf = (DESFECHOS.find(d => d[0] === f.desfecho) || [null, f.desfecho || ''])[1];
      bloco = `<div class="pend">
        <div class="pend-tit">⏳ Extubação registrada${f.extub_registrada_por_nome ? ' por ' + safe(f.extub_registrada_por_nome) : ''}</div>
        <div class="pend-sub">${safe(dtx)}${desf ? ' · ' + safe(desf) : ''} — aguarda confirmação</div>
        ${podeConfirmar ? `<button class="confirmar" type="button" onclick="confirmar(${f.id})">Confirmar encerramento</button>` : '<div class="pend-nota">Confirmação por fisioterapia ou SCIH.</div>'}
      </div>`;
    }

    const btnEncerrar = !pendente
      ? `<button class="encerrar" type="button" onclick="abrirEncerrar(${f.id}, '${nome.replace(/'/g,"\\'")}')">Registrar extubação</button>`
      : '';

    return `<div class="fcard ${feito ? 'done' : ''} ${pendente ? 'pendente' : ''}" data-ficha="${f.id}" data-nome="${nome}" data-sub="${safe(sub)}"${antAttr}>
      <div class="fc-head">
        <span class="nome">${nome}</span>
        ${dp ? `<span class="dp">${dp}</span>` : ''}
        ${feito && !pendente ? '<span class="badge-ok">✓ turno</span>' : ''}
      </div>
      <div class="sub">${sub || '—'}</div>
      ${bloco}
      ${btnBundle}
      ${btnEncerrar}
    </div>`;
  }

  // Bottom-sheet: um formulário genérico para os itens da categoria + parâmetros.
  function SHEET(itens, cat) {
    const linhasItem = itens.map(c => {
      if (c.tipo === 'valor') {
        return `<div class="row"><label>${safe(c.label)} <span class="ant" data-ant-key="${c.key}"></span></label>
          <input type="number" inputmode="decimal" name="v_${c.key}" placeholder="${safe(c.unidade || '')}"></div>`;
      }
      // sim_nao
      let extra = '';
      if (c.via) {
        const opts = SUBGLOTICA_VIA.map(([k, l]) =>
          `<option value="${safe(k)}"${k === SUBGLOTICA_VIA_DEFAULT ? ' selected' : ''}>${safe(l)}</option>`).join('');
        extra = `<select class="via" name="via_${c.key}" style="display:none">${opts}</select>`;
      }
      let just = '';
      if (c.justifica_se_nao) {
        just = `<input class="just" name="j_${c.key}" placeholder="Justificativa (obrigatória se Não)" style="display:none">`;
      }
      return `<div class="row simnao" data-key="${c.key}"${c.via ? ' data-via="1"' : ''}${c.justifica_se_nao ? ' data-just="1"' : ''}>
        <label>${safe(c.label)}${c.per === 'dia' ? ' <span class="tag1x">1×/dia</span>' : ''} <span class="ant" data-ant-key="${c.key}"></span></label>
        <div class="sn">
          <button type="button" class="sim" onclick="sn(this,'sim')">Sim</button>
          <button type="button" class="nao" onclick="sn(this,'nao')">Não</button>
          <input type="hidden" name="r_${c.key}" value="">
        </div>
        ${extra}${just}
      </div>`;
    }).join('');

    const secQtd = SECRECAO_QUANTIDADE.map(([k, l]) => `<option value="${safe(k)}">${safe(l)}</option>`).join('');
    const secAsp = SECRECAO_ASPECTO.map(([k, l]) => `<option value="${safe(k)}">${safe(l)}</option>`).join('');

    const idEnf = cat === 'enf'
      ? `<div class="row"><label>Identificação (nome · COREN)</label>
         <input name="identificacao" placeholder="Seu nome e COREN" autocomplete="name"></div>` : '';

    return `<div class="sheet-bg" id="bg" onclick="fechar()"></div>
<div class="sheet" id="sheet">
  <div class="sh-head"><b id="sh-nome">—</b><span id="sh-sub" class="mut"></span><button class="x" onclick="fechar()">✕</button></div>
  <div class="sh-body">
    ${linhasItem}
    <div class="sec-tit">Parâmetros ventilatórios</div>
    <div class="grid2">
      <div class="row"><label>FiO₂ (%) <span class="ant" data-ant-key="fio2"></span></label><input type="number" inputmode="decimal" name="fio2" oninput="calcPF()"></div>
      <div class="row"><label>PEEP (cmH₂O) <span class="ant" data-ant-key="peep"></span></label><input type="number" inputmode="decimal" name="peep"></div>
    </div>
    <div class="grid2">
      <div class="row"><label>PaO₂ (mmHg) <span class="ant" data-ant-key="pao2"></span></label><input type="number" inputmode="decimal" name="pao2" oninput="calcPF()"></div>
      <div class="row"><label>PaO₂/FiO₂</label><div class="pf" id="pf">—</div></div>
    </div>
    <div class="sec-tit">Secreção traqueal <span class="ant" data-ant-key="secrecao"></span></div>
    <div class="grid2">
      <div class="row"><label>Quantidade</label><select name="sec_quantidade"><option value="">—</option>${secQtd}</select></div>
      <div class="row"><label>Aspecto</label><select name="sec_aspecto"><option value="">—</option>${secAsp}</select></div>
    </div>
    ${idEnf}
  </div>
  <div class="sh-foot">
    <span id="sh-msg" class="mut"></span>
    <button class="salvar" id="btn-salvar" onclick="salvar()">Salvar turno</button>
  </div>
</div>`;
  }

  // Sheet de ABERTURA de ficha (novo paciente em VM).
  function SHEET_NOVO(saloesUsuario) {
    const opcSalao = saloesUsuario.map(k => `<option value="${safe(k)}">${safe(SALAO_LABEL[k] || k)}</option>`).join('');
    const hojeStr = new Date().toISOString().slice(0,10);
    return `<div class="sheet-bg" id="bg-novo" onclick="fecharNovo()"></div>
<div class="sheet" id="sheet-novo">
  <div class="sh-head"><b>Novo paciente em VM</b><button class="x" onclick="fecharNovo()">✕</button></div>
  <div class="sh-body">
    <div class="row"><label>Nome do paciente *</label><input name="n_nome" autocomplete="name"></div>
    <div class="grid2">
      <div class="row"><label>Prontuário</label><input name="n_prontuario" inputmode="numeric"></div>
      <div class="row"><label>Leito</label><input name="n_leito"></div>
    </div>
    <div class="grid2">
      <div class="row"><label>Salão *</label><select name="n_salao">${opcSalao}</select></div>
      <div class="row"><label>Data de intubação *</label><input type="date" name="n_data_intubacao" value="${hojeStr}"></div>
    </div>
    <div class="grid2">
      <div class="row"><label>Nº do tubo/TQT</label><input name="n_numero_tubo"></div>
      <div class="row"><label>Rima labial</label><input name="n_rima_labial"></div>
    </div>
  </div>
  <div class="sh-foot"><span id="novo-msg" class="mut"></span>
    <button class="salvar" id="btn-novo" onclick="salvarNovo()">Abrir ficha</button></div>
</div>`;
  }

  // Sheet de ENCERRAMENTO (registrar extubação: data + desfecho).
  function SHEET_ENCERRAR() {
    const opcDesf = DESFECHOS.map(([k,l]) => `<option value="${safe(k)}">${safe(l)}</option>`).join('');
    const hojeStr = new Date().toISOString().slice(0,10);
    return `<div class="sheet-bg" id="bg-enc" onclick="fecharEncerrar()"></div>
<div class="sheet" id="sheet-enc">
  <div class="sh-head"><b>Registrar extubação</b><span id="enc-nome" class="mut"></span><button class="x" onclick="fecharEncerrar()">✕</button></div>
  <div class="sh-body">
    <div class="row"><label>Data de extubação *</label><input type="date" name="e_data" value="${hojeStr}"></div>
    <div class="row"><label>Desfecho *</label><select name="e_desfecho"><option value="">—</option>${opcDesf}</select></div>
    <div class="row" id="enc-id-row" style="display:none"><label>Identificação (nome · COREN)</label><input name="e_identificacao" placeholder="Seu nome e COREN"></div>
    <div class="enc-nota mut">Fisioterapia e SCIH encerram direto. Enfermagem registra e a ficha aguarda confirmação de fisio/SCIH no período seguinte.</div>
  </div>
  <div class="sh-foot"><span id="enc-msg" class="mut"></span>
    <button class="salvar" id="btn-enc" onclick="salvarEncerrar()">Registrar</button></div>
</div>`;
  }

  // ── HTML shell (mobile PWA, paleta verde-clínico p/ distinguir do ATB azul) ──
  function HEAD(sigla, titulo) {
    return `<!doctype html><html lang="pt-BR"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, maximum-scale=1, user-scalable=no">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="theme-color" content="#0e6b52">
<title>PAV${sigla ? ' · ' + safe(sigla) : ''} — ${safe(titulo)}</title>
<style>
  :root{--pri:#0e6b52;--pri-d:#0a5240;--bg:#eef4f1;--card:#fff;--ink:#1e293b;--mut:#64748b;
    --line:#e2e8f0;--ok:#0e7a4b;--warn:#b45309;--warn-bg:#fef3e2;--danger:#c0392b;
    --sat:env(safe-area-inset-top);--sab:env(safe-area-inset-bottom)}
  *{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
  html,body{margin:0}
  body{font:15px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--ink);padding-bottom:calc(16px + var(--sab))}
  .mut{color:var(--mut)}
  .top{position:sticky;top:0;z-index:50;background:var(--pri);color:#fff;padding:calc(10px + var(--sat)) 14px 10px;box-shadow:0 2px 8px rgba(0,0,0,.15)}
  .top .l1{display:flex;align-items:center;gap:10px}
  .top h1{font-size:16px;font-weight:700;margin:0;flex:1;letter-spacing:.2px}
  .top a.full{color:#fff;font-size:12px;opacity:.9;text-decoration:none;background:rgba(255,255,255,.16);border-radius:8px;padding:6px 10px}
  .top .l2{display:flex;gap:10px;margin-top:7px;font-size:12.5px}
  .top .turno{background:rgba(255,255,255,.18);border-radius:7px;padding:3px 9px;font-weight:600}
  .top .cat{background:rgba(255,255,255,.1);border-radius:7px;padding:3px 9px}
  .wrap{max-width:640px;margin:0 auto;padding:12px 12px 0}
  .aviso{background:var(--warn-bg);border:1px solid #f0d8b0;color:var(--warn);border-radius:12px;padding:14px 15px;font-size:14px;margin-top:6px}
  .fcard{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:13px 14px;margin:0 0 11px;box-shadow:0 1px 3px rgba(15,23,42,.05)}
  .fcard.done{border-color:#bfe3d3;background:#f6fbf9}
  .fc-head{display:flex;align-items:center;gap:8px}
  .fcard .nome{font-weight:700;font-size:15px;flex:1}
  .fcard .dp{font-size:12px;font-weight:700;color:var(--pri);background:#e2f2ec;border-radius:6px;padding:2px 7px}
  .fcard .badge-ok{font-size:11px;font-weight:700;color:var(--ok);background:#dff2e8;border-radius:6px;padding:2px 7px}
  .fcard .sub{font-size:12px;color:var(--mut);margin:3px 0 10px}
  .fcard .abrir{width:100%;font:inherit;font-size:14px;font-weight:600;padding:10px;border:0;border-radius:10px;background:var(--pri);color:#fff;cursor:pointer}
  .fcard.done .abrir{background:#fff;color:var(--pri);border:1.5px solid var(--pri)}
  .salao-grid{display:flex;flex-direction:column;gap:12px;margin-top:8px}
  .salao-btn{width:100%;font:inherit;font-size:17px;font-weight:600;padding:22px;border:1.5px solid var(--line);border-radius:14px;background:#fff;color:var(--ink);cursor:pointer;display:flex;flex-direction:column;gap:4px}
  .salao-btn span{font-size:12px;color:var(--mut);font-weight:400}
  /* bottom-sheet */
  .sheet-bg{position:fixed;inset:0;background:rgba(15,23,42,.4);opacity:0;pointer-events:none;transition:.2s;z-index:60}
  .sheet-bg.on{opacity:1;pointer-events:auto}
  .sheet{position:fixed;left:0;right:0;bottom:0;z-index:70;background:var(--bg);border-radius:18px 18px 0 0;transform:translateY(100%);transition:.25s;max-height:92vh;display:flex;flex-direction:column}
  .sheet.on{transform:translateY(0)}
  .sh-head{display:flex;align-items:center;gap:8px;padding:14px 16px calc(12px);border-bottom:1px solid var(--line);background:#fff;border-radius:18px 18px 0 0}
  .sh-head b{font-size:15px}.sh-head .x{margin-left:auto;background:none;border:0;font-size:18px;color:var(--mut);cursor:pointer}
  .sh-body{overflow-y:auto;padding:12px 16px;-webkit-overflow-scrolling:touch}
  .row{margin-bottom:12px}
  .row label{display:block;font-size:13px;color:var(--mut);margin-bottom:5px}
  .row input,.row select{width:100%;font:inherit;font-size:15px;padding:10px 12px;border:1.5px solid var(--line);border-radius:10px;background:#fff;-webkit-appearance:none;appearance:none}
  .tag1x{font-size:10px;background:#eef2f7;color:var(--mut);border-radius:5px;padding:1px 5px;font-weight:600}
  .sn{display:flex;gap:8px}
  .sn button{flex:1;font:inherit;font-size:14px;font-weight:600;padding:11px 0;border:1.5px solid var(--line);border-radius:10px;background:#fff;color:var(--ink);cursor:pointer}
  .sn button.sim.on{background:#dff2e8;border-color:#9fd8bf;color:var(--ok)}
  .sn button.nao.on{background:#fdecea;border-color:#f2b8b0;color:var(--danger)}
  .just{margin-top:8px}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .sec-tit{font-size:13px;color:var(--mut);margin:16px 0 10px;padding-top:12px;border-top:1px solid var(--line)}
  .pf{font-size:18px;font-weight:700;padding:8px 0}
  .sh-foot{display:flex;align-items:center;gap:10px;padding:12px 16px calc(12px + var(--sab));border-top:1px solid var(--line);background:#fff}
  .sh-foot .salvar{margin-left:auto;font:inherit;font-size:15px;font-weight:700;padding:11px 22px;border:0;border-radius:10px;background:var(--pri);color:#fff;cursor:pointer}
  .sh-foot .salvar:disabled{opacity:.5}
  .novo{width:100%;font:inherit;font-size:15px;font-weight:600;padding:13px;border:1.5px dashed var(--pri);border-radius:12px;background:#fff;color:var(--pri);cursor:pointer;margin:2px 0 12px}
  .fcard.pendente{border-color:#f0d8b0;background:#fffaf2}
  .fcard .encerrar{width:100%;font:inherit;font-size:13px;padding:9px;border:1px solid var(--line);border-radius:10px;background:#fff;color:var(--mut);cursor:pointer;margin-top:7px}
  .pend{background:#fef3e2;border:1px solid #f0d8b0;border-radius:10px;padding:10px 12px;margin:0 0 8px}
  .pend-tit{font-size:13px;font-weight:600;color:var(--warn)}
  .pend-sub{font-size:12px;color:var(--warn);margin:2px 0 0;opacity:.85}
  .pend-nota{font-size:12px;color:var(--mut);margin-top:6px}
  .pend .confirmar{width:100%;font:inherit;font-size:14px;font-weight:600;padding:9px;border:0;border-radius:9px;background:var(--pri);color:#fff;cursor:pointer;margin-top:8px}
  .enc-nota{font-size:12px;line-height:1.4;margin-top:8px;padding-top:10px;border-top:1px solid var(--line)}
  .ant{font-size:11px;font-weight:400;color:var(--mut);background:#eef2f7;border-radius:5px;padding:1px 6px;margin-left:4px}
  .ant:empty{display:none}
</style></head><body>`;
  }
  function FOOT() { return `</body></html>`; }

  // ── Client: bottom-sheet, sim/não, P/F ao vivo, POST ──────────────────────
  function SCRIPT() {
    return `<script>
var atual=null;
function abrir(id){
  atual=id;
  var c=document.querySelector('.fcard[data-ficha="'+id+'"]');
  document.getElementById('sh-nome').textContent=c.dataset.nome||'';
  document.getElementById('sh-sub').textContent=c.dataset.sub||'';
  document.getElementById('sh-msg').textContent='';
  // limpa o form
  document.querySelectorAll('#sheet input,#sheet select').forEach(function(el){
    if(el.type==='hidden'){el.value='';} else if(el.tagName==='SELECT'){el.selectedIndex=el.classList.contains('via')?[].findIndex.call(el.options,function(o){return o.defaultSelected}):0;} else {el.value='';}
  });
  document.querySelectorAll('#sheet .sn button').forEach(function(b){b.classList.remove('on')});
  document.querySelectorAll('#sheet .via,#sheet .just').forEach(function(e){e.style.display='none'});
  document.getElementById('pf').textContent='—';
  // Preenche os rótulos "anterior: X" (Opção A: referência passiva; campos ficam
  // vazios, isto é só contexto ao lado). Lê data-ant do card.
  var ant={}; try{ ant=JSON.parse(c.dataset.ant||'{}'); }catch(e){ ant={}; }
  var rot=ant.__rot||'';
  document.querySelectorAll('#sheet .ant').forEach(function(sp){
    var k=sp.getAttribute('data-ant-key');
    if(k && ant[k]!=null && k!=='__rot'){ sp.textContent='anterior: '+ant[k]; sp.title=rot; }
    else { sp.textContent=''; }
  });
  document.getElementById('bg').classList.add('on');
  document.getElementById('sheet').classList.add('on');
}
function fechar(){document.getElementById('bg').classList.remove('on');document.getElementById('sheet').classList.remove('on');atual=null;}
function sn(btn,val){
  var row=btn.closest('.simnao');
  row.querySelectorAll('.sn button').forEach(function(b){b.classList.remove('on')});
  btn.classList.add('on');
  row.querySelector('input[type=hidden]').value=val;
  var via=row.querySelector('.via'), just=row.querySelector('.just');
  if(via) via.style.display=(val==='sim')?'block':'none';
  if(just) just.style.display=(val==='nao')?'block':'none';
}
function calcPF(){
  var f=parseFloat(document.querySelector('#sheet [name=fio2]').value);
  var p=parseFloat(document.querySelector('#sheet [name=pao2]').value);
  var el=document.getElementById('pf');
  if(f>0 && p>0){el.textContent=Math.round(p/(f/100));}else{el.textContent='—';}
}
function salvar(){
  if(!atual) return;
  var btn=document.getElementById('btn-salvar'); btn.disabled=true;
  var msg=document.getElementById('sh-msg'); msg.textContent='Salvando…';
  var data={};
  document.querySelectorAll('#sheet input,#sheet select').forEach(function(el){
    if(el.name && el.value!=='') data[el.name]=el.value;
  });
  fetch('/pav/api/check/'+atual,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j}})})
    .then(function(x){
      if(!x.ok){ msg.textContent=x.j.erro||'Erro ao salvar'; btn.disabled=false; return; }
      var c=document.querySelector('.fcard[data-ficha="'+atual+'"]');
      if(c){c.classList.add('done'); var b=c.querySelector('.abrir'); if(b) b.textContent='Revisar turno';
        if(!c.querySelector('.badge-ok')){var s=document.createElement('span');s.className='badge-ok';s.textContent='✓ turno';c.querySelector('.fc-head').appendChild(s);}}
      fechar();
    })
    .catch(function(){ msg.textContent='Falha de conexão'; btn.disabled=false; });
}

// ── Abrir nova ficha ──
function abrirNovo(){
  document.querySelectorAll('#sheet-novo input').forEach(function(el){ if(el.type!=='date') el.value=''; });
  document.getElementById('novo-msg').textContent='';
  document.getElementById('bg-novo').classList.add('on');
  document.getElementById('sheet-novo').classList.add('on');
}
function fecharNovo(){ document.getElementById('bg-novo').classList.remove('on'); document.getElementById('sheet-novo').classList.remove('on'); }
function salvarNovo(){
  var btn=document.getElementById('btn-novo'); btn.disabled=true;
  var msg=document.getElementById('novo-msg'); msg.textContent='Abrindo…';
  var g=function(n){var e=document.querySelector('#sheet-novo [name='+n+']');return e?e.value.trim():'';};
  var data={ paciente_nome:g('n_nome'), prontuario:g('n_prontuario'), leito:g('n_leito'),
    salao:g('n_salao'), data_intubacao:g('n_data_intubacao'), numero_tubo:g('n_numero_tubo'), rima_labial:g('n_rima_labial') };
  fetch('/pav/api/abrir',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j}})})
    .then(function(x){ if(!x.ok){ msg.textContent=x.j.erro||'Erro'; btn.disabled=false; return; } location.reload(); })
    .catch(function(){ msg.textContent='Falha de conexão'; btn.disabled=false; });
}

// ── Registrar extubação (encerrar) ──
var encAtual=null;
function abrirEncerrar(id,nome){
  encAtual=id;
  document.getElementById('enc-nome').textContent=nome||'';
  document.getElementById('enc-msg').textContent='';
  document.getElementById('bg-enc').classList.add('on');
  document.getElementById('sheet-enc').classList.add('on');
}
function fecharEncerrar(){ document.getElementById('bg-enc').classList.remove('on'); document.getElementById('sheet-enc').classList.remove('on'); encAtual=null; }
function salvarEncerrar(){
  if(!encAtual) return;
  var btn=document.getElementById('btn-enc'); btn.disabled=true;
  var msg=document.getElementById('enc-msg'); msg.textContent='Registrando…';
  var g=function(n){var e=document.querySelector('#sheet-enc [name='+n+']');return e?e.value.trim():'';};
  var data={ acao:'registrar', data_extubacao:g('e_data'), desfecho:g('e_desfecho'), identificacao:g('e_identificacao') };
  fetch('/pav/api/encerrar/'+encAtual,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j}})})
    .then(function(x){ if(!x.ok){ msg.textContent=x.j.erro||'Erro'; btn.disabled=false; return; } location.reload(); })
    .catch(function(){ msg.textContent='Falha de conexão'; btn.disabled=false; });
}

// ── Confirmar pendência (fisio/SCIH) ──
function confirmar(id){
  if(!confirm('Confirmar o encerramento deste episódio? A ficha sairá da lista e o VM-dia será fechado.')) return;
  fetch('/pav/api/encerrar/'+id,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({acao:'confirmar'})})
    .then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j}})})
    .then(function(x){ if(!x.ok){ alert(x.j.erro||'Erro'); return; } location.reload(); })
    .catch(function(){ alert('Falha de conexão'); });
}
</script>`;
  }
}
