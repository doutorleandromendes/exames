// diag-ficha-branco.mjs — SOMENTE LEITURA. Identifica a(s) ficha(s) "em branco".
// Rodar no Render Shell, em ~/project/src/aula-tracker :  node diag-ficha-branco.mjs
import pg from 'pg';

const url = process.env.DATABASE_URL || process.env.SUPABASE_POOLER_URL;
if (!url) { console.error('Sem DATABASE_URL/SUPABASE_POOLER_URL no ambiente.'); process.exit(1); }

const c = new pg.Client({ connectionString: url, ssl: { rejectUnauthorized: false } });
await c.connect();

try {
  // colunas reais da tabela
  const cols = (await c.query(
    `select column_name from information_schema.columns
      where table_name='atb_fichas' order by ordinal_position`
  )).rows.map(r => r.column_name);

  const temPacNome = cols.includes('paciente_nome');

  // total e quantas parecem vazias (sem nome de paciente)
  const tot = (await c.query(`select count(*)::int n from atb_fichas where deletado_em is null`)).rows[0].n;
  console.log('Fichas ativas (deletado_em null):', tot);
  if (temPacNome) {
    const vazias = (await c.query(
      `select count(*)::int n from atb_fichas
        where deletado_em is null and (paciente_nome is null or btrim(paciente_nome)='')`
    )).rows[0].n;
    console.log('Sem paciente_nome (candidatas a "em branco"):', vazias);
  }

  // top por data canônica = mesma ordem do /atb/admin/grid
  const q = await c.query(`
    select *,
      coalesce(data_referencia, jotform_created_at, created_at)                                   as _data_canon,
      (left(coalesce(jotform_submission_id,''),5) = 'form_')                                       as _nativa,
      to_char(created_at         at time zone 'America/Sao_Paulo','DD/MM/YYYY HH24:MI')            as _created_sp,
      to_char(jotform_created_at at time zone 'America/Sao_Paulo','DD/MM/YYYY HH24:MI')            as _jf_sp,
      to_char(data_referencia, 'DD/MM/YYYY')                                                       as _dref
    from atb_fichas
    where deletado_em is null
    order by coalesce(data_referencia, jotform_created_at, created_at) desc nulls last
    limit 8
  `);

  console.log('\n=== 8 fichas mais recentes (ordem do /grid) ===');
  for (const r of q.rows) {
    console.log('\n──────────────────────────────────────────────');
    console.log('id:', r.id, '|', r._nativa ? 'NATIVA (app)' : 'migrada (jotform)', '| submission_id:', r.jotform_submission_id);
    console.log('created_at(SP):', r._created_sp, '| jotform_created_at(SP):', r._jf_sp, '| data_referencia:', r._dref);
    console.log('link: /atb/admin/fichas/' + r.id);
    const preenchidos = [];
    for (const k of cols) {
      if (k === 'payload_raw') continue;
      const v = r[k];
      if (v !== null && v !== undefined && v !== '') preenchidos.push(k);
    }
    console.log('campos preenchidos (' + preenchidos.length + '):', preenchidos.join(', ') || '(NENHUM)');
    // mostra os valores curtos dos preenchidos relevantes
    for (const k of preenchidos) {
      if (['id','jotform_submission_id','created_at','jotform_created_at','data_referencia','deletado_em'].includes(k)) continue;
      let v = r[k];
      if (typeof v === 'object') v = JSON.stringify(v);
      console.log('     ', k, '=', String(v).slice(0, 140));
    }
    if (cols.includes('payload_raw')) {
      const p = r.payload_raw;
      console.log('      payload_raw:', p == null ? '(null)' : ('len=' + String(p).length + ' :: ' + String(p).slice(0, 160)));
    }
  }
  console.log('\n────────────────────────────────────────────── fim');
} catch (e) {
  console.error('ERRO:', e.message);
} finally {
  await c.end();
}
