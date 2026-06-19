// ════════════════════════════════════════════════════════════════════════════
//  CONSULTA DE FICHAS  —  /consulta
//
//  Visão enxuta e somente-leitura das fichas submetidas nos últimos 30 dias
//  (mais recentes no topo), para a FARMÁCIA e os PRESCRITORES conferirem se a
//  ficha foi recebida e qual o parecer.
//
//  Colunas: Data · Paciente · Prontuário · Setor · ATB · Parecer.
//  Fichas sem parecer → "Aguardando parecer" (cinza/itálico).
//
//  ACESSO: como lista dados de paciente e o app é público, o acesso é liberado
//  para ADMIN (cookie 'adm') OU para quem está DENTRO DA REDE DO HOSPITAL —
//  isto é, requisições vindas do IP público de saída do hospital.
//  Configure a env HOSPITAL_IPS (IPs/CIDR separados por vírgula). Depende de
//  app.set('trust proxy', 1), já configurado, p/ ler o IP real via X-Forwarded-For.
//  Não usa adminRequired (Farmácia/prescritores não são SCIH).
//
//  Integração em atb-routes.js:
//    import { registerConsultaRoutes } from './atb-consulta-routes.js';
//    // em registerAtbRoutes:  registerConsultaRoutes(app, pool);
//  Link amigável: https://app.lcmendes.med.br/consulta
// ════════════════════════════════════════════════════════════════════════════

import { getLatestHealthcheck, renderHealthCard } from './atb-healthcheck.js';

const ehAdmin = req => req.cookies?.adm === '1';

function normIp(ip) { return String(ip || '').replace(/^::ffff:/i, '').trim(); }
function ipv4ToInt(ip) {
  const p = ip.split('.'); if (p.length !== 4) return null;
  let n = 0; for (const o of p) { const x = parseInt(o, 10); if (isNaN(x) || x < 0 || x > 255) return null; n = (n * 256) + x; }
  return n >>> 0;
}
function matchEntry(ip, entry) {
  entry = entry.trim(); if (!entry) return false;
  if (entry.includes('/')) {                       // CIDR IPv4 (ex.: 200.130.1.0/24)
    const [base, bitsS] = entry.split('/'); const bits = parseInt(bitsS, 10);
    const ipN = ipv4ToInt(ip), baseN = ipv4ToInt(base);
    if (ipN == null || baseN == null || isNaN(bits)) return false;
    if (bits <= 0) return true; if (bits > 32) return false;
    const mask = bits === 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0;
    return (ipN & mask) === (baseN & mask);
  }
  return ip === entry;                              // IP exato (v4 ou v6)
}
function ipDoHospital(ipRaw) {
  const allow = (process.env.HOSPITAL_IPS || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!allow.length) return false;
  const ip = normIp(ipRaw);
  return allow.some(e => matchEntry(ip, e));
}
// acesso = admin (cookie) OU dentro da rede do hospital (IP público de saída)

// IP real do cliente atrás de Cloudflare+Render: CF-Connecting-IP é o mais
// confiável (a Cloudflare sobrescreve); senão o 1º IP do X-Forwarded-For.
function ipCliente(req) {
  const cf = req.headers['cf-connecting-ip'];
  if (cf) return cf.trim();
  const xff = req.headers['x-forwarded-for'];
  if (xff) return xff.split(',')[0].trim();
  return req.ip;
}

function temAcesso(req) { return ehAdmin(req) || ipDoHospital(ipCliente(req)); }

function _safe(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
const _arr = v => Array.isArray(v) ? v : (v == null ? [] : (typeof v === 'string'
  ? (() => { try { const x = JSON.parse(v); return Array.isArray(x) ? x : []; } catch { return []; } })()
  : []));

// veredito → rótulo + cores suaves (pill)
function _parecerPill(rec) {
  const v = _arr(rec)[0] || '';
  if (!v) return '<span class="aguard">Aguardando parecer</span>';
  let l = v, bg = '#eef0f2', fg = '#5f6368';
  if (v === 'Sim') { l = 'Favorável'; bg = '#e6f4ea'; fg = '#1a7a3a'; }
  else if (v === 'Não') { l = 'Negativo'; bg = '#fdecea'; fg = '#c0392b'; }
  else if (/Com ajustes/i.test(v)) { l = 'Condicional'; bg = '#fff7df'; fg = '#9a7a00'; }
  return `<span class="pill" style="background:${bg};color:${fg}">${_safe(l)}</span>`;
}

function _layout(titulo, miolo) {
  return `<!DOCTYPE html>
<html lang="pt-BR"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${_safe(titulo)}</title>
<style>
  :root{--azul:#00469e;--azul-claro:#e6eef8;--borda:#d8dee6;--fundo:#f4f6f9;--tinta:#202124;--mut:#5f6368}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--fundo);color:var(--tinta);font-size:14px}
  .cab{background:#fff;border-bottom:2px solid var(--azul);padding:14px 22px}
  .cab h1{font-size:17px;color:var(--azul)} .cab p{font-size:12.5px;color:var(--mut);margin-top:3px}
  .barra{padding:12px 22px;background:#fff;border-bottom:1px solid var(--borda);display:flex;gap:12px;align-items:center;flex-wrap:wrap}
  .barra input[type=search]{flex:1;min-width:200px;padding:9px 12px;border:1px solid var(--borda);border-radius:8px;font-size:14px}
  .barra .cont{font-size:12.5px;color:var(--mut)}
  .wrap{padding:0 16px 50px}
  table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--borda);border-radius:10px;overflow:hidden}
  th{background:#fff;color:var(--mut);text-align:left;font-size:11px;font-weight:600;padding:11px 12px;border-bottom:1px solid var(--borda);white-space:nowrap}
  td{padding:9px 12px;border-bottom:1px solid #f0f1f3;vertical-align:middle}
  tr:hover td{background:#fafbfc}
  td.dt{white-space:nowrap;color:var(--mut)}
  .nome{font-weight:600}
  td.atb{max-width:240px}
  .pill{display:inline-block;font-size:12px;font-weight:600;padding:3px 10px;border-radius:12px}
  .aguard{color:#b0b6bf;font-style:italic;font-size:13px}
  .espec{display:block;font-size:11.5px;color:var(--mut);margin-top:3px;max-width:340px;line-height:1.35}
  .vazio{padding:30px;text-align:center;color:var(--mut)}
  /* portão */
  .gate{max-width:380px;margin:60px auto;background:#fff;border:1px solid var(--borda);border-radius:12px;padding:26px}
  .gate h2{font-size:16px;color:var(--azul);margin-bottom:6px}
  .gate p{font-size:13px;color:var(--mut);margin-bottom:16px}
  .gate input{width:100%;padding:11px 12px;border:1px solid var(--borda);border-radius:8px;font-size:15px;margin-bottom:12px}
  .gate button{width:100%;background:var(--azul);color:#fff;border:none;border-radius:8px;padding:11px;font-size:15px;font-weight:600;cursor:pointer}
  .gate .err{background:#fdecea;border:1px solid #f5c2c0;color:#a01b1b;border-radius:8px;padding:9px 12px;font-size:13px;margin-bottom:12px}
</style></head>
<body>${miolo}</body></html>`;
}

function paginaRestrito(req) {
  const ip  = req ? normIp(ipCliente(req)) : '';
  const xff = req ? (req.headers['x-forwarded-for'] || '') : '';
  const temCfg = !!(process.env.HOSPITAL_IPS || '').trim();
  return _layout('Consulta de fichas', `
    <div class="gate">
      <h2>Acesso restrito</h2>
      <p>Esta consulta está disponível <b>dentro da rede do hospital</b>. Parece que você está acessando de fora da rede.</p>
      <p>Se você é do SCIH, entre como administrador em <a href="/admin" style="color:var(--azul)">/admin</a> e recarregue esta página.</p>
      <p style="font-size:12px;color:var(--mut);margin-top:14px;border-top:1px solid var(--borda);padding-top:10px">
        Diagnóstico — IP detectado: <b>${_safe(ip)}</b><br>
        X-Forwarded-For: ${_safe(xff)}<br>
        HOSPITAL_IPS definido: <b>${temCfg ? 'sim' : 'NÃO'}</b>
      </p>
    </div>`);
}

function paginaConsulta(rows, cardHtml = '') {
  const dt = d => d ? new Date(d).toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit', year: '2-digit' }) : '—';
  const linhas = rows.map(f => {
    const nome = f.paciente_nome || f.paciente_nome_raw || '—';
    const atb = _arr(f.atb_solicitado).join(', ');
    const temVerd = _arr(f.recomendacao_scih)[0];
    const espec = (temVerd && f.recomendacoes_especificacao)
      ? `<span class="espec">${_safe(f.recomendacoes_especificacao)}</span>` : '';
    return `<tr>
      <td class="dt">${dt(f.data_ficha)}</td>
      <td class="nome">${_safe(nome)}</td>
      <td>${_safe(f.prontuario || '')}</td>
      <td>${_safe(f.setor || '')}</td>
      <td class="atb">${_safe(atb)}</td>
      <td>${_parecerPill(f.recomendacao_scih)}${espec}</td>
    </tr>`;
  }).join('');

  return _layout('Consulta de fichas', `
    <div class="cab">
      <h1>Consulta de fichas</h1>
      <p>Fichas submetidas nos últimos 30 dias · mais recentes primeiro</p>
    </div>
    ${cardHtml}
    <div class="barra">
      <input type="search" id="busca" placeholder="Buscar por nome, prontuário ou ATB…">
      <span class="cont" id="cont">${rows.length} fichas</span>
    </div>
    <div class="wrap">
      <table>
        <thead><tr><th>Data</th><th>Paciente</th><th>Prontuário</th><th>Setor</th><th>ATB</th><th>Parecer</th></tr></thead>
        <tbody id="corpo">${linhas || `<tr><td colspan="6" class="vazio">Nenhuma ficha nos últimos 30 dias.</td></tr>`}</tbody>
      </table>
    </div>
    <script>
    (function(){
      var busca = document.getElementById('busca');
      var corpo = document.getElementById('corpo');
      var cont = document.getElementById('cont');
      var linhas = Array.prototype.slice.call(corpo.querySelectorAll('tr'));
      busca.addEventListener('input', function(){
        var q = busca.value.trim().toLowerCase();
        var n = 0;
        linhas.forEach(function(tr){
          var ok = !q || tr.textContent.toLowerCase().indexOf(q) !== -1;
          tr.style.display = ok ? '' : 'none';
          if(ok) n++;
        });
        cont.textContent = n + ' fichas';
      });
    })();
    </script>`);
}

export function registerConsultaRoutes(app, pool) {

  app.get('/consulta', async (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    if (!temAcesso(req)) return res.send(paginaRestrito(req));
    try {
      const { rows } = await pool.query(`
        SELECT f.id, f.paciente_nome, f.paciente_nome_raw, f.prontuario, f.setor,
               f.atb_solicitado, f.recomendacao_scih, f.recomendacoes_especificacao,
               COALESCE(f.data_referencia, f.jotform_created_at, f.created_at) AS data_ficha
        FROM atb_fichas f
        WHERE f.deletado_em IS NULL
          AND COALESCE(f.data_referencia, f.jotform_created_at, f.created_at) >= now() - interval '30 days'
        ORDER BY COALESCE(f.data_referencia, f.jotform_created_at, f.created_at) DESC`);
      const hc = await getLatestHealthcheck(pool).catch(() => null);
      res.send(paginaConsulta(rows, renderHealthCard(hc)));
    } catch (e) {
      console.error('[atb] consulta error:', e.message);
      res.status(500).send('Erro: ' + _safe(e.message));
    }
  });
}
