// ════════════════════════════════════════════════════════════════════════════
//  ANEXOS DO SCIH  —  upload / listagem / remoção de imagens e PDFs
//
//  Provisão para a equipe do SCIH anexar arquivos a uma ficha (complemento).
//  Reusa o R2 (uploadToR2 / deleteFromR2 de lab-storage.js) e a tabela
//  atb_ficha_imagens já existente — os anexos do SCIH ficam marcados com
//  origem='scih' (coluna adicionada via ALTER IF NOT EXISTS) e aparecem
//  normalmente no card, na ficha completa e na rota que serve o arquivo
//  (/atb/admin/ficha/:id/anexo/:aid).
//
//  Sem dependência nova: o upload chega como corpo bruto (express.raw),
//  evitando multer/multipart. Limite de 15 MB por arquivo.
//
//  Endpoints:
//    GET    /atb/admin/ficha/:id/anexos        → lista JSON
//    POST   /atb/admin/ficha/:id/anexo         → upload (corpo bruto; ?nome=&ct=)
//    DELETE /atb/admin/ficha/:id/anexo/:aid    → remove (somente origem='scih')
//
//  Integração em atb-routes.js:
//    import { ensureAnexosSchema, registerAnexosRoutes, anexosManagerWidget }
//      from './atb-anexos-routes.js';
//    // no boot:               ensureAnexosSchema(pool).catch(...);
//    // em registerAtbRoutes:  registerAnexosRoutes(app, pool, adminRequired);
//    // onde quiser o gestor:  ${anexosManagerWidget(f.id)}
//      (ex.: na página de Complementação e na ficha completa)
// ════════════════════════════════════════════════════════════════════════════

import express from 'express';
import { uploadToR2, deleteFromR2 } from './lab-storage.js';

function _safe(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function _slug(nome) {
  return String(nome || 'anexo').normalize('NFD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 80) || 'anexo';
}

export async function ensureAnexosSchema(pool) {
  // a tabela já existe em produção; garantimos a estrutura e as colunas de origem
  await pool.query(`
    CREATE TABLE IF NOT EXISTS atb_ficha_imagens (
      id            SERIAL PRIMARY KEY,
      ficha_id      INTEGER REFERENCES atb_fichas(id),
      tipo          TEXT,
      nome_original TEXT,
      r2_key        TEXT
    )`);
  await pool.query(`ALTER TABLE atb_ficha_imagens ADD COLUMN IF NOT EXISTS origem TEXT`);
  await pool.query(`ALTER TABLE atb_ficha_imagens ADD COLUMN IF NOT EXISTS adicionado_por INTEGER REFERENCES users(id)`);
  await pool.query(`ALTER TABLE atb_ficha_imagens ADD COLUMN IF NOT EXISTS adicionado_em TIMESTAMPTZ`);
}

export function registerAnexosRoutes(app, pool, adminRequired) {

  // ── lista ──────────────────────────────────────────────────────────────
  app.get('/atb/admin/ficha/:id/anexos', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const { rows } = await pool.query(
        `SELECT id, tipo, nome_original, origem FROM atb_ficha_imagens WHERE ficha_id = $1 ORDER BY tipo, id`, [id]);
      res.json({ ok: true, anexos: rows });
    } catch (e) {
      console.error('[atb] anexos list error:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  // ── upload (corpo bruto) ─────────────────────────────────────────────────
  app.post('/atb/admin/ficha/:id/anexo',
    adminRequired,
    express.raw({ type: () => true, limit: '15mb' }),
    async (req, res) => {
      try {
        const id = parseInt(req.params.id, 10);
        const buf = req.body;
        if (!buf || !buf.length) return res.status(400).json({ ok: false, error: 'Arquivo vazio' });

        const nome = (req.query.nome || 'anexo').toString();
        const ct = (req.query.ct || req.headers['content-type'] || 'application/octet-stream').toString();
        const tipo = ct.startsWith('image/') ? 'imagem' : 'pdf';
        const r2key = `atb-anexos-scih/${id}/${Date.now()}-${_slug(nome)}`;

        await uploadToR2(r2key, buf, ct);
        const { rows: [row] } = await pool.query(`
          INSERT INTO atb_ficha_imagens (ficha_id, tipo, nome_original, r2_key, origem, adicionado_por, adicionado_em)
          VALUES ($1,$2,$3,$4,'scih',$5,now()) RETURNING id, tipo, nome_original, origem`,
          [id, tipo, nome, r2key, req.user?.id || null]);
        res.json({ ok: true, anexo: row });
      } catch (e) {
        console.error('[atb] anexo upload error:', e.message);
        res.status(500).json({ ok: false, error: e.message });
      }
    });

  // ── remoção (somente anexos adicionados pelo SCIH) ───────────────────────
  app.delete('/atb/admin/ficha/:id/anexo/:aid', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const aid = parseInt(req.params.aid, 10);
      const { rows: [a] } = await pool.query(
        `SELECT r2_key, origem FROM atb_ficha_imagens WHERE id = $1 AND ficha_id = $2`, [aid, id]);
      if (!a) return res.status(404).json({ ok: false, error: 'Anexo não encontrado' });
      if (a.origem !== 'scih') {
        return res.status(403).json({ ok: false, error: 'Só é possível remover anexos adicionados pelo SCIH' });
      }
      try { await deleteFromR2(a.r2_key); } catch (e) { console.warn('[atb] R2 delete falhou:', e.message); }
      await pool.query(`DELETE FROM atb_ficha_imagens WHERE id = $1 AND ficha_id = $2`, [aid, id]);
      res.json({ ok: true });
    } catch (e) {
      console.error('[atb] anexo delete error:', e.message);
      res.status(500).json({ ok: false, error: e.message });
    }
  });
}

// ════════════════════════════════════════════════════════════════════════════
//  WIDGET EMBUTÍVEL  —  ${anexosManagerWidget(fichaId)}
//  Lista os anexos (busca sozinho), permite enviar novos e remover os do SCIH.
//  Linguagem clara (azul #00469e). Auto-contido: style + html + script.
// ════════════════════════════════════════════════════════════════════════════
export function anexosManagerWidget(fichaId) {
  const fid = parseInt(fichaId, 10);
  return `
  <style>
    .anx{border:1px solid #d8dee6;border-radius:10px;padding:14px 16px;background:#fff;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
    .anx h3{font-size:11px;font-weight:700;color:#0c447c;text-transform:uppercase;letter-spacing:.04em;margin:0 0 10px}
    .anx .lista{display:flex;flex-direction:column;gap:6px;margin-bottom:12px}
    .anx .item{display:flex;align-items:center;gap:8px;font-size:13px;padding:6px 9px;border:1px solid #eef1f5;border-radius:8px}
    .anx .item a{color:#0c447c;text-decoration:none;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .anx .item .tag{font-size:10px;color:#1a6b3a;background:#e7f4ec;padding:1px 7px;border-radius:6px}
    .anx .item .del{border:none;background:none;color:#e12229;cursor:pointer;font-size:15px;line-height:1;padding:0 4px}
    .anx .item img.thumb{width:34px;height:34px;object-fit:cover;border-radius:6px;border:1px solid #d8dee6}
    .anx .vazio{font-size:12px;color:#9aa0a6;margin-bottom:10px}
    .anx .enviar{display:inline-flex;align-items:center;gap:7px;cursor:pointer;font-size:13px;font-weight:600;
      color:#fff;background:#00469e;border-radius:8px;padding:9px 16px}
    .anx .enviar input{display:none}
    .anx .status{font-size:12px;color:#5f6368;margin-top:8px;min-height:16px}
  </style>
  <div class="anx" data-fid="${fid}">
    <h3>Anexos do SCIH</h3>
    <div class="lista" id="anx-lista-${fid}"><div class="vazio">Carregando…</div></div>
    <label class="enviar">📎 Anexar imagem ou PDF
      <input type="file" id="anx-input-${fid}" accept="image/*,application/pdf" multiple>
    </label>
    <div class="status" id="anx-status-${fid}"></div>
  </div>
  <script>
  (function(){
    var FID = ${fid};
    var lista = document.getElementById('anx-lista-'+FID);
    var input = document.getElementById('anx-input-'+FID);
    var status = document.getElementById('anx-status-'+FID);
    function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

    function carregar(){
      fetch('/atb/admin/ficha/'+FID+'/anexos').then(function(r){return r.json();}).then(function(j){
        var a = (j && j.anexos) || [];
        if(!a.length){ lista.innerHTML = '<div class="vazio">Nenhum anexo.</div>'; return; }
        lista.innerHTML = a.map(function(x){
          var url = '/atb/admin/ficha/'+FID+'/anexo/'+x.id;
          var thumb = x.tipo === 'imagem'
            ? '<img class="thumb" src="'+url+'" loading="lazy">'
            : '<span style="font-size:16px">📄</span>';
          var tag = x.origem === 'scih' ? '<span class="tag">SCIH</span>' : '';
          var del = x.origem === 'scih'
            ? '<button class="del" title="Remover" data-id="'+x.id+'">✕</button>' : '';
          return '<div class="item">'+thumb+'<a href="'+url+'" target="_blank" rel="noopener">'+esc(x.nome_original||('anexo '+x.id))+'</a>'+tag+del+'</div>';
        }).join('');
        lista.querySelectorAll('.del').forEach(function(b){
          b.addEventListener('click', function(){ remover(b.getAttribute('data-id')); });
        });
      }).catch(function(){ lista.innerHTML = '<div class="vazio">Falha ao carregar.</div>'; });
    }

    function remover(aid){
      if(!confirm('Remover este anexo?')) return;
      fetch('/atb/admin/ficha/'+FID+'/anexo/'+aid, {method:'DELETE'})
        .then(function(r){return r.json();}).then(function(j){
          if(j && j.ok){ carregar(); } else { status.textContent = (j && j.error) || 'Falha ao remover.'; }
        }).catch(function(){ status.textContent = 'Erro de rede.'; });
    }

    function enviarUm(file){
      return fetch('/atb/admin/ficha/'+FID+'/anexo?nome='+encodeURIComponent(file.name)+'&ct='+encodeURIComponent(file.type||''), {
        method:'POST', headers:{'Content-Type': file.type || 'application/octet-stream'}, body: file
      }).then(function(r){return r.json();});
    }

    input.addEventListener('change', function(){
      var files = Array.prototype.slice.call(input.files || []);
      if(!files.length) return;
      status.textContent = 'Enviando '+files.length+' arquivo(s)…';
      var ok = 0, falhas = 0, i = 0;
      (function proximo(){
        if(i >= files.length){
          status.textContent = ok+' enviado(s)'+(falhas?(' · '+falhas+' falha(s)'):'.');
          input.value = ''; carregar(); return;
        }
        var f = files[i++];
        if(f.size > 15*1024*1024){ falhas++; return proximo(); }
        enviarUm(f).then(function(j){ if(j && j.ok) ok++; else falhas++; proximo(); })
                   .catch(function(){ falhas++; proximo(); });
      })();
    });

    carregar();
  })();
  </script>`;
}
