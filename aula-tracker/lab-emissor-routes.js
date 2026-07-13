// ============================================================
//  lab-emissor-routes.js — EMISSOR DE LAUDOS redesenhado (PARALELO)
//  Não toca em lab-routes.js/lab-pdf.js. Reusa o MESMO banco e os
//  MESMOS endpoints de mutação já existentes (add/editar/apagar/
//  duplicar/imagens/LFA) — este módulo só troca a apresentação e a
//  fonte do catálogo (exames-catalogo.js → diagnostico/exams-data.js).
//
//  Rotas novas (coexistem com as atuais para comparação lado a lado):
//    GET /lab/admin/api/exames-catalogo   catálogo rico (nome, grupo, método, amostra, vr, kind)
//    GET /lab/admin/coletas/:id/emissor   página redesenhada
//    GET /lab/admin/coletas/:id/preview2  preview do PDF v2 (HTML)
//    GET /lab/admin/coletas/:id/pdf2      PDF v2 (não assinado — paridade com /pdf atual)
//
//  Registrar em app.js:
//    import { registerLabEmissorRoutes } from './lab-emissor-routes.js';
//    registerLabEmissorRoutes(app, pool, adminRequired, renderShell);
// ============================================================
import { catalogoParaEmissor } from './exames-catalogo.js';
import { buildPdfHtmlV2, generateLabPdfV2 } from './lab-pdf-v2.js';

function safe(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function toBR(d) {
  if (!d) return '—';
  const s = String(d);
  if (/^\d{2}\/\d{2}\/\d{4}$/.test(s)) return s;
  const dt = new Date(s.length === 10 ? s + 'T12:00:00' : s);
  return isNaN(dt) ? s : dt.toLocaleDateString('pt-BR');
}
// YYYY-MM-DD robusto (Date do node-postgres ou string ISO) — p/ nome de arquivo
function isoDate(v) {
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  return String(v || '').slice(0, 10);
}
function ageFrom(birth) {
  const d = new Date(String(birth).slice(0, 10) + 'T12:00:00');
  if (isNaN(d)) return null;
  const now = new Date();
  let a = now.getFullYear() - d.getFullYear();
  const m = now.getMonth() - d.getMonth();
  if (m < 0 || (m === 0 && now.getDate() < d.getDate())) a--;
  return a;
}
function resultColorCSS(value, storedColor) {
  if (storedColor === 'positivo') return '#6e2c3c';
  if (storedColor === 'negativo') return '#3f6b4c';
  if (storedColor === 'neutro')   return '#8a807c';
  const v = (value || '').toUpperCase();
  if (/NÃO\s+REAGENTE|NAO\s+REAGENTE|NÃO\s+DETECTADO|NAO\s+DETECTADO|NEGATIVO|AUSENTE/.test(v)) return '#3f6b4c';
  if (/REAGENTE|POSITIVO|PRESENTE|CRESCIMENTO|DETECTADO/.test(v)) return '#6e2c3c';
  return '#211c1d';
}
// Formatação de resultado para exibição na lista (espelha o PDF):
// *negrito*, _itálico_, SENSÍVEL/RESISTENTE, e quebras de linha.
function fmt(value) {
  return safe((value || '').trim())
    .replace(/\*(.+?)\*/gs, '<strong>$1</strong>')
    .replace(/_(.+?)_/gs,   '<em>$1</em>')
    .replace(/SENSÍVEL A:/gi,   '<span style="color:#3f6b4c;font-weight:700">SENSÍVEL A:</span>')
    .replace(/RESISTENTE A:/gi, '<span style="color:#6e2c3c;font-weight:700">RESISTENTE A:</span>')
    .replace(/\r\n|\r|\n/g, '<br>');
}

// Cópia local do carregador (não importa de lab-routes.js para manter
// o módulo autocontido; devolve collection.id para o nº do laudo).
async function getCollectionData(pool, collectionId) {
  const { rows: [collection] } = await pool.query(
    `SELECT lc.*, lp.full_name, lp.birth_date, lp.id AS patient_id
     FROM lab_collections lc JOIN lab_patients lp ON lp.id = lc.patient_id
     WHERE lc.id = $1`, [collectionId]);
  if (!collection) return null;

  const { rows: results } = await pool.query(
    `SELECT lr.*, (SELECT COUNT(*) FROM lab_result_images WHERE result_id = lr.id) AS _img_count
     FROM lab_results lr WHERE lr.collection_id=$1
     ORDER BY lr.sort_index NULLS LAST, lr.id ASC`, [collectionId]);

  const ids = results.map(r => r.id);
  const byResult = {};
  if (ids.length) {
    const { rows: imgs } = await pool.query(
      `SELECT * FROM lab_result_images WHERE result_id = ANY($1::int[])
       ORDER BY result_id, sort_index NULLS LAST, id`, [ids]);
    for (const img of imgs) (byResult[img.result_id] ||= []).push(img);
  }
  const { fetchR2ImageAsDataURI } = await import('./lab-storage.js');
  for (const r of results) {
    const imgs = byResult[r.id] || [];
    r.images = (await Promise.all(imgs.map(async img => {
      try { return { ...img, dataUri: await fetchR2ImageAsDataURI(img.r2_key) }; }
      catch { return null; }
    }))).filter(Boolean);
  }
  return {
    patient:    { id: collection.patient_id, full_name: collection.full_name, birth_date: collection.birth_date },
    collection: { id: collection.id, collected_at: collection.collected_at },
    results,
  };
}

export function registerLabEmissorRoutes(app, pool, adminRequired, renderShell) {

  // Migração idempotente (autocontida): largura de exibição por imagem (% da largura útil)
  (async () => {
    try { await pool.query(`ALTER TABLE lab_result_images ADD COLUMN IF NOT EXISTS display_width INTEGER`); }
    catch (e) { console.error('EMISSOR MIGRATION display_width', e); }
  })();

  // ── Imagem: atualizar largura e/ou legenda ───────────────────
  app.post('/lab/admin/images/:id/update', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const sets = [], vals = []; let i = 1;
      if (req.body?.display_width != null) {
        const w = Math.max(10, Math.min(100, parseInt(req.body.display_width, 10) || 50));
        sets.push(`display_width=$${i++}`); vals.push(w);
      }
      if (req.body?.caption != null) {
        sets.push(`caption=$${i++}`); vals.push(String(req.body.caption).trim() || null);
      }
      if (!sets.length) return res.json({ ok: true });
      vals.push(id);
      await pool.query(`UPDATE lab_result_images SET ${sets.join(', ')} WHERE id=$${i}`, vals);
      res.json({ ok: true });
    } catch (err) { console.error('EMISSOR IMG UPDATE', err); res.status(500).json({ error: err.message }); }
  });

  // ── Imagem: reordenar (troca sort_index com o vizinho) ───────
  app.post('/lab/admin/images/:id/move', adminRequired, async (req, res) => {
    try {
      const id  = parseInt(req.params.id, 10);
      const dir = req.body?.dir === 'up' ? 'up' : 'down';
      const { rows: [cur] } = await pool.query('SELECT result_id FROM lab_result_images WHERE id=$1', [id]);
      if (!cur) return res.status(404).json({ error: 'não encontrado' });
      const { rows } = await pool.query(
        'SELECT id, sort_index FROM lab_result_images WHERE result_id=$1 ORDER BY sort_index NULLS LAST, id', [cur.result_id]);
      const idx = rows.findIndex(x => x.id === id);
      const j = dir === 'up' ? idx - 1 : idx + 1;
      if (idx < 0 || j < 0 || j >= rows.length) return res.json({ ok: true });
      const a = rows[idx], b = rows[j];
      const sa = a.sort_index == null ? idx * 10 : a.sort_index;
      const sb = b.sort_index == null ? j   * 10 : b.sort_index;
      await pool.query('UPDATE lab_result_images SET sort_index=$1 WHERE id=$2', [sb, a.id]);
      await pool.query('UPDATE lab_result_images SET sort_index=$1 WHERE id=$2', [sa, b.id]);
      res.json({ ok: true });
    } catch (err) { console.error('EMISSOR IMG MOVE', err); res.status(500).json({ error: err.message }); }
  });

  // ── Catálogo rico ─────────────────────────────────────────────
  app.get('/lab/admin/api/exames-catalogo', adminRequired, (req, res) => {
    try { res.json(catalogoParaEmissor()); }
    catch (err) { console.error('EMISSOR CATALOGO ERROR', err); res.status(500).json([]); }
  });

  // ── Preview do PDF v2 (HTML) ─────────────────────────────────
  app.get('/lab/admin/coletas/:id/preview2', adminRequired, async (req, res) => {
    try {
      const data = await getCollectionData(pool, parseInt(req.params.id, 10));
      if (!data) return res.status(404).send('Coleta não encontrada');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(buildPdfHtmlV2(data));
    } catch (err) { console.error('EMISSOR PREVIEW2 ERROR', err); res.status(500).send(safe(err.message)); }
  });

  // ── PDF v2 (não assinado — paridade com o /pdf admin atual) ──
  app.get('/lab/admin/coletas/:id/pdf2', adminRequired, async (req, res) => {
    try {
      const data = await getCollectionData(pool, parseInt(req.params.id, 10));
      if (!data) return res.status(404).send('Coleta não encontrada');
      const pdf = await generateLabPdfV2(data);
      const fname = `Laudo_${data.patient.full_name.replace(/\s+/g, '_')}_${isoDate(data.collection.collected_at)}.pdf`;
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(fname)}"`);
      res.send(pdf);
    } catch (err) { console.error('EMISSOR PDF2 ERROR', err); res.status(500).send(safe(err.message)); }
  });

  // ── Página do emissor redesenhado ────────────────────────────
  app.get('/lab/admin/coletas/:id/emissor', adminRequired, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const data = await getCollectionData(pool, id);
      if (!data) return res.status(404).send('Coleta não encontrada');
      const { patient, collection, results } = data;
      const age = ageFrom(patient.birth_date);

      const rowsHtml = results.map(r => {
        const tcMatch = r.result_value ? r.result_value.match(/^([\s\S]*?)\|\|TC\|\|(.+)$/) : null;
        const mainValue = tcMatch ? tcMatch[1].trim() : r.result_value;
        const color = resultColorCSS(mainValue, r.result_color);
        const rich = /[\r\n*_]/.test(mainValue || '') || (mainValue || '').length > 48;
        const fmtVal = fmt(mainValue);
        const nImg = r._img_count || (r.images ? r.images.length : 0);
        const nList = (r.images || []).length;
        const imgManager = (r.images || []).map((im, ix) => {
          const w = Math.max(10, Math.min(100, im.display_width || 50));
          return `
          <div class="imgrow" data-img="${im.id}">
            <div class="ph" style="background-image:url('${im.dataUri}')"></div>
            <div class="imgmeta">
              <input class="capin" value="${safe(im.caption || '')}" placeholder="legenda (opcional)" data-cap="${im.id}">
              <div class="sizerow">
                <div class="presets" data-size="${im.id}">
                  <button type="button" data-w="25"  class="${w===25?'on':''}">P</button>
                  <button type="button" data-w="50"  class="${w===50?'on':''}">M</button>
                  <button type="button" data-w="75"  class="${w===75?'on':''}">G</button>
                  <button type="button" data-w="100" class="${w===100?'on':''}">Full</button>
                </div>
                <input type="range" min="10" max="100" step="5" value="${w}" class="wslider" data-slider="${im.id}">
                <span class="wval" data-wval="${im.id}">${w}%</span>
              </div>
            </div>
            <div class="imgacts">
              <button type="button" data-move="up"   data-id="${im.id}" ${ix===0?'disabled':''}>↑</button>
              <button type="button" data-move="down" data-id="${im.id}" ${ix===nList-1?'disabled':''}>↓</button>
              <button type="button" class="rmimg" data-del="/lab/admin/images/${im.id}/delete">×</button>
            </div>
          </div>`;
        }).join('');
        const rightCell = rich
          ? `<div class="rvr">ref: ${safe(r.reference_value || '—')}</div>`
          : `<div class="rv" style="color:${color}">${fmtVal}</div><div class="rvr">ref: ${safe(r.reference_value || '—')}</div>`;
        const richBlock = rich
          ? `<div class="res-full" style="border-color:${color}"><span class="rl">Resultado</span><div class="rt" style="color:${color}">${fmtVal}</div></div>`
          : '';
        return `
        <div class="res" data-id="${r.id}">
          <div class="head"><div class="rail" style="background:${color === '#6e2c3c' ? 'var(--safranin)' : 'var(--hair)'}"></div>
            <div class="body"><div class="rn">${safe(r.exam_name)}</div>
              <div class="rm">${safe(r.method)} · ${safe(r.sample_type)}</div></div>
            <div class="rr">${rightCell}</div></div>
          ${richBlock}
          <div class="acts">
            <button data-dup="${r.id}">duplicar</button>
            <button data-edit="${r.id}">editar</button>
            <button data-img="${r.id}" class="${nImg ? 'imgn' : ''}">imagens${nImg ? ' (' + nImg + ')' : ''}</button>
            <button data-del="/lab/admin/resultados/${r.id}/delete">remover</button>
          </div>
          <div class="tray" id="tray${r.id}">
            <div class="imglist">${imgManager}</div>
            <div class="trayfoot">
              <button class="trayadd" data-upl="${r.id}">+ imagem</button>
              <a class="lfabtn" href="/lab/admin/lfa?resultado=${r.id}">Analisar cassete LFA →</a>
            </div>
          </div>
        </div>`;
      }).join('') || `<div class="emptylist">Nenhum exame ainda. Adicione o primeiro acima.</div>`;

      const nImgTotal = results.reduce((a, r) => a + (r._img_count || 0), 0);

      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(pageHtml({ id, patient, collection, age, rowsHtml, nExames: results.length, nImgTotal }));
    } catch (err) {
      console.error('EMISSOR PAGE ERROR', err);
      res.status(500).send('Falha ao abrir o emissor: ' + safe(err.message));
    }
  });

  // ── Painel do laboratório (hub de features) ──────────────────
  app.get('/lab/admin/painel', adminRequired, (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(painelHtml());
  });
}

// ── HTML completo da página (skin do diagnostico/) ──────────────
function pageHtml({ id, patient, collection, age, rowsHtml, nExames, nImgTotal }) {
  const sampleOptions = ['Soro','Sangue Total','Plasma','Urina','Secreção','Swab','Linfa','Fezes','Líquor','Líquido Sinovial','Outro']
    .map(s => `<option>${s}</option>`).join('');
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Emissor · ${safe(patient.full_name)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,340;9..144,420;9..144,540;9..144,600&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--ink:#211c1d;--ink-soft:#3a2f31;--slide:#f6f3ee;--slide-2:#efeae1;--paper:#fdfcf9;--safranin:#6e2c3c;--safranin-soft:#8a3a4e;--muted:#6b615e;--muted-2:#8a807c;--hair:#e0d8cd;--hair-dark:#4a3d3f;--sans:"IBM Plex Sans",system-ui,sans-serif;--serif:"Fraunces",Georgia,serif;--mono:"IBM Plex Mono",ui-monospace,monospace}
*{box-sizing:border-box}body{margin:0;font-family:var(--sans);color:var(--ink);line-height:1.5;background:radial-gradient(120% 90% at 82% 8%,rgba(110,44,60,.05),transparent 60%),var(--slide);-webkit-font-smoothing:antialiased}
h2{font-family:var(--serif);font-weight:420;margin:0}
button{font-family:inherit;cursor:pointer}a{color:inherit}
.appbar{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:1rem;padding:.7rem 1.6rem;background:rgba(246,243,238,.86);backdrop-filter:blur(10px);border-bottom:1px solid var(--hair)}
.seal{width:38px;height:38px;border-radius:50%;border:1.5px solid var(--safranin);display:grid;place-items:center;color:var(--safranin)}
.seal span{font-family:var(--serif);font-weight:540;font-size:19px}
.t1{font-family:var(--serif);font-size:1rem;font-weight:540}.t2{font-family:var(--mono);font-size:.58rem;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin-top:2px}
.crumbs{margin-left:auto;font-size:.8rem;color:var(--muted)}.crumbs a{text-decoration:none;color:var(--safranin)}
.wrap{max-width:1200px;margin:0 auto;padding:1.6rem}
.pat{display:flex;align-items:flex-end;gap:1.4rem;flex-wrap:wrap;padding:0 .2rem 1.3rem}
.tag{font-family:var(--mono);font-size:.66rem;letter-spacing:.18em;text-transform:uppercase;color:var(--safranin);font-weight:500}
.pat .name{font-size:1.9rem;font-family:var(--serif);font-weight:420}.pat .meta{font-family:var(--mono);font-size:.78rem;color:var(--muted)}
.grid{display:grid;grid-template-columns:1fr 320px;gap:1.3rem;align-items:start}@media(max-width:880px){.grid{grid-template-columns:1fr}}
.card{background:var(--paper);border:1px solid var(--hair);border-radius:16px;padding:1.3rem 1.35rem}.card+.card{margin-top:1.3rem}
.card h2{font-size:1.15rem}.sub{font-size:.82rem;color:var(--muted);margin:.15rem 0 1rem}
.linkish{background:none;border:none;color:var(--safranin);font-size:.76rem;font-family:var(--mono);text-decoration:underline;text-underline-offset:2px;padding:0}
.searchwrap{position:relative}.search,.manualExam{width:100%;padding:.7rem .9rem;border:1px solid var(--hair);border-radius:10px;background:#fff;font-size:.95rem}
.drop{position:absolute;left:0;right:0;top:calc(100% + 6px);background:#fff;border:1px solid var(--hair);border-radius:12px;box-shadow:0 14px 40px rgba(33,28,29,.12);max-height:280px;overflow:auto;z-index:8;display:none}.drop.open{display:block}
.opt{padding:.6rem .85rem;cursor:pointer;border-bottom:1px solid var(--slide-2)}.opt:last-child{border-bottom:none}.opt:hover{background:var(--slide)}
.opt .on{font-size:.92rem}.opt .og{font-family:var(--mono);font-size:.66rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted-2);margin-top:2px}
.auto{margin-top:1rem;display:grid;grid-template-columns:1fr 1fr 1fr;gap:.7rem}@media(max-width:560px){.auto{grid-template-columns:1fr}}
.f label{display:flex;align-items:center;gap:.4rem;font-family:var(--mono);font-size:.62rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-bottom:.3rem}
.f label .ab{font-size:.54rem;color:var(--safranin);border:1px solid var(--hair);border-radius:4px;padding:0 .28rem}
.f .val{padding:.55rem .7rem;border:1px solid var(--hair);border-radius:9px;background:var(--slide);font-size:.9rem;min-height:38px;color:var(--ink-soft)}.f .val.empty{color:var(--muted-2);font-style:italic}
.fin{width:100%;padding:.55rem .7rem;border:1px solid var(--hair);border-radius:9px;background:#fff;font-size:.9rem;min-height:38px;color:var(--ink)}.fin::placeholder{color:var(--muted-2);font-style:italic}
.reslabel{font-family:var(--mono);font-size:.62rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin:1rem 0 .3rem}
.seg{display:inline-flex;border:1px solid var(--hair);border-radius:9px;overflow:hidden;background:#fff}
.seg button{border:none;background:transparent;padding:.5rem .8rem;font-size:.85rem;color:var(--muted);border-right:1px solid var(--hair)}.seg button:last-child{border-right:none}.seg button.on{background:var(--ink);color:var(--slide)}.seg button.on.reag{background:var(--safranin)}
.txtin,.numin{width:100%;padding:.55rem .7rem;border:1px solid var(--hair);border-radius:9px;background:#fff;font-size:.92rem}.unit{font-family:var(--mono);font-size:.78rem;color:var(--muted);margin-left:.4rem}
.ta{width:100%;padding:.6rem .7rem;border:1px solid var(--hair);border-radius:0 0 9px 9px;background:#fff;font-size:.9rem;resize:vertical;min-height:84px;border-top:none}
.tbar{display:flex;align-items:center;gap:.3rem;border:1px solid var(--hair);border-bottom:none;border-radius:9px 9px 0 0;background:var(--slide);padding:.3rem .4rem}
.tbtn{width:28px;height:26px;border:1px solid var(--hair);background:#fff;border-radius:6px}.tbtn.b{font-weight:700}.tbtn.i{font-style:italic}
.thint{font-family:var(--mono);font-size:.6rem;color:var(--muted-2);margin-left:.4rem}
.optrow{display:flex;align-items:center;gap:.55rem;margin-top:.7rem;font-size:.82rem;color:var(--muted);cursor:pointer;user-select:none}
.chk{width:34px;height:20px;border-radius:999px;background:var(--hair-dark);position:relative;flex:0 0 auto;transition:background .2s}
.chk::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:#fff;transition:left .2s}
.optrow.on .chk{background:var(--safranin)}.optrow.on .chk::after{left:16px}
.tc{margin-top:.7rem;padding:.8rem;background:var(--slide);border-radius:10px;display:none;gap:.7rem;align-items:flex-end;flex-wrap:wrap}.tc.open{display:flex}.tc .f{flex:1;min-width:120px}.tc .prev{flex-basis:100%;font-family:var(--mono);font-size:.74rem;color:var(--safranin-soft)}
.actionbar{margin-top:1rem;display:flex;gap:.7rem;align-items:center}
.addbtn{background:var(--ink);color:var(--slide);border:none;border-radius:10px;padding:.62rem 1.05rem;font-size:.9rem;font-weight:500}.addbtn:hover{background:var(--ink-soft)}.addbtn[disabled]{opacity:.4;cursor:not-allowed}
.count{font-family:var(--mono);font-size:.72rem;color:var(--muted)}
.res{border-top:1px solid var(--slide-2)}.res:first-child{border-top:none}
.res .head{display:flex;align-items:center;gap:1rem;padding:.85rem .3rem}.res .rail{width:3px;align-self:stretch;border-radius:3px;min-height:40px}
.res .body{flex:1;min-width:0}.res .rn{font-family:var(--serif);font-size:1.02rem;font-weight:500}.res .rm{font-family:var(--mono);font-size:.66rem;letter-spacing:.06em;color:var(--muted-2);text-transform:uppercase;margin-top:2px}
.res .rr{text-align:right;white-space:normal;max-width:46%}.res .rv{font-weight:600;font-size:.98rem}.res .rvr{font-family:var(--mono);font-size:.68rem;color:var(--muted);margin-top:2px}
.res-full{margin:0 .3rem .5rem 1.3rem;padding:.55rem .75rem;border-left:2px solid var(--hair);background:var(--slide);border-radius:0 8px 8px 0}
.res-full .rl{display:block;font-family:var(--mono);font-size:.58rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-bottom:.3rem}
.res-full .rt{font-size:.92rem;line-height:1.55;word-break:break-word}
.acts{display:flex;gap:.9rem;padding:0 .3rem .7rem 1.3rem;font-family:var(--mono);font-size:.68rem}.acts button{background:none;border:none;color:var(--muted);padding:0;text-decoration:underline;text-underline-offset:2px}.acts button:hover{color:var(--safranin)}.acts .imgn{color:var(--safranin)}
.tray{display:none;padding:.5rem .3rem 1rem 1.3rem;flex-direction:column;gap:.6rem}.tray.open{display:flex}
.imglist{display:flex;flex-direction:column;gap:.6rem}
.imgrow{display:flex;gap:.7rem;align-items:flex-start;padding:.6rem;border:1px solid var(--hair);border-radius:10px;background:#fff}
.imgrow .ph{width:96px;height:96px;flex:0 0 auto;border-radius:8px;border:1px solid var(--hair);background:var(--slide-2) center/cover no-repeat}
.imgmeta{flex:1;min-width:0;display:flex;flex-direction:column;gap:.5rem}
.capin{width:100%;padding:.4rem .6rem;border:1px solid var(--hair);border-radius:8px;font-size:.85rem;background:#fff}
.sizerow{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap}
.presets{display:inline-flex;border:1px solid var(--hair);border-radius:8px;overflow:hidden}
.presets button{border:none;background:#fff;padding:.35rem .6rem;font-size:.78rem;color:var(--muted);border-right:1px solid var(--hair)}
.presets button:last-child{border-right:none}.presets button.on{background:var(--safranin);color:#fff}
.wslider{flex:1;min-width:90px;accent-color:var(--safranin)}
.wval{font-family:var(--mono);font-size:.72rem;color:var(--muted);min-width:38px;text-align:right}
.imgacts{display:flex;flex-direction:column;gap:.3rem}
.imgacts button{width:28px;height:26px;border:1px solid var(--hair);background:#fff;border-radius:6px;color:var(--muted);font-size:.85rem}
.imgacts button[disabled]{opacity:.35}
.imgacts .rmimg{color:var(--safranin)}
.trayfoot{display:flex;gap:.7rem;align-items:center}
.trayadd{border:1px dashed var(--hair-dark);background:transparent;border-radius:9px;padding:.5rem .8rem;color:var(--muted);font-size:.74rem;font-family:var(--mono)}.trayadd:hover{border-color:var(--safranin);color:var(--safranin)}
.lfabtn{background:var(--safranin);color:#fff;border:none;border-radius:9px;padding:.5rem .8rem;font-size:.74rem;font-family:var(--mono);text-decoration:none}
.emptylist{padding:1.4rem .3rem;color:var(--muted-2);font-style:italic}
.emit{position:sticky;top:76px}.emit h2{font-size:1.1rem;margin-bottom:.9rem}
.line{display:flex;justify-content:space-between;padding:.5rem 0;font-size:.88rem;border-top:1px solid var(--slide-2)}.line:first-of-type{border-top:none}.line .k{color:var(--muted)}.line .v{font-family:var(--mono);font-weight:500}
.emitbtn{width:100%;background:var(--safranin);color:#fff;border:none;border-radius:11px;padding:.8rem;font-size:.95rem;font-weight:500;margin-top:.6rem;text-decoration:none;display:block;text-align:center}.emitbtn:hover{background:var(--safranin-soft)}
.ghost{width:100%;background:transparent;color:var(--ink);border:1px solid var(--hair-dark);border-radius:11px;padding:.65rem;font-size:.88rem;margin-top:.6rem;text-decoration:none;display:block;text-align:center}.ghost:hover{background:var(--ink);color:var(--slide);border-color:var(--ink)}
.note{margin-top:1rem;font-size:.75rem;color:var(--muted);line-height:1.45;padding-top:.9rem;border-top:1px solid var(--slide-2)}
.backdrop{position:fixed;inset:0;background:rgba(33,28,29,.42);display:none;z-index:40;align-items:center;justify-content:center;padding:1.5rem}.backdrop.open{display:flex}
.modal{background:var(--paper);border-radius:18px;max-width:520px;width:100%;padding:1.6rem;max-height:90vh;overflow:auto}
.modal h3{font-family:var(--serif);font-weight:420;font-size:1.35rem;margin:0 0 1rem}
.mfield{margin-bottom:.85rem}.mfield label{display:block;font-family:var(--mono);font-size:.62rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin-bottom:.3rem}
.mfield input,.mfield select,.mfield textarea{width:100%;padding:.55rem .7rem;border:1px solid var(--hair);border-radius:9px;background:#fff}.mfield textarea{min-height:80px;resize:vertical}
.mrow{display:grid;grid-template-columns:1fr 1fr;gap:.7rem}
.mactions{display:flex;gap:.7rem;margin-top:1.2rem}.mactions .save{flex:1;background:var(--ink);color:var(--slide);border:none;border-radius:10px;padding:.7rem;font-weight:500}.mactions .cancel{background:transparent;border:1px solid var(--hair-dark);border-radius:10px;padding:.7rem 1.1rem}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style></head>
<body>
<div class="appbar">
  <div class="seal"><span>LM</span></div>
  <div><div class="t1">Consultório Dr. Leandro Mendes</div><div class="t2">Emissor de Laudos · Infectologia</div></div>
  <div class="crumbs"><a href="/lab/admin/painel" style="color:var(--safranin)">Painel</a> &nbsp;·&nbsp; <a href="/lab/admin/coletas/${id}">clássico</a> &nbsp;·&nbsp; Coleta ${toBR(collection.collected_at)}</div>
</div>
<div class="wrap">
  <div class="pat"><div><div class="tag">Paciente</div>
    <div class="name">${safe(patient.full_name)}</div>
    <div class="meta">${age != null ? age + ' anos · ' : ''}nasc. ${toBR(patient.birth_date)} · coleta ${toBR(collection.collected_at)}</div></div></div>
  <div class="grid">
    <div>
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:baseline"><h2>Adicionar exame</h2>
          <button class="linkish" id="toggleManualExam">digitar exame manualmente</button></div>
        <div class="sub">Escolha do catálogo — método, amostra e VR entram sozinhos.</div>
        <div class="searchwrap" id="searchBox"><input class="search" id="search" placeholder="Buscar exame…" autocomplete="off"><div class="drop" id="drop"></div></div>
        <input class="manualExam" id="manualExam" placeholder="Nome do exame (livre)" style="display:none">
        <div class="auto">
          <div class="f"><label>Método <span class="ab">auto</span></label><input class="fin" id="fMet" placeholder="selecione um exame"></div>
          <div class="f"><label>Amostra <span class="ab">auto</span></label><input class="fin" id="fAmo" placeholder="—"></div>
          <div class="f"><label>Valor de referência <span class="ab">auto</span></label><input class="fin" id="fVr" placeholder="—"></div>
        </div>
        <div class="reslabel">Resultado</div>
        <div id="resField"><div class="val empty">selecione um exame</div></div>
        <div class="optrow" id="tcToggle"><div class="chk"></div><span>Relação T/C (teste rápido / LFA)</span></div>
        <div class="tc" id="tcBox">
          <div class="f"><label>Relação T/C</label><input class="numin" id="tcVal" inputmode="decimal" placeholder="ex.: 0,3"></div>
          <div class="f"><label>Limiar</label><input class="numin" id="tcThr" inputmode="decimal" value="1,0"></div>
          <div class="prev" id="tcPrev">VR: Não Reagente – relação T/C &lt; 1,0</div>
        </div>
        <div class="optrow" id="manualToggle"><div class="chk"></div><span>Inserir resultado manual (texto livre)</span></div>
        <div class="reslabel">Observação <span style="text-transform:none;letter-spacing:0;color:var(--muted-2)">(opcional)</span></div>
        <div id="obsWrap">
          <div class="tbar"><button type="button" class="tbtn b" data-w="*">B</button><button type="button" class="tbtn i" data-w="_">I</button><span class="thint">*negrito* _itálico_ · texto livre</span></div>
          <textarea class="ta" id="fObs" placeholder="observação do exame (opcional)"></textarea>
        </div>
        <div class="actionbar"><button class="addbtn" id="addBtn" disabled>Adicionar à coleta</button><span class="count" id="addhint" style="color:var(--muted-2)">preencha o resultado</span></div>
      </div>
      <div class="card"><h2>Exames na coleta <span class="count" id="count">· ${nExames}</span></h2><div id="list">${rowsHtml}</div></div>
    </div>
    <div class="card emit">
      <h2>Emitir laudo</h2>
      <div class="line"><span class="k">Exames</span><span class="v">${nExames}</span></div>
      <div class="line"><span class="k">Imagens</span><span class="v">${nImgTotal}</span></div>
      <div class="line"><span class="k">Papel</span><span class="v">A4</span></div>
      <a class="emitbtn" href="/lab/admin/coletas/${id}/pdf2">Baixar PDF</a>
      <a class="ghost" href="/lab/admin/coletas/${id}/preview2" target="_blank" rel="noopener">Pré-visualizar</a>
      <div class="note">Este PDF é <b>sem assinatura</b> (paridade com o <code>/pdf</code> atual). A assinatura ICP-Brasil pluga no fluxo assinado já existente — próximo passo.</div>
    </div>
  </div>
</div>

<div class="backdrop" id="backdrop"><div class="modal">
  <h3>Editar resultado</h3>
  <form id="editForm" method="POST">
    <div class="mfield"><label>Exame</label><input name="exam_name" id="m_nome" required></div>
    <div class="mrow">
      <div class="mfield"><label>Tipo de amostra</label><select name="sample_type" id="m_amostra">${sampleOptions}</select></div>
      <div class="mfield"><label>Método</label><input name="method" id="m_metodo" required></div>
    </div>
    <div class="mfield"><label>Valor de referência</label><input name="reference_value" id="m_vr"></div>
    <div class="mfield"><label>Resultado</label><textarea name="result_value" id="m_result" required></textarea></div>
    <div class="mfield"><label>Observação</label><input name="observation" id="m_obs" placeholder="opcional"></div>
    <div class="mactions"><button type="submit" class="save">Salvar</button><button type="button" class="cancel" id="m_cancel">Cancelar</button></div>
  </form>
</div></div>

<script>
const COLLECTION_ID=${id};
const $=s=>document.querySelector(s);
let CAT=[],sel=null,resultVal=null,manualMode=false;

fetch('/lab/admin/api/exames-catalogo').then(r=>r.json()).then(d=>{CAT=Array.isArray(d)?d:[];}).catch(()=>{});

const search=$("#search"),drop=$("#drop");
function renderDrop(q){const t=(q||"").toLowerCase();const hits=CAT.filter(e=>e.nome.toLowerCase().includes(t)).slice(0,8);
  drop.innerHTML=hits.map(e=>'<div class="opt" data-n="'+encodeURIComponent(e.nome)+'"><div class="on">'+e.nome+'</div><div class="og">'+e.grupo+' · '+e.metodo+'</div></div>').join('')||'<div class="opt"><div class="on" style="color:var(--muted-2)">nenhum — use \\'digitar manualmente\\'</div></div>';
  drop.classList.add("open");}
search.addEventListener("input",()=>renderDrop(search.value));
search.addEventListener("focus",()=>renderDrop(search.value));
document.addEventListener("click",e=>{if(!e.target.closest("#searchBox"))drop.classList.remove("open");});
drop.addEventListener("click",e=>{const o=e.target.closest(".opt[data-n]");if(o){const nm=decodeURIComponent(o.dataset.n);pick(CAT.find(x=>x.nome===nm));}});

$("#toggleManualExam").onclick=()=>{const on=$("#manualExam").style.display==="none";$("#manualExam").style.display=on?"block":"none";$("#searchBox").style.display=on?"none":"block";$("#toggleManualExam").textContent=on?"escolher do catálogo":"digitar exame manualmente";if(on)$("#manualExam").focus();};
$("#manualExam").addEventListener("input",e=>{const nm=e.target.value.trim();if(nm){sel={nome:nm,metodo:"",amostra:"",vr:"",kind:"texto"};set("#fMet","—");set("#fAmo","—");set("#fVr","—");if(!manualMode)buildField(sel);}});

function pick(e){if(!e)return;sel=e;resultVal=null;search.value=e.nome;drop.classList.remove("open");set("#fMet",e.metodo);set("#fAmo",e.amostra);set("#fVr",e.vr);if(!manualMode)buildField(e);syncAdd();}
function set(id,v){const el=$(id);if(!el)return;const blank=!v||v==="—"||v==="selecione";if(el.tagName==="INPUT"){el.value=blank?"":v;}else{el.textContent=v||"—";el.classList.toggle("empty",blank);}}

function buildField(e){const host=$("#resField");const kind=e.kind||"texto";
  if(kind==="reagente"||kind==="detectado"){const pos=kind==="detectado"?"Detectado":"Reagente",neg=kind==="detectado"?"Não detectado":"Não reagente";
    host.innerHTML='<div class="seg"><button data-v="'+neg+'" data-r="0">'+neg+'</button><button data-v="'+pos+'" data-r="1">'+pos+'</button><button data-v="Indeterminado" data-r="0">Indeterminado</button></div>';
    host.querySelectorAll(".seg button").forEach(b=>b.onclick=()=>{host.querySelectorAll(".seg button").forEach(x=>x.classList.remove("on","reag"));b.classList.add("on");if(b.dataset.r==="1")b.classList.add("reag");resultVal={value:b.dataset.v};syncAdd();});
  }else if(kind==="dosagem"){host.innerHTML='<div style="display:flex;align-items:center"><input class="numin" id="num" inputmode="decimal" placeholder="valor"></div>';
    $("#num").oninput=ev=>{const r=ev.target.value.trim();resultVal=r?{value:r}:null;syncAdd();};
  }else{host.innerHTML='<div class="tbar"><button type="button" class="tbtn b" data-w="*">B</button><button type="button" class="tbtn i" data-w="_">I</button><span class="thint">*negrito* _itálico_ · SENSÍVEL A: / RESISTENTE A:</span></div><textarea class="ta" id="txt" placeholder="descrição"></textarea>';
    wireTB($("#resField"),$("#txt"));$("#txt").oninput=ev=>{const r=ev.target.value.trim();resultVal=r?{value:r}:null;syncAdd();};}
}
function wireTB(host,ta){host.querySelectorAll(".tbtn").forEach(b=>b.onclick=()=>{const w=b.dataset.w,s=ta.selectionStart,en=ta.selectionEnd,v=ta.value;ta.value=v.slice(0,s)+w+v.slice(s,en)+w+v.slice(en);ta.focus();ta.dispatchEvent(new Event("input"));});}

$("#manualToggle").onclick=()=>{manualMode=!manualMode;$("#manualToggle").classList.toggle("on",manualMode);
  if(manualMode){const host=$("#resField");host.innerHTML='<div class="tbar"><button type="button" class="tbtn b" data-w="*">B</button><button type="button" class="tbtn i" data-w="_">I</button><span class="thint">texto livre</span></div><textarea class="ta" id="txt" placeholder="resultado livre"></textarea>';wireTB(host,$("#txt"));$("#txt").oninput=ev=>{const r=ev.target.value.trim();resultVal=r?{value:r}:null;syncAdd();};}
  else if(sel){buildField(sel);resultVal=null;syncAdd();}};

$("#tcToggle").onclick=()=>{const on=!$("#tcToggle").classList.contains("on");$("#tcToggle").classList.toggle("on",on);$("#tcBox").classList.toggle("open",on);if(on)updTC();};
function updTC(){const t=$("#tcThr").value||"1,0";set("#fVr","Não Reagente – relação T/C < "+t);$("#tcPrev").textContent="VR: Não Reagente – relação T/C < "+t;}
$("#tcThr").addEventListener("input",updTC);
$("#tcVal").addEventListener("input",e=>{const v=e.target.value.trim();if(v){resultVal={value:"Não Reagente||TC||relação T/C = "+v};syncAdd();}});

function syncAdd(){const ok=!!(sel&&resultVal);$("#addBtn").disabled=!ok;$("#addhint").textContent=ok?"pronto":"preencha o resultado";}

$("#addBtn").onclick=async()=>{if(!sel||!resultVal)return;$("#addBtn").disabled=true;
  const body=new URLSearchParams();body.set("exam_name",sel.nome);body.set("sample_type",($("#fAmo").value||"").trim()||"—");body.set("method",($("#fMet").value||"").trim()||"—");body.set("result_value",resultVal.value);body.set("reference_value",($("#fVr").value||"").trim());body.set("observation",($("#fObs").value||"").trim());
  try{const r=await fetch("/lab/admin/coletas/"+COLLECTION_ID+"/resultados",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded","X-Requested-With":"XMLHttpRequest"},body});
    if(!r.ok)throw new Error("falha");location.reload();}catch(err){alert("Erro ao adicionar exame.");$("#addBtn").disabled=false;}};

/* row actions (fetch + reload) */
$("#list").addEventListener("click",async e=>{
  const b=e.target.closest("button");if(!b)return;
  if(b.dataset.del){const isImg=b.classList.contains("rmimg");const msg=isImg?"Remover imagem?":"Remover exame?";if(!confirm(msg))return;if(isImg){const rid=b.closest(".res")&&b.closest(".res").dataset.id;if(rid)sessionStorage.setItem("openTray",rid);}await postForm(b.dataset.del);location.reload();}
  else if(b.dataset.dup){const r=await fetch("/lab/admin/resultados/"+b.dataset.dup+"/json");const d=await r.json();prefillDup(d);window.scrollTo({top:0,behavior:"smooth"});}
  else if(b.dataset.edit){openEdit(b.dataset.edit);}
  else if(b.dataset.img){$("#tray"+b.dataset.img).classList.toggle("open");}
  else if(b.dataset.upl){uploadImg(b.dataset.upl);}
  else if(b.dataset.move){const rid=b.closest(".res")&&b.closest(".res").dataset.id;moveImg(b.dataset.id,b.dataset.move,rid);}
  else if(b.dataset.w!==undefined&&b.closest(".presets")){const id=b.closest(".presets").dataset.size;const w=+b.dataset.w;setSize(id,w);syncSize(id,w);}
});
/* slider de tamanho (ao vivo, com debounce) */
let _szTimer={};
$("#list").addEventListener("input",e=>{const s=e.target.closest(".wslider");if(!s)return;const id=s.dataset.slider,w=+s.value;syncSize(id,w);clearTimeout(_szTimer[id]);_szTimer[id]=setTimeout(()=>setSize(id,w),300);});
/* editar legenda (ao sair do campo) */
$("#list").addEventListener("change",e=>{const c=e.target.closest(".capin");if(!c)return;setCaption(c.dataset.cap,c.value);});
function syncSize(id,w){const p=document.querySelector('.presets[data-size="'+id+'"]');if(p)p.querySelectorAll("button").forEach(b=>b.classList.toggle("on",+b.dataset.w===w));const s=document.querySelector('.wslider[data-slider="'+id+'"]');if(s&&+s.value!==w)s.value=w;const v=document.querySelector('[data-wval="'+id+'"]');if(v)v.textContent=w+"%";}
async function setSize(id,w){try{await fetch("/lab/admin/images/"+id+"/update",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({display_width:w})});}catch(e){}}
async function setCaption(id,cap){try{await fetch("/lab/admin/images/"+id+"/update",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({caption:cap})});}catch(e){}}
async function moveImg(id,dir,rid){if(rid)sessionStorage.setItem("openTray",rid);await fetch("/lab/admin/images/"+id+"/move",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({dir})});location.reload();}
/* reabre a bandeja após reload (reordenar/remover imagem) */
(function(){const ot=sessionStorage.getItem("openTray");if(ot){sessionStorage.removeItem("openTray");const t=document.getElementById("tray"+ot);if(t)t.classList.add("open");}})();
/* toolbar da observação */
wireTB($("#obsWrap"),$("#fObs"));

async function postForm(action){await fetch(action,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:""});}

function prefillDup(d){manualMode=false;$("#manualToggle").classList.remove("on");
  sel={nome:d.exam_name,metodo:d.method,amostra:d.sample_type,vr:d.reference_value||"",kind:(d.method==="Marcador"?"dosagem":(d.method==="Sorologia"?"reagente":(d.method==="Antígeno"?"detectado":"texto")))};
  search.value=d.exam_name;set("#fMet",d.method);set("#fAmo",d.sample_type);set("#fVr",d.reference_value||"—");
  $("#fObs").value=d.observation||"";
  buildField(sel);resultVal={value:d.result_value};syncAdd();}

function uploadImg(resultId){const inp=document.createElement("input");inp.type="file";inp.accept="image/*";
  inp.onchange=()=>{const file=inp.files[0];if(!file)return;const rd=new FileReader();
    rd.onload=async()=>{const b64=rd.result.split(",")[1];const cap=prompt("Legenda (opcional):")||"";
      try{const r=await fetch("/lab/admin/resultados/"+resultId+"/images",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({data:b64,contentType:file.type,caption:cap})});
        if(!r.ok)throw new Error();location.reload();}catch(e){alert("Falha no upload.");}};
    rd.readAsDataURL(file);};inp.click();}

/* edit modal → POST no endpoint existente, depois reload */
function openEdit(rid){fetch("/lab/admin/resultados/"+rid+"/json").then(r=>r.json()).then(d=>{
  $("#editForm").action="/lab/admin/resultados/"+rid+"/edit";
  $("#m_nome").value=d.exam_name||"";$("#m_metodo").value=d.method||"";$("#m_vr").value=d.reference_value||"";
  $("#m_result").value=d.result_value||"";$("#m_obs").value=d.observation||"";
  const selA=$("#m_amostra");
  if(d.sample_type && ![...selA.options].some(o=>o.value===d.sample_type)){const opt=document.createElement("option");opt.value=d.sample_type;opt.textContent=d.sample_type;selA.insertBefore(opt,selA.firstChild);}
  [...selA.options].forEach(o=>o.selected=(o.value===d.sample_type));
  $("#backdrop").classList.add("open");});}
$("#m_cancel").onclick=()=>$("#backdrop").classList.remove("open");
$("#backdrop").addEventListener("click",e=>{if(e.target===$("#backdrop"))$("#backdrop").classList.remove("open");});
$("#editForm").addEventListener("submit",async e=>{e.preventDefault();const f=e.target;
  const body=new URLSearchParams(new FormData(f));
  await fetch(f.action,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body});location.reload();});
</script>
</body></html>`;
}

// ── Painel do laboratório (hub de features, skin do diagnostico/) ──
function painelHtml() {
  const ic = {
    users: '<path d="M9 11a4 4 0 100-8 4 4 0 000 8zM3 21a6 6 0 0112 0M17 11a3 3 0 100-6M21 21a5 5 0 00-8-4"/>',
    doc:   '<path d="M7 3h7l5 5v13H7zM14 3v5h5M10 13h6M10 17h6"/>',
    box:   '<path d="M3 8l9-5 9 5v8l-9 5-9-5zM3 8l9 5 9-5M12 13v8"/>',
    scan:  '<path d="M4 8V5a1 1 0 011-1h3M20 8V5a1 1 0 00-1-1h-3M4 16v3a1 1 0 001 1h3M20 16v3a1 1 0 01-1 1h-3M4 12h16"/>',
    list:  '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    globe: '<path d="M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c2.5 2.5 3.5 6 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-6-3.5-9s1-6.5 3.5-9z"/>',
    key:   '<path d="M15 7a4 4 0 11-5.7 3.6L3 17v3h3l1-1h2v-2h2l1.3-1.3A4 4 0 0115 7zM16.5 7.5h.01"/>',
  };
  const tile = (t, d, href, icon, ext) => `
    <a class="tile" href="${href}"${ext ? ' target="_blank" rel="noopener"' : ''}>
      <span class="ti"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${ic[icon]}</svg></span>
      <span class="tt">${t}${ext ? ' <span class="ext">↗</span>' : ''}</span>
      <span class="td">${d}</span>
    </a>`;

  const tiles = [
    tile('Pacientes', 'Cadastrar e gerenciar pacientes e chaves de acesso.', '/lab/admin/pacientes', 'users', false),
    tile('Coletas &amp; Laudos', 'Coletas recentes, abrir no emissor e emitir laudos.', '/lab/admin/coletas', 'doc', false),
    tile('Estoque', 'Controle de estoque dos testes rápidos.', '/estoque', 'box', false),
    tile('Analisador LFA', 'Ler o cassete do teste rápido (relação T/C).', '/lab/admin/lfa', 'scan', false),
    tile('Cadastro de exames', 'Editar o catálogo — método, amostra, grupo, descrição.', 'https://consultorio.lcmendes.med.br/diagnostico/admin.html', 'list', true),
    tile('Catálogo público', 'Site “Testes Oferecidos” para os pacientes.', 'https://consultorio.lcmendes.med.br', 'globe', true),
    tile('Portal do paciente', 'Onde o paciente acessa os resultados por chave.', '/lab', 'key', false),
  ].join('');

  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Painel do Laboratório</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,340;9..144,420;9..144,540;9..144,600&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--ink:#211c1d;--ink-soft:#3a2f31;--slide:#f6f3ee;--slide-2:#efeae1;--paper:#fdfcf9;--safranin:#6e2c3c;--safranin-soft:#8a3a4e;--muted:#6b615e;--muted-2:#8a807c;--hair:#e0d8cd;--hair-dark:#4a3d3f;--sans:"IBM Plex Sans",system-ui,sans-serif;--serif:"Fraunces",Georgia,serif;--mono:"IBM Plex Mono",ui-monospace,monospace}
*{box-sizing:border-box}body{margin:0;font-family:var(--sans);color:var(--ink);line-height:1.5;background:radial-gradient(120% 90% at 82% 6%,rgba(110,44,60,.05),transparent 60%),var(--slide);-webkit-font-smoothing:antialiased}
a{color:inherit;text-decoration:none}
.appbar{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:1rem;padding:.7rem 1.6rem;background:rgba(246,243,238,.86);backdrop-filter:blur(10px);border-bottom:1px solid var(--hair)}
.seal{width:38px;height:38px;border-radius:50%;border:1.5px solid var(--safranin);display:grid;place-items:center;color:var(--safranin)}
.seal span{font-family:var(--serif);font-weight:540;font-size:19px}
.t1{font-family:var(--serif);font-size:1rem;font-weight:540}.t2{font-family:var(--mono);font-size:.58rem;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);margin-top:2px}
.wrap{max-width:1040px;margin:0 auto;padding:2rem 1.6rem 3rem}
.head{display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:1rem;margin-bottom:1.6rem}
.tag{font-family:var(--mono);font-size:.68rem;letter-spacing:.18em;text-transform:uppercase;color:var(--safranin);font-weight:500}
.head h1{font-family:var(--serif);font-weight:420;font-size:2rem;margin:.1rem 0 0;letter-spacing:-.01em}
.newpat{background:var(--ink);color:var(--slide);border-radius:10px;padding:.6rem 1rem;font-size:.9rem;font-weight:500}.newpat:hover{background:var(--ink-soft)}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem}
@media(max-width:820px){.grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:520px){.grid{grid-template-columns:1fr}}
.tile{display:flex;flex-direction:column;gap:.5rem;background:var(--paper);border:1px solid var(--hair);border-radius:16px;padding:1.2rem 1.25rem;transition:border-color .15s,transform .15s,box-shadow .15s}
.tile:hover{border-color:var(--safranin);transform:translateY(-2px);box-shadow:0 12px 30px rgba(33,28,29,.08)}
.ti{width:40px;height:40px;border-radius:10px;background:var(--slide-2);display:grid;place-items:center;color:var(--safranin)}
.ti svg{width:22px;height:22px}
.tt{font-family:var(--serif);font-size:1.12rem;font-weight:540}
.tt .ext{font-family:var(--sans);font-size:.8rem;color:var(--muted-2)}
.td{font-size:.85rem;color:var(--muted);line-height:1.45}
.foot{margin-top:1.6rem;font-family:var(--mono);font-size:.68rem;color:var(--muted-2);text-align:center}
</style></head>
<body>
<div class="appbar">
  <div class="seal"><span>LM</span></div>
  <div><div class="t1">Consultório Dr. Leandro Mendes</div><div class="t2">Painel do Laboratório · Infectologia</div></div>
</div>
<div class="wrap">
  <div class="head">
    <div><div class="tag">Laboratório</div><h1>Painel</h1></div>
    <a class="newpat" href="/lab/admin/pacientes/novo">+ Novo paciente</a>
  </div>
  <div class="grid">${tiles}</div>
  <div class="foot">Testes Complementares · uso propedêutico em caráter de triagem</div>
</div>
</body></html>`;
}
