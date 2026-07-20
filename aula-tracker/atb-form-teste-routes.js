// atb-form-teste-routes.js
// ════════════════════════════════════════════════════════════════════════════
// Ambiente de DRY-RUN do formulário (pipeline "teste → promove").
//
// Serve uma cópia-espelho do form (atb-form-engine-teste.js) numa URL separada,
// gated por admin, SEM tocar no form de produção. Aqui você testa mudanças (ex.:
// o nudge de história da Fase C) preenchendo fichas dummy antes de promover.
//
// Fichas dummy: use o nome de paciente começando com "ZZ_TESTE" — o hard-delete
// já existente (/atb/admin/api/form-test/hard-delete) só apaga essas.
//
// Produção fica intocada: atb-form.html e atb-form-engine.js NÃO mudam. Quando o
// teste aprovar, portamos o diff do espelho pro engine de produção.
//
// Registro no app.js: registerFormTesteRoutes(app, pool, adminRequired);
// ════════════════════════════════════════════════════════════════════════════

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export function registerFormTesteRoutes(app, pool, adminRequired) {
  const gate = adminRequired || ((req, res, next) => next());

  // Engine espelho (Fase C) — servido só a admin.
  app.get('/atb/form-engine-teste.js', gate, (req, res) => {
    res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    res.sendFile(path.join(__dirname, 'atb-form-engine-teste.js'));
  });

  // Página host de teste — reusa o atb-form.html real, mas aponta pro engine
  // espelho e adiciona um banner de "ambiente de teste".
  app.get('/atb/form-teste', gate, (req, res) => {
    const inst = (req.atbTenant || req.query.inst || 'HUSF').replace(/[^A-Za-z0-9_]/g, '');
    let html;
    try {
      html = fs.readFileSync(path.join(__dirname, 'atb-form.html'), 'utf8');
    } catch (e) {
      return res.status(500).send('atb-form.html não encontrado');
    }
    // aponta pro engine espelho em vez do de produção
    html = html.replace('/atb/form-engine.js', '/atb/form-engine-teste.js');
    // injeta instituição + flag de teste
    html = html.replace(
      `<script>window.ATB_INSTITUICAO = window.ATB_INSTITUICAO || 'HUSF';</script>`,
      `<script>window.ATB_INSTITUICAO=${JSON.stringify(inst)};window.ATB_TESTE=true;</script>`
    );
    // banner visual pra não confundir com produção
    html = html.replace('<div id="app">',
      '<div style="background:#fef7e0;border-bottom:1px solid #f0d58a;padding:7px 12px;' +
      'font:13px system-ui,sans-serif;color:#7a5b00;text-align:center">' +
      '⚠ Ambiente de TESTE — nomeie o paciente como <b>ZZ_TESTE…</b> (descartável). ' +
      'Não é o formulário de produção.</div><div id="app">');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  });
}
