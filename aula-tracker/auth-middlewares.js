// ====== Auth middlewares ======
// Extraído do app.js — sem alterações de comportamento.
// Factory: recebe pool, ADMIN_SECRET e renderShell e devolve todos os middlewares,
// preservando os mesmos closures que existiam no app.js.

const parseISO = s => (s ? new Date(s) : null);

// Aceita apenas caminhos internos absolutos ("/x"), rejeitando protocol-relative
// ("//host") e qualquer coisa que abra open-redirect. Compartilhado com aulas-routes.
export function safeNext(n){
  if (typeof n !== 'string') return null;
  if (!n.startsWith('/')) return null;      // precisa ser caminho interno
  if (n.startsWith('//') || n.startsWith('/\\')) return null; // sem protocol-relative
  return n;
}

// URL que o usuário tentou acessar, só para navegação GET (replay de POST perderia o corpo).
const wantedUrl = req => (req.method === 'GET' ? safeNext(req.originalUrl) : null);
const withNext = (base, req) => {
  const n = wantedUrl(req);
  return n ? `${base}${base.includes('?') ? '&' : '?'}next=${encodeURIComponent(n)}` : base;
};

export function createAuthMiddlewares({ pool, ADMIN_SECRET, renderShell }) {

  const isAdmin = req => req.cookies?.adm === '1';

  const adminRequired = (req,res,next)=>{ if(!ADMIN_SECRET) return res.status(500).send('ADMIN_SECRET não configurado'); if(!isAdmin(req)) return res.redirect(withNext('/admin', req)); next(); };

  const authRequired = async (req,res,next)=>{
    const uid = req.cookies?.uid;
    if(!uid) return res.redirect(withNext('/', req));
    try{
      const { rows } = await pool.query('SELECT id,email,full_name,expires_at,scih,super_admin,micro FROM users WHERE id=$1',[uid]);
      const user = rows[0];
      if(!user) return res.redirect('/');
      const exp = parseISO(user.expires_at);
      if (exp && new Date() > exp) return res.send(renderShell('Acesso expirado', `<div class="card"><h1>Acesso expirado</h1><a href="/">Voltar</a></div>`));
      req.user = user;
      next();
    }catch{
      return res.redirect('/');
    }
  };

  // SCIH: exige login com flag scih/super_admin; ADMIN_SECRET (cookie adm) é break-glass
  const scihRequired = async (req,res,next)=>{
    const adm = isAdmin(req);
    const uid = req.cookies?.uid;
    if(!uid){
      if(adm){ req.user = null; return next(); }
      return res.redirect('/');
    }
    try{
      const { rows } = await pool.query('SELECT id,email,full_name,expires_at,scih,super_admin,micro,instituicao FROM users WHERE id=$1',[uid]);
      const user = rows[0];
      if(!user){ if(adm){ req.user = null; return next(); } return res.redirect('/'); }
      const exp = parseISO(user.expires_at);
      if (exp && new Date() > exp) return res.send(renderShell('Acesso expirado', `<div class="card"><h1>Acesso expirado</h1><a href="/">Voltar</a></div>`));
      req.user = user;
      if(user.scih || user.super_admin || adm){
        // Fase 3: vínculo de instituição. super_admin e break-glass (adm) cruzam tudo.
        // Só restringe com portal travado (req.atbTenant) e usuário vinculado a OUTRO hospital.
        // Sem trava ou sem vínculo → não restringe (idêntico ao atual).
        if (!user.super_admin && !adm && req.atbTenant && user.instituicao && user.instituicao !== req.atbTenant)
          return res.status(403).send(renderShell('Outra unidade', `<div class="card"><h1>Acesso de outra unidade</h1><p class="mut">Sua conta é vinculada a outra unidade hospitalar. Use o endereço da sua unidade.</p></div>`));
        return next();
      }
      return res.status(403).send(renderShell('Sem acesso', `<div class="card"><h1>Acesso restrito ao SCIH</h1><p class="mut">Sua conta não tem permissão para esta área. Fale com a coordenação.</p><a href="/inicio">Início</a></div>`));
    }catch{ return res.redirect('/'); }
  };

  // Grade ATB: SCIH, super_admin OU coordenação de microbiologia (micro); adm é break-glass
  const gridRequired = async (req,res,next)=>{
    const adm = isAdmin(req);
    const uid = req.cookies?.uid;
    if(!uid){ if(adm){ req.user = null; return next(); } return res.redirect('/'); }
    try{
      const { rows } = await pool.query('SELECT id,email,full_name,expires_at,scih,super_admin,micro,instituicao FROM users WHERE id=$1',[uid]);
      const user = rows[0];
      if(!user){ if(adm){ req.user = null; return next(); } return res.redirect('/'); }
      const exp = parseISO(user.expires_at);
      if (exp && new Date() > exp) return res.send(renderShell('Acesso expirado', `<div class="card"><h1>Acesso expirado</h1><a href="/">Voltar</a></div>`));
      req.user = user;
      if(user.scih || user.super_admin || user.micro || adm){
        // Fase 3: vínculo de instituição (super_admin e break-glass cruzam tudo). micro
        // segue a mesma regra. Só restringe com portal travado e vínculo a outro hospital.
        if (!user.super_admin && !adm && req.atbTenant && user.instituicao && user.instituicao !== req.atbTenant)
          return res.status(403).send(renderShell('Outra unidade', `<div class="card"><h1>Acesso de outra unidade</h1><p class="mut">Sua conta é vinculada a outra unidade hospitalar. Use o endereço da sua unidade.</p></div>`));
        return next();
      }
      return res.status(403).send(renderShell('Sem acesso', `<div class="card"><h1>Acesso restrito</h1><p class="mut">Sua conta não tem permissão para a grade.</p><a href="/inicio">Início</a></div>`));
    }catch{ return res.redirect('/'); }
  };

  // Prontuário: exige login com flag pront (ou super_admin); ADMIN_SECRET (cookie adm) é break-glass
  const prontRequired = async (req,res,next)=>{
    const adm = isAdmin(req);
    const uid = req.cookies?.uid;
    if(!uid){ if(adm){ req.user = null; return next(); } return res.redirect('/'); }
    try{
      const { rows } = await pool.query('SELECT id,email,full_name,expires_at,scih,super_admin,micro,pront FROM users WHERE id=$1',[uid]);
      const user = rows[0];
      if(!user){ if(adm){ req.user = null; return next(); } return res.redirect('/'); }
      const exp = parseISO(user.expires_at);
      if (exp && new Date() > exp) return res.send(renderShell('Acesso expirado', `<div class="card"><h1>Acesso expirado</h1><a href="/">Voltar</a></div>`));
      req.user = user;
      if(user.pront || user.super_admin || adm) return next();
      return res.status(403).send(renderShell('Sem acesso', `<div class="card"><h1>Acesso restrito ao prontuário</h1><p class="mut">Sua conta não tem permissão para o prontuário. Fale com o Dr. Leandro.</p><a href="/inicio">Início</a></div>`));
    }catch{ return res.redirect('/'); }
  };

  // Médico (gerador de documentos / ações clínicas): exige super_admin; ADMIN_SECRET (cookie adm) é break-glass
  const medicoRequired = async (req,res,next)=>{
    const adm = isAdmin(req);
    const uid = req.cookies?.uid;
    if(!uid){ if(adm){ req.user = null; return next(); } return res.redirect('/'); }
    try{
      const { rows } = await pool.query('SELECT id,email,full_name,expires_at,scih,super_admin,micro,pront FROM users WHERE id=$1',[uid]);
      const user = rows[0];
      if(!user){ if(adm){ req.user = null; return next(); } return res.redirect('/'); }
      const exp = parseISO(user.expires_at);
      if (exp && new Date() > exp) return res.send(renderShell('Acesso expirado', `<div class="card"><h1>Acesso expirado</h1><a href="/">Voltar</a></div>`));
      req.user = user;
      if(user.super_admin || adm) return next();
      return res.status(403).send(renderShell('Área do médico', `<div class="card"><h1>Área do médico</h1><p class="mut">O gerador de documentos é restrito ao médico responsável.</p><a href="/pront">Voltar ao prontuário</a></div>`));
    }catch{ return res.redirect('/'); }
  };

  // Agenda: exige login com flag agenda (secretária), recepcao (recepção) ou super_admin; adm é break-glass.
  // A granularidade fina (editar × só check-in) é resolvida dentro das rotas via req.user.
  const agendaRequired = async (req,res,next)=>{
    const adm = isAdmin(req);
    const uid = req.cookies?.uid;
    if(!uid){ if(adm){ req.user = null; return next(); } return res.redirect('/'); }
    try{
      const { rows } = await pool.query('SELECT id,email,full_name,expires_at,super_admin,agenda,recepcao FROM users WHERE id=$1',[uid]);
      const user = rows[0];
      if(!user){ if(adm){ req.user = null; return next(); } return res.redirect('/'); }
      const exp = parseISO(user.expires_at);
      if (exp && new Date() > exp) return res.send(renderShell('Acesso expirado', `<div class="card"><h1>Acesso expirado</h1><a href="/">Voltar</a></div>`));
      req.user = user;
      if(user.agenda || user.recepcao || user.super_admin || adm) return next();
      return res.status(403).send(renderShell('Sem acesso', `<div class="card"><h1>Acesso restrito à agenda</h1><p class="mut">Sua conta não tem permissão para a agenda. Fale com o Dr. Leandro.</p><a href="/inicio">Início</a></div>`));
    }catch{ return res.redirect('/'); }
  };

  // Secretária (flag agenda): app mobile próprio — pacientes, docs, agenda, orçamento.
  // Recepção (flag recepcao) NÃO entra aqui: ela só faz check-in em /agenda.
  const secretariaRequired = async (req,res,next)=>{
    const adm = isAdmin(req);
    const uid = req.cookies?.uid;
    if(!uid){ if(adm){ req.user = null; return next(); } return res.redirect('/'); }
    try{
      const { rows } = await pool.query('SELECT id,email,full_name,expires_at,super_admin,agenda,pront FROM users WHERE id=$1',[uid]);
      const user = rows[0];
      if(!user){ if(adm){ req.user = null; return next(); } return res.redirect('/'); }
      const exp = parseISO(user.expires_at);
      if (exp && new Date() > exp) return res.send(renderShell('Acesso expirado', `<div class="card"><h1>Acesso expirado</h1><a href="/">Voltar</a></div>`));
      req.user = user;
      if(user.agenda || user.super_admin || adm) return next();
      return res.status(403).send(renderShell('Sem acesso', `<div class="card"><h1>Área da secretaria</h1><p class="mut">Esta área é restrita à secretária. Recepção usa o check-in em <a href="/agenda">/agenda</a>.</p><a href="/inicio">Início</a></div>`));
    }catch{ return res.redirect('/'); }
  };

  // PAV (bundle de prevenção de PAV): exige login com flag pav (fisio/enf) ou
  // super_admin; adm é break-glass. A CATEGORIA (fisio × enf) e o CONSELHO vêm
  // no req.user — as rotas usam categoria_pav p/ decidir itens e alcance de salão
  // (fisio: dois salões; enf: o da sessão). Mesma disciplina de vínculo de
  // instituição do scihRequired (super_admin e adm cruzam tudo).
  const pavRequired = async (req,res,next)=>{
    const adm = isAdmin(req);
    const uid = req.cookies?.uid;
    if(!uid){ if(adm){ req.user = null; return next(); } return res.redirect('/'); }
    try{
      const { rows } = await pool.query('SELECT id,email,full_name,expires_at,scih,super_admin,pav,categoria_pav,conselho,treino,instituicao FROM users WHERE id=$1',[uid]);
      const user = rows[0];
      if(!user){ if(adm){ req.user = null; return next(); } return res.redirect('/'); }
      const exp = parseISO(user.expires_at);
      if (exp && new Date() > exp) return res.send(renderShell('Acesso expirado', `<div class="card"><h1>Acesso expirado</h1><a href="/">Voltar</a></div>`));
      req.user = user;
      if(user.pav || user.scih || user.super_admin || adm){
        if (!user.super_admin && !adm && req.atbTenant && user.instituicao && user.instituicao !== req.atbTenant)
          return res.status(403).send(renderShell('Outra unidade', `<div class="card"><h1>Acesso de outra unidade</h1><p class="mut">Sua conta é vinculada a outra unidade hospitalar. Use o endereço da sua unidade.</p></div>`));
        return next();
      }
      return res.status(403).send(renderShell('Sem acesso', `<div class="card"><h1>Acesso restrito ao bundle de PAV</h1><p class="mut">Sua conta não tem permissão para esta área. Fale com a coordenação.</p><a href="/inicio">Início</a></div>`));
    }catch{ return res.redirect('/'); }
  };

  return {
    isAdmin,
    adminRequired,
    authRequired,
    scihRequired,
    gridRequired,
    prontRequired,
    medicoRequired,
    agendaRequired,
    secretariaRequired,
    pavRequired,
  };
}
