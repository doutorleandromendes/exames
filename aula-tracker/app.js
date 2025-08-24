// Aula Tracker — app único (Express + SQLite) com páginas de Login/Registro, Player e Relatório
ORDER BY u.email, e.client_ts`, [videoId], (err,rows)=>{
if(err) return res.status(500).send('erro');
const byUser = new Map();
for (const r of rows){
if(!byUser.has(r.email)) byUser.set(r.email, []);
byUser.get(r.email).push(r);
}
const lines = [];
byUser.forEach((events,email)=>{
const watched = new Set(); // aproximação: marca segundos reportados
for (const ev of events){
if(ev.type==='progress' || ev.type==='ended') watched.add(ev.video_time);
}
const percent = '≈ ' + Math.min(100, Math.round((watched.size / (/*dur*/ Math.max(...[...watched,0])+1 || 1)) * 100)) + '%';
lines.push(`<tr><td>${email}</td><td>${events[0]?.client_ts||''}</td><td>${events[events.length-1]?.client_ts||''}</td><td>${percent}</td></tr>`);
});
const body = `
<div class="card">
<div style="display:flex;justify-content:space-between;align-items:center">
<h1>Relatório da Aula #${videoId}</h1>
<a href="/admin/relatorio/${videoId}.csv">Baixar CSV</a>
</div>
<table>
<thead><tr><th>Aluno (e-mail)</th><th>Primeiro acesso</th><th>Último evento</th><th>Percentual (aprox.)</th></tr></thead>
<tbody>${lines.join('')}</tbody>
</table>
<p class="mut">Dica: o CSV tem todos os eventos (play/pause/progresso). Para cálculo preciso de % por aluno, consolide intervalos no backend em produção.</p>
</div>`;
res.send(renderPage('Relatório', body));
});
});


// ====== APIs ======
app.post('/api/register', async (req,res)=>{
const { email, password } = req.body || {};
if(!email || !password) return res.status(400).json({error:'Dados obrigatórios'});
try{
const hash = await bcrypt.hash(password, 10);
db.run('INSERT INTO users(email,password_hash) VALUES(?,?)',[email, hash], function(err){
if(err) return res.status(400).json({error:'E-mail já cadastrado'});
res.json({ok:true});
});
}catch{
res.status(500).json({error:'Falha ao registrar'});
}
});


app.post('/api/login', (req,res)=>{
const { email, password } = req.body || {};
if(!email || !password) return res.status(400).json({error:'Dados obrigatórios'});
db.get('SELECT id, password_hash FROM users WHERE email=?',[email], async (err,row)=>{
if(!row) return res.status(401).json({error:'Credenciais inválidas'});
const ok = await bcrypt.compare(password, row.password_hash);
if(!ok) return res.status(401).json({error:'Credenciais inválidas'});
res.cookie('uid', row.id, { httpOnly:true, sameSite:'lax' });
res.json({ok:true});
});
});


app.post('/track', (req,res)=>{
const { sessionId, type, videoTime, clientTs } = req.body || {};
if(!sessionId || !type) return res.status(400).end();
db.run('INSERT INTO events(session_id,type,video_time,client_ts) VALUES(?,?,?,?)',[sessionId,type,videoTime??0,clientTs??null],()=>res.status(204).end());
});


app.listen(PORT, ()=> console.log(`Aula Tracker rodando na porta ${PORT}`));
