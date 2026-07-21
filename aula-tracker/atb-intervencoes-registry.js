// atb-intervencoes-registry.js
// Registro das intervenções EMBUTIDO no código — não em disco. O Render é
// efêmero e o commit por arquivo (GitHub web UI) não preserva subpastas de
// forma confiável (achata os .json para a raiz). Embutidas aqui, as
// intervenções viajam com este módulo. Editar = editar este arquivo e commitar.
// Gerado a partir dos .json validados; mantê-lo como fonte única.


export const INTERVENCOES = {
  "gatilho-ia-narrativa": {
    "nome": "gatilho-ia-narrativa",
    "alvo": "atb-form-engine.js",
    "promovivel": true,
    "descricao": "Gatilho de IA: história narrativa. Blur informativo + bloqueio condicional no submit (obrigatoriedade), fail-open com tag. Regra vem de schema.narrativaCond; sem regra = nao bloqueia (producao segura).",
    "transformacoes": [
      {
        "nota": "state",
        "ancora": "    var sendState = useState(false), enviando = sendState[0], setEnviando = sendState[1];",
        "vira": "    var sendState = useState(false), enviando = sendState[0], setEnviando = sendState[1];\n    // Gatilho de IA — historia narrativa (Fase C)\n    var avisoSt = useState(null), historiaAviso = avisoSt[0], setHistoriaAviso = avisoSt[1];\n    var hChecSt = useState(false), historiaChecando = hChecSt[0], setHistoriaChecando = hChecSt[1];\n    var nudgeSt = useState(false), nudge = nudgeSt[0], setNudge = nudgeSt[1];\n    var hCacheRef = React.useRef({});\n    var hUltimoRef = React.useRef('');"
      },
      {
        "nota": "enviar+regra+modal",
        "ancora": "    function enviar() {\n      if (PREVIEW) { alert('Modo pré-visualização — o envio está desabilitado.'); return; }\n      if (!validar()) {\n        var primeiro = document.querySelector('.erro, .erro-msg');\n        if (primeiro) primeiro.scrollIntoView({ behavior: 'smooth', block: 'center' });\n        return;\n      }\n      setEnviando(true);\n      fetch('/atb/api/fichas', {\n        method: 'POST', headers: { 'Content-Type': 'application/json' },\n        body: JSON.stringify({ instituicao: inst, dados: valores })\n      })\n        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })\n        .then(function (res) {\n          setEnviando(false);\n          if (res.ok) setEnviado(true);\n          else alert('Erro ao enviar: ' + (res.d.error || res.d.erro || 'tente novamente'));\n        })\n        .catch(function (err) { setEnviando(false); alert('Erro de conexão: ' + err.message); });\n    }",
        "vira": "    // Regra de historia narrativa: vem de schema (campo historia_clinica -> narrativaCond).\n    // Sem regra configurada = nao bloqueia (producao segura). window.ATB_TESTE ativa a\n    // condicao de teste so no ambiente HUSF_TESTE (inerte em producao).\n    function regraNarrativa() {\n      var campo = null;\n      ((schema && schema.secoes) || []).forEach(function (s) {\n        (s.campos || []).forEach(function (c) { if (c.key === 'historia_clinica') campo = c; });\n      });\n      if (campo && campo.narrativaCond) return campo.narrativaCond;\n      if (window.ATB_TESTE) return { all: [ { campo: 'setor', op: 'in', valor: ['UTI', 'UTI C'] } ] };\n      return null;\n    }\n    function checarHistoria(texto) {\n      var t = String(texto || '').trim();\n      if (t.length < 15) { setHistoriaAviso(null); return; }\n      var cache = hCacheRef.current;\n      if (cache[t]) { setHistoriaAviso(cache[t].narrativa === false ? cache[t] : null); return; }\n      hUltimoRef.current = t;\n      setHistoriaChecando(true);\n      fetch('/atb/api/checar-historia', {\n        method: 'POST', headers: { 'Content-Type': 'application/json' },\n        body: JSON.stringify({ historia: t, inst: inst })\n      })\n        .then(function (r) { return r.json(); })\n        .then(function (d) {\n          setHistoriaChecando(false);\n          if (hUltimoRef.current !== t) return;\n          if (d && d.disponivel) {\n            cache[t] = { narrativa: d.narrativa, checagem_id: d.checagem_id };\n            setHistoriaAviso(d.narrativa === false ? cache[t] : null);\n          } else { setHistoriaAviso(null); }\n        })\n        .catch(function () { setHistoriaChecando(false); setHistoriaAviso(null); });\n    }\n    function postFicha(tagNarrativa) {\n      setNudge(false);\n      setEnviando(true);\n      fetch('/atb/api/fichas', {\n        method: 'POST', headers: { 'Content-Type': 'application/json' },\n        body: JSON.stringify({ instituicao: inst, dados: valores, historia_narrativa: (tagNarrativa === undefined ? null : tagNarrativa) })\n      })\n        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })\n        .then(function (res) {\n          setEnviando(false);\n          if (res.ok) setEnviado(true);\n          else alert('Erro ao enviar: ' + (res.d.error || res.d.erro || 'tente novamente'));\n        })\n        .catch(function (err) { setEnviando(false); alert('Erro de conexão: ' + err.message); });\n    }\n    function enviar() {\n      if (PREVIEW) { alert('Modo pré-visualização — o envio está desabilitado.'); return; }\n      if (!validar()) {\n        var primeiro = document.querySelector('.erro, .erro-msg');\n        if (primeiro) primeiro.scrollIntoView({ behavior: 'smooth', block: 'center' });\n        return;\n      }\n      var cond = regraNarrativa();\n      var t = String(valores['historia_clinica'] || '').trim();\n      if (!cond || !avaliaCond(cond, valores)) return postFicha(null);\n      var r = (t.length >= 15) ? hCacheRef.current[t] : null;\n      if (r && r.narrativa === true)  return postFicha(true);\n      if (r && r.narrativa === false) { setNudge(true); return; }\n      setHistoriaChecando(true);\n      var ctrl = new AbortController();\n      var to = setTimeout(function () { ctrl.abort(); }, 20000);\n      fetch('/atb/api/checar-historia', {\n        method: 'POST', headers: { 'Content-Type': 'application/json' },\n        body: JSON.stringify({ historia: t, inst: inst }), signal: ctrl.signal\n      })\n        .then(function (r2) { return r2.json(); })\n        .then(function (d) {\n          clearTimeout(to); setHistoriaChecando(false);\n          if (d && d.disponivel) {\n            hCacheRef.current[t] = { narrativa: d.narrativa, checagem_id: d.checagem_id };\n            if (d.narrativa === false) { setHistoriaAviso(hCacheRef.current[t]); setNudge(true); }\n            else postFicha(true);\n          } else { postFicha(null); }\n        })\n        .catch(function () { clearTimeout(to); setHistoriaChecando(false); postFicha(null); });\n    }\n    function modalNudge() {\n      return e('div', { style: { position: 'fixed', inset: 0, background: 'rgba(0,0,0,.45)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '16px' } },\n        e('div', { style: { background: '#fff', borderRadius: '12px', maxWidth: '480px', width: '100%', padding: '22px', boxShadow: '0 10px 40px rgba(0,0,0,.2)' } },\n          e('h3', { style: { margin: '0 0 8px', fontSize: '17px' } }, 'Complete a história clínica'),\n          e('p', { style: { margin: '0 0 14px', color: '#3c4043', fontSize: '14px', lineHeight: 1.5 } }, 'História Clínica sem informações suficientes sobre a indicação do ATB. Descreva melhor o quadro antes de enviar.'),\n          e('div', { style: { display: 'flex', justifyContent: 'flex-end', marginTop: '14px' } },\n            e('button', { onClick: function () { setNudge(false); var el = document.getElementById('campo-historia'); if (el) { el.scrollIntoView({ behavior: 'smooth', block: 'center' }); el.focus(); } }, style: { padding: '9px 16px', border: 0, borderRadius: '8px', background: '#1a73e8', color: '#fff', cursor: 'pointer', font: 'inherit' } }, 'Revisar história')\n          )\n        )\n      );\n    }"
      },
      {
        "nota": "textarea-hook",
        "ancora": "      taProps.onDragOver = function (ev) { ev.preventDefault(); };\n    }\n    return e('div', { className: 'campo' },",
        "vira": "      taProps.onDragOver = function (ev) { ev.preventDefault(); };\n    }\n    if (p.historiaHook) {\n      taProps.id = 'campo-historia';\n      taProps.onBlur = function (ev) { p.historiaHook.onBlur(ev.target.value); };\n    }\n    var _hh = p.historiaHook, _avisoBox = null;\n    if (_hh) {\n      if (_hh.checando) _avisoBox = e('div', { style: { marginTop: '6px', fontSize: '12.5px', color: '#5f6368' } }, 'verificando história…');\n      else if (_hh.aviso) _avisoBox = e('div', { style: { marginTop: '8px', padding: '9px 11px', background: '#fef7e0', border: '1px solid #f0d58a', borderRadius: '8px', fontSize: '13px', color: '#7a5b00', lineHeight: 1.45 } }, 'História Clínica sem informações suficientes sobre a indicação do ATB. Descreva melhor o quadro.');\n    }\n    return e('div', { className: 'campo' },"
      },
      {
        "nota": "textarea-box",
        "ancora": "      e('textarea', taProps),\n      f.bloquearColar ? e('div', { className: 'dica' },\n        'Para garantir o registro real, este campo não aceita colar — digite a história clínica.') : null,",
        "vira": "      e('textarea', taProps),\n      _avisoBox,\n      f.bloquearColar ? e('div', { className: 'dica' },\n        'Para garantir o registro real, este campo não aceita colar — digite a história clínica.') : null,"
      },
      {
        "nota": "campo-prop",
        "ancora": "              return e(Campo, {\n                key: c.key, campo: c, valor: valores[c.key], valores: valores,\n                erro: erros[c.key], set: set, inst: inst,\n                erroNome: erros['crm__nome'], erroDecl: erros['crm__decl'],\n                crmState: crm, setCrm: setCrm\n              });",
        "vira": "              return e(Campo, {\n                key: c.key, campo: c, valor: valores[c.key], valores: valores,\n                erro: erros[c.key], set: set, inst: inst,\n                erroNome: erros['crm__nome'], erroDecl: erros['crm__decl'],\n                crmState: crm, setCrm: setCrm,\n                historiaHook: c.key === 'historia_clinica'\n                  ? { onBlur: checarHistoria, aviso: historiaAviso, checando: historiaChecando }\n                  : null\n              });"
      },
      {
        "nota": "modal-render",
        "ancora": "      e('div', { className: 'rodape' },\n        e('span', { className: 'prog' }, progresso + '% preenchido · ' + inst),\n        e('button', { className: 'enviar', disabled: enviando, onClick: enviar },\n          enviando ? 'Enviando…' : 'Enviar solicitação →'))\n    );",
        "vira": "      e('div', { className: 'rodape' },\n        e('span', { className: 'prog' }, progresso + '% preenchido · ' + inst),\n        e('button', { className: 'enviar', disabled: enviando, onClick: enviar },\n          enviando ? 'Enviando…' : 'Enviar solicitação →')),\n      nudge ? modalNudge() : null\n    );"
      }
    ]
  },
  "form-teste-schema-override": {
    "nome": "form-teste-schema-override",
    "alvo": "atb-form-engine.js",
    "promovivel": false,
    "descricao": "CÓDIGO SÓ-DE-TESTE: schema vem de ATB_SCHEMA_INST. NÃO promover — só o ambiente de teste usa.",
    "transformacoes": [
      {
        "ancora": "      fetch('/atb/api/form-schema?inst=' + encodeURIComponent(inst))",
        "vira": "      fetch('/atb/api/form-schema?inst=' + encodeURIComponent(window.ATB_SCHEMA_INST || inst))",
        "nota": "só-teste"
      }
    ]
  }
};

export const ORDEM_INTERVENCOES = ["gatilho-ia-narrativa","form-teste-schema-override"];

export function listarIntervencoes() {
  return ORDEM_INTERVENCOES.map((nome) => ({ ...INTERVENCOES[nome], _nome: nome }));
}
