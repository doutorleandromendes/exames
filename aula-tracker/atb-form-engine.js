// atb-form-engine.js
// ════════════════════════════════════════════════════════════════════════════
// Motor de renderização do formulário ATB, orientado a schema.
// Lê a definição via /atb/api/form-schema?inst=XXX e se monta sozinho.
// Sem build: React via UMD (global window.React / window.ReactDOM).
// Condicionais reagem em tempo real. Campos aparecem/somem suavemente.
// ════════════════════════════════════════════════════════════════════════════
(function () {
  'use strict';
  var e = React.createElement;
  var useState = React.useState, useEffect = React.useEffect, useMemo = React.useMemo;

  var LOGO = window.ATB_LOGO || '/atb/logo.png'; // injeção (data URI) OU arquivo servido

  // ── Avaliação de condicionais ─────────────────────────────────────────────
  // cond = { campo, op, valor }. Retorna true se o campo deve aparecer.
  function avaliaCond(cond, valores) {
    if (!cond) return true;
    var v = valores[cond.campo];
    switch (cond.op) {
      case 'eq':  return v === cond.valor;
      case 'neq': return v !== cond.valor;
      case 'in':  return Array.isArray(cond.valor) && cond.valor.indexOf(v) !== -1;
      case 'contains': // v é array (checkbox); contém o valor?
        return Array.isArray(v) && v.indexOf(cond.valor) !== -1;
      case 'contains_any': // v é array; contém algum dos valores?
        return Array.isArray(v) && Array.isArray(cond.valor) &&
               cond.valor.some(function (x) { return v.indexOf(x) !== -1; });
      default: return true;
    }
  }

  // ── Idade a partir da data de nascimento ──────────────────────────────────
  function calcIdade(dn) {
    if (!dn) return null;
    var d = new Date(dn + 'T00:00:00'); if (isNaN(d)) return null;
    var hoje = new Date(), anos = hoje.getFullYear() - d.getFullYear();
    var m = hoje.getMonth() - d.getMonth();
    if (m < 0 || (m === 0 && hoje.getDate() < d.getDate())) anos--;
    if (anos < 0) return null;
    if (anos === 0) {
      var meses = m < 0 ? m + 12 : m;
      return meses + (meses === 1 ? ' mês' : ' meses');
    }
    return anos + (anos === 1 ? ' ano' : ' anos');
  }

  // ── Validação de nome completo (≥2 palavras, sem vírgula/ponto) ───────────
  function validaNomeCompleto(v) {
    if (!v) return 'Campo obrigatório';
    if (/[.,]/.test(v)) return 'Não usar vírgula nem ponto (não abreviar)';
    var partes = v.trim().split(/\s+/).filter(Boolean);
    if (partes.length < 2) return 'Preencher nome completo (não abreviar)';
    return null;
  }

  // ════════════════════════════════════════════════════════════════════════
  // Componentes de campo
  // ════════════════════════════════════════════════════════════════════════

  function Rotulo(props) {
    return e('label', { className: 'rotulo' }, props.texto,
      props.required ? e('span', { className: 'req' }, '*') : null);
  }

  function CampoTexto(p) {
    var f = p.campo;
    function onCh(ev) {
      var v = ev.target.value;
      if (f.transform === 'upper') v = v.toUpperCase();
      p.set(f.key, v);
    }
    return e('div', { className: 'campo' },
      e(Rotulo, { texto: f.label, required: f.required }),
      e('input', {
        type: f.type === 'number' ? 'number' : (f.type === 'date' ? 'date' : 'text'),
        className: p.erro ? 'erro' : '', value: p.valor || '',
        placeholder: f.placeholder || '', readOnly: f.readonly,
        onChange: onCh
      }),
      f.showAge && p.valor ? e('span', { className: 'idade' }, 'Idade: ' + (calcIdade(p.valor) || '—')) : null,
      p.erro ? e('div', { className: 'erro-msg' }, p.erro) : null,
      f.hint ? e('div', { className: 'dica' }, f.hint) : null
    );
  }

  function CampoTextarea(p) {
    var f = p.campo;
    return e('div', { className: 'campo' },
      e(Rotulo, { texto: f.label, required: f.required }),
      e('textarea', {
        className: p.erro ? 'erro' : '', value: p.valor || '',
        placeholder: f.placeholder || '',
        onChange: function (ev) { p.set(f.key, ev.target.value); }
      }),
      p.erro ? e('div', { className: 'erro-msg' }, p.erro) : null,
      f.hint ? e('div', { className: 'dica' }, f.hint) : null
    );
  }

  function CampoSelect(p) {
    var f = p.campo;
    return e('div', { className: 'campo' },
      e(Rotulo, { texto: f.label, required: f.required }),
      e('div', { className: 'sel-wrap' },
        e('select', {
          className: p.erro ? 'erro' : '', value: p.valor || '',
          onChange: function (ev) { p.set(f.key, ev.target.value); }
        },
          e('option', { value: '' }, '— selecione —'),
          (f.options || []).map(function (o) { return e('option', { key: o, value: o }, o); })
        ),
        e('span', { className: 'seta' }, '▼')
      ),
      p.erro ? e('div', { className: 'erro-msg' }, p.erro) : null,
      f.hint ? e('div', { className: 'dica' }, f.hint) : null
    );
  }

  function CampoRadio(p) {
    var f = p.campo;
    return e('div', { className: 'campo' },
      e(Rotulo, { texto: f.label, required: f.required }),
      e('div', { className: 'opcoes' },
        (f.options || []).map(function (o) {
          var on = p.valor === o;
          return e('div', {
            key: o, className: 'opc' + (on ? ' on' : ''),
            onClick: function () { p.set(f.key, o); }
          },
            e('span', { className: 'marca radio' }), o);
        })
      ),
      p.erro ? e('div', { className: 'erro-msg' }, p.erro) : null,
      f.hint ? e('div', { className: 'dica' }, f.hint) : null
    );
  }

  function CampoCheckbox(p) {
    var f = p.campo;
    var arr = Array.isArray(p.valor) ? p.valor : [];
    function toggle(o) {
      var novo;
      // exclusivo: marcar 'Não' limpa o resto; marcar outro tira o exclusivo
      if (f.exclusivo) {
        if (o === f.exclusivo) { novo = arr.indexOf(o) !== -1 ? [] : [o]; }
        else {
          novo = arr.indexOf(o) !== -1 ? arr.filter(function (x) { return x !== o; })
                                       : arr.filter(function (x) { return x !== f.exclusivo; }).concat(o);
        }
      } else if (arr.indexOf(o) !== -1) {
        novo = arr.filter(function (x) { return x !== o; });
      } else {
        if (f.max && arr.length >= f.max) return; // respeita máximo
        novo = arr.concat(o);
      }
      p.set(f.key, novo);
    }
    return e('div', { className: 'campo' },
      e(Rotulo, { texto: f.label, required: f.required }),
      e('div', { className: 'opcoes' },
        (f.options || []).map(function (o) {
          var on = arr.indexOf(o) !== -1;
          var bloq = f.max && !on && arr.length >= f.max;
          return e('div', {
            key: o, className: 'opc' + (on ? ' on' : '') + (bloq ? ' dim' : ''),
            onClick: function () { if (!bloq) toggle(o); }
          },
            e('span', { className: 'marca check' }), o);
        })
      ),
      p.erro ? e('div', { className: 'erro-msg' }, p.erro) : null,
      f.hint ? e('div', { className: 'dica' }, f.hint) : null
    );
  }

  // ── Matriz como cartões empilhados ────────────────────────────────────────
  // Três modos: linhasFixas (lista fixa), sincronizaCom (linhas vêm de outro
  // campo checkbox), ou livre (até maxLinhas, add/remove manual).
  function CampoMatriz(p) {
    var f = p.campo;
    var linhas = Array.isArray(p.valor) ? p.valor : [];

    // sincronizaCom: as linhas espelham as drogas selecionadas em outro campo
    var sincro = f.sincronizaCom ? (p.valores[f.sincronizaCom] || []) : null;

    function setLinha(i, key, val) {
      var nv = linhas.slice();
      nv[i] = Object.assign({}, nv[i], {}); nv[i][key] = val;
      p.set(f.key, nv);
    }
    function addLinha() {
      if (f.maxLinhas && linhas.length >= f.maxLinhas) return;
      p.set(f.key, linhas.concat({}));
    }
    function rmLinha(i) {
      p.set(f.key, linhas.filter(function (_, j) { return j !== i; }));
    }

    // Modo linhasFixas: render direto, uma linha por item fixo
    if (f.linhasFixas) {
      return e('div', { className: 'campo matriz' },
        e(Rotulo, { texto: f.label, required: f.required }),
        f.linhasFixas.map(function (nome, i) {
          var row = linhas[i] || {};
          return e('div', { key: nome, className: 'check-linha' },
            e('span', { className: 'nome' }, nome),
            f.colunas.map(function (c) {
              if (c.type === 'check') {
                var on = !!row[c.key];
                return e('span', {
                  key: c.key, className: 'opc' + (on ? ' on' : ''),
                  style: { display: 'inline-flex' },
                  onClick: function () { setLinha(i, c.key, !on); }
                }, e('span', { className: 'marca check' }));
              }
              return e('input', {
                key: c.key, type: c.type === 'date' ? 'date' : 'text',
                style: { maxWidth: '150px' }, value: row[c.key] || '',
                placeholder: c.label,
                onChange: function (ev) { setLinha(i, c.key, ev.target.value); }
              });
            })
          );
        }),
        f.hint ? e('div', { className: 'dica' }, f.hint) : null
      );
    }

    // Modo sincronizaCom: uma linha por droga selecionada (read-only na 1ª col)
    if (sincro) {
      return e('div', { className: 'campo matriz' },
        e(Rotulo, { texto: f.label, required: f.required }),
        sincro.length === 0
          ? e('div', { className: 'dica' }, 'Selecione os antimicrobianos acima para preencher a posologia.')
          : sincro.map(function (droga, i) {
              var row = linhas[i] || {};
              return e('div', { key: droga + i, className: 'cartao' },
                e('div', { className: 'cartao-cab' },
                  e('span', { className: 'cartao-tag' }, droga)),
                f.colunas.map(function (c) {
                  if (c.readonly) return null;
                  return e('div', { key: c.key, className: 'mini-campo' },
                    e('span', { className: 'mini' }, c.label),
                    e('input', {
                      type: 'text', value: row[c.key] || '', placeholder: c.placeholder || '',
                      onChange: function (ev) {
                        var nv = linhas.slice();
                        nv[i] = Object.assign({}, nv[i], { droga: droga });
                        nv[i][c.key] = ev.target.value;
                        p.set(f.key, nv);
                      }
                    })
                  );
                })
              );
            }),
        f.hint ? e('div', { className: 'dica' }, f.hint) : null
      );
    }

    // Modo livre: cartões add/remove
    return e('div', { className: 'campo matriz' },
      e(Rotulo, { texto: f.label, required: f.required }),
      linhas.map(function (row, i) {
        return e('div', { key: i, className: 'cartao' },
          e('div', { className: 'cartao-cab' },
            e('span', { className: 'cartao-tag' }, (f.linhaLabel || 'Item') + ' ' + (i + 1)),
            e('button', { className: 'cartao-x', onClick: function () { rmLinha(i); }, title: 'Remover' }, '×')
          ),
          // agrupa datas lado a lado quando há inicio/termino
          renderColunasMatriz(f, row, i, setLinha)
        );
      }),
      e('button', {
        className: 'add-btn',
        disabled: f.maxLinhas && linhas.length >= f.maxLinhas,
        onClick: addLinha
      }, '+ Adicionar ' + (f.linhaLabel || 'item').toLowerCase()),
      f.hint ? e('div', { className: 'dica' }, f.hint) : null
    );
  }

  function renderColunasMatriz(f, row, i, setLinha) {
    var datas = f.colunas.filter(function (c) { return c.type === 'date'; });
    var outras = f.colunas.filter(function (c) { return c.type !== 'date'; });
    function campoCol(c) {
      if (c.type === 'select') {
        return e('div', { key: c.key, className: 'mini-campo' },
          e('span', { className: 'mini' }, c.label),
          e('div', { className: 'sel-wrap' },
            e('select', {
              value: row[c.key] || '',
              onChange: function (ev) { setLinha(i, c.key, ev.target.value); }
            },
              e('option', { value: '' }, '—'),
              (c.options || []).map(function (o) { return e('option', { key: o, value: o }, o); })),
            e('span', { className: 'seta' }, '▼'))
        );
      }
      return e('div', { key: c.key, className: 'mini-campo' },
        e('span', { className: 'mini' }, c.label),
        e('input', {
          type: 'text', value: row[c.key] || '', placeholder: c.placeholder || '',
          onChange: function (ev) { setLinha(i, c.key, ev.target.value); }
        })
      );
    }
    var blocos = [];
    outras.forEach(function (c) {
      if (c.key === datas[0] && datas.length) return;
      blocos.push(campoCol(c));
    });
    if (datas.length === 2) {
      blocos.push(e('div', { key: 'datas', className: 'mini-linha' },
        datas.map(function (c) {
          return e('div', { key: c.key },
            e('span', { className: 'mini' }, c.label),
            e('input', {
              type: 'date', value: row[c.key] || '',
              onChange: function (ev) { setLinha(i, c.key, ev.target.value); }
            }));
        })));
    } else {
      datas.forEach(function (c) { blocos.push(campoCol(c)); });
    }
    return blocos;
  }

  // ── CRM: formato → cadastrado (auto) ou fora do cadastro (nome + declaração) ──
  function CampoCRM(p) {
    var f = p.campo;
    var st = p.crmState; // { status, nome }  status: ''|checando|ok|fora|invalido|erro
    function valida(crm) {
      if (!crm) {
        p.setCrm({ status: '', nome: '' });
        p.set('prescritor_nome', ''); p.set('_crm_cadastrado', undefined);
        p.set('_declaracao', undefined);
        return;
      }
      p.setCrm({ status: 'checando', nome: '' });
      fetch('/atb/api/validar-crm?crm=' + encodeURIComponent(crm))
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (!d.valido) {
            // Salvaguarda 1: formato reprovado
            p.setCrm({ status: 'invalido', nome: '', motivo: d.motivo || 'CRM inválido' });
            p.set('prescritor_nome', ''); p.set('_crm_cadastrado', false);
            p.set('_declaracao', undefined);
          } else if (d.cadastrado) {
            // cadastrado: preenche nome automaticamente
            p.setCrm({ status: 'ok', nome: d.nome });
            p.set('prescritor_nome', d.nome); p.set('_crm_cadastrado', true);
            p.set('_declaracao', undefined);
          } else {
            // formato ok, fora do cadastro: exige nome manual + declaração
            p.setCrm({ status: 'fora', nome: '' });
            p.set('prescritor_nome', ''); p.set('_crm_cadastrado', false);
            p.set('_declaracao', false);
          }
        })
        .catch(function () { p.setCrm({ status: 'erro', nome: '' }); });
    }

    var fora = st && st.status === 'fora';
    var declarado = p.valores['_declaracao'] === true;

    return e('div', { className: 'campo' },
      e(Rotulo, { texto: f.label, required: f.required }),
      e('input', {
        type: 'text', className: (p.erro || (st && st.status === 'invalido')) ? 'erro' : '',
        value: p.valor || '', placeholder: 'Digite o CRM (somente números)',
        inputMode: 'numeric',
        onChange: function (ev) { p.set(f.key, ev.target.value.replace(/\D/g, '')); },
        onBlur: function (ev) { valida(ev.target.value.trim()); }
      }),
      st && st.status === 'checando' ? e('div', { className: 'dica' }, 'Verificando…') : null,
      st && st.status === 'ok' ? e('div', { className: 'idade' }, '✓ ' + st.nome + ' · cadastrado') : null,
      st && st.status === 'invalido' ? e('div', { className: 'erro-msg' }, st.motivo) : null,
      st && st.status === 'erro' ? e('div', { className: 'dica' }, 'Não foi possível verificar agora. Tente novamente.') : null,
      p.erro ? e('div', { className: 'erro-msg' }, p.erro) : null,

      // Fluxo "fora do cadastro": aviso + nome manual + declaração
      fora ? e('div', { className: 'aviso-fora' },
        e('div', { className: 'aviso-titulo' }, '⚠ CRM não consta no cadastro do hospital'),
        e('div', { className: 'aviso-texto' },
          'Para prosseguir, informe seu nome completo e confirme a declaração abaixo.'),
        e('div', { className: 'mini-campo', style: { marginTop: '12px' } },
          e('span', { className: 'mini' }, 'Nome completo do prescritor'),
          e('input', {
            type: 'text', className: p.erroNome ? 'erro' : '',
            value: p.valores['prescritor_nome'] || '',
            placeholder: 'Digite seu nome completo',
            onChange: function (ev) { p.set('prescritor_nome', ev.target.value.toUpperCase()); }
          })),
        e('div', {
          className: 'declaracao' + (declarado ? ' on' : '') + (p.erroDecl ? ' erro' : ''),
          onClick: function () { p.set('_declaracao', !declarado); }
        },
          e('span', { className: 'marca check' }),
          e('span', { className: 'declaracao-txt' },
            'Declaro que sou o(a) profissional responsável por esta solicitação, ' +
            'portador(a) do CRM ' + (p.valor || '') + ', e que as informações são verídicas.')),
        p.erroDecl ? e('div', { className: 'erro-msg' }, 'É necessário confirmar a declaração para enviar.') : null
      ) : null
    );
  }

  // ── SOFA (bloco especial — cálculo de gravidade) ──────────────────────────
  // Placeholder funcional do bloco 3. Por ora soma simples de 6 sistemas (0–4).
  var SOFA_SISTEMAS = [
    { key: 'resp', label: 'Respiratório (PaO₂/FiO₂)' },
    { key: 'coag', label: 'Coagulação (plaquetas)' },
    { key: 'hep', label: 'Hepático (bilirrubina)' },
    { key: 'cardio', label: 'Cardiovascular (PAM/aminas)' },
    { key: 'neuro', label: 'Neurológico (Glasgow)' },
    { key: 'renal', label: 'Renal (creatinina/diurese)' }
  ];
  function CampoSofa(p) {
    var f = p.campo;
    var val = (p.valor && typeof p.valor === 'object') ? p.valor : {};
    function setSis(k, v) {
      var nv = Object.assign({}, val); nv[k] = v; p.set(f.key, nv);
    }
    var total = SOFA_SISTEMAS.reduce(function (s, sis) {
      return s + (parseInt(val[sis.key], 10) || 0);
    }, 0);
    return e('div', { className: 'campo' },
      SOFA_SISTEMAS.map(function (sis) {
        return e('div', { key: sis.key, className: 'sofa-item' },
          e('span', { className: 'mini' }, sis.label),
          e('div', { className: 'sel-wrap' },
            e('select', {
              value: val[sis.key] || '',
              onChange: function (ev) { setSis(sis.key, ev.target.value); }
            },
              e('option', { value: '' }, '— pontos —'),
              [0, 1, 2, 3, 4].map(function (n) { return e('option', { key: n, value: n }, n + ' pontos'); })),
            e('span', { className: 'seta' }, '▼'))
        );
      }),
      e('div', { className: 'sofa-total' }, 'SOFA total: ' + total + ' pontos')
    );
  }

  // ── Despachante de campo por tipo ─────────────────────────────────────────
  function Campo(p) {
    var t = p.campo.type;
    if (t === 'text' || t === 'number' || t === 'date') return e(CampoTexto, p);
    if (t === 'textarea') return e(CampoTextarea, p);
    if (t === 'select')   return e(CampoSelect, p);
    if (t === 'radio')    return e(CampoRadio, p);
    if (t === 'checkbox') return e(CampoCheckbox, p);
    if (t === 'matrix')   return e(CampoMatriz, p);
    if (t === 'crm')      return e(CampoCRM, p);
    if (t === 'sofa')     return e(CampoSofa, p);
    return null;
  }

  // ════════════════════════════════════════════════════════════════════════
  // App principal
  // ════════════════════════════════════════════════════════════════════════
  function App() {
    var schemaState = useState(null), schema = schemaState[0], setSchema = schemaState[1];
    var loadErr = useState(null), erroLoad = loadErr[0], setErroLoad = loadErr[1];
    var valState = useState({}), valores = valState[0], setValores = valState[1];
    var errState = useState({}), erros = errState[0], setErros = errState[1];
    var crmState = useState({ status: '', nome: '' }), crm = crmState[0], setCrm = crmState[1];
    var okState = useState(false), enviado = okState[0], setEnviado = okState[1];
    var sendState = useState(false), enviando = sendState[0], setEnviando = sendState[1];

    var inst = window.ATB_INSTITUICAO || 'HUSF';

    useEffect(function () {
      fetch('/atb/api/form-schema?inst=' + encodeURIComponent(inst))
        .then(function (r) { if (!r.ok) throw new Error('schema indisponível'); return r.json(); })
        .then(function (d) { setSchema(d); })
        .catch(function (err) { setErroLoad(err.message); });
    }, []);

    function set(key, val) {
      setValores(function (prev) {
        var nv = Object.assign({}, prev); nv[key] = val; return nv;
      });
      // limpa erro do campo ao editar
      setErros(function (prev) {
        if (!prev[key]) return prev;
        var ne = Object.assign({}, prev); delete ne[key]; return ne;
      });
    }

    // Seções e campos visíveis dado o estado atual (condicionais reativas)
    var visiveis = useMemo(function () {
      if (!schema) return [];
      return schema.secoes
        .filter(function (sec) { return avaliaCond(sec.cond, valores); })
        .map(function (sec) {
          return Object.assign({}, sec, {
            campos: sec.campos.filter(function (c) { return avaliaCond(c.cond, valores); })
          });
        })
        .filter(function (sec) { return sec.campos.length > 0; });
    }, [schema, valores]);

    // Progresso: % de campos obrigatórios visíveis preenchidos
    var progresso = useMemo(function () {
      var obrig = [], preenchidos = 0;
      visiveis.forEach(function (sec) {
        sec.campos.forEach(function (c) {
          if (c.required) {
            obrig.push(c.key);
            var v = valores[c.key];
            if (Array.isArray(v) ? v.length : (v !== undefined && v !== '' && v !== null)) preenchidos++;
          }
        });
      });
      return obrig.length ? Math.round(preenchidos / obrig.length * 100) : 0;
    }, [visiveis, valores]);

    function validar() {
      var novos = {};
      visiveis.forEach(function (sec) {
        sec.campos.forEach(function (c) {
          var v = valores[c.key];
          if (c.type === 'crm') {
            // CRM: precisa de status resolvido. Se fora do cadastro, exige nome + declaração.
            if (!v) { novos[c.key] = 'Campo obrigatório'; return; }
            if (valores['_crm_cadastrado'] === false) {
              var nomeManual = valores['prescritor_nome'];
              if (!nomeManual || String(nomeManual).trim().split(/\s+/).filter(Boolean).length < 2) {
                novos['crm__nome'] = 'Informe o nome completo';
              }
              if (valores['_declaracao'] !== true) {
                novos['crm__decl'] = 'Confirme a declaração';
              }
            }
          } else if (c.validate === 'nome_completo') {
            var msg = validaNomeCompleto(v); if (msg) novos[c.key] = msg;
          } else if (c.required) {
            var vazio = Array.isArray(v) ? v.length === 0 : (v === undefined || v === '' || v === null);
            if (vazio) novos[c.key] = 'Campo obrigatório';
          }
        });
      });
      setErros(novos);
      return Object.keys(novos).length === 0;
    }

    function enviar() {
      if (!validar()) {
        var primeiro = document.querySelector('.erro, .erro-msg');
        if (primeiro) primeiro.scrollIntoView({ behavior: 'smooth', block: 'center' });
        return;
      }
      setEnviando(true);
      fetch('/atb/api/fichas', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ instituicao: inst, dados: valores })
      })
        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
        .then(function (res) {
          setEnviando(false);
          if (res.ok) setEnviado(true);
          else alert('Erro ao enviar: ' + (res.d.erro || 'tente novamente'));
        })
        .catch(function (err) { setEnviando(false); alert('Erro de conexão: ' + err.message); });
    }

    // Estados de carregamento
    if (erroLoad) return e('div', { className: 'erro-load' },
      'Não foi possível carregar o formulário. ', e('br'), erroLoad);
    if (!schema) return e('div', { className: 'carregando' }, 'Carregando formulário…');
    if (enviado) return e('div', null,
      cabecalho(schema, inst),
      e('div', { className: 'ok' },
        e('div', { className: 'icone' }, '✓'),
        e('h2', null, 'Solicitação enviada'),
        e('p', null, 'A SCIH foi notificada e dará retorno em breve.'))
    );

    var num = 0;
    return e('div', null,
      cabecalho(schema, inst),
      visiveis.map(function (sec) {
        num++;
        var n = ('0' + num).slice(-2);
        return e('div', { key: sec.id, className: 'secao' },
          e('div', { className: 'secao-cab' },
            e('span', { className: 'secao-num' }, n),
            e('span', { className: 'secao-tit' }, sec.titulo)),
          e('div', { className: 'secao-corpo' },
            sec.campos.map(function (c) {
              return e(Campo, {
                key: c.key, campo: c, valor: valores[c.key], valores: valores,
                erro: erros[c.key], set: set, inst: inst,
                erroNome: erros['crm__nome'], erroDecl: erros['crm__decl'],
                crmState: crm, setCrm: setCrm
              });
            }))
        );
      }),
      e('div', { className: 'rodape' },
        e('span', { className: 'prog' }, progresso + '% preenchido · ' + inst),
        e('button', { className: 'enviar', disabled: enviando, onClick: enviar },
          enviando ? 'Enviando…' : 'Enviar solicitação →'))
    );
  }

  function cabecalho(schema, inst) {
    return e('div', null,
      LOGO ? e('div', { className: 'cab' }, e('img', { src: LOGO, alt: 'HU São Francisco' })) : null,
      e('div', { className: 'faixa' },
        e('h1', null, schema.titulo || 'Ficha de solicitação de ATB de uso restrito'),
        e('div', { className: 'sub' }, 'SCIH · ' + inst))
    );
  }

  // Monta
  var root = ReactDOM.createRoot(document.getElementById('app'));
  root.render(e(App));
})();
