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
  function _normTxt(s) {
    return String(s == null ? '' : s).toLowerCase()
      .normalize('NFD').replace(/[\u0300-\u036f]/g, ''); // tira acentos
  }
  function _filled(v) {
    if (v == null) return false;
    if (Array.isArray(v)) return v.length > 0;
    return String(v).trim() !== '';
  }
  // texto contém algum token (sem caixa/acento; tokens de até 3 letras exigem limite de palavra)
  function _textContainsAny(v, tokens) {
    var hay = _normTxt(v);
    if (!hay || !Array.isArray(tokens)) return false;
    return tokens.some(function (t) {
      var nt = _normTxt(t);
      if (!nt) return false;
      if (nt.length <= 3) {
        var esc = nt.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        return new RegExp('(^|[^a-z0-9])' + esc + '([^a-z0-9]|$)').test(hay);
      }
      return hay.indexOf(nt) !== -1;
    });
  }
  function avaliaCond(cond, valores) {
    if (!cond) return true;
    if (cond.all) return cond.all.every(function (c) { return avaliaCond(c, valores); });
    if (cond.any) return cond.any.some(function (c) { return avaliaCond(c, valores); });
    var v = valores[cond.campo];
    switch (cond.op) {
      case 'eq':  return v === cond.valor;
      case 'neq': return v !== cond.valor;
      case 'in':  return Array.isArray(cond.valor) && cond.valor.indexOf(v) !== -1;
      case 'filled':     return _filled(v);
      case 'not_filled': return !_filled(v);
      case 'contains': // v é array (checkbox); contém o valor?
        return Array.isArray(v) && v.indexOf(cond.valor) !== -1;
      case 'contains_any': // v é array; contém algum dos valores?
        return Array.isArray(v) && Array.isArray(cond.valor) &&
               cond.valor.some(function (x) { return v.indexOf(x) !== -1; });
      case 'text_contains_any': // v é texto livre; casa algum token (robusto a abreviações)
        return _textContainsAny(v, cond.valor);
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
    var taProps = {
      className: p.erro ? 'erro' : '', value: p.valor || '',
      placeholder: f.placeholder || '',
      onChange: function (ev) { p.set(f.key, ev.target.value); }
    };
    if (f.bloquearColar) {
      var bloqueia = function (ev) {
        ev.preventDefault();
        var el = ev.currentTarget;
        el.style.outline = '2px solid #d9534f';
        el.title = 'Colar desativado neste campo — digite o texto.';
        setTimeout(function () { el.style.outline = ''; }, 600);
      };
      taProps.onPaste = bloqueia;                                  // Ctrl+V, menu, clique-do-meio
      taProps.onDrop = bloqueia;                                   // arrastar-soltar texto
      taProps.onDragOver = function (ev) { ev.preventDefault(); };
    }
    return e('div', { className: 'campo' },
      e(Rotulo, { texto: f.label, required: f.required }),
      e('textarea', taProps),
      f.bloquearColar ? e('div', { className: 'dica' },
        'Para garantir o registro real, este campo não aceita colar — digite a história clínica.') : null,
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

  // ── SOFA (bloco especial — fiel ao formulário JotForm) ────────────────────
  // Grava nas chaves planas que o parser (atb-parser.js) já espera: sofa_suporte,
  // sofa_spo2_aa, sofa_spo2_o2, sofa_pf, sofa_pam, sofa_plaq, sofa_bili,
  // sofa_glasgow, sofa_creat, sofa_diurese. O total exibido espelha o parser.
  var SOFA_RESP_SUPORTE = ['Ar ambiente', 'Oxigênio suplementar (cateter/máscara)', 'VNI ou Ventilação Mecânica (VM)'];
  var SOFA_OPC = {
    spo2_aa: ['≥ 97%', '95–96%', '92–94%', '< 92%'],
    spo2_o2: ['≥ 95%', '92–94%', '< 92%'],
    pf:      ['≥ 400', '300–399', '200–299', '100–199', '< 100'],
    pam:     ['PAM > 70 (sem DVA)', 'PAM < 70 (sem DVA)', 'Em uso de Dopamina ≤ 5 µg/kg/min ou qualquer dose de Dobutamina', 'Em uso de Dopamina > 5 ou Noradrenalina ≤ 0,1 µg/kg/min', 'Em uso de Dopamina > 15 ou Noradrenalina > 0,1 µg/kg/min'],
    plaq:    ['≥ 150 mil', '100–149 mil', '50–99 mil', '20–49 mil', '< 20 mil', 'Não disponível'],
    bili:    ['< 1,2', '1,2–1,9', '2,0–5,9', '6,0–11,9', '≥ 12,0', 'Não disponível'],
    glasgow: ['15', '13-14', '10-12', '6-9', '< 6', 'Não avaliado'],
    creat:   ['< 1,2', '1,2–1,9', '2,0–3,4', '3,5–4,9', '≥ 5,0', 'Não disponível'],
    diurese: ['> 500ml', '< 500ml', '< 200ml', 'Não mensurada']
  };
  var SOFA_SC = {
    spo2_aa: [0, 1, 2, 3],
    spo2_o2: [1, 2, 3],
    pf:      [0, 1, 2, 3, 4],
    pam:     [0, 1, 2, 3, 4],
    plaq:    [0, 1, 2, 3, 4, 0],
    bili:    [0, 1, 2, 3, 4, 0],
    glasgow: [0, 1, 2, 3, 4, 0],
    creat:   [0, 1, 2, 3, 4, 0],
    diurese: [0, 1, 2, 0]
  };
  function sofaScore(key, val) {
    var i = SOFA_OPC[key].indexOf(val);
    return (i >= 0 && SOFA_SC[key][i] != null) ? SOFA_SC[key][i] : 0;
  }
  function CampoSofa(p) {
    var V = p.valores || {};
    var grpStyle = { fontWeight: 600, color: '#0c447c', margin: '14px 0 6px', fontSize: '13px' };
    function selSofa(key, label) {
      return e('div', { key: key, className: 'sofa-item' },
        e('span', { className: 'mini' }, label),
        e('div', { className: 'sel-wrap' },
          e('select', {
            value: V['sofa_' + key] || '',
            onChange: function (ev) { p.set('sofa_' + key, ev.target.value); }
          },
            e('option', { value: '' }, '— selecione —'),
            SOFA_OPC[key].map(function (o, i) {
              return e('option', { key: o, value: o }, o + ' (+' + (SOFA_SC[key][i] || 0) + ')');
            })),
          e('span', { className: 'seta' }, '▼'))
      );
    }
    var suporte = V['sofa_suporte'] || '';
    var respSub = null, resp_sc = 0;
    if (suporte === 'Ar ambiente') { respSub = selSofa('spo2_aa', 'SpO₂ em ar ambiente'); resp_sc = sofaScore('spo2_aa', V['sofa_spo2_aa']); }
    else if (suporte === 'Oxigênio suplementar (cateter/máscara)') { respSub = selSofa('spo2_o2', 'SpO₂ com O₂ suplementar'); resp_sc = sofaScore('spo2_o2', V['sofa_spo2_o2']); }
    else if (suporte === 'VNI ou Ventilação Mecânica (VM)') { respSub = selSofa('pf', 'Relação PaO₂/FiO₂'); resp_sc = sofaScore('pf', V['sofa_pf']); }

    var renal_sc = Math.max(sofaScore('creat', V['sofa_creat']), sofaScore('diurese', V['sofa_diurese']));
    var total = resp_sc + sofaScore('pam', V['sofa_pam']) + sofaScore('plaq', V['sofa_plaq'])
      + sofaScore('bili', V['sofa_bili']) + sofaScore('glasgow', V['sofa_glasgow']) + renal_sc;

    return e('div', { className: 'campo' },
      e('div', { style: grpStyle }, 'Respiratório'),
      e('div', { className: 'sofa-item' },
        e('span', { className: 'mini' }, 'Suporte respiratório'),
        e('div', { className: 'sel-wrap' },
          e('select', {
            value: suporte,
            onChange: function (ev) { p.set('sofa_suporte', ev.target.value); }
          },
            e('option', { value: '' }, '— selecione —'),
            SOFA_RESP_SUPORTE.map(function (o) { return e('option', { key: o, value: o }, o); })),
          e('span', { className: 'seta' }, '▼'))),
      respSub,
      e('div', { style: grpStyle }, 'Cardiovascular (PAM / drogas vasoativas)'),
      selSofa('pam', 'Pressão arterial / DVA'),
      e('div', { style: grpStyle }, 'Coagulação'),
      selSofa('plaq', 'Plaquetas (/mm³)'),
      e('div', { style: grpStyle }, 'Hepático'),
      selSofa('bili', 'Bilirrubina (mg/dL)'),
      e('div', { style: grpStyle }, 'Neurológico'),
      selSofa('glasgow', 'Escala de coma de Glasgow'),
      e('div', { style: grpStyle }, 'Renal'),
      selSofa('creat', 'Creatinina (mg/dL)'),
      selSofa('diurese', 'Diurese (24h)'),
      e('div', { className: 'sofa-total' }, 'SOFA total: ' + total + ' pontos'),
      p.erro ? e('div', { className: 'erro-msg', style: { color: '#8a1414', marginTop: '8px', fontSize: '13px' } }, p.erro) : null
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
          } else if (c.type === 'sofa' && c.required) {
            var sup = valores['sofa_suporte'];
            var falta = !sup || !valores['sofa_pam'] || !valores['sofa_plaq']
              || !valores['sofa_bili'] || !valores['sofa_glasgow'] || !valores['sofa_creat'];
            if (sup === 'Ar ambiente' && !valores['sofa_spo2_aa']) falta = true;
            else if (sup === 'Oxigênio suplementar (cateter/máscara)' && !valores['sofa_spo2_o2']) falta = true;
            else if (sup === 'VNI ou Ventilação Mecânica (VM)' && !valores['sofa_pf']) falta = true;
            if (falta) novos[c.key] = 'Preencha todos os sistemas do SOFA';
         } else if (c.required || (c.requiredCond && avaliaCond(c.requiredCond, valores))) {
            var sv = Array.isArray(v) ? v : (v == null ? '' : String(v).trim());
            var vazio = Array.isArray(v) ? v.length === 0 : sv === '';
            if (vazio) novos[c.key] = 'Campo obrigatório';
            else if (c.minChars && !Array.isArray(v) && sv.length < c.minChars)
              novos[c.key] = 'Muito curto — descreva melhor (mín. ' + c.minChars + ' caracteres)';
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
