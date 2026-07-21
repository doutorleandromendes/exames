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
      case 'not_contains': // v é array; NÃO contém o valor (array ausente/vazio conta como não-contém)
        return !(Array.isArray(v) && v.indexOf(cond.valor) !== -1);
      case 'contains_any': // v é array; contém algum dos valores?
        return Array.isArray(v) && Array.isArray(cond.valor) &&
               cond.valor.some(function (x) { return v.indexOf(x) !== -1; });
      case 'not_contains_any': // v é array; NÃO contém nenhum dos valores
        return !(Array.isArray(v) && Array.isArray(cond.valor) &&
               cond.valor.some(function (x) { return v.indexOf(x) !== -1; }));
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

  // Campo é obrigatório agora? — fixo (required) OU condicional satisfeito
  // (requiredCond). Espelha a validação real (linha ~915) para o asterisco
  // aparecer/sumir em tempo real conforme o preenchimento.
  function _ehObrigatorio(f, valores) {
    if (f.required) return true;
    if (f.requiredCond) return avaliaCond(f.requiredCond, valores || {});
    return false;
  }

  function CampoTexto(p) {
    var f = p.campo;
    function onCh(ev) {
      var v = ev.target.value;
      if (f.transform === 'upper') v = v.toUpperCase();
      p.set(f.key, v);
    }
    return e('div', { className: 'campo' },
      e(Rotulo, { texto: f.label, required: _ehObrigatorio(f, p.valores) }),
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
      e(Rotulo, { texto: f.label, required: _ehObrigatorio(f, p.valores) }),
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
      e(Rotulo, { texto: f.label, required: _ehObrigatorio(f, p.valores) }),
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
      e(Rotulo, { texto: f.label, required: _ehObrigatorio(f, p.valores) }),
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
      e(Rotulo, { texto: f.label, required: _ehObrigatorio(f, p.valores) }),
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
        e(Rotulo, { texto: f.label, required: _ehObrigatorio(f, p.valores) }),
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
        e(Rotulo, { texto: f.label, required: _ehObrigatorio(f, p.valores) }),
        sincro.length === 0
          ? e('div', { className: 'dica' }, 'Selecione os antimicrobianos acima para preencher a posologia.')
          : sincro.map(function (droga, i) {
              var row = linhas[i] || {};
              return e('div', { key: droga + i, className: 'cartao' },
                e('div', { className: 'cartao-cab' },
                  e('span', { className: 'cartao-tag' }, droga)),
                e('div', { className: 'poso-linha',
                    style: { display: 'flex', alignItems: 'flex-end', gap: '12px', flexWrap: 'wrap' } },
                  f.colunas.map(function (c) {
                    if (c.readonly) return null;
                    if (!_celulaVisivel(c, row)) return null;
                    var onCell = function (v) {
                      var nv = linhas.slice();
                      nv[i] = Object.assign({}, nv[i], { droga: droga });
                      nv[i][c.key] = v;
                      p.set(f.key, nv);
                    };
                    // freq_horas: campo estreito + sufixo "h", sem rótulo empilhado
                    if (c.key === 'freq_horas') {
                      return e('div', { key: c.key, className: 'mini-campo poso-horas',
                          style: { display: 'flex', alignItems: 'center', gap: '6px', marginBottom: 0, paddingBottom: '1px' } },
                        e('div', { style: { width: '56px' } }, _celulaMatriz(c, row, onCell)),
                        e('span', { className: 'poso-sufixo', style: { fontSize: '13px', color: '#5f6b7a' } }, 'h'));
                    }
                    // largura por coluna: dose e unidade estreitos; frequência ao conteúdo
                    var larg = c.key === 'dose_valor' ? '76px'
                             : c.key === 'dose_unidade' ? '88px'
                             : c.key === 'freq_tipo' ? '150px' : 'auto';
                    return e('div', { key: c.key, className: 'mini-campo',
                        style: { width: larg, marginBottom: 0 } },
                      e('span', { className: 'mini' }, c.label),
                      _celulaMatriz(c, row, onCell));
                  })
                )
              );
            }),
        f.hint ? e('div', { className: 'dica' }, f.hint) : null
      );
    }

    // Modo livre: cartões add/remove
    return e('div', { className: 'campo matriz' },
      e(Rotulo, { texto: f.label, required: _ehObrigatorio(f, p.valores) }),
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

  function _celulaVisivel(c, row) {
    if (!c || !c.mostrarSe) return true;
    return row[c.mostrarSe.campo] === c.mostrarSe.valor;
  }
  function _celulaMatriz(c, row, onChange) {
    var val = row[c.key];
    if (c.type === 'select') {
      return e('div', { className: 'sel-wrap' },
        e('select', {
          value: val == null ? '' : val,
          onChange: function (ev) { onChange(ev.target.value); }
        },
          e('option', { value: '' }, '\u2014'),
          (c.options || []).map(function (o) {
            var v = (o && typeof o === 'object') ? o.v : o;
            var l = (o && typeof o === 'object') ? o.l : o;
            return e('option', { key: v, value: v }, l);
          })),
        e('span', { className: 'seta' }, '\u25bc'));
    }
    if (c.type === 'number') {
      return e('input', {
        type: 'text', inputMode: 'decimal', style: { maxWidth: '110px' },
        value: (val === null || val === undefined) ? '' : String(val),
        placeholder: c.placeholder || '',
        onChange: function (ev) { onChange(ev.target.value); },
        onBlur: function (ev) {
          var t = String(ev.target.value == null ? '' : ev.target.value).trim().replace(',', '.');
          if (t === '') return onChange('');
          var n = Number(t);
          if (!isNaN(n) && isFinite(n)) onChange(n);
        }
      });
    }
    return e('input', {
      type: 'text',
      value: val == null ? '' : val, placeholder: c.placeholder || '',
      onChange: function (ev) { onChange(ev.target.value); }
    });
  }

  function renderColunasMatriz(f, row, i, setLinha) {
    var datas = f.colunas.filter(function (c) { return c.type === 'date'; });
    var outras = f.colunas.filter(function (c) { return c.type !== 'date'; });
    function campoCol(c) {
      if (!_celulaVisivel(c, row)) return null;
      return e('div', { key: c.key, className: 'mini-campo' },
        e('span', { className: 'mini' }, c.label),
        _celulaMatriz(c, row, function (v) { setLinha(i, c.key, v); })
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
      e(Rotulo, { texto: f.label, required: _ehObrigatorio(f, p.valores) }),
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

  // ── Auxílio de dose — Vancomicina (alvo AUC 400–600) ──────────────────────
  // Widget de apoio ao prescritor. Lê peso real e ClCr atual (chaves reais
  // 'peso'/'clcr', que persistem), foco e CIM (estado local). Sugere ataque,
  // manutenção e intervalo, estima a AUC24 a priori e alerta por CIM. Botão
  // "aplicar na posologia" grava dose+intervalo na linha da Vancomicina.
  // Estimativa populacional — SEMPRE refinar por nível/AUC bayesiano real.
  var VANCO_CL_COEF = 0.048; // CL vanco (L/h) ≈ 0,048 × ClCr(mL/min) — a priori
  var VANCO_FOCOS = [
    { v:'Bacteremia / sepse',            grave:true,  mgkg:20 },
    { v:'Endocardite',                   grave:true,  mgkg:20 },
    { v:'SNC / meningite',               grave:true,  mgkg:20 },
    { v:'Osteoarticular',                grave:true,  mgkg:20 },
    { v:'Pneumonia',                     grave:true,  mgkg:20 },
    { v:'ICS relacionada a cateter',     grave:true,  mgkg:20 },
    { v:'Pele e partes moles',           grave:false, mgkg:15 },
    { v:'ITU',                           grave:false, mgkg:15 },
    { v:'Outro / não especificado',      grave:false, mgkg:15 }
  ];
  function _vNum(v) { var n = parseFloat(String(v == null ? '' : v).replace(',', '.')); return isFinite(n) ? n : NaN; }
  function _vRound250(mg) { return Math.round(mg / 250) * 250; }
  function _vFmtG(mg) {
    if (!isFinite(mg)) return '—';
    var g = mg / 1000, s = (Math.round(g * 100) / 100).toString().replace('.', ',');
    return s + ' g';
  }
  function _vIntervaloHoras(clcr, aggressive) {
    if (!isFinite(clcr)) return null;
    if (clcr >= 90) return { horas: aggressive ? 8 : 12, label: aggressive ? '8/8h' : '12/12h', aplica: aggressive ? '8/8h' : '12/12h', nota: aggressive ? 'intervalo encurtado (foco grave / CIM 2)' : '' };
    if (clcr >= 50) return { horas:12, label:'12/12h',  aplica:'12/12h', nota:'' };
    if (clcr >= 30) return { horas:24, label:'24/24h',  aplica:'24/24h', nota:'' };
    if (clcr >= 15) return { horas:null, label:'24–48h', aplica:'24/24h', nota:'guiar por nível — sem cálculo automático de dose', guiado:true };
    return { horas:null, label:'pós-HD / por nível', aplica:'', nota:'ataque + reposição pós-diálise; guiar por nível', guiado:true };
  }
  // Núcleo. Dois modos:
  //  • HD intermitente alto fluxo (HUSF): remove ~30–50%/sessão → carga 20–25 mg/kg
  //    + manutenção ~10 mg/kg APÓS cada sessão, guiada por nível pré-HD (alvo 15–20).
  //    Não calcula AUC (targeting por nível pré-HD é o padrão prático em HD).
  //  • Não-HD: AUC-driven (dose calculada p/ AUC-alvo dado o ClCr; foco/CIM encurtam
  //    intervalo). Teto por dose 2 g e diário 4,5 g. IMC≥30 dispara avisos de obesidade.
  function computeVanco(peso, clcr, foco, tipoTerapia, mic, altura, hd) {
    var r = { ok:false, avisos:[] };
    var pesoN = _vNum(peso), clcrN = _vNum(clcr), altN = _vNum(altura);
    r.pesoOk = isFinite(pesoN) && pesoN > 0;
    r.clcrOk = isFinite(clcrN) && clcrN >= 0;
    var focoDef = null, i;
    for (i = 0; i < VANCO_FOCOS.length; i++) if (VANCO_FOCOS[i].v === foco) focoDef = VANCO_FOCOS[i];
    r.grave = !!(focoDef && focoDef.grave);
    var profilaxia = tipoTerapia === 'Profilaxia cirúrgica';
    r.profilaxia = profilaxia;

    // IMC / obesidade
    if (r.pesoOk && isFinite(altN) && altN > 0) {
      r.imc = pesoN / Math.pow(altN / 100, 2);
      r.obeso = r.imc >= 30;
    }

    // Ataque (mg/kg peso real, teto 3 g) — suprimido em profilaxia cirúrgica
    if (r.pesoOk && !profilaxia) {
      r.ataqueMg = Math.min(_vRound250(25 * pesoN), 3000);
      r.ataqueFaixa = r.obeso ? '20–25 mg/kg' : '25–30 mg/kg';
    }

    // ── Modo HD intermitente alto fluxo ─────────────────────────────────────
    if (hd) {
      r.hd = true;
      if (r.pesoOk) {
        r.doseMg = _vRound250(10 * pesoN);           // ~7,5–10 mg/kg
        if (r.doseMg < 500) r.doseMg = 500;
        if (r.doseMg > 1500) r.doseMg = 1500;
        r.doseTxt = _vFmtG(r.doseMg);
        r.mgkg = Math.round(r.doseMg / pesoN);
      }
      r.intervalo = { label:'após cada sessão de HD', aplica:'após cada HD' };
      r.alvoTxt = 'nível pré-HD 15–20 µg/mL';
      r.avisos.push('Alto fluxo remove ~30–50% da vancomicina por sessão — administrar a manutenção APÓS a HD.');
      r.avisos.push('Guiar pelo nível PRÉ-HD (alvo 15–20 µg/mL): segurar a dose se pré-HD > 20–25 µg/mL. TDM antes de cada sessão até estabilizar; depois semanal.');
      r.avisos.push('Rebote 3–6h pós-HD: se colher nível pós-HD, aguardar 4–6h para não subestimar.');
      if (mic === '2') { r.micFlag = 'atencao'; r.avisos.push('CIM 2: alvo difícil de atingir com segurança. Considerar alternativa (daptomicina/linezolida).'); }
      else if (mic === '≥ 4') { r.micFlag = 'critico'; r.avisos.push('CIM ≥4: vancomicina inadequada. Trocar a droga.'); }
      else r.micFlag = 'ok';
      r.podeAplicar = !!(r.doseTxt);
      r.ok = r.pesoOk;
      return r;
    }

    // ── Modo não-HD: AUC-driven ─────────────────────────────────────────────
    var aggressive = r.grave || mic === '2';
    var aucAlvo = r.grave ? 500 : 450;
    if (mic === '2') aucAlvo = 600;
    r.aucAlvo = aucAlvo;

    r.intervalo = r.clcrOk ? _vIntervaloHoras(clcrN, aggressive) : null;

    if (r.clcrOk && clcrN > 0 && r.intervalo && r.intervalo.horas) {
      var cl = VANCO_CL_COEF * clcrN;                 // L/h
      var freq = 24 / r.intervalo.horas;
      var perDose = (aucAlvo * cl) / freq;
      var dose = _vRound250(perDose);
      if (dose < 250) dose = 250;
      if (dose > 2000) { dose = 2000; r.avisos.push('Dose por administração limitada a 2 g — considerar intervalo menor ou monitorização por nível.'); }
      // Teto diário ~4,5 g
      if (dose * freq > 4500) {
        dose = Math.max(250, _vRound250(4500 / freq));
        r.avisos.push('Dose diária limitada a ~4,5 g — ajustar por nível/AUC real.');
      }
      r.doseMg = dose;
      r.doseTxt = _vFmtG(dose);
      var tddReal = dose * freq;
      r.auc = tddReal / cl;
      if (r.pesoOk) r.mgkg = Math.round(dose / pesoN);
      if (r.auc < 400) { r.aucFlag = 'baixo'; r.avisos.push('AUC estimada < 400 — considerar dose maior ou intervalo menor.'); }
      else if (r.auc > 600) { r.aucFlag = 'alto'; r.avisos.push('AUC estimada > 600 — risco de nefrotoxicidade; considerar reduzir.'); }
      else r.aucFlag = 'alvo';
    } else if (r.clcrOk && r.intervalo && r.intervalo.guiado) {
      r.guiado = true;
    }

    if (r.obeso) {
      r.avisos.push('Obesidade (IMC ' + Math.round(r.imc) + '): risco aumentado de nefrotoxicidade e acúmulo. A dose acima é baseada no clearance (evita a superdose do mg/kg linear); confirmar AUC/nível em 24–48h e monitorizar de perto.');
    }

    if (mic === '2') { r.micFlag = 'atencao'; r.avisos.push('CIM 2: atingir AUC/CIM ≥400 exigiria AUC ≈800 (nefrotóxico). Considerar alternativa (daptomicina/linezolida) ou monitorização rigorosa.'); }
    else if (mic === '≥ 4') { r.micFlag = 'critico'; r.avisos.push('CIM ≥4: vancomicina inadequada. Trocar a droga.'); }
    else r.micFlag = 'ok';

    r.podeAplicar = !!(r.doseTxt && r.intervalo && r.intervalo.aplica);
    r.ok = r.pesoOk && r.clcrOk;
    return r;
  }

  function CampoDoseVanco(p) {
    var f = p.campo;
    var V = p.valores || {};
    var focoSt = useState(''), foco = focoSt[0], setFoco = focoSt[1];
    var micSt = useState('não disponível'), mic = micSt[0], setMic = micSt[1];
    var aplSt = useState(false), aplicado = aplSt[0], setAplicado = aplSt[1];

    // HD detectada pelos campos existentes da ficha (diálise / setor)
    var hd = V['dialise'] === 'Sim' || /hemodial/i.test(String(V['setor'] || ''));
    var res = computeVanco(V['peso'], V['clcr'], foco, V['tipo_terapia'], mic, V['altura'], hd);

    var box = { background:'#f4f8ff', border:'1px solid #cfe0f7', borderRadius:'10px', padding:'14px', marginTop:'6px' };
    var grpStyle = { fontWeight:600, color:'#0c447c', margin:'2px 0 8px', fontSize:'13px' };
    var linha = { display:'flex', flexWrap:'wrap', gap:'10px', marginBottom:'10px' };
    var mini = { fontSize:'12px', color:'#456', display:'block', marginBottom:'3px' };
    var inp = { width:'96px', padding:'7px 8px', border:'1px solid #b9cae6', borderRadius:'7px', fontSize:'14px' };
    var sel = { padding:'7px 8px', border:'1px solid #b9cae6', borderRadius:'7px', fontSize:'14px', background:'#fff' };

    function setKey(k) { return function (v) { p.set(k, v); setAplicado(false); }; }
    var setPeso = setKey('peso'), setClcr = setKey('clcr'), setAltura = setKey('altura');

    function aplicar() {
      var atb = Array.isArray(V['atb_solicitado']) ? V['atb_solicitado'] : [];
      var idx = atb.indexOf('Vancomicina');
      if (idx < 0 || !res.podeAplicar) return;
      var pos = Array.isArray(V['posologia']) ? V['posologia'].slice() : [];
      pos[idx] = Object.assign({}, pos[idx], {
        droga: 'Vancomicina',
        dose: res.doseTxt,
        intervalo: res.intervalo.aplica || res.intervalo.label,
        dose_valor: res.doseMg || '',
        dose_unidade: res.doseMg ? 'mg' : '',
        freq_tipo: res.intervalo.horas ? 'cada' : (res.intervalo.aplica === 'ap\u00f3s cada HD' ? 'hd' : ''),
        freq_horas: res.intervalo.horas || ''
      });
      p.set('posologia', pos);
      setAplicado(true);
    }

    var aucCor = res.aucFlag === 'alvo' ? '#1c7c3c' : (res.aucFlag ? '#a4700a' : '#556');

    var resultado = [];
    if (res.ok) {
      if (res.ataqueMg) resultado.push(e('div', { key:'atq', style:{ marginBottom:'6px' } },
        e('b', null, 'Ataque: '), _vFmtG(res.ataqueMg),
        e('span', { style:{ color:'#667', fontSize:'12px' } }, '  (' + (res.ataqueFaixa || '25–30 mg/kg') + ', dose única — prescrever à parte)')));
      if (res.profilaxia) resultado.push(e('div', { key:'prof', style:{ marginBottom:'6px', color:'#667', fontSize:'12px' } },
        'Profilaxia cirúrgica: dose única de 15 mg/kg pré-incisão (sem ataque).'));

      if (res.hd) {
        resultado.push(e('div', { key:'hdman', style:{ marginBottom:'6px' } },
          e('b', null, 'Manutenção: '), (res.doseTxt || '—') + (res.mgkg ? ' (≈ ' + res.mgkg + ' mg/kg)' : ''),
          e('span', null, '  —  após cada sessão de HD')));
        resultado.push(e('div', { key:'hdalvo', style:{ marginBottom:'6px', color:'#1c7c3c', fontWeight:600 } },
          'Alvo: ' + res.alvoTxt));
      } else if (res.guiado) {
        resultado.push(e('div', { key:'guiado', style:{ marginBottom:'6px' } },
          e('b', null, 'Intervalo: '), res.intervalo.label,
          e('div', { style:{ color:'#667', fontSize:'12px', marginTop:'3px' } }, 'Função renal baixa — dose guiada por nível sérico (sem cálculo automático de dose).')));
      } else if (res.doseTxt) {
        resultado.push(e('div', { key:'man', style:{ marginBottom:'6px' } },
          e('b', null, 'Manutenção: '), res.doseTxt + (res.mgkg ? ' (≈ ' + res.mgkg + ' mg/kg)' : ''),
          res.intervalo ? e('span', null, '  —  ' + res.intervalo.label) : null));
        if (res.intervalo && res.intervalo.nota) resultado.push(e('div', { key:'intn', style:{ color:'#667', fontSize:'12px', marginBottom:'6px' } }, res.intervalo.nota));
        if (res.auc) resultado.push(e('div', { key:'auc', style:{ marginBottom:'6px', color:aucCor, fontWeight:600 } },
          'AUC24 estimada: ≈ ' + Math.round(res.auc) + ' mg·h/L  (alvo ' + res.aucAlvo + ', faixa 400–600)'));
      }
    } else {
      resultado.push(e('div', { key:'faltam', style:{ color:'#a4700a', fontSize:'13px' } },
        hd ? 'Informe o peso para calcular.' : 'Informe peso e ClCr para calcular.'));
    }

    var avisos = res.avisos.map(function (a, i) {
      var crit = /inadequada|Trocar|> 600/.test(a);
      return e('div', { key:'av' + i, style:{ background: crit ? '#fdecec' : '#fff6e5', border:'1px solid ' + (crit ? '#f1c2c2' : '#f0d9a8'), color: crit ? '#8a1414' : '#7a5300', borderRadius:'7px', padding:'8px 10px', fontSize:'12.5px', marginTop:'6px' } }, a);
    });

    var cabecalho = res.hd
      ? 'HD intermitente alto fluxo · manutenção pós-HD guiada por nível pré-HD (15–20 µg/mL)'
      : 'Alvo AUC 400–600 · estimativa a priori — refinar por nível/AUC bayesiano';

    var badges = [];
    if (res.hd) badges.push(e('span', { key:'bhd', style:{ background:'#e6f0fb', color:'#0c447c', border:'1px solid #cfe0f7', borderRadius:'20px', padding:'2px 10px', fontSize:'11.5px', fontWeight:600 } }, 'HD alto fluxo'));
    if (res.obeso) badges.push(e('span', { key:'bob', style:{ background:'#fff2e0', color:'#8a5300', border:'1px solid #f0d9a8', borderRadius:'20px', padding:'2px 10px', fontSize:'11.5px', fontWeight:600, marginLeft:'6px' } }, 'IMC ' + Math.round(res.imc)));

    return e('div', { className:'campo' },
      e(Rotulo, { texto: f.label || 'Auxílio de dose — Vancomicina', required:false }),
      e('div', { style: box },
        e('div', { style:{ display:'flex', alignItems:'center', flexWrap:'wrap', gap:'6px', marginBottom:'8px' } },
          e('span', { style: grpStyle }, cabecalho), badges),
        e('div', { style: linha },
          e('div', null, e('span', { style: mini }, 'Peso real (kg)'),
            e('input', { style: inp, type:'number', inputMode:'decimal', value: V['peso'] || '', placeholder:'kg', onChange:function (ev) { setPeso(ev.target.value); } })),
          e('div', null, e('span', { style: mini }, 'Altura (cm)'),
            e('input', { style: inp, type:'number', inputMode:'decimal', value: V['altura'] || '', placeholder:'cm', onChange:function (ev) { setAltura(ev.target.value); } })),
          hd ? null : e('div', null, e('span', { style: mini }, 'ClCr atual (mL/min)'),
            e('input', { style: inp, type:'number', inputMode:'decimal', value: V['clcr'] || '', placeholder:'mL/min', onChange:function (ev) { setClcr(ev.target.value); } }))
        ),
        e('div', { style: linha },
          e('div', null, e('span', { style: mini }, 'Foco'),
            e('select', { style: sel, value: foco, onChange:function (ev) { setFoco(ev.target.value); setAplicado(false); } },
              e('option', { value:'' }, '— selecione —'),
              VANCO_FOCOS.map(function (o) { return e('option', { key:o.v, value:o.v }, o.v); }))),
          e('div', null, e('span', { style: mini }, 'CIM de Vanco'),
            e('select', { style: sel, value: mic, onChange:function (ev) { setMic(ev.target.value); setAplicado(false); } },
              ['não disponível', '≤ 1', '2', '≥ 4'].map(function (o) { return e('option', { key:o, value:o }, o); })))
        ),
        e('div', { style:{ borderTop:'1px dashed #cfe0f7', margin:'4px 0 10px' } }),
        resultado,
        avisos,
        e('button', {
          type:'button',
          disabled: !res.podeAplicar,
          onClick: aplicar,
          style:{ marginTop:'12px', padding:'9px 14px', border:'none', borderRadius:'8px', fontSize:'14px', fontWeight:600, cursor: res.podeAplicar ? 'pointer' : 'not-allowed', background: res.podeAplicar ? (aplicado ? '#1c7c3c' : '#0c447c') : '#c3ccd8', color:'#fff' }
        }, aplicado ? '✓ Aplicado na posologia' : 'Aplicar na posologia'),
        e('div', { style:{ color:'#889', fontSize:'11.5px', marginTop:'8px' } },
          'Apoio à decisão. Ataque é dose única (prescrever à parte). Não substitui o julgamento clínico nem a monitorização por nível/AUC.')
      ),
      f.hint ? e('div', { className:'dica' }, f.hint) : null
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
    if (t === 'dose_vanco') return e(CampoDoseVanco, p);
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
    var PREVIEW = new URLSearchParams(window.location.search).get('preview') === '1';

    useEffect(function () {
      if (PREVIEW) {
        // MODO PREVIEW (editor estrutural): o schema chega do editor-pai via
        // postMessage e re-renderiza a cada edição; envio fica desabilitado.
        function onMsg(ev) {
          if (ev.origin !== window.location.origin) return;
          var m = ev.data || {};
          if (m && m.tipo === 'atb-preview-schema' && m.schema) setSchema(m.schema);
        }
        window.addEventListener('message', onMsg);
        document.body.insertAdjacentHTML('afterbegin',
          '<div style="position:sticky;top:0;z-index:99;background:#9a6700;color:#fff;' +
          'font:600 12px/1 sans-serif;padding:7px 12px;text-align:center">' +
          'PRÉ-VISUALIZAÇÃO — reflete o editor em tempo real · envio desabilitado</div>');
        try { window.parent.postMessage({ tipo: 'atb-preview-ready' }, window.location.origin); } catch (e2) {}
        return function () { window.removeEventListener('message', onMsg); };
      }
      fetch('/atb/api/form-schema?inst=' + encodeURIComponent(window.ATB_SCHEMA_INST || inst))
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

    // Preenchimento condicional: deriva/sobrescreve valores conforme regras do schema.
    // schema.preenchimentos = [{ quando:<cond>, campo, valor, sobrescrever }]
    // Mesma gramática de `cond`. 'inserir' = só se vazio; 'sobrescrever' = força enquanto a condição vale.
    useEffect(function () {
      if (!schema || !Array.isArray(schema.preenchimentos)) return;
      var patch = null;
      schema.preenchimentos.forEach(function (r) {
        if (!r || !r.campo || !avaliaCond(r.quando, valores)) return;
        var atual = valores[r.campo];
        var vazio = atual === undefined || atual === null || atual === ''
          || (Array.isArray(atual) && atual.length === 0);
        if (!r.sobrescrever && !vazio) return;   // 'inserir': preenche só se estiver vazio
        if (atual === r.valor) return;           // já está no alvo (converge, sem loop)
        (patch = patch || {})[r.campo] = r.valor;
      });
      if (patch) setValores(function (prev) { return Object.assign({}, prev, patch); });
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
              novos[c.key] = c.minMsg || 'Descreva a histórica clínica com mais detalhes';
          }
        });
      });
      setErros(novos);
      return Object.keys(novos).length === 0;
    }

    function enviar() {
      if (PREVIEW) { alert('Modo pré-visualização — o envio está desabilitado.'); return; }
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
          else alert('Erro ao enviar: ' + (res.d.error || res.d.erro || 'tente novamente'));
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
