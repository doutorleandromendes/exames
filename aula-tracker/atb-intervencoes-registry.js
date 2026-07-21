// atb-intervencoes-registry.js
// Registro das intervenções EMBUTIDO no código — não em disco. O Render é
// efêmero e o commit por arquivo (GitHub web UI) não preserva subpastas de
// forma confiável (achata os .json para a raiz). Embutidas aqui, as
// intervenções viajam com este módulo. Editar = editar este arquivo e commitar.
// Gerado a partir dos .json validados; mantê-lo como fonte única.

export const INTERVENCOES = {
  "posologia-estruturada": {
    "nome": "posologia-estruturada",
    "alvo": "atb-form-engine.js",
    "promovivel": true,
    "descricao": "Matriz aprende number/select; posologia estruturada. Aditivo e retrocompatível.",
    "transformacoes": [
      {
        "ancora": "  function renderColunasMatriz(f, row, i, setLinha) {",
        "vira": "  function _celulaVisivel(c, row) {\n    if (!c || !c.mostrarSe) return true;\n    return row[c.mostrarSe.campo] === c.mostrarSe.valor;\n  }\n  function _celulaMatriz(c, row, onChange) {\n    var val = row[c.key];\n    if (c.type === 'select') {\n      return e('div', { className: 'sel-wrap' },\n        e('select', {\n          value: val == null ? '' : val,\n          onChange: function (ev) { onChange(ev.target.value); }\n        },\n          e('option', { value: '' }, '\\u2014'),\n          (c.options || []).map(function (o) {\n            var v = (o && typeof o === 'object') ? o.v : o;\n            var l = (o && typeof o === 'object') ? o.l : o;\n            return e('option', { key: v, value: v }, l);\n          })),\n        e('span', { className: 'seta' }, '\\u25bc'));\n    }\n    if (c.type === 'number') {\n      return e('input', {\n        type: 'text', inputMode: 'decimal', style: { maxWidth: '110px' },\n        value: (val === null || val === undefined) ? '' : String(val),\n        placeholder: c.placeholder || '',\n        onChange: function (ev) { onChange(ev.target.value); },\n        onBlur: function (ev) {\n          var t = String(ev.target.value == null ? '' : ev.target.value).trim().replace(',', '.');\n          if (t === '') return onChange('');\n          var n = Number(t);\n          if (!isNaN(n) && isFinite(n)) onChange(n);\n        }\n      });\n    }\n    return e('input', {\n      type: 'text',\n      value: val == null ? '' : val, placeholder: c.placeholder || '',\n      onChange: function (ev) { onChange(ev.target.value); }\n    });\n  }\n\n  function renderColunasMatriz(f, row, i, setLinha) {",
        "nota": "helper"
      },
      {
        "ancora": "    function campoCol(c) {\n      if (c.type === 'select') {\n        return e('div', { key: c.key, className: 'mini-campo' },\n          e('span', { className: 'mini' }, c.label),\n          e('div', { className: 'sel-wrap' },\n            e('select', {\n              value: row[c.key] || '',\n              onChange: function (ev) { setLinha(i, c.key, ev.target.value); }\n            },\n              e('option', { value: '' }, '—'),\n              (c.options || []).map(function (o) { return e('option', { key: o, value: o }, o); })),\n            e('span', { className: 'seta' }, '▼'))\n        );\n      }\n      return e('div', { key: c.key, className: 'mini-campo' },\n        e('span', { className: 'mini' }, c.label),\n        e('input', {\n          type: 'text', value: row[c.key] || '', placeholder: c.placeholder || '',\n          onChange: function (ev) { setLinha(i, c.key, ev.target.value); }\n        })\n      );\n    }",
        "vira": "    function campoCol(c) {\n      if (!_celulaVisivel(c, row)) return null;\n      return e('div', { key: c.key, className: 'mini-campo' },\n        e('span', { className: 'mini' }, c.label),\n        _celulaMatriz(c, row, function (v) { setLinha(i, c.key, v); })\n      );\n    }",
        "nota": "campoCol"
      },
      {
        "ancora": "                f.colunas.map(function (c) {\n                  if (c.readonly) return null;\n                  return e('div', { key: c.key, className: 'mini-campo' },\n                    e('span', { className: 'mini' }, c.label),\n                    e('input', {\n                      type: 'text', value: row[c.key] || '', placeholder: c.placeholder || '',\n                      onChange: function (ev) {\n                        var nv = linhas.slice();\n                        nv[i] = Object.assign({}, nv[i], { droga: droga });\n                        nv[i][c.key] = ev.target.value;\n                        p.set(f.key, nv);\n                      }\n                    })\n                  );\n                })",
        "vira": "                f.colunas.map(function (c) {\n                  if (c.readonly) return null;\n                  if (!_celulaVisivel(c, row)) return null;\n                  return e('div', { key: c.key, className: 'mini-campo' },\n                    e('span', { className: 'mini' }, c.label),\n                    _celulaMatriz(c, row, function (v) {\n                      var nv = linhas.slice();\n                      nv[i] = Object.assign({}, nv[i], { droga: droga });\n                      nv[i][c.key] = v;\n                      p.set(f.key, nv);\n                    })\n                  );\n                })",
        "nota": "sincronizaCom"
      },
      {
        "ancora": "      pos[idx] = Object.assign({}, pos[idx], {\n        droga: 'Vancomicina',\n        dose: res.doseTxt,\n        intervalo: res.intervalo.aplica || res.intervalo.label\n      });",
        "vira": "      pos[idx] = Object.assign({}, pos[idx], {\n        droga: 'Vancomicina',\n        dose: res.doseTxt,\n        intervalo: res.intervalo.aplica || res.intervalo.label,\n        dose_valor: res.doseMg || '',\n        dose_unidade: res.doseMg ? 'mg' : '',\n        freq_tipo: res.intervalo.horas ? 'cada' : (res.intervalo.aplica === 'ap\\u00f3s cada HD' ? 'hd' : ''),\n        freq_horas: res.intervalo.horas || ''\n      });",
        "nota": "vanco"
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
  },
  "posologia-layout-inline": {
    "nome": "posologia-layout-inline",
    "alvo": "atb-form-engine.js",
    "promovivel": true,
    "dependeDe": [
      "posologia-estruturada"
    ],
    "descricao": "Layout: células da posologia em uma linha. Puramente visual.",
    "transformacoes": [
      {
        "ancora": "                f.colunas.map(function (c) {\n                  if (c.readonly) return null;\n                  if (!_celulaVisivel(c, row)) return null;\n                  return e('div', { key: c.key, className: 'mini-campo' },\n                    e('span', { className: 'mini' }, c.label),\n                    _celulaMatriz(c, row, function (v) {\n                      var nv = linhas.slice();\n                      nv[i] = Object.assign({}, nv[i], { droga: droga });\n                      nv[i][c.key] = v;\n                      p.set(f.key, nv);\n                    })\n                  );\n                })",
        "vira": "                e('div', { className: 'poso-linha',\n                    style: { display: 'flex', alignItems: 'flex-end', gap: '12px', flexWrap: 'wrap' } },\n                  f.colunas.map(function (c) {\n                    if (c.readonly) return null;\n                    if (!_celulaVisivel(c, row)) return null;\n                    var onCell = function (v) {\n                      var nv = linhas.slice();\n                      nv[i] = Object.assign({}, nv[i], { droga: droga });\n                      nv[i][c.key] = v;\n                      p.set(f.key, nv);\n                    };\n                    if (c.key === 'freq_horas') {\n                      return e('div', { key: c.key, className: 'mini-campo poso-horas',\n                          style: { display: 'flex', alignItems: 'center', gap: '6px', marginBottom: 0, paddingBottom: '1px' } },\n                        e('div', { style: { width: '56px' } }, _celulaMatriz(c, row, onCell)),\n                        e('span', { className: 'poso-sufixo', style: { fontSize: '13px', color: '#5f6b7a' } }, 'h'));\n                    }\n                    var larg = c.key === 'dose_valor' ? '76px'\n                             : c.key === 'dose_unidade' ? '88px'\n                             : c.key === 'freq_tipo' ? '150px' : 'auto';\n                    return e('div', { key: c.key, className: 'mini-campo',\n                        style: { width: larg, marginBottom: 0 } },\n                      e('span', { className: 'mini' }, c.label),\n                      _celulaMatriz(c, row, onCell));\n                  })\n                )",
        "nota": "flex-row + sufixo h"
      }
    ]
  }
};

export const ORDEM_INTERVENCOES = ["posologia-estruturada", "posologia-layout-inline", "form-teste-schema-override"];

export function listarIntervencoes() {
  return ORDEM_INTERVENCOES.map((nome) => ({ ...INTERVENCOES[nome], _nome: nome }));
}
