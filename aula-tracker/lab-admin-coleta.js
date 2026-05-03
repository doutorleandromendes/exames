// lab-admin-coleta.js
// Script do formulário de cadastro de exame — Portal Lab Admin
// Salvar em: public/lab-admin-coleta.js

(function () {
  'use strict';

  // ── Configuração centralizada ──────────────────────────────────────────

  const DOSAGEM_SUBTYPES = {
    procalcitonina: { vr: 'Inferior a 0,10 ng/mL',          unit: ' ng/mL' },
    cistatina:      { vr: 'Entre 0,57 e 1,06 mg/L',         unit: ' mg/L'  },
    reativa:        { vr: 'Inferior a 0,1 mg/L',            unit: ' mg/L'  },
    glicada:        { vr: 'Inferior a 5,7 % (Diagnóstico)', unit: ' %'     },
  };

  const SELECT_OPTIONS = [
    'NÃO REAGENTE',
    'REAGENTE',
    'FRACAMENTE REAGENTE',
    'INDETERMINADO',
  ];

  // Exames que usam textarea livre diretamente (sem dropdown)
  const TEXT_KEYWORDS = [
    'microscopia', 'cultura', 'gram', 'giemsa',
    'kinyoun', 'grocott', 'leishman', 'trichrome',
  ];

  // ── Helpers ────────────────────────────────────────────────────────────

  function getExamType(name) {
    const n = (name || '').toLowerCase();
    if (n.includes('dosagem'))                         return 'dosagem';
    if (TEXT_KEYWORDS.some(k => n.includes(k)))        return 'texto';
    return 'select';
  }

  function getDosagemConfig(name) {
    const n = (name || '').toLowerCase();
    for (const key in DOSAGEM_SUBTYPES) {
      if (n.includes(key)) return DOSAGEM_SUBTYPES[key];
    }
    return null;
  }

  function styleInput(el) {
    Object.assign(el.style, {
      width: '100%', padding: '10px', borderRadius: '8px',
      border: '1px solid #2a2f39', background: '#0f1116',
      color: '#e7e9ee', fontSize: '14px',
    });
  }

  function syncHidden(value) {
    const h = document.getElementById('result_hidden');
    if (h) h.value = value;
  }

  // ── Referências aos elementos ──────────────────────────────────────────

  const examSelect       = document.getElementById('examSelect');
  const examHidden       = document.getElementById('examSelectHidden');
  const examManualInput  = document.getElementById('examManualInput');
  const examManualToggle = document.getElementById('examManualToggle');
  const vrInput          = document.querySelector('[name="reference_value"]');
  const methodInput      = document.querySelector('[name="method"]');
  const resultContainer  = document.getElementById('result-container');
  const theForm          = document.getElementById('exam-form');

  if (!resultContainer) {
    console.error('[lab-admin-coleta] #result-container não encontrado');
    return;
  }

  // ── Aplica defaults de VR e Método ────────────────────────────────────

  function applyDefaults(name) {
    const type = getExamType(name);

    if (type === 'dosagem') {
      if (methodInput) methodInput.value = 'Imunofluorescência';
      const cfg = getDosagemConfig(name);
      if (vrInput) vrInput.value = cfg ? cfg.vr : '—';
    } else {
      // Imunocromatográficos e outros: VR padrão NÃO REAGENTE
      if (vrInput) vrInput.value = 'NÃO REAGENTE';
    }

    buildResultField(type);
  }

  // ── Monta o campo de resultado conforme tipo ──────────────────────────

  function buildResultField(type) {
    resultContainer.innerHTML = '';

    let primary;

    if (type === 'dosagem') {
      primary = document.createElement('input');
      primary.type      = 'text';
      primary.inputMode = 'decimal';
      primary.placeholder = 'Digite o número';
      Object.assign(primary.style, { fontWeight: '600' });
      primary.addEventListener('input', e => {
        e.target.value = e.target.value.replace(/[^\d.,<>]/g, '');
        syncHidden(e.target.value);
      });

    } else if (type === 'texto') {
      // Textarea direto — sem toggle manual (já é livre)
      primary = document.createElement('textarea');
      primary.rows = 5;
      primary.placeholder =
        'Digite o resultado\n\nPara antibiograma:\nSENSÍVEL A: Meropenem, Imipenem...\nRESISTENTE A: Ciprofloxacina...';
      Object.assign(primary.style, { resize: 'vertical', fontFamily: 'inherit' });
      primary.addEventListener('input', e => syncHidden(e.target.value));

    } else {
      // Dropdown padrão (imunocromatografia, etc.)
      primary = document.createElement('select');
      SELECT_OPTIONS.forEach(v => {
        const o = document.createElement('option');
        o.value = o.textContent = v;
        primary.appendChild(o);
      });
      Object.assign(primary.style, { fontWeight: '600' });
      primary.addEventListener('change', e => syncHidden(e.target.value));
      syncHidden(SELECT_OPTIONS[0]);
    }

    primary.id = 'result_primary';
    styleInput(primary);
    resultContainer.appendChild(primary);

    // Input hidden — único campo submetido com name=result_value
    const hidden = document.createElement('input');
    hidden.type  = 'hidden';
    hidden.name  = 'result_value';
    hidden.id    = 'result_hidden';
    resultContainer.appendChild(hidden);

    // Toggle "inserir manualmente" só aparece para dosagem e select
    // (texto já é livre por definição)
    if (type !== 'texto') {
      addManualToggle(resultContainer, type);
    }
  }

  // ── Toggle de resultado manual ─────────────────────────────────────────

  function addManualToggle(container) {
    const wrap = document.createElement('div');
    wrap.style.marginTop = '8px';

    const lbl = document.createElement('label');
    Object.assign(lbl.style, {
      display: 'flex', alignItems: 'center', gap: '6px',
      fontSize: '12px', textTransform: 'none', letterSpacing: '0',
      cursor: 'pointer', color: '#a7adbb',
    });

    const chk = document.createElement('input');
    chk.type = 'checkbox';
    chk.id   = 'resultManualToggle';
    lbl.appendChild(chk);
    lbl.appendChild(document.createTextNode(' Inserir resultado manual (texto livre)'));
    wrap.appendChild(lbl);

    const ta = document.createElement('textarea');
    ta.id          = 'resultManualTA';
    ta.rows        = 4;
    ta.placeholder = 'Digite o resultado completo';
    Object.assign(ta.style, { display: 'none', resize: 'vertical', fontFamily: 'inherit', marginTop: '6px' });
    styleInput(ta);
    ta.style.display = 'none'; // styleInput sobrescreve display, força none novamente
    ta.addEventListener('input', e => syncHidden(e.target.value));
    wrap.appendChild(ta);

    container.appendChild(wrap);

    chk.addEventListener('change', function () {
      const primary = document.getElementById('result_primary');
      if (this.checked) {
        // Pega valor atual para pré-preencher o textarea
        const currentVal = primary
          ? (primary.tagName === 'SELECT'
              ? primary.options[primary.selectedIndex]?.value
              : primary.value) || ''
          : '';
        ta.value = currentVal;
        ta.style.display = '';
        if (primary) { primary.style.opacity = '0.35'; primary.disabled = true; }
        syncHidden(ta.value);
      } else {
        ta.style.display = 'none';
        if (primary) { primary.style.opacity = ''; primary.disabled = false; }
        const val = primary
          ? (primary.tagName === 'SELECT'
              ? primary.options[primary.selectedIndex]?.value
              : primary.value) || ''
          : '';
        syncHidden(val);
      }
    });
  }

  
  // ── Carrega lista de exames ────────────────────────────────────────────

  fetch('/lab/admin/api/exames')
    .then(r => r.json())
    .then(exames => {
      examSelect.innerHTML = '<option value="">— selecione o exame —</option>';
      exames.forEach(nome => {
        const opt = document.createElement('option');
        opt.value = opt.textContent = nome;
        examSelect.appendChild(opt);
      });
    })
    .catch(() => {
      examSelect.innerHTML = '<option value="">Falha ao carregar — use digitação manual</option>';
      if (examManualToggle) {
        examManualToggle.checked = true;
        examManualToggle.dispatchEvent(new Event('change'));
      }
    });

  // ── Eventos de seleção/digitação do nome do exame ─────────────────────

  // ── Eventos de seleção/digitação do nome do exame ─────────────────────

  examSelect?.addEventListener('change', function () {
    examHidden.value = this.value;
    if (this.value) applyDefaults(this.value);
  });

  examManualToggle?.addEventListener('change', function () {
    const isManual = this.checked;
    examSelect.style.display      = isManual ? 'none' : '';
    examHidden.disabled           = isManual;
    examManualInput.style.display = isManual ? '' : 'none';
    // nunca usar required em campos que podem estar ocultos
    examManualInput.required      = false;
    if (!isManual) examHidden.value = examSelect.value;
  });

  examManualInput?.addEventListener('input', function () {
    applyDefaults(this.value);
  });

  // ── Validação manual no submit (substitui required nativo) ────────────
  theForm?.addEventListener('submit', function (e) {
    // Valida nome do exame
    const isManual = examManualToggle?.checked;
    const examName = isManual
      ? (examManualInput?.value || '').trim()
      : (examHidden?.value || '').trim();

    if (!examName) {
      e.preventDefault();
      alert('Selecione ou digite o nome do exame.');
      return;
    }

    // Garante que o nome correto vai no hidden antes de submeter
    if (isManual) {
      examHidden.value    = examName;
      examHidden.disabled = false;
    }

    // Valida resultado
    const resultHidden = document.getElementById('result_hidden');
    if (!resultHidden || !resultHidden.value.trim()) {
      e.preventDefault();
      alert('Preencha o resultado do exame.');
      return;
    }

    // Formatação numérica para dosagem (mantida aqui também)
    if (getExamType(examName) === 'dosagem') {
      const manualToggle = document.getElementById('resultManualToggle');
      if (!manualToggle?.checked) {
        const cfg = getDosagemConfig(examName);
        if (cfg && resultHidden.value) {
          const raw = resultHidden.value.trim().replace(',', '.');
          const n   = parseFloat(raw);
          if (!isNaN(n)) {
            const decimals = raw.includes('.') ? 2 : 0;
            resultHidden.value = n.toFixed(decimals).replace('.', ',') + cfg.unit;
          } else if (!resultHidden.value.includes(cfg.unit.trim())) {
            resultHidden.value += cfg.unit;
          }
        }
      }
    }
  });

  // Remove o listener de submit duplicado que estava no final do arquivo
  // (o que estava dentro de `if (theForm)` pode ser removido)

  // ── Inicializa com campo select vazio ──────────────────────────────────
  buildResultField('select');

})();
