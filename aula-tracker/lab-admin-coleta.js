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
      resultContainer.appendChild(makeToolbar(null)); // toolbar antes do textarea
      primary = document.createElement('textarea');
      primary.rows = 5;
      primary.placeholder =
        'Digite o resultado\n\nFormato:\n*negrito*   _itálico_\n\nAntibiograma:\nSENSÍVEL A: Meropenem...\nRESISTENTE A: Ciprofloxacina...';
      Object.assign(primary.style, { resize: 'vertical', fontFamily: 'inherit' });
      primary.addEventListener('input', e => syncHidden(e.target.value));
      // associa toolbar ao textarea
      resultContainer.querySelector('.fmt-toolbar').dataset.target = 'result_primary';

    } else {
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

    const hidden = document.createElement('input');
    hidden.type  = 'hidden';
    hidden.name  = 'result_value';
    hidden.id    = 'result_hidden';
    resultContainer.appendChild(hidden);

    if (type !== 'texto') {
      addManualToggle(resultContainer);
      if (type === 'select') {
        addTCToggle(resultContainer);
      }
    }
  }
  function makeToolbar(targetId) {
    const bar = document.createElement('div');
    bar.className = 'fmt-toolbar';
    Object.assign(bar.style, {
      display: 'flex', gap: '6px', marginBottom: '6px',
    });

    function fmtBtn(label, before, after, title) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = label;
      btn.title = title;
      Object.assign(btn.style, {
        padding: '3px 10px', borderRadius: '5px', border: '1px solid #2a2f39',
        background: '#20242b', color: '#e7e9ee', cursor: 'pointer',
        fontSize: '13px', fontWeight: label === 'B' ? '700' : '400',
        fontStyle: label === 'I' ? 'italic' : 'normal',
      });
      btn.addEventListener('click', () => {
        const tid = bar.dataset.target || (targetId);
        const ta = document.getElementById(tid);
        if (!ta) return;
        const start = ta.selectionStart;
        const end   = ta.selectionEnd;
        const sel   = ta.value.substring(start, end) || 'texto';
        ta.value = ta.value.substring(0, start) + before + sel + after + ta.value.substring(end);
        ta.focus();
        ta.selectionStart = start + before.length;
        ta.selectionEnd   = start + before.length + sel.length;
        syncHidden(ta.value);
      });
      return btn;
    }

    bar.appendChild(fmtBtn('B', '*', '*', 'Negrito: *texto*'));
    bar.appendChild(fmtBtn('I', '_', '_', 'Itálico: _texto_'));

    const hint = document.createElement('span');
    hint.textContent = '← selecione o texto antes de clicar';
    Object.assign(hint.style, { fontSize: '11px', color: '#666', alignSelf: 'center', marginLeft: '4px' });
    bar.appendChild(hint);

    if (targetId) bar.dataset.target = targetId;
    return bar;
  }
  // ── Toggle de relação T/C (LFA) ───────────────────────────────────────

  function addTCToggle(container) {
    const wrap = document.createElement('div');
    wrap.id = 'tc-toggle-wrap';
    wrap.style.marginTop = '10px';

    const lbl = document.createElement('label');
    Object.assign(lbl.style, {
      display: 'flex', alignItems: 'center', gap: '6px',
      fontSize: '12px', cursor: 'pointer', color: '#a7adbb',
    });

    const chk = document.createElement('input');
    chk.type = 'checkbox';
    chk.id   = 'tcToggle';
    lbl.appendChild(chk);
    lbl.appendChild(document.createTextNode(' Incluir relação T/C no laudo'));
    wrap.appendChild(lbl);

    // Sub-bloco (oculto até marcar)
    const sub = document.createElement('div');
    sub.id = 'tc-sub';
    Object.assign(sub.style, {
      display: 'none', marginTop: '8px',
      padding: '10px', borderRadius: '8px',
      border: '1px solid #2a2f39', background: '#0d1017',
      display: 'none',
    });

    // Linha superior: valor medido + threshold lado a lado
    const row = document.createElement('div');
    Object.assign(row.style, { display: 'flex', gap: '10px', alignItems: 'flex-end' });

    // Campo valor T/C medido
    const colVal = document.createElement('div');
    Object.assign(colVal.style, { flex: '1 1 0' });
    const lblVal = document.createElement('label');
    Object.assign(lblVal.style, { fontSize: '11px', color: '#8891a4', display: 'block', marginBottom: '5px' });
    lblVal.textContent = 'T/C medido (0 – 1,000)';
    colVal.appendChild(lblVal);
    const numInput = document.createElement('input');
    numInput.type        = 'text';
    numInput.inputMode   = 'decimal';
    numInput.id          = 'tcInput';
    numInput.placeholder = 'ex: 0,6999';
    styleInput(numInput);
    Object.assign(numInput.style, { fontWeight: '600' });
    numInput.addEventListener('input', e => {
      e.target.value = e.target.value.replace(/[^\d.,]/g, '');
      updateTCPreview(e.target.value);
    });
    colVal.appendChild(numInput);
    row.appendChild(colVal);

    // Campo threshold
    const colThr = document.createElement('div');
    Object.assign(colThr.style, { flex: '0 0 120px' });
    const lblThr = document.createElement('label');
    Object.assign(lblThr.style, { fontSize: '11px', color: '#8891a4', display: 'block', marginBottom: '5px' });
    lblThr.textContent = 'Threshold (VR)';
    colThr.appendChild(lblThr);
    const thrInput = document.createElement('input');
    thrInput.type        = 'text';
    thrInput.inputMode   = 'decimal';
    thrInput.id          = 'tcThreshold';
    thrInput.value       = '0,1';
    styleInput(thrInput);
    Object.assign(thrInput.style, { fontWeight: '600' });
    thrInput.addEventListener('input', e => {
      e.target.value = e.target.value.replace(/[^\d.,]/g, '');
      syncVR(e.target.value);
    });
    colThr.appendChild(thrInput);
    row.appendChild(colThr);

    sub.appendChild(row);

    const preview = document.createElement('div');
    preview.id = 'tc-preview';
    Object.assign(preview.style, {
      marginTop: '7px', fontSize: '11px', color: '#6ee7b7',
      fontStyle: 'italic', minHeight: '16px',
    });
    sub.appendChild(preview);
    wrap.appendChild(sub);
    container.appendChild(wrap);

    function syncVR(rawThr) {
      if (!vrInput) return;
      const t = (rawThr || '').trim() || '?';
      vrInput.value = `Não Reagente - relação T/C < ${t}`;
    }

    function updateTCPreview(raw) {
      const v = parseFloat((raw || '').replace(',', '.'));
      if (isNaN(v)) { preview.textContent = ''; return; }
      const exp = Math.pow(10, v).toFixed(2).replace('.', ',');
      preview.textContent = `→ será exibido como T/C ${exp}`;
    }

    chk.addEventListener('change', function () {
      sub.style.display = this.checked ? '' : 'none';
      if (this.checked) {
        syncVR(thrInput.value);
        numInput.focus();
      } else {
        if (vrInput) vrInput.value = 'NÃO REAGENTE';
        numInput.value = '';
        thrInput.value = '0,1';
        preview.textContent = '';
      }
    });
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

   // toolbar de formatação para o textarea manual
    const fmtBar = makeToolbar('resultManualTA');
    fmtBar.style.marginTop = '8px';
    wrap.insertBefore(fmtBar, ta);

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
  // ── Submit via AJAX para suportar upload de imagens ─────────────────────────
  theForm?.addEventListener('submit', async function (e) {
    e.preventDefault();

    // Validação do nome do exame
    const isManualExam = examManualToggle?.checked;
    const examName = isManualExam
      ? (examManualInput?.value || '').trim()
      : (examHidden?.value || '').trim();
    if (!examName) { alert('Selecione ou digite o nome do exame.'); return; }
    if (isManualExam) { examHidden.value = examName; examHidden.disabled = false; }

    // Validação do resultado
    const resultHidden = document.getElementById('result_hidden');
    if (!resultHidden || !resultHidden.value.trim()) {
      alert('Preencha o resultado do exame.'); return;
    }

    // Formatação numérica para dosagem
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

    // Envia dados do exame via fetch (URLSearchParams — compatível com express.urlencoded)
    // Formata e embute valor T/C se ativado (apenas para exames tipo select)
    const tcToggle = document.getElementById('tcToggle');
    const tcInput  = document.getElementById('tcInput');
    if (tcToggle?.checked && tcInput?.value.trim()) {
      const tcRaw = parseFloat(tcInput.value.trim().replace(',', '.'));
      if (!isNaN(tcRaw) && tcRaw >= 0 && tcRaw <= 1) {
        const tcDisplay = Math.pow(10, tcRaw).toFixed(2).replace('.', ',');
        resultHidden.value = resultHidden.value.trim() + '||TC||' + tcDisplay;
      }
    }

    const sampleSelectEl = document.getElementById('sampleSelect');
    const sampleManualEl = document.getElementById('sampleManualInput');
    const sampleManualTg = document.getElementById('sampleManualToggle');
    const methodEl       = document.querySelector('[name="method"]');
    const refEl          = document.querySelector('[name="reference_value"]');
    const obsEl          = document.querySelector('[name="observation"]');

    const isManualSample = sampleManualTg?.checked;
    const sampleType     = isManualSample
      ? (sampleManualEl?.value || 'Soro').trim()
      : (sampleSelectEl?.value || 'Soro');

    const params = new URLSearchParams();
    params.set('exam_name',       examName);
    params.set('sample_type',     sampleType);
    params.set('method',          (methodEl?.value  || '').trim());
    params.set('result_value',    resultHidden.value.trim());
    params.set('reference_value', (refEl?.value     || '').trim());
    params.set('observation',     (obsEl?.value     || '').trim());

    let result_id = null;
    try {
      const resp = await fetch(this.action, {
        method: 'POST',
        headers: {
          'X-Requested-With': 'XMLHttpRequest',
          'Content-Type':     'application/x-www-form-urlencoded',
        },
        body: params,
      });
      const json = await resp.json();
      if (!resp.ok) { alert(json.error || 'Erro ao adicionar exame.'); return; }
      result_id = json.result_id;
    } catch (err) {
      alert('Erro de conexão ao adicionar exame.'); return;
    }

    // Upload de imagens selecionadas (se houver)
    const imgInput = document.getElementById('img-inline-input');
    const imgCaption = document.getElementById('img-inline-caption');
    const files = imgInput?.files;

    if (files && files.length && result_id) {
      for (const file of files) {
        if (file.size > 8 * 1024 * 1024) { console.warn('Imagem grande pulada:', file.name); continue; }
        try {
          const base64 = await new Promise((res, rej) => {
            const r = new FileReader();
            r.onload  = e => res(e.target.result.split(',')[1]);
            r.onerror = rej;
            r.readAsDataURL(file);
          });
          await fetch('/lab/admin/resultados/' + result_id + '/images', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ data: base64, contentType: file.type, caption: imgCaption?.value || '' }),
          });
        } catch (e) { console.error('Upload de imagem falhou:', e); }
      }
    }

    // Recarrega a página da coleta
    window.location.reload();
  });
  // Remove o listener de submit duplicado que estava no final do arquivo
  // (o que estava dentro de `if (theForm)` pode ser removido)

  // ── Inicializa com campo select vazio ──────────────────────────────────
  // ── Toggle amostra manual ─────────────────────────────────────────────
  const sampleSelect       = document.getElementById('sampleSelect');
  const sampleManualToggle = document.getElementById('sampleManualToggle');
  const sampleManualInput  = document.getElementById('sampleManualInput');

  sampleManualToggle?.addEventListener('change', function () {
    const isManual = this.checked;
    sampleSelect.style.display      = isManual ? 'none' : '';
    sampleSelect.disabled           = isManual;
    sampleManualInput.style.display = isManual ? '' : 'none';
    sampleManualInput.required      = false;
    sampleManualInput.name          = isManual ? 'sample_type' : 'sample_type_manual';
    sampleSelect.name               = isManual ? 'sample_type_disabled' : 'sample_type';
  });
  buildResultField('select');

})();
