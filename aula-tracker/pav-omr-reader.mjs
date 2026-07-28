// pav-omr-reader.mjs
// Leitor OMR do instrumento PAV (template PAV-SEM-DN-v3).
// JS puro, sem dependências: roda no NAVEGADOR (câmera do celular, offline)
// e no NODE (testes). A geometria vem do template JSON gerado por gen_omr.py
// — fonte única de verdade, verificada contra o PDF.
//
// Pipeline:
//   1. findFiducials  — localiza os 4 quadrados pretos de canto na foto
//   2. solveHomography — mapeia mm-do-template → pixel-da-foto (perspectiva)
//   3. readSheet      — amostra cada bolha na posição conhecida e classifica
//                       com fundo LOCAL (robusto a gradiente de iluminação)
//
// A classificação de bolha usa os parâmetros calibrados no template:
//   disco interno inner_frac×r (exclui o contorno impresso), fundo estimado
//   num anel ao redor, marcada se fração de tinta ≥ mark_min_frac.

// ── fiduciais ──────────────────────────────────────────────────────────────
// Procura, em cada janela de canto (fração `win` da imagem), o blob escuro
// mais parecido com um quadrado do tamanho esperado. Retorna 4 centros em px
// na ordem do template (TL, TR, BL, BR) ou null se algum canto falhar.
export function findFiducials(gray, w, h, opts = {}) {
  const win = opts.win ?? 0.28;                 // janela de busca por canto
  const wins = [
    [0, 0],                                     // TL
    [w - Math.floor(w * win), 0],               // TR
    [0, h - Math.floor(h * win)],               // BL
    [w - Math.floor(w * win), h - Math.floor(h * win)], // BR
  ];
  const ww = Math.floor(w * win), wh = Math.floor(h * win);
  const out = [];
  for (const [ox, oy] of wins) {
    const c = darkestSquareBlob(gray, w, h, ox, oy, Math.min(ww, w - ox), Math.min(wh, h - oy));
    if (!c) return null;
    out.push(c);
  }
  return out;
}

function darkestSquareBlob(gray, w, h, ox, oy, ww, wh) {
  // limiar local da janela (média-k*desvio ~ Otsu simplificado é suficiente:
  // o fiducial é MUITO mais escuro que o papel)
  let sum = 0, n = 0;
  for (let y = oy; y < oy + wh; y += 2)
    for (let x = ox; x < ox + ww; x += 2) { sum += gray[y * w + x]; n++; }
  const mean = sum / n;
  const thr = Math.min(mean * 0.55, 110);

  const seen = new Uint8Array(ww * wh);
  let best = null;
  const minA = ww * wh * 0.0015, maxA = ww * wh * 0.12;
  for (let y0 = 0; y0 < wh; y0++) {
    for (let x0 = 0; x0 < ww; x0++) {
      const gi = (oy + y0) * w + (ox + x0);
      if (seen[y0 * ww + x0] || gray[gi] >= thr) continue;
      // BFS
      let head = 0; const qx = [x0], qy = [y0];
      seen[y0 * ww + x0] = 1;
      let area = 0, sx = 0, sy = 0, minx = x0, maxx = x0, miny = y0, maxy = y0;
      while (head < qx.length) {
        const cx = qx[head], cy = qy[head]; head++;
        area++; sx += cx; sy += cy;
        if (cx < minx) minx = cx; if (cx > maxx) maxx = cx;
        if (cy < miny) miny = cy; if (cy > maxy) maxy = cy;
        for (const [dx, dy] of [[1,0],[-1,0],[0,1],[0,-1]]) {
          const nx = cx + dx, ny = cy + dy;
          if (nx < 0 || ny < 0 || nx >= ww || ny >= wh) continue;
          const ii = ny * ww + nx;
          if (seen[ii]) continue;
          if (gray[(oy + ny) * w + (ox + nx)] < thr) { seen[ii] = 1; qx.push(nx); qy.push(ny); }
          else seen[ii] = 1 * 0; // não marca claros: podem pertencer a outro blob? marcamos p/ custo
        }
      }
      if (area < minA || area > maxA) continue;
      const bw = maxx - minx + 1, bh = maxy - miny + 1;
      const aspect = bw / bh;
      const fill = area / (bw * bh);
      if (aspect < 0.55 || aspect > 1.8 || fill < 0.55) continue;   // quer quadrado cheio
      const score = area * fill;
      if (!best || score > best.score)
        best = { score, x: ox + sx / area, y: oy + sy / area };
    }
  }
  return best ? [best.x, best.y] : null;
}

// ── homografia 4-pontos (DLT, eliminação gaussiana 8×8) ───────────────────
export function solveHomography(src, dst) {
  // src/dst: [[x,y]×4]; retorna H 3×3 (array de 9) com h33=1
  const A = [], b = [];
  for (let i = 0; i < 4; i++) {
    const [x, y] = src[i], [u, v] = dst[i];
    A.push([x, y, 1, 0, 0, 0, -u * x, -u * y]); b.push(u);
    A.push([0, 0, 0, x, y, 1, -v * x, -v * y]); b.push(v);
  }
  const hh = gauss(A, b);
  if (!hh) return null;
  return [hh[0], hh[1], hh[2], hh[3], hh[4], hh[5], hh[6], hh[7], 1];
}

function gauss(A, b) {
  const n = b.length;
  const M = A.map((row, i) => [...row, b[i]]);
  for (let c = 0; c < n; c++) {
    let p = c;
    for (let r = c + 1; r < n; r++) if (Math.abs(M[r][c]) > Math.abs(M[p][c])) p = r;
    if (Math.abs(M[p][c]) < 1e-10) return null;
    [M[c], M[p]] = [M[p], M[c]];
    for (let r = 0; r < n; r++) {
      if (r === c) continue;
      const f = M[r][c] / M[c][c];
      for (let k = c; k <= n; k++) M[r][k] -= f * M[c][k];
    }
  }
  return M.map((row, i) => row[n] / row[i]);
}

export function applyH(H, x, y) {
  const d = H[6] * x + H[7] * y + H[8];
  return [(H[0] * x + H[1] * y + H[2]) / d, (H[3] * x + H[4] * y + H[5]) / d];
}

// ── amostragem de bolha com fundo local ───────────────────────────────────
function px(gray, w, h, x, y) {
  const xi = Math.round(x), yi = Math.round(y);
  if (xi < 0 || yi < 0 || xi >= w || yi >= h) return 255;
  return gray[yi * w + xi];
}

export function sampleBubble(gray, w, h, H, cx_mm, cy_mm, r_mm, params) {
  const innerF = params?.inner_frac ?? 0.75;
  const [r0, r1] = params?.bg_ring ?? [1.5, 2.1];
  // escala local mm→px pela homografia (distância de dois pontos a 1mm)
  const [ax, ay] = applyH(H, cx_mm, cy_mm);
  const [bx, by] = applyH(H, cx_mm + 1, cy_mm);
  const pxPerMm = Math.hypot(bx - ax, by - ay);

  // fundo: mediana de amostras no anel (papel ao redor da bolha)
  const bgS = [];
  for (let a = 0; a < 24; a++) {
    const ang = (a / 24) * 2 * Math.PI;
    const rr = (r0 + (r1 - r0) * ((a % 3) / 2)) * r_mm;
    const [sx, sy] = applyH(H, cx_mm + rr * Math.cos(ang), cy_mm + rr * Math.sin(ang));
    bgS.push(px(gray, w, h, sx, sy));
  }
  bgS.sort((p, q) => p - q);
  const bg = bgS[Math.floor(bgS.length / 2)];
  const thr = bg * 0.72;                       // tinta é MUITO mais escura que papel

  // disco interno
  const rIn = innerF * r_mm;
  const step = Math.max(0.5 / pxPerMm, rIn / 7); // ~7 amostras por raio
  let dark = 0, tot = 0;
  for (let dy = -rIn; dy <= rIn; dy += step) {
    for (let dx = -rIn; dx <= rIn; dx += step) {
      if (dx * dx + dy * dy > rIn * rIn) continue;
      const [sx, sy] = applyH(H, cx_mm + dx, cy_mm + dy);
      tot++;
      if (px(gray, w, h, sx, sy) < thr) dark++;
    }
  }
  return { frac: tot ? dark / tot : 0, bg };
}

// ── leitura da folha inteira ──────────────────────────────────────────────
// Retorna, por linha-sim/não: cells[dia][periodo] = 'S' | 'N' | null (vazio)
//         | 'AMBAS' (dupla marcação → conferência humana)
// Campos numéricos NÃO são lidos automaticamente (v1): devolvemos as caixas
// em px para a UI recortar e o humano digitar.
// ── plausibilidade do quadrilátero ────────────────────────────────────────
// Falsos fiduciais (sombras/móveis nos cantos) formam quadriláteros com
// geometria errada. Antes de aceitar, exigimos: ordem correta, convexidade,
// área mínima e proporção compatível com a folha (fiduciais: 276×189mm ≈ 1.46;
// perspectiva razoável fica entre ~1.0 e ~2.2).
export function plausibleFiducials(fid, w, h) {
  if (!fid || fid.length !== 4) return false;
  const [tl, tr, bl, br] = fid;
  // ordem: cada canto no seu quadrante relativo, com separação mínima
  if (!(tl[0] < tr[0] - w * 0.2 && bl[0] < br[0] - w * 0.2)) return false;
  if (!(tl[1] < bl[1] - h * 0.2 && tr[1] < br[1] - h * 0.2)) return false;
  // área (shoelace, ordem tl→tr→br→bl) — a folha deve ocupar boa parte do quadro
  const pts = [tl, tr, br, bl];
  let area = 0;
  for (let i = 0; i < 4; i++) {
    const [x1, y1] = pts[i], [x2, y2] = pts[(i + 1) % 4];
    area += x1 * y2 - x2 * y1;
  }
  area = Math.abs(area) / 2;
  if (area < 0.25 * w * h) return false;
  // proporção média largura/altura do quadrilátero
  const wTop = Math.hypot(tr[0] - tl[0], tr[1] - tl[1]);
  const wBot = Math.hypot(br[0] - bl[0], br[1] - bl[1]);
  const hEsq = Math.hypot(bl[0] - tl[0], bl[1] - tl[1]);
  const hDir = Math.hypot(br[0] - tr[0], br[1] - tr[1]);
  const ratio = ((wTop + wBot) / 2) / ((hEsq + hDir) / 2);
  if (ratio < 1.0 || ratio > 2.2) return false;
  // lados opostos não podem divergir absurdamente (perspectiva extrema/lixo)
  if (Math.max(wTop, wBot) / Math.min(wTop, wBot) > 1.8) return false;
  if (Math.max(hEsq, hDir) / Math.min(hEsq, hDir) > 1.8) return false;
  return true;
}

export function readSheet(gray, w, h, template, opts = {}) {
  const fid = opts.fiducials ?? findFiducials(gray, w, h);
  if (!fid) return { ok: false, erro: 'fiduciais não encontrados' };
  if (!opts.skipPlausible && !plausibleFiducials(fid, w, h))
    return { ok: false, erro: 'enquadramento implausível — os 4 cantos detectados não formam a folha' };
  const H = solveHomography(template.fiducials_mm, fid);
  if (!H) return { ok: false, erro: 'homografia degenerada' };

  const P = template.read_params;
  const minF = P.mark_min_frac;
  const out = { ok: true, fiducials: fid, H, marks: [], numeric_boxes: [], meta_boxes: {} };

  for (const row of template.rows) {
    if (row.tipo === 'sn') {
      const dias = [];
      for (let d = 0; d < template.dias; d++) {
        const per = [];
        for (let p = 0; p < 2; p++) {
          const cell = row.cells[d][p];
          const s = sampleBubble(gray, w, h, H, cell.S[0], cell.S[1], cell.r, P);
          const n = sampleBubble(gray, w, h, H, cell.N[0], cell.N[1], cell.r, P);
          const sm = s.frac >= minF, nm = n.frac >= minF;
          per.push({
            valor: sm && nm ? 'AMBAS' : sm ? 'S' : nm ? 'N' : null,
            fracS: +s.frac.toFixed(3), fracN: +n.frac.toFixed(3),
          });
        }
        dias.push(per);
      }
      out.marks.push({ key: row.key, enf: row.enf, label: row.label, dias });
    } else {
      // caixas numéricas: converter mm→px para a UI recortar
      const dias = row.cells.map(perList =>
        perList.map(caixas => caixas.map(([x, y, bw, bh]) => {
          const [x0, y0] = applyH(H, x, y);
          const [x1, y1] = applyH(H, x + bw, y + bh);
          return [x0, y0, x1 - x0, y1 - y0].map(v => Math.round(v));
        })));
      out.numeric_boxes.push({ key: row.key, label: row.label, por_dia: row.por_dia, dias });
    }
  }
  // metadados (recortes p/ a UI): prontuário, datas, horas
  const toPx = ([x, y, bw, bh]) => {
    const [x0, y0] = applyH(H, x, y);
    const [x1, y1] = applyH(H, x + bw, y + bh);
    return [x0, y0, x1 - x0, y1 - y0].map(v => Math.round(v));
  };
  out.meta_boxes.prontuario = template.prontuario_boxes.map(toPx);
  out.meta_boxes.datas = template.date_boxes.map(bs => bs.map(toPx));
  out.meta_boxes.horas = template.hora_boxes.map(dd => dd.map(bs => bs.map(toPx)));
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════
//  OCR DE DÍGITO MANUSCRITO  (dígitos já segmentados pela geometria)
//  A caixa isola o dígito — o problema difícil (segmentação) some. Aqui:
//    normalizeDigit → recorte 28×28 centrado pela massa (padrão MNIST)
//    classifyDigit  → rótulo 0-9 + confiança (interface plugável)
//  v1: classificador por características (sem treino, funciona já; confiança
//  honesta — baixa nos ambíguos → o portão manda revisar). v2: trocar
//  setDigitModel() por uma CNN treinada com o log, MESMA interface.
// ═══════════════════════════════════════════════════════════════════════════

// recorta a caixa da imagem cinza e devolve {px:Uint8Array(28*28), vazio:bool}
export function normalizeDigit(gray, w, h, box) {
  const [bx, by, bw, bh] = box.map(Math.round);
  // margem interna: descarta a borda impressa da caixa
  const mx = Math.max(1, Math.round(bw * 0.16)), my = Math.max(1, Math.round(bh * 0.16));
  const x0 = bx + mx, y0 = by + my, x1 = bx + bw - mx, y1 = by + bh - my;
  const iw = Math.max(1, x1 - x0), ih = Math.max(1, y1 - y0);

  // fundo local (mediana das bordas) e limiar
  const borda = [];
  for (let x = x0; x < x1; x += 2) { borda.push(px(gray, w, h, x, y0)); borda.push(px(gray, w, h, x, y1 - 1)); }
  borda.sort((a, b) => a - b);
  const bg = borda[borda.length >> 1] || 200;
  const thr = bg * 0.62;

  // massa de tinta + bounding box do traço
  let minx = iw, miny = ih, maxx = 0, maxy = 0, tinta = 0;
  const buf = new Uint8Array(iw * ih);
  for (let y = 0; y < ih; y++) for (let x = 0; x < iw; x++) {
    const v = px(gray, w, h, x0 + x, y0 + y);
    if (v < thr) { buf[y * iw + x] = 1; tinta++; if (x < minx) minx = x; if (x > maxx) maxx = x; if (y < miny) miny = y; if (y > maxy) maxy = y; }
  }
  const areaFrac = tinta / (iw * ih);
  if (tinta < 6 || areaFrac < 0.02) return { px: null, vazio: true };

  // recorta no traço, escala mantendo proporção p/ caber em 20×20, centra em 28×28
  const tw = maxx - minx + 1, th = maxy - miny + 1;
  const scale = 20 / Math.max(tw, th);
  const out = new Float32Array(28 * 28);
  const offx = Math.round((28 - tw * scale) / 2), offy = Math.round((28 - th * scale) / 2);
  for (let y = 0; y < th; y++) for (let x = 0; x < tw; x++) {
    if (!buf[(miny + y) * iw + (minx + x)]) continue;
    const dx = Math.round(x * scale) + offx, dy = Math.round(y * scale) + offy;
    if (dx >= 0 && dy >= 0 && dx < 28 && dy < 28) out[dy * 28 + dx] = 1;
  }
  // centra pela massa (como o MNIST faz)
  let cx = 0, cy = 0, m = 0;
  for (let i = 0; i < 784; i++) if (out[i]) { cx += i % 28; cy += (i / 28) | 0; m++; }
  cx = Math.round(14 - cx / m); cy = Math.round(14 - cy / m);
  const cen = new Float32Array(784);
  for (let y = 0; y < 28; y++) for (let x = 0; x < 28; x++) {
    const sx = x - cx, sy = y - cy;
    if (sx >= 0 && sy >= 0 && sx < 28 && sy < 28) cen[y * 28 + x] = out[sy * 28 + sx];
  }
  return { px: cen, vazio: false, areaFrac };
}

// ── classificador: MLP 784→64→10 treinada (pesos carregados de JSON) ────────
// Rede densa pequena, inferência em JS puro (sem runtime externo). A confiança
// é o softmax do topo — CALIBRADA (ao contrário de heurísticas): o portão de
// revisão confia nela. setDigitModel troca por um modelo melhor (mesma saída),
// afinado com o log de dígitos reais.
let _mlp = null;                           // {W0,b0,W1,b1}
let _model = null;                         // override opcional (ex.: CNN futura)
export function setDigitModel(fn) { _model = fn; }
export function loadDigitMLP(weights) { _mlp = weights; }

export function classifyDigit(px28) {
  if (_model) return _model(px28);
  if (!_mlp) return { digito: null, conf: 0, probs: null };   // sem modelo → tudo revisa
  const { W0, b0, W1, b1 } = _mlp;
  // camada 1: relu(x·W0 + b0)   (W0: 784×64)
  const h = new Float32Array(64);
  for (let j = 0; j < 64; j++) {
    let s = b0[j];
    for (let i = 0; i < 784; i++) if (px28[i]) s += W0[i][j];   // px binário: soma só onde há tinta
    h[j] = s > 0 ? s : 0;
  }
  // camada 2: logits = h·W1 + b1   (W1: 64×10)
  const z = new Float32Array(10);
  let mx = -1e9;
  for (let k = 0; k < 10; k++) {
    let s = b1[k];
    for (let j = 0; j < 64; j++) s += h[j] * W1[j][k];
    z[k] = s; if (s > mx) mx = s;
  }
  // softmax
  let sum = 0; for (let k = 0; k < 10; k++) { z[k] = Math.exp(z[k] - mx); sum += z[k]; }
  let best = 0; for (let k = 0; k < 10; k++) { z[k] /= sum; if (z[k] > z[best]) best = k; }
  return { digito: best, conf: z[best], probs: Array.from(z) };
}

// lê um campo numérico inteiro (várias caixas) → {valor, conf_min, digitos:[...]}
// conf_min governa o portão: se abaixo do limiar, o campo pede revisão.
export function readNumber(gray, w, h, caixasPx, params = {}) {
  const digs = [];
  let confMin = 1, algum = false;
  for (const box of caixasPx) {
    const norm = normalizeDigit(gray, w, h, box);
    if (norm.vazio) { digs.push({ d: null, conf: 1, vazio: true }); continue; }
    algum = true;
    const r = classifyDigit(norm.px);
    digs.push({ d: r.digito, conf: r.conf, px: norm.px });
    if (r.conf < confMin) confMin = r.conf;
  }
  if (!algum) return { valor: null, conf_min: 1, vazio: true, digitos: digs };
  const valor = digs.filter(x => x.d != null).map(x => x.d).join('');
  return { valor: valor === '' ? null : Number(valor), conf_min: confMin, digitos: digs };
}

