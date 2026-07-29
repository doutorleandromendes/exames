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

  // fundo: amostras no anel ao redor da bolha, em LÓBULOS HORIZONTAIS.
  // O anel (até 2.1×r = 4.2mm) passaria da meia-altura da linha (3.75mm) e
  // cairia nas bordas — na linha da enfermagem, na MOLDURA PRETA do selo, que
  // explodiria a textura de fundo e cancelaria a caneta. Ângulos até ±40° da
  // horizontal mantêm o anel dentro da própria linha.
  const bgS = [];
  const LOBO = 40 * Math.PI / 180;
  for (let a = 0; a < 24; a++) {
    const t = (a / 24) * 2 * LOBO - LOBO;              // [-40°, +40°]
    const ang = (a % 2 === 0) ? t : Math.PI + t;       // lóbulo direito e esquerdo
    const rr = (r0 + (r1 - r0) * ((a % 3) / 2)) * r_mm;
    const [sx, sy] = applyH(H, cx_mm + rr * Math.cos(ang), cy_mm + rr * Math.sin(ang));
    bgS.push(px(gray, w, h, sx, sy));
  }
  bgS.sort((p, q) => p - q);
  const bg = bgS[Math.floor(bgS.length / 2)];
  // Limiar com REFERÊNCIA DUPLA: papel local (bg) × preto real da folha (darkRef,
  // medido nos fiduciais). Caneta azul em luz fraca fica ~120 num papel ~180:
  // bg*0.72=130 falhava por um triz; bg-0.35*(bg-dark) adapta ao contraste da foto.
  const darkRef = params?.darkRef;
  const thr = (darkRef != null && darkRef < bg - 20)
    ? bg - 0.35 * (bg - darkRef)
    : bg * 0.72;

  // norma de contraste da foto: papel local × preto real da folha
  const norm = Math.max(30, bg - (darkRef ?? bg * 0.15));

  // "massa de tinta" do ANEL (textura de fundo: meio-tom da impressão laser,
  // linhas de grade) — baseline a subtrair do disco
  // média APARADA (descarta os 25% mais escuros): robusta a acertos residuais
  // do anel em linhas de grade/contorno da bolha vizinha
  const defs = bgS.map(v => Math.max(0, bg - v)).sort((a, b) => a - b);
  const nKeep = Math.max(1, Math.floor(defs.length * 0.75));
  let ringMass = 0;
  for (let i = 0; i < nKeep; i++) ringMass += defs[i];
  ringMass /= (nKeep * norm);

  // disco interno: fração dura (marcas fortes) + massa de tinta (marcas fracas)
  const rIn = innerF * r_mm;
  const step = Math.max(0.5 / pxPerMm, rIn / 7); // ~7 amostras por raio
  let dark = 0, tot = 0, mass = 0;
  for (let dy = -rIn; dy <= rIn; dy += step) {
    for (let dx = -rIn; dx <= rIn; dx += step) {
      if (dx * dx + dy * dy > rIn * rIn) continue;
      const [sx, sy] = applyH(H, cx_mm + dx, cy_mm + dy);
      const v = px(gray, w, h, sx, sy);
      tot++;
      if (v < thr) dark++;
      mass += Math.max(0, bg - v);
    }
  }
  mass = tot ? mass / (tot * norm) : 0;
  // v = massa ACIMA da textura de fundo — caneta sobra; meio-tom se cancela
  const vInk = Math.max(0, mass - ringMass);
  return { frac: tot ? dark / tot : 0, mass: vInk, bg };
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

// ── refinamento do centro de UM fiducial ───────────────────────────────────
// Em mesa escura, o blob do fiducial pode se fundir com o fundo pela sombra da
// borda do papel — o centroide é puxado p/ fora e a homografia desloca TUDO.
// Aqui re-detectamos numa janela pequena ao redor do centro grosseiro, exigindo
// blob do TAMANHO esperado do fiducial (5mm), com limiar progressivamente mais
// escuro até o blob caber (o fiducial impresso é mais preto que a sombra).
function refineFiducial(gray, w, h, cx0, cy0, pxPerMm) {
  const half = Math.max(6, Math.round(8 * pxPerMm));
  const x0 = Math.max(0, Math.round(cx0) - half), y0 = Math.max(0, Math.round(cy0) - half);
  const x1 = Math.min(w, Math.round(cx0) + half), y1 = Math.min(h, Math.round(cy0) + half);
  const ww = x1 - x0, wh = y1 - y0;
  if (ww < 4 || wh < 4) return null;
  const expArea = Math.pow(5 * pxPerMm, 2);
  // limiares candidatos: do mais claro ao mais escuro
  for (const thr of [110, 90, 70, 50, 35]) {
    const seen = new Uint8Array(ww * wh);
    let best = null;
    for (let y = 0; y < wh; y++) for (let x = 0; x < ww; x++) {
      if (seen[y * ww + x] || gray[(y0 + y) * w + (x0 + x)] >= thr) continue;
      let head = 0; const qx = [x], qy = [y]; seen[y * ww + x] = 1;
      let area = 0, sx = 0, sy = 0, minx = x, maxx = x, miny = y, maxy = y;
      while (head < qx.length) {
        const px_ = qx[head], py_ = qy[head]; head++;
        area++; sx += px_; sy += py_;
        if (px_ < minx) minx = px_; if (px_ > maxx) maxx = px_;
        if (py_ < miny) miny = py_; if (py_ > maxy) maxy = py_;
        for (const [dx, dy] of [[1,0],[-1,0],[0,1],[0,-1]]) {
          const nx = px_ + dx, ny = py_ + dy;
          if (nx < 0 || ny < 0 || nx >= ww || ny >= wh) continue;
          const ii = ny * ww + nx;
          if (!seen[ii] && gray[(y0 + ny) * w + (x0 + nx)] < thr) { seen[ii] = 1; qx.push(nx); qy.push(ny); }
        }
      }
      if (area < 0.35 * expArea || area > 2.4 * expArea) continue;   // tamanho do fiducial
      const bw = maxx - minx + 1, bh = maxy - miny + 1;
      if (bw / bh < 0.55 || bw / bh > 1.8) continue;                 // quadrado
      const dc = Math.hypot(sx / area - ww / 2, sy / area - wh / 2); // perto do centro grosseiro
      if (!best || dc < best.dc) best = { dc, x: x0 + sx / area, y: y0 + sy / area };
    }
    if (best) return [best.x, best.y];
  }
  return null;
}

// ── auto-alinhamento fino pelos CONTORNOS impressos das bolhas ─────────────
// A folha carrega centenas de círculos impressos em posições conhecidas: eles
// são um alvo de calibração gratuito. Varremos um deslocamento (dx,dy) pequeno
// no espaço do template e ficamos com o que deixa os contornos mais escuros
// sob os pontos amostrados — corrige o resíduo que os fiduciais não pegam.
function refineOffset(gray, w, h, H, template) {
  const px_ = (x, y) => { const xi = Math.round(x), yi = Math.round(y);
    return (xi < 0 || yi < 0 || xi >= w || yi >= h) ? 255 : gray[yi * w + xi]; };
  const cells = [];
  for (const row of template.rows) {
    if (row.tipo !== 'sn') continue;
    for (const per of row.cells) for (const c of per) { cells.push(c.S); cells.push(c.N); }
  }
  // subamostra p/ velocidade (a cada 3 células é suficiente)
  const sub = cells.filter((_, i) => i % 3 === 0);
  const score = (dx, dy) => {
    let s = 0;
    for (const [cx, cy] of sub) for (let a = 0; a < 6; a++) {
      const ang = a / 6 * 2 * Math.PI;
      const [sx, sy] = applyH(H, cx + dx + 2.0 * Math.cos(ang), cy + dy + 2.0 * Math.sin(ang));
      s += 255 - px_(sx, sy);
    }
    return s;
  };
  let best = { v: -1, dx: 0, dy: 0 };
  for (let dy = -3; dy <= 3; dy += 0.5) for (let dx = -2; dx <= 2; dx += 0.5) {
    const v = score(dx, dy); if (v > best.v) best = { v, dx, dy };
  }
  for (let dy = best.dy - 0.5; dy <= best.dy + 0.5; dy += 0.25)
    for (let dx = best.dx - 0.5; dx <= best.dx + 0.5; dx += 0.25) {
      const v = score(dx, dy); if (v > best.v) best = { v, dx, dy };
    }
  return { dx: best.dx, dy: best.dy };
}

export function readSheet(gray, w, h, template, opts = {}) {
  let fid = opts.fiducials ?? findFiducials(gray, w, h);
  if (!fid) return { ok: false, erro: 'fiduciais não encontrados' };
  if (!opts.skipPlausible && !plausibleFiducials(fid, w, h))
    return { ok: false, erro: 'enquadramento implausível — os 4 cantos detectados não formam a folha' };

  // escala aproximada (px/mm) a partir do quadrilátero grosseiro
  const wTop = Math.hypot(fid[1][0] - fid[0][0], fid[1][1] - fid[0][1]);
  const pxPerMm = wTop / 276;    // 276mm entre centros dos fiduciais superiores

  // 1º refino: centro real de cada fiducial (imune à fusão com mesa escura)
  const ref = fid.map(([cx, cy]) => refineFiducial(gray, w, h, cx, cy, pxPerMm));
  if (ref.every(Boolean)) {
    if (plausibleFiducials(ref, w, h)) fid = ref;
  }

  let H = solveHomography(template.fiducials_mm, fid);
  if (!H) return { ok: false, erro: 'homografia degenerada' };

  // 2º refino: deslocamento fino pelos contornos impressos (auto-calibração)
  const off = opts.skipRefine ? { dx: 0, dy: 0 } : refineOffset(gray, w, h, H, template);

  // referência de preto da folha: mediana da intensidade nos 4 fiduciais
  const darks = fid.map(([cx, cy]) => {
    let s = 0, n = 0;
    for (let dy = -1; dy <= 1; dy++) for (let dx = -1; dx <= 1; dx++) {
      const xi = Math.round(cx) + dx, yi = Math.round(cy) + dy;
      if (xi >= 0 && yi >= 0 && xi < w && yi < h) { s += gray[yi * w + xi]; n++; }
    }
    return s / n;
  }).sort((a, b) => a - b);
  const darkRef = darks[1];   // 2º mais escuro (robusto a 1 fiducial ruim)

  const P = { ...template.read_params, darkRef, off };
  const minF = P.mark_min_frac;
  const out = { ok: true, fiducials: fid, H, marks: [], numeric_boxes: [], meta_boxes: {} };

  for (const row of template.rows) {
    if (row.tipo === 'sn') {
      const dias = [];
      for (let d = 0; d < template.dias; d++) {
        const per = [];
        for (let p = 0; p < 2; p++) {
          const cell = row.cells[d][p];
          const s = sampleBubble(gray, w, h, H, cell.S[0] + P.off.dx, cell.S[1] + P.off.dy, cell.r, P);
          const n = sampleBubble(gray, w, h, H, cell.N[0] + P.off.dx, cell.N[1] + P.off.dy, cell.r, P);
          // Decisão em duas vias:
          //  1. fração dura (>= minF): marcas fortes (preenchimento, X firme)
          //  2. massa de tinta acima do fundo (>= MASSA): marcas fracas (caneta
          //     desbotada, resolução média) — com guarda de IRMÃO: a bolha
          //     marcada deve ter bem mais massa que a vizinha da mesma célula
          const MASSA = 0.045;
          const smF = s.frac >= minF, nmF = n.frac >= minF;
          const smM = s.mass >= MASSA && (s.mass >= 1.8 * n.mass || s.mass >= 3 * MASSA);
          const nmM = n.mass >= MASSA && (n.mass >= 1.8 * s.mass || n.mass >= 3 * MASSA);
          const sm = smF || smM, nm = nmF || nmM;
          per.push({
            valor: sm && nm ? 'AMBAS' : sm ? 'S' : nm ? 'N' : null,
            fracS: +Math.max(s.frac, s.mass).toFixed(3), fracN: +Math.max(n.frac, n.mass).toFixed(3),
          });
        }
        dias.push(per);
      }
      out.marks.push({ key: row.key, enf: row.enf, label: row.label, dias });
    } else {
      // caixas numéricas: converter mm→px para a UI recortar
      const dias = row.cells.map(perList =>
        perList.map(caixas => caixas.map(([x, y, bw, bh]) => {
          const [x0, y0] = applyH(H, x + P.off.dx, y + P.off.dy);
          const [x1, y1] = applyH(H, x + bw + P.off.dx, y + bh + P.off.dy);
          return [x0, y0, x1 - x0, y1 - y0].map(v => Math.round(v));
        })));
      out.numeric_boxes.push({ key: row.key, label: row.label, por_dia: row.por_dia, dias });
    }
  }
  // metadados (recortes p/ a UI): prontuário, datas, horas
  const toPx = ([x, y, bw, bh]) => {
    const [x0, y0] = applyH(H, x + P.off.dx, y + P.off.dy);
    const [x1, y1] = applyH(H, x + bw + P.off.dx, y + bh + P.off.dy);
    return [x0, y0, x1 - x0, y1 - y0].map(v => Math.round(v));
  };
  out.refino = { off: P.off, darkRef: Math.round(darkRef), fiducials_refinados: fid };
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

