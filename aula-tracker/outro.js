// public/js/outro.js

const ReviewViewer = (() => {
  let cfg = {};
  let container;
  let currentIndex = 0;
  let questions = [];
  let stream = null;

  async function init(options) {
    cfg = options;
    container = document.querySelector(cfg.container);
    if (!container) {
      console.error("Container não encontrado");
      return;
    }

    try {
      const res = await fetch(`/api/review/bootstrap?token=${encodeURIComponent(cfg.token)}`);
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setup(data);
    } catch (err) {
      container.innerHTML = `<div class="error">Erro ao carregar revisão: ${err.message}</div>`;
    }
  }

  function setup(data) {
    cfg.bootstrap = data;

    // monta lista de questões erradas (mapeadas para canônica)
    const wrong = [];
    const { wrongPositions, versionMap, keyVersion } = data;
    wrongPositions.forEach(pos => {
      const canon = versionMap ? versionMap[pos] : pos;
      wrong.push({
        pos,
        canon,
        selected: data.selectedByPosition[pos] || "—"
      });
    });

    questions = wrong;
    if (questions.length === 0) {
      container.innerHTML = `<p>Parabéns, você não errou nenhuma questão.</p>`;
      return;
    }

    // inicia webcam
    navigator.mediaDevices.getUserMedia({ video: true })
      .then(s => { stream = s; })
      .catch(err => { console.warn("Webcam não disponível:", err); });

    showQuestion(0);
  }

  function showQuestion(idx) {
    if (idx >= questions.length) {
      container.innerHTML = `<p>Fim da revisão.</p>`;
      stopCamera();
      return;
    }
    currentIndex = idx;
    const q = questions[idx];

    // URL dos assets (stem + questão)
    const stemObj = cfg.bootstrap.stemsRanges.find(s => q.canon >= s.range[0] && q.canon <= s.range[1]);
    const stemUrl = `${cfg.bootstrap.r2Base}/stems/${stemObj.id}.png`;
    const itemUrl = `${cfg.bootstrap.r2Base}/items/q${String(q.canon).padStart(2, "0")}.png`;

    container.innerHTML = `
      <div class="review-item">
        <img class="stem" src="${stemUrl}" />
        <img class="question" src="${itemUrl}" />
        <p class="feedback">Você <b>ERROU</b> ao selecionar a alternativa <b>${q.selected}</b>.</p>
        <div class="countdown"></div>
      </div>
    `;

    // captura foto imediata
    captureSnapshot(q);

    // agenda foto aleatória
    const randomDelay = 5000 + Math.random() * (cfg.bootstrap.questionSeconds * 1000 - 10000);
    setTimeout(() => captureSnapshot(q), randomDelay);

    // countdown
    let seconds = cfg.bootstrap.questionSeconds;
    const countdownEl = container.querySelector(".countdown");
    countdownEl.textContent = `${seconds}s restantes`;

    const timer = setInterval(() => {
      seconds--;
      countdownEl.textContent = `${seconds}s restantes`;
      if (seconds <= 0) {
        clearInterval(timer);
        showQuestion(idx + 1);
      }
    }, 1000);
  }

  function captureSnapshot(q) {
    if (!stream) return;
    const video = document.createElement("video");
    video.srcObject = stream;
    video.play();

    const canvas = document.createElement("canvas");
    const [track] = stream.getVideoTracks();
    const settings = track.getSettings();
    canvas.width = settings.width || 640;
    canvas.height = settings.height || 480;

    const ctx = canvas.getContext("2d");
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

    canvas.toBlob(blob => {
      const url = `/api/review/snapshot?attemptId=${cfg.bootstrap.attemptId}&courseId=${cfg.bootstrap.student.id}&examId=${cfg.bootstrap.examId}&pos=${q.pos}&canon=${q.canon}&t=${Date.now()}`;
      fetch(url, {
        method: "POST",
        headers: { "Content-Type": "image/jpeg" },
        body: blob
      }).catch(err => console.warn("Erro ao enviar snapshot:", err));
    }, "image/jpeg", 0.8);
  }

  function stopCamera() {
    if (stream) {
      stream.getTracks().forEach(t => t.stop());
      stream = null;
    }
  }

  return { init };
})();

export default ReviewViewer;
