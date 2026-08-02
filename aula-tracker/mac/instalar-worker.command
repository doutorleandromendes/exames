#!/bin/zsh
# ─────────────────────────────────────────────────────────────────────
#  INSTALAR / ATUALIZAR O WORKER  —  duplo-clique neste arquivo.
#
#  Instala o agendamento: o Mac esvazia a fila sozinho, de hora em hora,
#  com teto de tempo por varredura. Você não precisa abrir nada no dia a dia.
#
#  Pode rodar quantas vezes quiser — é idempotente.
# ─────────────────────────────────────────────────────────────────────

# ── DOIS BOTÕES, e só estes dois ──────────────────────────────────────
#
#  INTERVALO_SEG: de quanto em quanto tempo o Mac varre a fila.
#    3600 = 1h (padrão) · 7200 = 2h · 1800 = 30min · 0 = NÃO AGENDAR
#    Com 0, nada roda sozinho: você aciona pelo 'worker-agora.command'.
INTERVALO_SEG=3600
#
#  TETO_MIN: quantos minutos, no máximo, cada varredura pode trabalhar.
#    É o freio de mão. Uma fila grande NÃO vira uma maratona de GPU:
#    o worker para no teto e o que sobrou espera a próxima varredura.
TETO_MIN=10
# ──────────────────────────────────────────────────────────────────────

set -e
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:$PATH"

LABEL="com.clinicakadri.pront-worker"
PROJ="$(cd "$(dirname "$0")/.." && pwd)"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG="$HOME/Library/Logs/pront-worker.log"

fim() { echo ""; echo "Enter para fechar."; read _; exit "${1:-0}"; }

echo "=================================================="
echo "  Worker de OCR/transcrição — instalação"
echo "=================================================="
echo ""

# ── 1. checagens ──
NODE="$(command -v node || true)"
if [[ -z "$NODE" ]]; then
  echo "ERRO: 'node' não encontrado.  Instale com: brew install node"; fim 1
fi

if [[ ! -f "$PROJ/pront-worker.js" ]]; then
  echo "ERRO: não achei 'pront-worker.js' em:"
  echo "  $PROJ"
  echo "Este arquivo precisa ficar na pasta 'mac/' dentro do projeto."; fim 1
fi

# ── TRAVA CRÍTICA ─────────────────────────────────────────────────────
# O worker antigo IGNORA flags que não conhece e cai em loop eterno. Se o
# launchd disparar isso, vira um daemon permanente que ele nem substitui
# (não reinicia enquanto a instância anterior está viva) — GPU ocupada
# sem parar. Já aconteceu. Sem suporte a --drain, não instala. Ponto.
if ! grep -q -- "--drain" "$PROJ/pront-worker.js"; then
  echo "ERRO: o 'pront-worker.js' desta pasta NÃO suporta '--drain'."
  echo ""
  echo "Sua cópia local está velha. Agendar assim faria o worker rodar"
  echo "em loop eterno e esquentar a máquina. Atualize primeiro:"
  echo ""
  echo "    cd \"$PROJ\" && git pull --ff-only"
  echo "    grep -c drain pront-worker.js     # tem que ser 6 ou mais"
  echo ""
  echo "Depois rode este instalador de novo."; fim 1
fi
node --check "$PROJ/pront-worker.js" || { echo "ERRO: pront-worker.js com erro de sintaxe."; fim 1; }

if [[ ! -f "$PROJ/.env" ]]; then
  echo "AVISO: não achei o '.env' em $PROJ"
  echo "Sem ele o worker não conecta no banco. (O .env é local, não vem do git.)"
  echo ""
fi

echo "node      : $NODE"
echo "projeto   : $PROJ"
echo "log       : $LOG"
if (( INTERVALO_SEG > 0 )); then
  echo "intervalo : ${INTERVALO_SEG}s  (~$((INTERVALO_SEG/60)) min)"
  echo "teto      : ${TETO_MIN} min de trabalho por varredura"
else
  echo "intervalo : DESLIGADO — só sob demanda"
fi
echo ""

# ── 2. modo sob demanda: remove o agendamento e sai ──
if (( INTERVALO_SEG <= 0 )); then
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
  rm -f "$PLIST"
  echo "✓ Agendamento REMOVIDO. Nada roda sozinho."
  echo "  Para processar a fila: duplo-clique em 'worker-agora.command'."
  fim 0
fi

# ── 3. escreve o agente ──
mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"
cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!-- GERADO POR mac/instalar-worker.command — não edite à mão, rode o instalador de novo. -->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>

  <key>ProgramArguments</key>
  <array>
    <string>$NODE</string>
    <string>pront-worker.js</string>
    <string>--drain</string>
  </array>

  <!-- roda a partir da pasta do projeto: é assim que o dotenv acha o .env -->
  <key>WorkingDirectory</key><string>$PROJ</string>

  <key>EnvironmentVariables</key>
  <dict>
    <!-- ffmpeg, ollama, pdftoppm (poppler), whisper-cli -->
    <key>PATH</key>
    <string>/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <!-- freio de mão: teto de trabalho por varredura. O que sobrar fica
         'pendente' e é pego na próxima — backlog se parcela sozinho. -->
    <key>PRONT_DRAIN_MAX_MS</key><string>$((TETO_MIN * 60 * 1000))</string>
  </dict>

  <!-- varre ao ligar e a cada ${INTERVALO_SEG}s. Mac dormindo: dispara ao acordar. -->
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>$INTERVALO_SEG</integer>
  <!-- sem KeepAlive: o processo é curto por desenho e deve mesmo sair -->

  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>

  <key>Nice</key><integer>5</integer>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
PLISTEOF

# ── 4. recarrega e confirma ──
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
sleep 2

echo ""
if launchctl list | grep -q "$LABEL"; then
  launchctl list | grep "$LABEL"
  echo ""
  echo "✓ Worker agendado e ativo."
  echo "  Varre a fila a cada ~$((INTERVALO_SEG/60)) min, no máximo ${TETO_MIN} min por vez."
  echo "  Forçar agora : duplo-clique em 'worker-agora.command'"
  echo "  Acompanhar   : tail -f \"$LOG\""
  echo "  Desligar     : ponha INTERVALO_SEG=0 no topo deste arquivo e rode de novo"
else
  echo "✗ O agente não apareceu no launchctl. Algo falhou acima."
fi
fim 0
