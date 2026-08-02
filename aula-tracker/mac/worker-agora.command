#!/bin/zsh
# ─────────────────────────────────────────────────────────────────────
#  ESVAZIAR A FILA AGORA  —  duplo-clique neste arquivo.
#
#  Não substitui o agendamento: o worker já roda sozinho. Use isto
#  quando você acabou de subir um áudio/exame e quer ver processar
#  na hora, ou quando quiser ler a saída de um erro.
#
#  Processa tudo que estiver pendente e fecha. Não deixa nada rodando.
# ─────────────────────────────────────────────────────────────────────

cd "$(dirname "$0")/.." || { echo "Não achei a pasta do projeto."; exit 1; }
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:$PATH"

echo "=================================================="
echo "  Esvaziando a fila — $(pwd)"
echo "=================================================="
echo ""

if ! command -v node >/dev/null 2>&1; then
  echo "ERRO: 'node' não encontrado no PATH."
  echo ""; echo "Enter para fechar."; read _; exit 1
fi

# o Ollama precisa estar de pé para visão/transcrição
if ! curl -s --max-time 3 http://localhost:11434/api/tags >/dev/null 2>&1; then
  echo "AVISO: o Ollama não respondeu em localhost:11434."
  echo "Suba com:  brew services start ollama"
  echo "Sem ele, os documentos vão falhar e contar tentativa."
  echo ""
fi

node pront-worker.js --drain

echo ""
echo "Confira o resultado em: https://app.lcmendes.med.br/pront/conferencia"
echo ""
echo "Enter para fechar."
read _
