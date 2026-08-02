# Worker local — o que rodar, e onde

Tudo que precisa rodar **no Mac** (e não no Render) está nesta pasta.
Se você não lembra de nada, lembre de uma frase:

> **Duplo-clique em `worker-agora.command`.**

---

## Por que existe um worker local

O app (`app.lcmendes.med.br`) roda no Render. O Ollama e o Whisper rodam
no seu Mac. Quando alguém envia um exame ou um áudio, o arquivo vai pro R2
e entra na fila do banco como `pendente` — **ninguém leu ainda**.

Quem lê é o worker, aqui. Por isso nenhum botão no site consegue "ligar"
o worker: o site está na nuvem, o Ollama está na sua mesa.

---

## Os dois arquivos desta pasta

| Arquivo | Quando usar |
|---|---|
| `instalar-worker.command` | **Uma vez.** Instala o agendamento. Rode de novo para mudar o intervalo, desligar, ou se desconfiar que parou. |
| `worker-agora.command` | **Quando quiser ver acontecer agora.** Esvazia a fila na sua frente e fecha sozinho. |

Instalado, o worker varre a fila **de hora em hora**, sozinho, inclusive no
login — com **teto de 10 minutos de trabalho por varredura**. Fila grande não
vira maratona de GPU: o que sobra fica `pendente` e é pego na hora seguinte.

Os dois botões ficam no **topo do `instalar-worker.command`**:
`INTERVALO_SEG` (use `0` para desligar o agendamento por completo) e
`TETO_MIN`. Mudou, rode o instalador de novo.

---

## Regra que vem antes de tudo: sincronizar

Este projeto costuma ser editado pelo **editor web do GitHub**. Isso significa
que sua cópia local fica atrás do repo sem aviso — em 01/ago ela estava
89 arquivos e 14 mil linhas atrás, e o worker rodava código de junho.

Antes de rodar ou editar qualquer coisa aqui:

```bash
cd ~/Documents/Developer/exames/aula-tracker
git pull --ff-only
```

Se o `--ff-only` recusar, **não force**: significa divergência real e há
trabalho a preservar de algum lado.

E o editor web tem uma armadilha conhecida: **ele sobe edições de arquivos
existentes, mas não cria arquivos novos.** Arquivo novo tem que ir por
`git add`/`push` local — foi por isso que esta pasta `mac/` demorou a
existir no repo.

---

## Se algo parecer travado

```bash
cd ~/Documents/Developer/exames/aula-tracker

npm run worker:status    # o agendamento está de pé?
npm run worker:log       # ver o worker trabalhando
npm run worker:agora     # mesma coisa que o worker-agora.command
```

Checklist, na ordem:

1. **Ollama de pé?** `brew services list | grep ollama` → precisa dizer `started`.
2. **Agendamento carregado?** `npm run worker:status` → precisa listar o agente.
3. **Código atualizado?** `git pull --ff-only` e `grep -c drain pront-worker.js` (≥ 6).
4. Nada disso resolveu → duplo-clique em `instalar-worker.command`.

---

## Se o Mac esquentar

```bash
launchctl bootout gui/$(id -u)/com.clinicakadri.pront-worker
pkill -f pront-worker.js
ollama stop qwen2.5vl:7b
```

O que esquenta **não é o Node** — é o `ollama serve` rodando `qwen2.5vl:7b`
no GPU, e ele é um processo separado, fora do alcance do `nice` do worker.
O modelo ocupa ~7 GB residentes; num Mac de 16 GB isso é metade da máquina.
`ollama stop` devolve na hora, em vez de esperar o keep-alive de 5 min.

Depois de parar, veja o tamanho da fila em `/pront` (cartão "Na fila de OCR")
antes de religar: esse número é quantas passadas de visão o GPU vai fazer.

---

## Modos do `pront-worker.js`

| Comando | O que faz |
|---|---|
| `node pront-worker.js --drain` | esvazia a fila e sai — **é o que o agendamento usa** |
| `node pront-worker.js --once` | processa **um** documento e sai (depuração) |
| `node pront-worker.js` | loop eterno em primeiro plano (legado) |

O agendamento usa `--drain` de propósito: processo curto, sem estado. Cada
execução recarrega o código do disco — então **não precisa reiniciar nada
depois de um deploy** — e não há como ficar "vivo mas morto" com pool de
conexão zumbi depois de um sleep/wake.

**Cuidado histórico:** o worker antigo ignorava `--drain` silenciosamente e
caía no loop eterno. Agendado, isso virou um daemon permanente que o launchd
nem substituía. O instalador hoje **se recusa a instalar** se o
`pront-worker.js` da pasta não suportar `--drain`.

---

## O que este worker *não* resolve

- **Mac dormindo com a tampa fechada não processa nada.** O launchd dispara
  ao acordar, mas a fila espera até lá.
- **A leitura da máquina não é confiável sozinha.** Nada entra na ficha do
  paciente sem sua conferência em `/pront/conferencia`. Isso é por desenho.
- **Documento que falhou 3 vezes vai pra `erro` e não é re-tentado.** Hoje
  se resolve no banco (`UPDATE pront_documentos SET status='pendente',
  tentativas=0, erro=NULL WHERE id=…`).

---

## Nunca dê `git add .` nesta pasta

O repo é **público** e há arquivos locais que não podem sair daqui:
`submissions-delta.json`, `backfill-log-*.jsonl` (dados de paciente) e
`blackbook_ebook_cor.pdf` (obra sob direito autoral). O `.gitignore` atual
não cobre esses padrões. Sempre `git add` com os arquivos nomeados.
