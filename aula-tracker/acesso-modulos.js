// acesso-modulos.js
// ──────────────────────────────────────────────────────────────────────────
// Registro dos módulos que aceitam solicitação de acesso.
//
// Mesma disciplina do array ROLES em aulas-admin-usuarios-routes.js: a página
// pública, a fila do admin e a rota de aprovação derivam DESTA lista.
// Acrescentar um módulo é acrescentar uma entrada — não copiar rota.
//
// Campos da entrada:
//   chave        valor gravado em access_requests.kind
//   flag         coluna booleana em users concedida na aprovação
//   solicitavel  false = não aparece no formulário público, mas continua
//                aprovável (usado para módulos cujo acesso é concedido
//                diretamente, e para não travar pedidos antigos pendentes)
//   rotulo       nome do módulo como a pessoa o conhece
//   publico      a quem se destina
//   descricao    o que a pessoa passa a poder fazer
//   aprovadoPor  quem revisa o pedido
//   vinculo      grava a instituição do pedido (subdomínio) no usuário
//   dominio      exige o domínio institucional de e-mail
//   campos       dados adicionais pedidos no formulário. Guardados em
//                access_requests.dados (JSONB) e, se `coluna` estiver
//                preenchida, gravados nessa coluna de users na aprovação.
//                A coluna vem SEMPRE daqui — nunca da requisição.
// ──────────────────────────────────────────────────────────────────────────

export const MODULOS = [
  {
    chave: 'scih',
    flag: 'scih',
    solicitavel: true,
    rotulo: 'Sistemas do SCIH',
    publico: 'Equipe do Serviço de Controle de Infecção Hospitalar',
    descricao: 'Controle de antimicrobianos, vigilância pós-alta de infecção de sítio cirúrgico e indicadores do serviço.',
    aprovadoPor: 'coordenação do SCIH',
    vinculo: true,
    dominio: true,
    campos: [],
  },
  {
    chave: 'pav',
    flag: 'pav',
    solicitavel: true,
    rotulo: 'Bundle de Prevenção de PAV',
    publico: 'Fisioterapia e enfermagem das unidades de terapia intensiva',
    descricao: 'Registro das verificações do bundle à beira-leito, por turno e por salão.',
    aprovadoPor: 'coordenação do SCIH',
    vinculo: true,
    dominio: true,
    // A flag sozinha não basta: a categoria decide os itens e o alcance de
    // salão, e o conselho assina cada verificação. Sem isso o acesso nasce
    // incompleto e a autoria do registro fica sem lastro.
    campos: [
      { nome: 'categoria_pav', coluna: 'categoria_pav', obrigatorio: true,
        rotulo: 'Categoria profissional', tipo: 'select',
        opcoes: [['fisio', 'Fisioterapia'], ['enf', 'Enfermagem']] },
      { nome: 'conselho', coluna: 'conselho', obrigatorio: true,
        rotulo: 'Registro no conselho', tipo: 'texto',
        dica: 'CREFITO para fisioterapia, COREN para enfermagem.' },
    ],
  },
  {
    chave: 'gestao',
    flag: 'gestao',
    solicitavel: true,
    rotulo: 'Painel de Governança',
    publico: 'Membros do Comitê de Gestão Estratégica e Governança',
    descricao: 'Indicadores assistenciais e operacionais da instituição, por competência.',
    aprovadoPor: 'coordenação do comitê',
    vinculo: true,
    dominio: true,
    campos: [],
  },
  {
    // Consultório. O acesso é concedido diretamente, não por formulário público.
    // Permanece no registro para que pedidos antigos ainda pendentes continuem
    // aprováveis pela fila do admin.
    chave: 'pront',
    flag: 'pront',
    solicitavel: false,
    rotulo: 'Prontuário',
    publico: 'Equipe do consultório',
    descricao: 'Pacientes, consultas e emissão de documentos.',
    aprovadoPor: 'Dr. Leandro',
    vinculo: false,
    dominio: true,
    campos: [],
  },
];

export const SOLICITAVEIS = MODULOS.filter(m => m.solicitavel);
export const CHAVES = MODULOS.map(m => m.chave);

export function moduloPorChave(k) {
  return MODULOS.find(m => m.chave === k) || null;
}
