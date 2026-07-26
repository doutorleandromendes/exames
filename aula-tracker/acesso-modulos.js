// acesso-modulos.js
// ──────────────────────────────────────────────────────────────────────────
// Registro dos módulos que aceitam solicitação de acesso.
//
// Mesma disciplina do array ROLES em aulas-admin-usuarios-routes.js: a página
// de solicitação, a fila do admin e a rota de aprovação derivam DESTA lista.
// Acrescentar um módulo é acrescentar uma entrada — não copiar rota.
//
// Campos:
//   chave        valor gravado em access_requests.kind
//   flag         coluna booleana em users concedida na aprovação
//   rotulo       nome do módulo como a pessoa o conhece
//   publico      a quem se destina (aparece na escolha)
//   descricao    o que a pessoa passa a poder fazer
//   aprovadoPor  quem revisa o pedido (aparece na confirmação)
//   destino      para onde a pessoa vai depois de definir a senha
//   vinculo      grava a instituição do pedido (subdomínio) no usuário
//   dominio      exige o domínio institucional de e-mail
//   justifica    pede um campo de justificativa no formulário
// ──────────────────────────────────────────────────────────────────────────

export const MODULOS = [
  {
    chave: 'scih',
    flag: 'scih',
    rotulo: 'Controle de Antimicrobianos',
    publico: 'Equipe do SCIH',
    descricao: 'Pareceres, grade de monitoramento e indicadores de infecção relacionada à assistência.',
    aprovadoPor: 'coordenação do SCIH',
    destino: '/atb/admin/grid',
    vinculo: true,
    dominio: true,
    justifica: false,
  },
  {
    chave: 'pront',
    flag: 'pront',
    rotulo: 'Prontuário',
    publico: 'Equipe do consultório',
    descricao: 'Pacientes, consultas e emissão de documentos.',
    aprovadoPor: 'Dr. Leandro',
    destino: '/pront',
    vinculo: false,
    dominio: true,
    justifica: false,
  },
  {
    chave: 'gestao',
    flag: 'gestao',
    rotulo: 'Painel de Governança',
    publico: 'Membros do Comitê de Gestão Estratégica e Governança',
    descricao: 'Indicadores assistenciais e operacionais da instituição, por competência.',
    aprovadoPor: 'coordenação do comitê',
    destino: '/gov',
    vinculo: true,
    dominio: true,
    // Diferente dos demais: o painel expõe mortalidade por unidade e reinternação
    // ajustada. Quem pede precisa declarar o vínculo com o comitê, e fica registrado.
    justifica: true,
    justificaRotulo: 'Vínculo com o comitê',
    justificaDica: 'Ex.: membro titular indicado pela diretoria clínica em 12/2025.',
  },
];

export const CHAVES = MODULOS.map(m => m.chave);

export function moduloPorChave(k) {
  return MODULOS.find(m => m.chave === k) || null;
}
