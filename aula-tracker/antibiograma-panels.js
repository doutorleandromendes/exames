// ============================================================
//  antibiograma-panels.js — Painéis de antibiograma por isolado
//  Rol reportável de ATBs para os principais isolados clínicos,
//  orientado por BrCAST/EUCAST (categorias S / I / R).
//
//  ⚠ CONTEÚDO CLÍNICO — revise e ajuste conforme a tabela vigente
//  do ano. As tabelas BrCAST/EUCAST são atualizadas anualmente.
//  Editar aqui e commitar; o emissor injeta estes dados na página.
//
//  Categorias (EUCAST):
//    S = Sensível
//    I = Sensível com exposição otimizada
//    R = Resistente
// ============================================================
export const ANTIBIOGRAMA = {
  legend: {
    S: 'Sensível',
    I: 'Sensível com exposição otimizada',
    R: 'Resistente',
  },
  standardNote: 'Interpretação conforme BrCAST/EUCAST. Categorias: S = Sensível · I = Sensível com exposição otimizada · R = Resistente.',
  organisms: [
    { nome: 'Escherichia coli', grupo: 'Enterobacterales', atbs: [
      'Ampicilina', 'Amoxicilina-clavulanato', 'Piperacilina-tazobactam',
      'Cefuroxima', 'Ceftriaxona', 'Ceftazidima', 'Cefepime',
      'Ertapenem', 'Meropenem', 'Ciprofloxacino', 'Sulfametoxazol-trimetoprima',
      'Gentamicina', 'Amicacina', 'Nitrofurantoína', 'Fosfomicina' ] },

    { nome: 'Klebsiella pneumoniae', grupo: 'Enterobacterales', atbs: [
      'Amoxicilina-clavulanato', 'Piperacilina-tazobactam',
      'Cefuroxima', 'Ceftriaxona', 'Ceftazidima', 'Cefepime',
      'Ertapenem', 'Meropenem', 'Ciprofloxacino', 'Sulfametoxazol-trimetoprima',
      'Gentamicina', 'Amicacina', 'Ceftazidima-avibactam' ] },

    { nome: 'Proteus mirabilis', grupo: 'Enterobacterales', atbs: [
      'Ampicilina', 'Amoxicilina-clavulanato', 'Piperacilina-tazobactam',
      'Cefuroxima', 'Ceftriaxona', 'Ceftazidima', 'Cefepime',
      'Ertapenem', 'Meropenem', 'Ciprofloxacino', 'Sulfametoxazol-trimetoprima',
      'Gentamicina', 'Amicacina' ] },

    { nome: 'Enterobacter cloacae', grupo: 'Enterobacterales', atbs: [
      'Piperacilina-tazobactam', 'Cefepime', 'Ertapenem', 'Meropenem',
      'Ciprofloxacino', 'Sulfametoxazol-trimetoprima', 'Gentamicina', 'Amicacina' ] },

    { nome: 'Enterobacterales (outros)', grupo: 'Enterobacterales', atbs: [
      'Amoxicilina-clavulanato', 'Piperacilina-tazobactam', 'Cefuroxima',
      'Ceftriaxona', 'Ceftazidima', 'Cefepime', 'Ertapenem', 'Meropenem',
      'Ciprofloxacino', 'Sulfametoxazol-trimetoprima', 'Gentamicina', 'Amicacina' ] },

    { nome: 'Pseudomonas aeruginosa', grupo: 'Não-fermentadores', atbs: [
      'Piperacilina-tazobactam', 'Ceftazidima', 'Cefepime',
      'Imipenem', 'Meropenem', 'Ciprofloxacino', 'Amicacina', 'Gentamicina',
      'Ceftazidima-avibactam', 'Ceftolozano-tazobactam' ] },

    { nome: 'Acinetobacter baumannii', grupo: 'Não-fermentadores', atbs: [
      'Ampicilina-sulbactam', 'Imipenem', 'Meropenem', 'Ciprofloxacino',
      'Amicacina', 'Gentamicina', 'Sulfametoxazol-trimetoprima', 'Polimixina B' ] },

    { nome: 'Staphylococcus aureus', grupo: 'Gram-positivos', atbs: [
      'Cefoxitina (triagem MRSA)', 'Penicilina', 'Oxacilina',
      'Clindamicina', 'Eritromicina', 'Sulfametoxazol-trimetoprima',
      'Ciprofloxacino', 'Gentamicina', 'Rifampicina', 'Doxiciclina',
      'Vancomicina', 'Teicoplanina', 'Linezolida', 'Daptomicina' ] },

    { nome: 'Staphylococcus coagulase-negativo', grupo: 'Gram-positivos', atbs: [
      'Cefoxitina (triagem)', 'Penicilina', 'Oxacilina',
      'Clindamicina', 'Eritromicina', 'Sulfametoxazol-trimetoprima',
      'Ciprofloxacino', 'Gentamicina', 'Rifampicina',
      'Vancomicina', 'Teicoplanina', 'Linezolida', 'Daptomicina' ] },

    { nome: 'Enterococcus faecalis', grupo: 'Gram-positivos', atbs: [
      'Ampicilina', 'Penicilina', 'Vancomicina', 'Teicoplanina',
      'Linezolida', 'Daptomicina', 'Gentamicina (alta carga)', 'Estreptomicina (alta carga)',
      'Nitrofurantoína', 'Fosfomicina', 'Ciprofloxacino' ] },

    { nome: 'Enterococcus faecium', grupo: 'Gram-positivos', atbs: [
      'Ampicilina', 'Vancomicina', 'Teicoplanina',
      'Linezolida', 'Daptomicina', 'Gentamicina (alta carga)', 'Estreptomicina (alta carga)' ] },

    { nome: 'Streptococcus pneumoniae', grupo: 'Estreptococos', atbs: [
      'Penicilina (triagem oxacilina)', 'Ceftriaxona', 'Eritromicina',
      'Clindamicina', 'Sulfametoxazol-trimetoprima', 'Levofloxacino',
      'Vancomicina', 'Tetraciclina' ] },

    { nome: 'Streptococcus agalactiae (GBS)', grupo: 'Estreptococos', atbs: [
      'Penicilina', 'Ampicilina', 'Ceftriaxona', 'Clindamicina',
      'Eritromicina', 'Vancomicina' ] },

    { nome: 'Streptococcus pyogenes', grupo: 'Estreptococos', atbs: [
      'Penicilina', 'Ampicilina', 'Ceftriaxona', 'Clindamicina',
      'Eritromicina', 'Vancomicina' ] },

    { nome: 'Haemophilus influenzae', grupo: 'Fastidiosos', atbs: [
      'Ampicilina', 'Amoxicilina-clavulanato', 'Cefuroxima', 'Ceftriaxona',
      'Levofloxacino', 'Sulfametoxazol-trimetoprima', 'Azitromicina' ] },
  ],
};
