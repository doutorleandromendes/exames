/* ============================================================
   BASE DE EXAMES — Consultório Dr. Leandro Mendes
   Fonte única de dados do catálogo (site + admin).
   NÃO edite à mão em produção: use admin.html e exporte este arquivo.
   Campos: nome, grupo, metodo, amostra, desc, triagem, notifica, sm
   sm = {usar, interp, vant, rec, refs:[{t,u}]} ou null
   ============================================================ */
window.EXAMS = [
  {
    "nome": "Chikungunya — anticorpos IgG",
    "grupo": "Arboviroses e doenças febris",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgG contra o vírus Chikungunya. Esses anticorpos são produzidos depois da primeira semana após o início dos sintomas e indicam infecção passada, podendo ser detectados por toda a vida.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia para chikungunya na fase de convalescença. O IgG surge após a primeira semana de sintomas e persiste por anos.",
      "interp": "IgG reagente isolado indica infecção passada. Soroconversão ou aumento de título em amostras pareadas apoia infecção recente. Na fase aguda (<5 dias), prefira detecção direta (molecular); a partir da 2ª semana a sorologia é o método de escolha.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Chikungunya — anticorpos IgM",
    "grupo": "Arboviroses e doenças febris",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgM contra o vírus Chikungunya. Esses anticorpos são produzidos já após 3 a 4 dias depois do início dos sintomas e permanecem detectáveis por, no máximo, 3-4 meses. Eles são usados, portanto, para diagnosticar infecções atuais/recentes pelo vírus.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia para infecção recente/atual por chikungunya. O IgM torna-se detectável ~3–4 dias após o início dos sintomas e persiste por semanas a poucos meses.",
      "interp": "IgM reagente em quadro compatível indica infecção recente. Reação cruzada com outros alfavírus é possível. Diferencial importante com dengue e zika em áreas de cocirculação. Negativo muito precoce não exclui — associar detecção molecular.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Dengue — anticorpos IgG",
    "grupo": "Arboviroses e doenças febris",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgG contra o virus da Dengue. Esses anticorpos são produzidos tardiamente no curso na doença e, portanto, indicam infecção (ou vacinação) que ocorreu há mais de 15 dias.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia; o IgG anti-dengue aparece tardiamente e persiste por toda a vida. Ajuda a caracterizar infecção prévia e a distinguir infecção primária de secundária.",
      "interp": "IgG reagente isolado indica exposição prévia. Aumento de título em amostras pareadas apoia infecção recente. Não é o exame para diagnóstico agudo precoce (use NS1 e/ou IgM).",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        },
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Dengue — anticorpos IgM",
    "grupo": "Arboviroses e doenças febris",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgM contra o virus da Dengue. Esses anticorpos são produzidos precocemente no curso na doença e, portanto, indicam infecção (ou vacinação) que ocorreu há menos de 15 dias",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia para infecção recente por dengue; o IgM é detectável a partir de ~4–5 dias de sintomas e é o exame primário após o 7º dia.",
      "interp": "IgM reagente indica infecção recente/atual e pode persistir por ~3 meses. Reação cruzada com outros flavivírus (zika, febre amarela) ocorre. Idealmente combinar com NS1 na janela aguda. Negativo precoce não exclui.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        },
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Dengue — antígeno NS1",
    "grupo": "Arboviroses e doenças febris",
    "metodo": "Antígeno",
    "amostra": "Sangue",
    "desc": "Detecta a presença do antígeno NS1 do vírus da Dengue, que é um componente do próprio vírus e, portanto, não depende de resposta imunológica do hospedeiro.. A detecção do NS1 ocorre já nos primeiros dias após o início dos sintomas, sendo útil para o diagnóstico precoce da doença.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Solicite na fase aguda, idealmente entre o 1º e o 5º dia de febre. O antígeno NS1 é secretado pelas células infectadas logo no início da replicação viral, antes da soroconversão. Após o 7º dia a sensibilidade cai e a sorologia IgM passa a ser o exame de escolha.",
      "interp": "Um NS1 reagente confirma infecção aguda por dengue (especificidade em torno de 98–100%), sem necessidade de teste confirmatório. Resultado não reagente não exclui a doença — sobretudo fora da janela ideal ou em infecção secundária, na qual o IgG pré-existente reduz a sensibilidade (cerca de 67–77%, contra >94% na infecção primária). Nesses casos, combine NS1 com IgM/IgG.",
      "vant": "Entrega diagnóstico precoce e específico já nas primeiras 24 horas de febre, quando a sorologia ainda é negativa — antecipando a vigilância de sinais de alarme na fase crítica (4º–6º dia) e evitando exames e prescrições desnecessárias.",
      "rec": false,
      "refs": [
        {
          "t": "CDC. Clinical Testing Guidance for Dengue, 2025.",
          "u": "https://www.cdc.gov/dengue/hcp/diagnosis-testing/index.html"
        },
        {
          "t": "WHO. Laboratory testing for dengue virus: interim guidance, 2025.",
          "u": "https://szu.gov.cz/wp-content/uploads/2025/04/Laboratory-testing-for-dengue-virus-Interim-guidance-April-2025.pdf"
        }
      ]
    }
  },
  {
    "nome": "Dengue — antígeno NS1 + anticorpos (combo)",
    "grupo": "Arboviroses e doenças febris",
    "metodo": "Antígeno",
    "amostra": "Sangue",
    "desc": "Exame que auxilia no diagnóstico definitivo da Dengue, procurando tanto o antígeno do vírus (que ocorre mais no início da infecção) quanto anticorpos (produzidos mais tardiamente).",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Teste combinado que detecta simultaneamente o antígeno NS1 e os anticorpos IgM/IgG, ampliando a janela diagnóstica em uma única amostra.",
      "interp": "Aumenta a chance de captar tanto a fase aguda inicial (NS1+) quanto a mais tardia (IgM+). Interprete cada componente como no exame isolado: NS1+/IgM− sugere fase muito inicial; NS1−/IgM+ sugere fase mais tardia.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        },
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Febre amarela — anticorpos IgG",
    "grupo": "Arboviroses e doenças febris",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgG contra o vírus da Febre Amarela. Esses anticorpos são produzidos tanto em infecções passadas/resolvidas quanto nas pessoas que receberam vacina. Sua positividade de forma isolada indica que o indivíduo está imune contra o vírus.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia; o IgG surge tanto após infecção natural quanto após vacinação e indica imunidade.",
      "interp": "IgG reagente isolado indica imunidade (vacinal ou pós-infecção), não infecção aguda. Há reação cruzada com outros flavivírus. Para suspeita de doença aguda, use IgM e/ou detecção viral.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        },
        {
          "t": "CDC Yellow Book: Health Information for International Travel.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Febre amarela — anticorpos IgM",
    "grupo": "Arboviroses e doenças febris",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgM contra o vírus da Febre Amarela. Esses anticorpos são produzidos precocemente (em até duas semanas depois do início dos sintomas na infecção e em até uma semana após a vacinação). Em pessoas com suspeita clínica de Febre Amarela, eles podem ser usados para confirmar o diagnóstico da doença.",
    "triagem": false,
    "notifica": true,
    "sm": {
      "usar": "Sorologia para suspeita de febre amarela aguda; o IgM é detectável em ~1–2 semanas após o início dos sintomas (e ~1 semana após vacinação recente).",
      "interp": "IgM reagente em quadro compatível apoia o diagnóstico, exigindo confirmação (epidemiologia, exclusão de vacinação recente e de reação cruzada com flavivírus). Doença de notificação compulsória.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "West Nile — anticorpos IgG",
    "grupo": "Arboviroses e doenças febris",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgG contra o vírus West Nile. Esses anticorpos surgem tardiamente durante a infecção e indicam contato prévio com o vírus, geralmente há mais de 15 dias.",
    "triagem": true,
    "notifica": false,
    "sm": {
      "usar": "Sorologia; o IgG anti-West Nile indica contato prévio com o vírus.",
      "interp": "IgG reagente isolado indica exposição passada. A reação cruzada entre flavivírus (dengue, zika, febre amarela) é intensa — confirmar por neutralização (PRNT) quando disponível.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "West Nile — anticorpos IgM",
    "grupo": "Arboviroses e doenças febris",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgM contra o vírus West Nile. Esses anticorpos são produzidos depois da 3 a 8 dias após o início dos sintomas e deixam de ser detectáveis, em geral, após 30 a 90 dias. Eles são usados para o diagnóstico de infecção recente/atual em pessoas com suspeita clínica da doença.",
    "triagem": true,
    "notifica": false,
    "sm": {
      "usar": "Sorologia para infecção recente; o IgM surge ~3–8 dias após os sintomas e decai em 30–90 dias.",
      "interp": "IgM reagente sugere infecção recente/atual; na doença neuroinvasiva, pesquisar IgM no líquor. A reação cruzada com flavivírus exige confirmação por neutralização.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Zika — anticorpos IgG",
    "grupo": "Arboviroses e doenças febris",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgG contra o vírus Zika. Esses anticorpos são produzidos tardiamente durante a infecção e indicam uma infecção passada, que ocorreu geralmente há mais de 15 dias.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia; o IgG é tardio e indica infecção passada.",
      "interp": "IgG reagente isolado indica exposição prévia. A ampla reação cruzada com dengue e outros flavivírus limita a especificidade — interpretar com a epidemiologia; confirmação por neutralização em contextos críticos (ex.: gestação).",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        },
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Zika — anticorpos IgM",
    "grupo": "Arboviroses e doenças febris",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgM contra o vírus Zika. Esses anticorpos são produzidos precocemente, geralmente nos primeiros dias após o início dos sintomas, indicando infecção recente/atual pelo vírus.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia para infecção recente por zika; o IgM aparece nos primeiros dias.",
      "interp": "IgM reagente sugere infecção recente. A reação cruzada com flavivírus é relevante, sobretudo em gestantes — a confirmação (PRNT/molecular) importa pelo risco de síndrome congênita. Na fase muito aguda, preferir detecção molecular.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        },
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Anaplasma — antígeno",
    "grupo": "Zoonoses, vetores e negligenciadas",
    "metodo": "Antígeno",
    "amostra": "Sangue",
    "desc": "Exame usado para auxiliar no diagnóstico de infecção pela bactéria Anaplasma phagocytophilum. Essa é uma infecção transmitida por carrapatos e que pode causar febre, cefaleia, dor no corpo, manchas na pele e alterações sanguíneas.",
    "triagem": true,
    "notifica": false,
    "sm": {
      "usar": "Apoio ao diagnóstico de anaplasmose (Anaplasma phagocytophilum), transmitida por carrapatos. Suspeitar em febre + citopenias + exposição a carrapato.",
      "interp": "Positividade apoia o diagnóstico em contexto compatível; a doença também é sugerida por mórulas em neutrófilos no esfregaço, sorologia pareada ou PCR. Negativo não exclui na fase inicial. O tratamento empírico com doxiciclina não deve aguardar o exame.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Babesia — antígeno",
    "grupo": "Zoonoses, vetores e negligenciadas",
    "metodo": "Antígeno",
    "amostra": "Sangue",
    "desc": "Exame usado para auxiliar no diagnóstico de infecção pela pelo parasita Babesia sp. Essa é uma infecção transmitida por carrapatos e que pode se parecer com a malária.",
    "triagem": true,
    "notifica": false,
    "sm": {
      "usar": "Apoio ao diagnóstico de babesiose (Babesia spp.), protozoário intraeritrocitário transmitido por carrapatos; suspeitar em febre + anemia hemolítica + exposição.",
      "interp": "Positividade apoia o diagnóstico; o padrão é a visualização em esfregaço (formas intraeritrocitárias, tétrade em 'cruz de Malta') e a PCR, com estimativa da parasitemia. Coinfecção com Borrelia/Anaplasma é possível.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Doença de Chagas (T. cruzi) — anticorpos totais",
    "grupo": "Zoonoses, vetores e negligenciadas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Exame usado para diagnóstico de infecção aguda ou crônica pelo Trypanossoma cruzi (doença de Chagas).",
    "triagem": false,
    "notifica": true,
    "sm": {
      "usar": "Sorologia para infecção crônica por Trypanosoma cruzi — forma como a doença de Chagas é diagnosticada na fase crônica.",
      "interp": "O diagnóstico da fase crônica requer DOIS testes sorológicos de princípios diferentes reagentes; um único reagente deve ser confirmado. Na fase aguda, prefira a pesquisa direta do parasita. Positividade indica infecção — avaliar a forma clínica (indeterminada, cardíaca, digestiva).",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. Protocolo Clínico e Diretrizes Terapêuticas — Doença de Chagas.",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Ehrlichia — antígeno",
    "grupo": "Zoonoses, vetores e negligenciadas",
    "metodo": "Antígeno",
    "amostra": "Sangue",
    "desc": "Exame usado para auxiliar no diagnóstico de infecção pela bactéria Ehrlichia chaffeensis. Essa é uma infecção transmitida por carrapatos e que pode causar febre, cefaleia, dor no corpo e alterações sanguíneas.",
    "triagem": true,
    "notifica": false,
    "sm": {
      "usar": "Apoio ao diagnóstico de erliquiose (Ehrlichia spp.), transmitida por carrapatos; febre + citopenias + transaminases elevadas + exposição.",
      "interp": "Positividade apoia o diagnóstico em contexto compatível; confirmação por mórulas em monócitos no esfregaço, sorologia pareada ou PCR. A doxiciclina empírica não deve aguardar o resultado.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Hanseníase — antígeno (anti-PGL-1)",
    "grupo": "Zoonoses, vetores e negligenciadas",
    "metodo": "Antígeno",
    "amostra": "Sangue",
    "desc": "Esse exame auxilia no diagnóstico de infecção pela bactéria causadora da lepra (hanseníase). Ele é especialmente útil na avaliação de pessoas quem entraram em contato com a doença e não tem sintomas.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Apoio laboratorial ao diagnóstico da hanseníase, que é essencialmente clínico (lesões de pele com alteração de sensibilidade, espessamento neural) e baciloscópico.",
      "interp": "Exame auxiliar; não substitui a avaliação clínica e a baciloscopia/histopatologia. A sorologia anti-PGL-1 correlaciona-se com a carga bacilar (formas multibacilares). Negativo não exclui formas paucibacilares.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. Diretrizes para vigilância, atenção e eliminação da Hanseníase.",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Leishmaniose visceral — antígeno (rK39)",
    "grupo": "Zoonoses, vetores e negligenciadas",
    "metodo": "Antígeno",
    "amostra": "Sangue",
    "desc": "Detecta a presença de antígenos do parasita Leishmania donovani. Essa parasita é causador de doenças disseminadas nos seres humanos como o Kalazar, transmitido pela picada do mosquito-palha. A positividade do exame confirma a infecção.",
    "triagem": false,
    "notifica": true,
    "sm": {
      "usar": "Apoio ao diagnóstico de leishmaniose visceral (calazar). Suspeitar em febre prolongada + esplenomegalia + citopenias + exposição em área endêmica.",
      "interp": "Testes de detecção (ex.: rK39) têm boa sensibilidade na LV; positividade em quadro compatível apoia fortemente o diagnóstico. Confirmação parasitológica pode ser necessária. A sorologia pode permanecer positiva após a cura — não serve para monitorar tratamento.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. Manual de Vigilância e Controle da Leishmaniose Visceral.",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Leptospirose — anticorpos IgG",
    "grupo": "Zoonoses, vetores e negligenciadas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgG contra a bactéria causadora da Leptospirose. Esses anticorpos indicam infecção passada/resolvida, podendo ser detectados por toda a vida. É importante salientar que várias outras bactérias semelhantes (presentes no ambiente) podem induzir produção de anticorpos semelhantes e, portanto, resultados positivos devem ser confirmados por outros métodos",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia; o IgG indica contato prévio com Leptospira.",
      "interp": "Isoladamente sugere exposição passada. Há reação cruzada com bactérias ambientais; positivos devem ser confirmados (MAT, o padrão-ouro sorológico). Para doença aguda, o par sorológico com soroconversão é mais informativo.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Leptospirose — anticorpos IgM",
    "grupo": "Zoonoses, vetores e negligenciadas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgM contra a bactéria causadora da Leptospirose. Esses anticorpos são produzidos já após 3 a 10 dias depois do início dos sintomas.. Eles são usados, portanto, para diagnosticar infecções atuais/recentes. Resultados negativos em pessoas com suspeita clínica da doença podem ter que ser repetidos duas semanas após para excluir o diagnóstico.",
    "triagem": false,
    "notifica": true,
    "sm": {
      "usar": "Sorologia para leptospirose aguda; o IgM surge ~3–10 dias após os sintomas.",
      "interp": "IgM reagente em quadro compatível (febre, mialgia em panturrilhas, exposição a água/enchente) apoia infecção recente. Negativo na primeira semana não exclui — repetir em ~2 semanas. Confirmação por MAT.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Doença de Lyme — anticorpos IgG",
    "grupo": "Zoonoses, vetores e negligenciadas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Exame usado como ferramenta auxiliar no diagnóstico de casos humanos suspeitos de doença de Lyme, causada pela bactéria Borrelia burgdorferi. Os anticorpos de classe IgG indicam, quando encontrado isoladamente, infecção passada/resolvida.",
    "triagem": true,
    "notifica": false,
    "sm": {
      "usar": "Sorologia para doença de Lyme (Borrelia burgdorferi) na fase tardia/disseminada. Na fase precoce com eritema migratório típico, o diagnóstico é clínico.",
      "interp": "Usar em algoritmo de duas etapas (triagem por imunoensaio → confirmação por Western blot ou segundo imunoensaio). IgG reagente confirmado indica infecção estabelecida. A sorologia pode persistir após tratamento e não monitora cura. Baixa probabilidade pré-teste gera falsos-positivos.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Doença de Lyme — anticorpos IgM",
    "grupo": "Zoonoses, vetores e negligenciadas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Exame usado como ferramenta auxiliar no diagnóstico de casos humanos suspeitos de doença de Lyme, causada pela bactéria Borrelia burgdorferi. Os anticorpos de classe IgM indicam, em pacientes com suspeita clínica da doença, infecção atual/recente.",
    "triagem": true,
    "notifica": false,
    "sm": {
      "usar": "Sorologia para Lyme precoce; o IgM aparece na fase inicial.",
      "interp": "Em algoritmo de duas etapas. O IgM isolado após 4–6 semanas de doença tem baixo valor (alto risco de falso-positivo) e não deve ser usado sozinho em doença de longa duração. Interpretar com exposição e quadro clínico.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Malária — antígeno de P. falciparum",
    "grupo": "Zoonoses, vetores e negligenciadas",
    "metodo": "Antígeno",
    "amostra": "Sangue",
    "desc": "Detecta a presença de antígenos do parasita Plasmodium falciparum. Essa parasita é um dos causadores de formas graves de malária em algumas regiões do Brasil e, principalmente, na África e Ásia. A identificação correta da espécie do parasita causador de quadros de malária é essencial para o tratamento correto, principalmente nos casos graves",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Teste rápido de antígeno (HRP-2) para malária por P. falciparum, a espécie associada a doença grave. Suspeitar em febre + viagem/residência em área endêmica.",
      "interp": "Positividade confirma P. falciparum; sempre associar à gota espessa/esfregaço para espécie e parasitemia (guiam gravidade e tratamento). O HRP-2 pode permanecer positivo por dias a semanas após o tratamento. Negativo não exclui — repetir e fazer microscopia.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. Guia de Tratamento da Malária no Brasil.",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Malária — antígeno de P. vivax",
    "grupo": "Zoonoses, vetores e negligenciadas",
    "metodo": "Antígeno",
    "amostra": "Sangue",
    "desc": "Detecta a presença de antígenos do parasita Plasmodium vivax. Essa parasita é um dos causadores da Malária no Brasil e em outros países, principalmente da América Latina e Central. A identificação correta da espécie do parasita causador de quadros de malária é essencial para o tratamento correto dos pacientes.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Teste rápido (antígeno pLDH espécie-específico) para P. vivax, espécie predominante na Amazônia brasileira.",
      "interp": "Positividade apoia o diagnóstico; confirmar por microscopia (espécie/parasitemia). Considerar hipnozoítos: a cura radical com primaquina exige avaliação prévia de G6PD. Negativo não exclui.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. Guia de Tratamento da Malária no Brasil.",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Malária — antígeno pan-malárico",
    "grupo": "Zoonoses, vetores e negligenciadas",
    "metodo": "Antígeno",
    "amostra": "Sangue",
    "desc": "Detecta a presença de antígenos do parasita causador da malária (Plasmodium spp.). Esse exame permite detectar a presença de qualquer um dos cinco principais parasitas causadores de malária no mundo (sem diferenciar entre eles). A positividade no exame confirma que o paciente tem malária e indica outros exames para identificação correta da espécie causadora.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Teste rápido pan-malárico (detecta o gênero Plasmodium) para triagem de síndrome febril com risco epidemiológico.",
      "interp": "Positivo indica malária, sem definir a espécie — a microscopia (gota espessa, padrão-ouro no Brasil) é indispensável para espécie e parasitemia. Método de triagem, não substitui a microscopia.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. Guia de Tratamento da Malária no Brasil.",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Clamídia (C. trachomatis) — antígeno",
    "grupo": "Infecções sexualmente transmissíveis",
    "metodo": "Antígeno",
    "amostra": "Swab / amostra genital",
    "desc": "Exame usado para diagnóstico de infecção pela bactéria Chlamydia trachomatis. Nos seres humanos, essa é uma infecção de transmissão sexual que pode causar desde uretrite até infecções pélvicas profundas e infertilidade. Porém, a maioria dos casos não tem sintomas e, então é importante realizar o exame de forma preventiva, já que se trata de uma infecção que tem cura.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Detecção de Chlamydia trachomatis, IST frequentemente assintomática. Diagnóstico de uretrite/cervicite/DIP e rastreio.",
      "interp": "Positividade indica infecção ativa — tratável e curável; rastrear parceiros e coinfecções (gonorreia). Os testes de amplificação (NAAT) têm sensibilidade superior à do antígeno; um antígeno negativo em alta suspeita pode requerer NAAT.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. PCDT para Atenção Integral às Pessoas com IST.",
          "u": ""
        },
        {
          "t": "CDC. Sexually Transmitted Infections Treatment Guidelines.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Gonorreia (N. gonorrhoeae) — antígeno",
    "grupo": "Infecções sexualmente transmissíveis",
    "metodo": "Antígeno",
    "amostra": "Swab / amostra genital",
    "desc": "Exame usado para o diagnóstico de infecção pela bactéria Neisseria gonorrhea. Essa é uma infecção sexualmente transmissível que pode causar sintomas restritos ao trato genital (como corrimento uretral) ou, até, infecção generalizada. O tratamento oportuno e correto alivia os sintomas, previne complicações e impede a transmissão.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Detecção de Neisseria gonorrhoeae (uretrite, cervicite, infecção disseminada; pode ser assintomática).",
      "interp": "Positividade indica infecção ativa; tratar conforme diretriz (atenção à resistência antimicrobiana) e rastrear parceiros/coinfecções. O NAAT é mais sensível; a cultura é útil para teste de sensibilidade.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. PCDT para Atenção Integral às Pessoas com IST.",
          "u": ""
        },
        {
          "t": "CDC. Sexually Transmitted Infections Treatment Guidelines.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "HIV — sorologia de 3ª geração",
    "grupo": "Infecções sexualmente transmissíveis",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Exame usado para o diagnóstico da infecção pelo HIV por meio da detecção de anticorpos totais circulantes. Esses anticorpos são produzidos após, no mínimo, 4 semanas da infecção e, portanto, a realização do exame deve respeitar esse período de janela. Em caso de suspeita de infecção recente, testes de quarta geração devem ser usados. Ele tem especificidade >99%, ou seja, tem menos de 0,1% de falsos positivos. Em caso de positividade, outro teste é utilizado na mesma amostra para confirmar o diagnóstico.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Triagem baseada apenas na detecção de anticorpos totais. Em suspeita de infecção recente ou síndrome retroviral aguda, prefira o teste de 4ª geração.",
      "interp": "Janela mais longa (aproximadamente 23–90 dias), pois depende exclusivamente da soroconversão — a detecção é mais tardia que a da 4ª geração. Reagente exige confirmação na mesma amostra.",
      "vant": "Alta especificidade para infecção estabelecida; útil como triagem quando a 4ª geração não está disponível, respeitando a janela mais ampla.",
      "rec": false,
      "refs": [
        {
          "t": "CDC. Laboratory Testing for the Diagnosis of HIV Infection: Updated Recommendations, 2014.",
          "u": "https://stacks.cdc.gov/view/cdc/23447/cdc_23447_DS1.pdf"
        }
      ]
    }
  },
  {
    "nome": "HIV — sorologia de 4ª geração (Ag/Ac)",
    "grupo": "Infecções sexualmente transmissíveis",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Exame usado para o diagnóstico da infecção pelo HIV por meio da detecção de anticorpos E ANTÍGENOS circulantes. A detecção de antígenos permite que o período de janela seja abreviado. Em caso de exposições recentes, espera-se que exames de quarta geração já se tornem positivos após 15 dias da infecção. Ele tem especificidade superior a 99%, ou seja, apresenta menos de 0,1% de falsos positivos.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Teste de triagem de escolha (recomendação do CDC desde 2014). Combina, em uma única amostra, anticorpos anti-HIV-1/2 e o antígeno p24, que se torna detectável antes da soroconversão.",
      "interp": "Janela típica de aproximadamente 18–45 dias: cerca de 95% dos casos são detectados em 4 semanas e ~99% em 6 semanas. Não cobre a fase de eclipse inicial. Resultado reagente exige exames complementares (diferenciação HIV-1/HIV-2 e, se p24 positivo com anticorpo negativo, RNA viral). Não reagente após 45 dias da exposição é conclusivo.",
      "vant": "Encurta a janela em relação ao teste de anticorpos isolado, permitindo diagnóstico mais precoce da infecção aguda — justamente o período de maior transmissibilidade — e início mais rápido do tratamento.",
      "rec": false,
      "refs": [
        {
          "t": "CDC. Laboratory Testing for the Diagnosis of HIV Infection: Updated Recommendations, 2014.",
          "u": "https://stacks.cdc.gov/view/cdc/23447/cdc_23447_DS1.pdf"
        },
        {
          "t": "NYSDOH AIDS Institute. HIV Testing — Clinical Guidelines.",
          "u": "https://www.hivguidelines.org/guideline/hiv-testing/"
        }
      ]
    }
  },
  {
    "nome": "Herpes simples 1 (HSV-1) — anticorpos IgG",
    "grupo": "Infecções sexualmente transmissíveis",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgG contra o vírus Herpes Simples do tipo 1. Esses anticorpos, quando positivos isoladamente, indicam infecção passada com imunidade atual, podendo ser detectados por toda a vida.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia tipo-específica para herpes simples tipo 1. Indica infecção prévia (oral e, cada vez mais, genital).",
      "interp": "IgG reagente indica infecção passada/latente; não informa o sítio nem se há lesão ativa. A soroprevalência é alta. Para lesão ativa, prefira detecção direta (PCR/cultura da lesão).",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        },
        {
          "t": "CDC. Sexually Transmitted Infections Treatment Guidelines.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Herpes simples 1 (HSV-1) — anticorpos IgM",
    "grupo": "Infecções sexualmente transmissíveis",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgM contra o vírus Herpes Simples do tipo 1. Em pessoas com suspeita clínica de doença causada pelo HSV1 (como úlceras orais, por exemplo) esses anticorpos podem indicar infecção aguda/recente e ajudar a confirmar o diagnóstico.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia IgM anti-HSV1.",
      "interp": "Uso limitado: pode ser negativo em recorrências, reage de forma cruzada entre HSV-1/2 e não distingue com segurança infecção primária de recorrente. Para doença ativa, a detecção direta na lesão é preferível. Interpretar com cautela.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        },
        {
          "t": "CDC. Sexually Transmitted Infections Treatment Guidelines.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Herpes simples 2 (HSV-2) — anticorpos IgG",
    "grupo": "Infecções sexualmente transmissíveis",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgG contra o vírus Herpes Simples do tipo 2 (herpes genital). Esses anticorpos, quando positivos isoladamente, indicam infecção passada com imunidade atual, podendo ser detectados por toda a vida.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia tipo-específica para HSV-2, principal causa de herpes genital recorrente.",
      "interp": "IgG-2 reagente indica infecção genital prévia/latente (mesmo sem história de lesões). Resultados fracos podem requerer confirmação pela chance de falso-positivo em baixa prevalência. Para lesão ativa, use PCR da lesão.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "CDC. Sexually Transmitted Infections Treatment Guidelines.",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Herpes simples 2 (HSV-2) — anticorpos IgM",
    "grupo": "Infecções sexualmente transmissíveis",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgM contra o vírus Herpes Simples do tipo 2 (herpes genital). Em pessoas com suspeita clínica de doença de transmissão sexual causada pelo HSV2 (como úlceras genitais, por exemplo) esses anticorpos podem indicar infecção aguda/recente e ajudar a confirmar o diagnóstica.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia IgM anti-HSV2.",
      "interp": "Uso limitado (reação cruzada, positividade em recorrências); não recomendável para definir infecção primária. Prefira detecção direta em lesão ativa e IgG tipo-específico para o status sorológico.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "CDC. Sexually Transmitted Infections Treatment Guidelines.",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Mpox — anticorpos IgG",
    "grupo": "Infecções sexualmente transmissíveis",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgG contra o vírus MPOX (previamente conhecido como Monkeypox). Esses anticorpos são produzidos tanto após infecção natural quanto após vacinação e permanecem positivos pela vida toda.",
    "triagem": true,
    "notifica": false,
    "sm": {
      "usar": "Sorologia; o IgG surge após infecção natural ou vacinação (orthopoxvírus) e persiste.",
      "interp": "IgG reagente indica exposição prévia/vacinação, não infecção aguda. Há reação cruzada entre orthopoxvírus (inclusive vacínia). Não é o exame para diagnóstico agudo (use PCR da lesão).",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        },
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Mpox — anticorpos IgM",
    "grupo": "Infecções sexualmente transmissíveis",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgM contra o vírus MPOX (previamente conhecido como Monkeypox). Esses anticorpos são produzidos tanto após infecção natural quanto após vacinação e seus níveis decaem após 30-60 dias. Eles são usados como ferramentas auxiliares no diagnóstico de infecções recentes/atuais.",
    "triagem": true,
    "notifica": false,
    "sm": {
      "usar": "Sorologia para exposição recente a orthopoxvírus/mpox.",
      "interp": "IgM sugere contato recente; a confirmação de caso agudo é molecular (PCR da lesão). Interpretar com a epidemiologia, considerando reação cruzada e status vacinal.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        },
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Mpox — antígeno",
    "grupo": "Infecções sexualmente transmissíveis",
    "metodo": "Antígeno",
    "amostra": "Sangue",
    "desc": "Exame usado como ferramenta auxiliar no diagnóstico de casos humanos de infecção pelo vírus MPOX (previamente conhecido como Monkeypox). Ele detecta fragmentos do vírus diretamente no material analisado. Em caso de positividade, é necessária a confirmação por métodos moleculares.",
    "triagem": true,
    "notifica": false,
    "sm": {
      "usar": "Detecção direta de antígeno de mpox como auxílio em caso suspeito (lesões cutâneas características + epidemiologia).",
      "interp": "Positividade apoia o diagnóstico, exigindo confirmação molecular (PCR), que é o padrão. Negativo não exclui — coletar amostra adequada da lesão. Notificação conforme a vigilância.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        },
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Sífilis — anticorpos treponêmicos totais",
    "grupo": "Infecções sexualmente transmissíveis",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Exame usado para o diagnóstico de Sífilis. Os anticorpos totais treponêmicos (ou seja, aqueles que são dirigidos especificamente contra a bactéria causados da Sífilis) são produzidos entre 3 e 6 semanas após a infecção e permanecem positivos para toda a vida (mesmo após a cura). Eles são usados para a investigação de casos suspeitos de sífilis e, caso sejam positivos, tornam necessários outros exames para diferenciar infecções ativas/atuais de infecções resolvidas.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Teste treponêmico empregado como triagem no algoritmo reverso. Detecta anticorpos específicos contra T. pallidum, que surgem em 3–6 semanas e persistem por toda a vida, mesmo após tratamento adequado.",
      "interp": "Reagente indica sífilis atual OU pregressa/tratada — não distingue as duas. Deve ser reflexado com teste não-treponêmico quantitativo (VDRL/RPR): ambos reagentes → estadiar e tratar; discordância (treponêmico+ / VDRL−) → um segundo treponêmico (TP-PA) atua como desempate. O algoritmo reverso aumenta a detecção em sífilis primária inicial e latente tardia, quando o VDRL pode ser não reagente.",
      "vant": "Automatizável e de alto rendimento, capta casos que o rastreio não-treponêmico isolado perderia, sem abrir mão da confirmação sequencial.",
      "rec": false,
      "refs": [
        {
          "t": "CDC. Sexually Transmitted Infections Treatment Guidelines — Syphilis.",
          "u": "https://www.cdc.gov/std/treatment-guidelines/syphilis.htm"
        },
        {
          "t": "CDC. Laboratory Recommendations for Syphilis Testing, MMWR 2024.",
          "u": "https://www.cdc.gov/mmwr/volumes/73/rr/pdfs/rr7301a1-H.pdf"
        }
      ]
    }
  },
  {
    "nome": "Sífilis — VDRL (não-treponêmico)",
    "grupo": "Infecções sexualmente transmissíveis",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Exame usado para auxiliar no manejo da Sífilis. Os anticorpos não-treponêmicos detectados e quantificados pela reação de VDRL permitem estadiar a sífilis no diagnóstico, monitorar a eficácia do tratamento e detectar eventuais recidivas ou reinfecções.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Teste não-treponêmico quantitativo (titulação 1:2, 1:4, 1:8…). Complementa o teste treponêmico e é a ferramenta de acompanhamento da doença.",
      "interp": "A titulação guia estadiamento e resposta ao tratamento: queda de duas diluições (ex.: 1:16 → 1:4) indica sucesso terapêutico; aumento de duas diluições sugere reinfecção ou falha. Alguns pacientes permanecem serofast (título baixo persistente) apesar de curados. Falsos-positivos podem ocorrer em gestação, doenças autoimunes, HIV e outras infecções.",
      "vant": "É o único marcador que quantifica a atividade da doença, permitindo monitoramento objetivo da resposta ao tratamento e detecção de recidiva/reinfecção.",
      "rec": false,
      "refs": [
        {
          "t": "CDC. Laboratory Recommendations for Syphilis Testing, MMWR 2024.",
          "u": "https://www.cdc.gov/mmwr/volumes/73/rr/pdfs/rr7301a1-H.pdf"
        }
      ]
    }
  },
  {
    "nome": "Trichomonas vaginalis — antígeno",
    "grupo": "Infecções sexualmente transmissíveis",
    "metodo": "Antígeno",
    "amostra": "Swab / amostra genital",
    "desc": "Exame usado para o diagnóstico de infecção pelo parasita Trichomonas vaginalis. Essa é uma infecção sexualmente transmissível que pode causar infecções na vulva e vagina. O tratamento oportuno (incluindo das parcerias sexuais) alivia os sintomas, previne recidivas e impede a transmissão.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Detecção de Trichomonas vaginalis, IST curável (corrimento, mas frequentemente assintomática, sobretudo em homens).",
      "interp": "Positividade indica infecção ativa — tratar paciente e parceiros. Antígeno/NAAT são mais sensíveis que o exame a fresco. Rastrear coinfecções.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. PCDT para Atenção Integral às Pessoas com IST.",
          "u": ""
        },
        {
          "t": "CDC. Sexually Transmitted Infections Treatment Guidelines.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Hepatite A — anticorpos IgG",
    "grupo": "Hepatites virais",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos da classe IgG contra o vírus da hepatite A. Esses anticorpos são produzidos após a infecção natural pelo vírus ou por meio de vacinação. Quando positivos isoladamente, eles indicam infecção passada/resolvida ou vacinação e duram para a vida toda.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia; o anti-HAV IgG indica imunidade (infecção passada ou vacinação).",
      "interp": "IgG reagente isolado = imune, sem infecção aguda; não requer conduta se assintomático. Para hepatite A aguda, use o IgM.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. PCDT para Hepatites Virais.",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Hepatite A — anticorpos IgM",
    "grupo": "Hepatites virais",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos da classe IgM contra o vírus da hepatite A. Esses anticorpos são produzidos durante a infecção aguda (geralmente produzidos até uma semana antes do início dos sintomas) e decaem após cerca de 2 meses. Quando positivos em pessoas com suspeita clínica de hepatite A, eles indicam, portanto, infecção aguda/recente.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia para hepatite A aguda; o IgM é detectável desde ~1 semana antes dos sintomas e decai em ~2 meses.",
      "interp": "IgM reagente em quadro de hepatite aguda confirma infecção recente por HAV. Doença autolimitada na maioria; notificação.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. PCDT para Hepatites Virais.",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Hepatite B — anti-HBc (total)",
    "grupo": "Hepatites virais",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Exame usado para o diagnóstico hepatite B. O anticorpo contra o antígeno do core viral aparece logo no início da infecção e persiste pela vida toda, mesmo nas pessoas curadas da infecção.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "O anti-HBc (total) marca contato com o vírus; surge cedo e persiste por toda a vida, mesmo após a cura.",
      "interp": "Anti-HBc reagente indica exposição ao HBV (atual ou passada). No painel: HBsAg+/anti-HBc+ = infecção; anti-HBc+/anti-HBs+/HBsAg− = infecção passada resolvida; anti-HBc isolado exige investigação (janela, infecção oculta, falso-positivo). O anti-HBc IgM ajuda a caracterizar fase aguda.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. PCDT para Hepatites Virais.",
          "u": ""
        },
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Hepatite B — anti-HBs",
    "grupo": "Hepatites virais",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Exame usado para avaliar imunidade contra o vírus da hepatite B. O anticorpo contra o antígeno de superfície é amplamente neutralizante e pode surgir tanto à partir da vacinação quanto da infecção natural resolvida.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "O anti-HBs é anticorpo neutralizante; marca imunidade contra o HBV (vacinal ou pós-infecção resolvida).",
      "interp": "Anti-HBs reagente isolado (anti-HBc−) = imunidade vacinal; anti-HBs+ com anti-HBc+ = imunidade pós-infecção resolvida. Título ≥10 mUI/mL costuma indicar proteção. Não coexiste tipicamente com HBsAg (exceções raras).",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. PCDT para Hepatites Virais.",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Hepatite B — HBsAg (antígeno de superfície)",
    "grupo": "Hepatites virais",
    "metodo": "Antígeno",
    "amostra": "Sangue",
    "desc": "Exame usado para o diagnóstico hepatite B. O antígeno de superfície do vírus da hepatite B pode ser encontrado no sangue após 6-60 dias da infecção e permanece detectável enquanto o vírus estiver presente no organismo. Em se tratando de um antígeno, ou seja, uma parte do próprio vírus, ele não depende de resposta imunológica do hospedeiro. Além de ajudar em casos suspeitos de hepatite B aguda ou crônica, o exame também pode ser usado para monitorar o tratamento da doença.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Marcador central da hepatite B: sua presença indica infecção ativa (aguda ou crônica). Detectável ~6–60 dias após a exposição.",
      "interp": "HBsAg reagente = infecção presente. Persistência por >6 meses define cronicidade. Interpretar sempre no painel (com anti-HBc, anti-HBs, HBeAg) e estadiar com carga viral (HBV-DNA). Notificação.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. PCDT para Hepatites Virais.",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Hepatite B — HBeAg",
    "grupo": "Hepatites virais",
    "metodo": "Antígeno",
    "amostra": "Sangue",
    "desc": "Exame usado para o diagnóstico hepatite B. O antígeno E do vírus da hepatite B geralmente se associa com altos níveis de replicação viral e é usado tanto no diagnóstico quanto no monitoramento da infecção crônica.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "O HBeAg associa-se a alta replicação e infectividade; usado no diagnóstico e no monitoramento da hepatite B crônica.",
      "interp": "HBeAg+ costuma indicar replicação viral ativa e maior infectividade; sua perda com soroconversão para anti-HBe sugere menor replicação. Existem cepas pré-core (HBeAg− com replicação ativa) — sempre correlacionar com HBV-DNA e ALT.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. PCDT para Hepatites Virais.",
          "u": ""
        },
        {
          "t": "EASL/AASLD. Clinical Practice Guidelines on Hepatitis B.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Hepatite C — anticorpos totais",
    "grupo": "Hepatites virais",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Exame usado para o diagnóstico de hepatite C. Os anticorpos totais contra o vírus da hepatite C são produzidos depois de 2-3 meses da infecção e permanecem detectáveis por toda a vida (mesmo após a cura da infecção, por exemplo). Por causa disso, em caso de positividade, é necessária a realização de exames de biologia molecular que buscam o RNA do vírus para diferenciar casos de infecção crônica/atual de casos de infecção passada/resolvida.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Triagem de hepatite C. O anti-HCV surge ~2–3 meses após a infecção e persiste mesmo após a cura.",
      "interp": "Anti-HCV reagente indica contato com o vírus, mas NÃO distingue infecção ativa de resolvida — exige confirmação com HCV-RNA (carga viral). RNA detectável = infecção ativa, tratável e curável com antivirais de ação direta. Notificação.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. PCDT para Hepatites Virais.",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Hepatite E — anticorpos IgG",
    "grupo": "Hepatites virais",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos da classe IgG contra o vírus da hepatite E. Esses anticorpos são produzidos precocemente na infecção e permanecem positivos por toda a vida.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia; o anti-HEV IgG indica infecção prévia; surge cedo e persiste.",
      "interp": "IgG reagente isolado indica exposição passada/imunidade. Para doença aguda, use o IgM.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Hepatite E — anticorpos IgM",
    "grupo": "Hepatites virais",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos da classe IgG contra o vírus da hepatite E. Esses anticorpos são produzidos precocemente na infecção e tornam-se negativos na fase de convalescença/cura. Eles auxiliam na confirmação do diagnóstico em paciente com suspeita clínica de hepatite E.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia para hepatite E aguda; o IgM aparece na fase aguda e negativa na convalescença.",
      "interp": "IgM reagente em quadro de hepatite aguda apoia HEV (relevante em gestantes e imunossuprimidos, e como diferencial de hepatite medicamentosa). Em imunossuprimidos, que podem não soroconverter, a confirmação é molecular.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Adenovírus — antígeno",
    "grupo": "Infecções respiratórias",
    "metodo": "Antígeno",
    "amostra": "Swab respiratório",
    "desc": "Exame usado para auxiliar no diagnóstico de infecções causadas pelos Adenovírus. Eles são uma grande família de vírus que podem causar várias doenças como conjuntivites, pneumonias, hepatites e infecções generalizadas.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Detecção rápida de adenovírus em quadro respiratório agudo (também conjuntivite e gastroenterite).",
      "interp": "Positividade apoia etiologia adenoviral em contexto compatível; os testes de antígeno têm sensibilidade variável (menor que a molecular) — negativo não exclui. Conduta geralmente de suporte.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        },
        {
          "t": "Manual of Clinical Microbiology (ASM Press).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Influenza A — antígeno",
    "grupo": "Infecções respiratórias",
    "metodo": "Antígeno",
    "amostra": "Swab respiratório",
    "desc": "Detecta a presença de antígenos do vírus Influenza A. Quanto positivo, ele permite confirmar a presença de infecção aguda pelo vírus Influenza A com alta especificidade.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Teste rápido de antígeno para influenza A em síndrome gripal — orienta antiviral precoce (oseltamivir) em grupos de risco.",
      "interp": "Positivo apoia influenza A e favorece o início oportuno do antiviral. Sensibilidade moderada: negativo com alta suspeita não exclui (considerar molecular). Melhor rendimento nas primeiras 48–72 h.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. Protocolo de tratamento de Influenza.",
          "u": ""
        },
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Influenza B — antígeno",
    "grupo": "Infecções respiratórias",
    "metodo": "Antígeno",
    "amostra": "Swab respiratório",
    "desc": "Detecta a presença de antígenos do vírus Influenza B. Quanto positivo, ele permite confirmar a presença de infecção aguda pelo vírus Influenza A com alta especificidade.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Teste rápido para influenza B (mais comum em crianças) em síndrome gripal.",
      "interp": "Positivo apoia influenza B e orienta antiviral em pacientes de risco. Sensibilidade moderada; negativo não exclui. O timing precoce melhora o rendimento.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde. Protocolo de tratamento de Influenza.",
          "u": ""
        },
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Legionella — antígeno urinário",
    "grupo": "Infecções respiratórias",
    "metodo": "Antígeno",
    "amostra": "Urina",
    "desc": "Detecta a presença de antígenos da bactéria Legionalla pneumophila. Essa bactéria é uma das causas de pneumonias graves nos seres humanos e representa, na maior parte das vezes, um diagnóstico difícil de ser feito. A positividade do exame confirma que a bactéria é a causa da doença do paciente e permite, assim, com que o tratamento seja adequadamente direcionado contra ela.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Antígeno urinário para Legionella pneumophila sorogrupo 1, causa de pneumonia grave/atípica. Suspeitar em PAC grave, surto, viagem ou imunossupressão.",
      "interp": "Positivo apoia fortemente legionelose (alta especificidade); detecta principalmente o sorogrupo 1 — negativo não exclui outros sorogrupos/espécies. A antigenúria pode persistir por semanas. Combinar com clínica e imagem.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "IDSA/ATS. Diagnosis and Treatment of Community-Acquired Pneumonia.",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Mycoplasma pneumoniae — antígeno",
    "grupo": "Infecções respiratórias",
    "metodo": "Antígeno",
    "amostra": "Sangue",
    "desc": "Detecta a presença de antígenos da bactéria Mycoplasma pneumoniae. Essa bactéria é uma das causas de várias doenças nos seres humanos, incluindo pneumonias. A positividade do exame confirma que a Mycoplasma é a causa da doença do paciente e, assim, permite que o tratamento seja adequadamente direcionado contra ela.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Detecção para Mycoplasma pneumoniae, causa de pneumonia atípica (sobretudo crianças e adultos jovens).",
      "interp": "Positividade apoia etiologia por M. pneumoniae em contexto compatível; métodos moleculares e sorologia pareada complementam. Orienta a escolha de macrolídeo/tetraciclina/fluoroquinolona (sem cobertura por betalactâmicos).",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        },
        {
          "t": "Manual of Clinical Microbiology (ASM Press).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Painel respiratório — COVID-19 / Influenza A/B / VSR",
    "grupo": "Infecções respiratórias",
    "metodo": "Antígeno",
    "amostra": "Swab respiratório",
    "desc": "Exame que permite diagnosticar, ao mesmo tempo, infecções pelos vírus da COVID19, gripe/influenza A (incluindo H1N1 e H3N2), gripe/influenza B e vírus sincicial respiratório.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Painel de antígenos que diferencia, em um único teste, os quatro principais vírus respiratórios sazonais. Útil na triagem de síndrome gripal para conduta e isolamento.",
      "interp": "Identifica o agente predominante, orientando antiviral (influenza), isolamento (COVID-19) e conduta em VSR. O antígeno tem sensibilidade menor que a molecular; negativo em alta suspeita pode requerer PCR. Coinfecções são possíveis.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "SARS-CoV-2 (COVID-19) — antígeno",
    "grupo": "Infecções respiratórias",
    "metodo": "Antígeno",
    "amostra": "Swab respiratório",
    "desc": "Detecta a presença do antígeno de superfície do vírus causador da COVID. Sua positividade confirma o diagnóstico de infecção aguda e pode auxiliar, ainda, na determinação do risco de transmissibiliade da doença.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Teste rápido de antígeno para SARS-CoV-2 em sintomáticos ou triagem. Melhor rendimento na primeira semana e com alta carga viral.",
      "interp": "Positivo confirma COVID-19 em contexto compatível (alta especificidade). Negativo não exclui — sobretudo muito precoce ou fora do pico de carga viral; repetir ou usar PCR quando a suspeita é alta.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        },
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Streptococcus pneumoniae — antígeno urinário",
    "grupo": "Infecções respiratórias",
    "metodo": "Antígeno",
    "amostra": "Urina",
    "desc": "Detecta a presença de antígenos da bactéria Streptococcus pneumoniae. Essa bactéria causa diversas doenças potencialmente graves nos seres humanos como pneumonias, meningites e infecções generalizadas. A positividade do exame confirma que a bactéria é a causadora da doença do paciente e, assim, permite que o tratamento seja direcionado especificamente pra ela.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Antígeno urinário para pneumococo na pneumonia adquirida na comunidade do adulto — apoio etiológico rápido.",
      "interp": "Positivo apoia pneumonia pneumocócica e permite direcionar/desescalonar a terapia. Pode persistir após infecção recente e dar falso-positivo em colonizados/crianças; interpretar com a clínica. Negativo não exclui.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "IDSA/ATS. Diagnosis and Treatment of Community-Acquired Pneumonia.",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Streptococcus pyogenes (grupo A) — antígeno",
    "grupo": "Infecções respiratórias",
    "metodo": "Antígeno",
    "amostra": "Swab respiratório",
    "desc": "Detecta a presença de antígenos da bactéria Streptococcus pyogenes. Essa bactéria é a principal causadora de várias infecções nos seres humanos como as faringites bacterianas, a escarlatina e as erisipelas. A positividade no exame confirma que a bactéria é a causa da doença que o paciente está apresentando e, assim, permite direcionar o tratamento contra ela.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Teste rápido de antígeno para estreptococo do grupo A (faringite estreptocócica), orientando a antibioticoterapia e evitando uso desnecessário.",
      "interp": "Positivo em faringite compatível indica infecção por SGA e justifica tratamento (prevenção de febre reumática). Alta especificidade; a sensibilidade é boa, mas imperfeita — em crianças, um negativo com alta suspeita pode requerer cultura de orofaringe.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "IDSA. Clinical Practice Guideline for Group A Streptococcal Pharyngitis.",
          "u": ""
        },
        {
          "t": "American Academy of Pediatrics. Red Book: Report of the Committee on Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Metapneumovírus — antígeno",
    "grupo": "Infecções respiratórias",
    "metodo": "Antígeno",
    "amostra": "Swab respiratório",
    "desc": "Exame usado para o diagnóstico infecções respiratórias causadas pelo Metapneumovírus humano. As infecções humanas pelo vírus parainfluenza podem se manifestar de diferentes formas, desde uma síndrome gripal até quadros graves parecidos com a bronquiolite aguda. Quando positivo, ele confirma o diagnóstico em pessoas com suspeita clínica da doença.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Detecção de metapneumovírus humano, causa de IVAS, bronquiolite e pneumonia (crianças, idosos, imunossuprimidos).",
      "interp": "Positividade apoia a etiologia em quadro compatível; conduta de suporte. A sensibilidade do antígeno é inferior à molecular — negativo não exclui.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        },
        {
          "t": "Manual of Clinical Microbiology (ASM Press).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Parainfluenza — antígeno",
    "grupo": "Infecções respiratórias",
    "metodo": "Antígeno",
    "amostra": "Swab respiratório",
    "desc": "Exame usado para o diagnóstico infecções respiratórias causadas pelo vírus Parainfluenza. As infecções humanas pelo vírus parainfluenza podem se manifestar de diferentes formas, desde uma síndrome gripal até quadros graves parecidos com a coqueluche (síndrome coqueluchóide). Quando positivo, ele confirma o diagnóstico de infecção pelo vírus parainfluenza em pessoas com suspeita clínica da doença",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Detecção de parainfluenza (crupe, laringotraqueíte, bronquiolite, pneumonia).",
      "interp": "Positividade apoia a etiologia; conduta de suporte. O antígeno é menos sensível que a detecção molecular.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        },
        {
          "t": "Manual of Clinical Microbiology (ASM Press).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Vírus sincicial respiratório (VSR) — antígeno",
    "grupo": "Infecções respiratórias",
    "metodo": "Antígeno",
    "amostra": "Swab respiratório",
    "desc": "Exame usado para o diagnóstico infecções respiratórias causadas pelo VSR. As infecções humanas pelo vírus sincitial respiratório são as principais causadoras de bronquiolites e doença respiratória aguda em bebês e pessoas idosas. A positividade do exame confirma o diagnóstico em pessoas com suspeita clínica da infecção.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Teste rápido para VSR, principal causa de bronquiolite em lactentes e de doença respiratória em idosos.",
      "interp": "Positivo apoia VSR e orienta manejo e isolamento (coorte hospitalar). Boa sensibilidade em crianças (alta carga viral), menor em adultos — negativo em adulto não exclui.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "American Academy of Pediatrics. Red Book: Report of the Committee on Infectious Diseases.",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Citomegalovírus (CMV) — anticorpos IgG",
    "grupo": "Congênitas e sistêmicas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgG contra o Citomegalovírus. Esses anticorpos, quando positivos isoladamente, indicam infecção passada com imunidade atual, podendo ser detectados por toda a vida.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia; o IgG anti-CMV indica infecção prévia/latência (soroprevalência alta).",
      "interp": "IgG reagente = infecção passada, com risco de reativação em imunossupressão. A soroconversão indica infecção nova. Em gestante, IgG+ prévio reduz (não elimina) o risco de infecção congênita; a avidez de IgG ajuda a datar.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        },
        {
          "t": "American Academy of Pediatrics. Red Book: Report of the Committee on Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Citomegalovírus (CMV) — anticorpos IgM",
    "grupo": "Congênitas e sistêmicas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgM contra o Citomegalovírus. Em pessoas com suspeita clínica de doença causada pelo HSV1 (como febre prolongada com linfonodomegalias e/ou lesões oculares, por exemplo) esses anticorpos podem indicar infecção aguda/recente e ajudar a confirmar o diagnóstico.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia para infecção recente/reativação por CMV; auxílio em mononucleose-símile, doença em imunossuprimido e rastreio gestacional.",
      "interp": "IgM reagente sugere infecção recente, mas pode persistir por meses e ocorrer em reativação/reação cruzada — não é específico de primoinfecção. Combinar com IgG e avidez; em imunossuprimidos e doença invasiva, a carga viral (PCR) é mais útil.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        },
        {
          "t": "American Academy of Pediatrics. Red Book: Report of the Committee on Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Epstein-Barr (EBV) — anti-EBNA IgG",
    "grupo": "Congênitas e sistêmicas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Exame usado para o diagnóstico de Mononucleose Infecciosa causada pelo vírus de Epstein-Barr. Os anticorpos de classe IgG contra o antígeno nuclear (EBNA) são produzidos após vários meses da infecção e permanecem positivos para a vida toda. Sua positividade vitualmente exclui a possibilidade de infecção aguda pelo EBV e, portanto, ele ajuda a investigar possíveis falsos positivos de outros marcadores.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "O anti-EBNA IgG surge tardiamente (semanas a meses após a infecção); marcador de infecção passada por EBV.",
      "interp": "Anti-EBNA reagente indica infecção pregressa (não aguda). Sua ausência com VCA IgM/IgG reagentes sugere infecção recente. Compõe o perfil sorológico para datar a infecção.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        },
        {
          "t": "American Academy of Pediatrics. Red Book: Report of the Committee on Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Epstein-Barr (EBV) — anticorpos heterófilos",
    "grupo": "Congênitas e sistêmicas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Exame usado para o diagnóstico de Mononucleose Infecciosa. Os anticorpos heterófilos são imunoglobulinas com alvos hetero-específicos que indicam ativação disseminada de linfócitos B, eles são produzidos precocemente em casos de mononucleose infecciosa causada pelo EBV e seus níveis decaem rapidamente após 3-4 semanas.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Teste de anticorpos heterófilos (monoteste) para mononucleose infecciosa aguda por EBV.",
      "interp": "Positivo em quadro compatível (faringite, adenomegalia, linfocitose atípica) apoia mononucleose. Pode ser negativo no início e em crianças pequenas (menor sensibilidade) — nesses casos, usar sorologia específica (VCA/EBNA).",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        },
        {
          "t": "American Academy of Pediatrics. Red Book: Report of the Committee on Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Epstein-Barr (EBV) — anti-VCA IgG",
    "grupo": "Congênitas e sistêmicas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Exame usado para o diagnóstico de Mononucleose Infecciosa causada pelo vírus de Epstein-Barr. Os anticorpos de classe IgG contra o capsídeo víral (VCA) são produzidos após a primeira semana de doença e permanecem detectável por toda a vida.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "O anti-VCA IgG surge cedo e persiste por toda a vida.",
      "interp": "VCA IgG reagente indica infecção por EBV (recente ou passada). No perfil: VCA IgM+/VCA IgG+/EBNA− = infecção recente; VCA IgG+/EBNA+ = infecção passada.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        },
        {
          "t": "American Academy of Pediatrics. Red Book: Report of the Committee on Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Epstein-Barr (EBV) — anti-VCA IgM",
    "grupo": "Congênitas e sistêmicas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Exame usado para o diagnóstico de Mononucleose Infecciosa causada pelo vírus de Epstein-Barr. Os anticorpos de classe IgM contra o capsídeo víral (VCA) são produzidos após a primeira semana de doença e decaem após 3-6 meses da infecção indicando, portanto, infecção aguda/recente. Sua positividade ajuda a confirmar o diagnóstico de mononucleose em pessoas com suspeita clínica da doença.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "O anti-VCA IgM marca infecção aguda por EBV.",
      "interp": "VCA IgM reagente em quadro compatível apoia mononucleose aguda; desaparece em semanas a poucos meses. Combinar com VCA IgG e EBNA para datar. Reação cruzada (ex.: com CMV) pode ocorrer.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        },
        {
          "t": "American Academy of Pediatrics. Red Book: Report of the Committee on Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Rubéola — anticorpos IgG",
    "grupo": "Congênitas e sistêmicas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgG contra o vírus da Rubéola. Esses anticorpos, quando positivos isoladamente, indicam infecção passada com imunidade atual, podendo ser detectados por toda a vida.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia; o IgG indica imunidade (infecção prévia ou vacinal). Relevante na avaliação pré-concepcional/gestacional.",
      "interp": "IgG reagente = imune. A ausência em mulher em idade fértil indica suscetibilidade (orientar vacinação fora da gestação). Não indica infecção aguda.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        },
        {
          "t": "American Academy of Pediatrics. Red Book: Report of the Committee on Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Rubéola — anticorpos IgM",
    "grupo": "Congênitas e sistêmicas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgM contra o vírus da Rubéola. Em pessoas com suspeita clínica de infecção aguda/recente, esse exame pode ajudar a confirmar o diagnóstico.",
    "triagem": true,
    "notifica": false,
    "sm": {
      "usar": "Sorologia para rubéola aguda; relevante pelo risco de síndrome da rubéola congênita.",
      "interp": "IgM reagente sugere infecção recente — confirmar (avidez de IgG, soroconversão, molecular) pelo impacto gestacional e pela possibilidade de falsos-positivos/reação cruzada. Notificação compulsória.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        },
        {
          "t": "American Academy of Pediatrics. Red Book: Report of the Committee on Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Sarampo — anticorpos IgG",
    "grupo": "Congênitas e sistêmicas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgG contra o vírus do Sarampo. Esses anticorpos, quando positivos isoladamente, indicam infecção passada ou vacinação efetiva com imunidade atual, podendo ser detectados por toda a vida.",
    "triagem": true,
    "notifica": false,
    "sm": {
      "usar": "Sorologia; o IgG indica imunidade (infecção prévia ou vacinal).",
      "interp": "IgG reagente = imune. A suscetibilidade em não reagentes orienta vacinação. Em surto, avaliar o status imune de contatos.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        },
        {
          "t": "American Academy of Pediatrics. Red Book: Report of the Committee on Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Sarampo — anticorpos IgM",
    "grupo": "Congênitas e sistêmicas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgM contra o vírus da Rubéola. Em pessoas com suspeita clínica de infecção aguda/recente, esse exame pode ajudar a corroborar o diagnóstico, devendo ser confirmado por outras metodologias.",
    "triagem": true,
    "notifica": false,
    "sm": {
      "usar": "Sorologia para sarampo agudo (doença de notificação imediata).",
      "interp": "IgM reagente em quadro compatível (febre, exantema, tosse/coriza/conjuntivite) apoia sarampo agudo; confirmar conforme protocolo (molecular, epidemiologia). Coletar na fase adequada (o IgM pode ser negativo nos primeiros dias). Notificação imediata.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Toxoplasmose — anticorpos IgG",
    "grupo": "Congênitas e sistêmicas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgG contra o parasita causador da Toxoplasmose. Esses anticorpos, quando positivos isoladamente, indicam infecção passada e latente, podendo ser detectados por toda a vida.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia; o IgG indica infecção prévia/imunidade por Toxoplasma gondii.",
      "interp": "IgG reagente = infecção passada (com risco de reativação em imunossupressão grave). Em gestante, IgG+ prévio geralmente protege; a preocupação é a soroconversão durante a gestação. A avidez de IgG ajuda a datar (alta avidez no 1º trimestre afasta infecção recente).",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        },
        {
          "t": "American Academy of Pediatrics. Red Book: Report of the Committee on Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Toxoplasmose — anticorpos IgM",
    "grupo": "Congênitas e sistêmicas",
    "metodo": "Sorologia",
    "amostra": "Sangue",
    "desc": "Detecta anticorpos de classe IgM contra o parasita causador da Toxoplasmose. Em pessoas com suspeita clínica Toxoplasmose aguda esses anticorpos podem indicar infecção aguda/recente e ajudar a confirmar o diagnóstico.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Sorologia para infecção recente por toxoplasma; rastreio gestacional.",
      "interp": "IgM reagente sugere infecção recente, mas pode persistir por meses/anos e dar falso-positivo — NÃO confirma isoladamente infecção aguda. Sempre associar IgG e teste de avidez; em gestante, encaminhar para investigação pelo risco de toxoplasmose congênita.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Ministério da Saúde (Brasil). Guia de Vigilância em Saúde.",
          "u": ""
        },
        {
          "t": "American Academy of Pediatrics. Red Book: Report of the Committee on Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Calprotectina fecal",
    "grupo": "Gastrointestinais",
    "metodo": "Marcador",
    "amostra": "Fezes",
    "desc": "Exame que mostra a ocorrência de de inflamações no intestino, útil para avaliação de infecções que causam diarreia.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Marcador de inflamação intestinal; auxilia a distinguir doença inflamatória intestinal (DII) de distúrbios funcionais (ex.: síndrome do intestino irritável).",
      "interp": "Elevada sugere inflamação da mucosa (DII ativa, infecções, outras causas) e orienta investigação/colonoscopia; baixa favorece causa funcional e reduz a necessidade de endoscopia. Não é específica de DII — interpretar com o quadro. Útil também no monitoramento de atividade.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "ECCO. European Crohn's and Colitis Organisation — Guidelines.",
          "u": ""
        },
        {
          "t": "Feldman M. Sleisenger and Fordtran's Gastrointestinal and Liver Disease.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Clostridioides difficile — GDH",
    "grupo": "Gastrointestinais",
    "metodo": "Antígeno",
    "amostra": "Fezes",
    "desc": "Exame de triagem usado para auxiliar no diagnóstico de diarreias associadas ao uso de antibióticos causadas pela bactéria Clostridioides difficile.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Etapa de triagem do algoritmo em duas fases recomendado por IDSA/SHEA e ESCMID. A GDH é uma enzima produzida por todas as cepas de C. difficile — muito sensível, mas não distingue cepa toxigênica. Solicitar apenas em diarreia clinicamente significativa (≥3 evacuações amolecidas/24h) sem uso de laxantes.",
      "interp": "GDH detecta a presença do organismo; deve ser sempre combinada à pesquisa de toxina A/B. GDH+ / toxina+ = ICD provável; GDH+ / toxina− = arbitrar com teste molecular (colonização vs. infecção); GDH− = ICD improvável.",
      "vant": "Alta sensibilidade como porta de entrada do algoritmo: um resultado negativo praticamente exclui a doença, reduzindo testes e tratamentos desnecessários.",
      "rec": false,
      "refs": [
        {
          "t": "McDonald LC et al. Clinical Practice Guidelines for C. difficile — IDSA/SHEA, 2017.",
          "u": "https://pmc.ncbi.nlm.nih.gov/articles/PMC11614105/"
        },
        {
          "t": "Crobach MJT et al. ESCMID: diagnostic guidance for C. difficile infection, 2016.",
          "u": "https://pmc.ncbi.nlm.nih.gov/articles/PMC11614105/"
        }
      ]
    }
  },
  {
    "nome": "Clostridioides difficile — toxina A (confirmatório)",
    "grupo": "Gastrointestinais",
    "metodo": "Antígeno",
    "amostra": "Fezes",
    "desc": "Exame confirmatório usado para auxiliar no diagnóstico de diarreias associadas ao uso de antibióticos causadas pela bactéria Clostridioides difficile. A toxina A (também chamada de Enterotoxina) é responsável por diarreia secretória e menor risco de perfurações ou complicações sistêmicas",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Detecção isolada da toxina A como etapa confirmatória do algoritmo de ICD, evidenciando produção de toxina (doença ativa).",
      "interp": "Toxina detectável confirma ICD ativa em paciente com diarreia significativa. Como algumas cepas são A−/B+, a pesquisa conjunta de A e B amplia a sensibilidade. Deve compor o algoritmo (triagem por GDH/molecular + toxina), não uso isolado como triagem.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "McDonald LC et al. Clinical Practice Guidelines for C. difficile — IDSA/SHEA, 2017.",
          "u": ""
        },
        {
          "t": "Crobach MJT et al. ESCMID: diagnostic guidance for C. difficile infection, 2016.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Clostridioides difficile — toxina B (confirmatório)",
    "grupo": "Gastrointestinais",
    "metodo": "Antígeno",
    "amostra": "Fezes",
    "desc": "Exame confirmatório usado para auxiliar no diagnóstico de diarreias associadas ao uso de antibióticos causadas pela bactéria Clostridioides difficile. A toxina B (também chamada de Citotoxina) tem potência muito maior comparada à toxina A e se associa com maior risco de complicações locais, colite grave e manifestações sistêmicas",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Detecção isolada da toxina B como etapa confirmatória do algoritmo de ICD; a toxina B é o principal fator de virulência e está presente na maioria das cepas patogênicas.",
      "interp": "Toxina B detectável confirma ICD ativa em diarreia significativa. Compõe a etapa confirmatória após triagem sensível (GDH/molecular); a associação A+B amplia a sensibilidade. Não usar isoladamente como triagem.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "McDonald LC et al. Clinical Practice Guidelines for C. difficile — IDSA/SHEA, 2017.",
          "u": ""
        },
        {
          "t": "Crobach MJT et al. ESCMID: diagnostic guidance for C. difficile infection, 2016.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Clostridioides difficile — toxinas A/B",
    "grupo": "Gastrointestinais",
    "metodo": "Antígeno",
    "amostra": "Fezes",
    "desc": "Exame confirmatório usado para auxiliar no diagnóstico de diarreias associadas ao uso de antibióticos causadas pela bactéria Clostridioides difficile.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Etapa confirmatória do algoritmo em duas fases: após triagem sensível (GDH ou molecular), a detecção da toxina livre define doença ativa. Reservado a pacientes com diarreia clinicamente significativa.",
      "interp": "A toxina A/B confirma ICD ativa (não apenas colonização). GDH+ / toxina+ = ICD provável; GDH+ / toxina− = resultado discordante, arbitrar com teste molecular. O teste molecular isolado é muito sensível, mas não separa colonização de doença — daí a importância da toxina para evitar superdiagnóstico.",
      "vant": "A abordagem sequencial equilibra sensibilidade e especificidade, diferencia colonização de infecção e reduz tratamento desnecessário e falsos-positivos — impacto direto em stewardship e controle de infecção.",
      "rec": false,
      "refs": [
        {
          "t": "McDonald LC et al. Clinical Practice Guidelines for C. difficile — IDSA/SHEA, 2017.",
          "u": "https://pmc.ncbi.nlm.nih.gov/articles/PMC11614105/"
        },
        {
          "t": "Crobach MJT et al. ESCMID: diagnostic guidance for C. difficile infection, 2016.",
          "u": "https://pmc.ncbi.nlm.nih.gov/articles/PMC11614105/"
        }
      ]
    }
  },
  {
    "nome": "Cryptosporidium — antígeno",
    "grupo": "Gastrointestinais",
    "metodo": "Antígeno",
    "amostra": "Fezes",
    "desc": "Exame usado para auxiliar no diagnóstico de diarreias e infecções abdominais ou sistêmicas, especialmente em pessoas imunocomprometidas, com maior sensibilidade quando comparado ao exame microscópico.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Detecção de Cryptosporidium em diarreia (aquosa, por vezes prolongada), especialmente em imunossuprimidos, crianças e surtos hídricos.",
      "interp": "Positividade confirma criptosporidiose; a pesquisa dirigida por antígeno é mais sensível que a microscopia de rotina (o parasita não é bem visto no protoparasitológico comum). Em HIV avançado, pode causar doença grave/prolongada.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Giardia — antígeno",
    "grupo": "Gastrointestinais",
    "metodo": "Antígeno",
    "amostra": "Fezes",
    "desc": "Exame usado para auxiliar no diagnóstico de diarreias, com maior sensibilidade quando comparado ao exame protoparasitológico tradicional.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Detecção de Giardia em diarreia/má absorção, sobretudo em crianças e viajantes.",
      "interp": "Positividade confirma giardíase (tratável). O antígeno tem sensibilidade superior à microscopia isolada, dada a eliminação intermitente de cistos. Rastrear contatos em surtos.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Centers for Disease Control and Prevention — páginas por agravo (cdc.gov).",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Helicobacter pylori — antígeno fecal",
    "grupo": "Gastrointestinais",
    "metodo": "Antígeno",
    "amostra": "Fezes",
    "desc": "Exame que permite diagnosticar e avaliar a cura da infecção pelo Helicobacter pylori, bactéria que pode causar desde gastrite até úlceras no estômago e no duodeno.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Antígeno fecal para H. pylori — diagnóstico não invasivo de infecção ativa e controle pós-tratamento.",
      "interp": "Positivo indica infecção ativa (dispepsia, úlcera, prevenção de câncer gástrico). Suspender IBP (~2 semanas), antibióticos e bismuto antes do teste para evitar falso-negativo. Confirmar a erradicação ≥4 semanas após o tratamento.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Malfertheiner P et al. Management of Helicobacter pylori infection — Maastricht/Florence Consensus.",
          "u": ""
        },
        {
          "t": "Feldman M. Sleisenger and Fordtran's Gastrointestinal and Liver Disease.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Cryptococcus — antígeno (CrAg)",
    "grupo": "Micologia e microscopia",
    "metodo": "Antígeno",
    "amostra": "Sangue",
    "desc": "Detecta a presença de antígenos do fungo Cryptococcus neoformans. Esse fungo pode causar várias doenças potencialmente graves nos seres humanos, como meningites e infecções generalizadas. A positividade no exame permite confirmar o diagnóstico em pacientes com suspeita clínica da doença e, ainda, monitorar a eficácia do tratamento.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Detecção do antígeno capsular de Cryptococcus (CrAg) em soro/líquor — diagnóstico de criptococose/meningite criptocócica, sobretudo em HIV avançado e outros imunossuprimidos.",
      "interp": "CrAg tem alta sensibilidade e especificidade para criptococose; no soro, apoia o rastreio em HIV com CD4 baixo (permite terapia pré-emptiva). Positivo no líquor confirma meningite criptocócica. O título não é bom marcador de cura. Superior à tinta nanquim (menos sensível).",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        },
        {
          "t": "IDSA. Clinical Practice Guidelines for the Management of Cryptococcal Disease.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Microscopia — azul de lactofenol",
    "grupo": "Micologia e microscopia",
    "metodo": "Microscopia",
    "amostra": "Material a definir",
    "desc": "Exame usado para avaliação de fungos filamentosos. O exame permite identificação do agente e direcionamento adequado do tratamento.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Montagem com azul de algodão-lactofenol para identificação morfológica de fungos filamentosos em cultura.",
      "interp": "Cora e preserva estruturas fúngicas (hifas, conídios), permitindo identificar o gênero/espécie do bolor. Etapa de identificação micológica, não de detecção direta na amostra clínica.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Manual of Clinical Microbiology (ASM Press).",
          "u": ""
        },
        {
          "t": "Larone DH. Medically Important Fungi: A Guide to Identification.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Microscopia — Giemsa",
    "grupo": "Micologia e microscopia",
    "metodo": "Microscopia",
    "amostra": "Material a definir",
    "desc": "Exame usado para o diagnóstico de doenças causadas por fungos e parasitas. O exame microscópico do material corado pela coloração de Giemsa nos permite avaliar a presença de fungos intracelulares e de parasitas (como hematozoários, por exemplo).",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Coloração de Giemsa para hemoparasitas e estruturas celulares — malária (gota espessa), Babesia, Leishmania (amastigotas), Trypanosoma, Histoplasma intracelular.",
      "interp": "Permite identificar e, na malária, quantificar parasitas (parasitemia) e definir a espécie. Fundamental na investigação de febre com exposição endêmica. Requer examinador experiente.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Manual of Clinical Microbiology (ASM Press).",
          "u": ""
        },
        {
          "t": "World Health Organization — diretrizes por agravo (who.int).",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Microscopia — Gram",
    "grupo": "Micologia e microscopia",
    "metodo": "Microscopia",
    "amostra": "Material a definir",
    "desc": "Exame usado para o diagnóstico de doenças causadas por bactérias e alguns fungos. O exame microscópico do material corado pela coloração de gram nos permite avaliar a presença de bactérias e alguns fungos, sua morfologia e, ainda, estimar a quantidade de microrganismos causando a infecção.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Coloração de Gram para triagem rápida de bactérias (e leveduras) em amostras clínicas, orientando a terapia empírica inicial.",
      "interp": "Diferencia Gram-positivos (roxo) de Gram-negativos (rosa) e a morfologia (cocos/bacilos), além de avaliar a resposta inflamatória e a qualidade da amostra. Orienta, mas não substitui, a cultura. Interpretar conforme o sítio.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Manual of Clinical Microbiology (ASM Press).",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Microscopia — Grocott (GMS)",
    "grupo": "Micologia e microscopia",
    "metodo": "Microscopia",
    "amostra": "Material a definir",
    "desc": "Exame baseado em coloração pela prata usado para o diagnóstico de doenças causadas por fungos leveduriformes ou filamentosos. O exame microscópico do material corado pela coloração de Grocott-Gomori nos permite avaliar a presença de fungos intra ou extracelulares que podem ter visualização difícil em outros métodos.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Coloração de prata (Grocott-Gomori, GMS) para fungos em amostras — Pneumocystis jirovecii, hifas, leveduras.",
      "interp": "Realça estruturas fúngicas em preto sobre fundo claro; método sensível para Pneumocystis e fungos filamentosos/dimórficos em material respiratório ou tecidual. Confirmação por cultura/molecular conforme o caso.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Manual of Clinical Microbiology (ASM Press).",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Microscopia — Ziehl-Neelsen a frio (Kinyoun)",
    "grupo": "Micologia e microscopia",
    "metodo": "Microscopia",
    "amostra": "Material a definir",
    "desc": "Exame usado para o diagnóstico de doenças causadas por micobactérias e alguns fungos. O exame microscópico do material corado pela coloração de Kinyoun nos permite avaliar a presença de micobactérias (como aquelas que causam a tuberculose, por exemplo) ou de alguns parasitas (como os coccídeos).",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Coloração álcool-ácido resistente a frio (Kinyoun) para BAAR — micobactérias e também coccídios intestinais (Cryptosporidium, Cystoisospora, Cyclospora).",
      "interp": "A presença de estruturas álcool-ácido resistentes apoia micobactéria (baciloscopia) ou coccídio, conforme a amostra/contexto. A sensibilidade depende da carga; negativo não exclui. Complementar com cultura/molecular.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Manual of Clinical Microbiology (ASM Press).",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Microscopia — Leishman",
    "grupo": "Micologia e microscopia",
    "metodo": "Microscopia",
    "amostra": "Material a definir",
    "desc": "Exame usado para o diagnóstico de doenças causadas por bactérias e alguns parasitas. O exame microscópico corado pela coloração de Leishmann nos permite avaliar a presença de bactérias e alguns parasitas (como as Leishmanias) no material.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Coloração de Leishman (tipo Romanowsky) para esfregaços — hemoparasitas e morfologia celular/leucocitária.",
      "interp": "Semelhante ao Giemsa: identifica parasitas intracelulares e o padrão celular. Útil na investigação de hemoparasitoses e de alterações associadas a infecção.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Manual of Clinical Microbiology (ASM Press).",
          "u": ""
        },
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Microscopia — tinta nanquim",
    "grupo": "Micologia e microscopia",
    "metodo": "Microscopia",
    "amostra": "Material a definir",
    "desc": "Exame usado para o diagnóstico de infecções causadas por leveduras como o Cryptococcus. O exame microscópico do material corado pelo Nanquim nos permite avaliar a presença de fungos leveduriformes com grandes cápsulas polissacardídicas.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Coloração negativa com tinta nanquim (tinta da China) para pesquisa de Cryptococcus no líquor (evidencia a cápsula).",
      "interp": "A visualização de leveduras encapsuladas (halo) apoia meningite criptocócica. É menos sensível que o antígeno criptocócico (CrAg) — um nanquim negativo não exclui; preferir CrAg quando disponível.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        },
        {
          "t": "IDSA. Clinical Practice Guidelines for the Management of Cryptococcal Disease.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Microscopia — KOH",
    "grupo": "Micologia e microscopia",
    "metodo": "Microscopia",
    "amostra": "Material a definir",
    "desc": "Exame usado para o diagnóstico de doenças causadas fungos. O exame microscópico do material tratado pelo KOH nos permite avaliar a presença de fungos filamentosos (como aqueles que causam as micoses de pele, cabelos e unhas).",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Exame direto com hidróxido de potássio (KOH) para pesquisa de fungos em pele, unhas, cabelos e secreções.",
      "interp": "O KOH dissolve a queratina e revela hifas/leveduras. Positivo apoia micose (dermatofitose, candidíase); negativo não exclui. Rápido e de baixo custo, complementa a cultura.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Manual of Clinical Microbiology (ASM Press).",
          "u": ""
        },
        {
          "t": "Larone DH. Medically Important Fungi: A Guide to Identification.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Cistatina C",
    "grupo": "Marcadores clínicos",
    "metodo": "Marcador",
    "amostra": "Sangue",
    "desc": "Exame usado para monitorar de forma mais detalhada a função dos rins, em pessoas nas quais os exames rotineiros (como a creatinina, por exemplo) pode estar sofrer interferências por diferentes motivos (como peso, massa muscular, uso de medicamentos, etc).",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Marcador de função renal (filtração glomerular) alternativo/complementar à creatinina; menos influenciado por massa muscular, idade e sexo.",
      "interp": "Elevação indica queda da TFG; útil quando a creatinina é pouco confiável (idosos, extremos de massa muscular, cirróticos) e para estimar a TFG com maior acurácia em situações selecionadas. Relevante em infectologia para ajuste de fármacos nefrotóxicos.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "KDIGO. Clinical Practice Guideline for the Evaluation and Management of CKD.",
          "u": ""
        },
        {
          "t": "Harrison's Principles of Internal Medicine.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Dímero-D",
    "grupo": "Marcadores clínicos",
    "metodo": "Marcador",
    "amostra": "Sangue",
    "desc": "Exame usado para auxiliar no diagnóstico de quadros trombóticos, em conjunto com outros testes e o julgamento clínico do caso.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Produto de degradação da fibrina; tem alto valor preditivo negativo para excluir tromboembolismo venoso (TVP/TEP) em pacientes de baixa/moderada probabilidade.",
      "interp": "Normal, com baixa probabilidade clínica, torna o TEV improvável (bom exame de exclusão). Elevado é inespecífico — sobe em infecção/sepse, inflamação, gestação, idade avançada, câncer e pós-operatório — e exige imagem para confirmar. Usar sempre com escores de probabilidade.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "ISTH/ESC. Guidelines on the diagnosis of venous thromboembolism.",
          "u": ""
        },
        {
          "t": "Harrison's Principles of Internal Medicine.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Procalcitonina",
    "grupo": "Marcadores clínicos",
    "metodo": "Marcador",
    "amostra": "Sangue",
    "desc": "A procalcitonina é uma substância que nosso organismo produz em resposta a infecções causadas por bactérias (mas não em outras doenças e/ou infecções causadas por outros tipos de microrganismo). Desse modo, sua dosagem nos permite avaliar a probabilidade de que uma determinada doença esteja sendo causada por uma bactéria e, mais do que isso, estimar o tempo necessário de antibiótico para que ela seja tratada.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Biomarcador de apoio à decisão de iniciar ou suspender antibiótico em infecções respiratórias baixas e sepse. Eleva-se de forma mais específica na infecção bacteriana do que a proteína C reativa.",
      "interp": "Valores baixos favorecem etiologia não-bacteriana/viral e apoiam a não-prescrição ou a suspensão precoce; valores altos e sua cinética reforçam infecção bacteriana. Sempre interpretada junto ao quadro clínico — não substitui o julgamento médico (o estudo PROACT mostrou benefício limitado quando a aderência ao protocolo é baixa).",
      "vant": "Meta-análise de dados individuais com mais de 6.700 pacientes (Lancet Infect Dis, 2018) associou o manejo guiado por procalcitonina a menor exposição a antibióticos e redução de mortalidade em infecções respiratórias agudas — uma ferramenta objetiva de antibiotic stewardship.",
      "rec": false,
      "refs": [
        {
          "t": "Schuetz P et al. Effect of procalcitonin-guided antibiotic treatment on mortality in acute respiratory infections. Lancet Infect Dis 2018.",
          "u": "https://www.thelancet.com/article/S1473-3099(17)30592-3/fulltext"
        },
        {
          "t": "Huang DT et al. Procalcitonin-Guided Use of Antibiotics for Lower Respiratory Tract Infection (PROACT). NEJM 2018.",
          "u": "https://www.nejm.org/doi/full/10.1056/NEJMoa1802670"
        }
      ]
    }
  },
  {
    "nome": "Hemoglobina glicada (HbA1c)",
    "grupo": "Marcadores clínicos",
    "metodo": "Marcador",
    "amostra": "Sangue",
    "desc": "A Hemoglobina Glicada reflete a média de glicemia dos últimos 3 meses e auxilia, assim, no diagnóstico e acompanhamento de pré-diabetes e diabetes.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Reflete a glicemia média dos últimos ~2–3 meses; usada no diagnóstico e no monitoramento do diabetes.",
      "interp": "≥6,5% apoia o diagnóstico de diabetes (confirmar conforme diretriz); as metas de controle são individualizadas. Condições que alteram a hemácia (anemias, hemoglobinopatias, gravidez) podem falsear o resultado. Em infectologia, importa pelo impacto do controle glicêmico em infecções e cicatrização.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "American Diabetes Association. Standards of Care in Diabetes.",
          "u": ""
        },
        {
          "t": "Diretrizes da Sociedade Brasileira de Diabetes.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Proteína C reativa (PCR)",
    "grupo": "Marcadores clínicos",
    "metodo": "Marcador",
    "amostra": "Sangue",
    "desc": "A Proteína C Reativa é uma substância que nosso organismo produz em resposta a infecções e inflamações. Desse modo, sua dosagem nos permite diagnosticar essas condições e monitorar tratamentos.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Marcador de fase aguda; auxilia a avaliar a presença/intensidade de inflamação ou infecção e a acompanhar a resposta ao tratamento.",
      "interp": "Elevação indica inflamação (infecção bacteriana costuma elevar mais que a viral, com sobreposição), sem especificar a causa. A tendência seriada é mais útil que um valor isolado. É menos específica que a procalcitonina para infecção bacteriana. Interpretar com a clínica.",
      "vant": "",
      "rec": true,
      "refs": [
        {
          "t": "Bennett JE, Dolin R, Blaser MJ. Mandell, Douglas, and Bennett's Principles and Practice of Infectious Diseases.",
          "u": ""
        },
        {
          "t": "Harrison's Principles of Internal Medicine.",
          "u": ""
        }
      ]
    }
  },
  {
    "nome": "Investigação de mecanismos de resistência bacteriana",
    "grupo": "Resistência antimicrobiana",
    "metodo": "Fenotípico",
    "amostra": "Isolado bacteriano / cultura",
    "desc": "Detecção dirigida dos principais mecanismos de resistência em bactérias — carbapenemases (KPC, NDM, VIM, IMP, OXA-48), ESBL, AmpC e resistência à meticilina — por métodos fenotípicos e imunocromatográficos, a partir do isolado em cultura. Caracteriza o perfil de resistência para além do antibiograma convencional e orienta a escolha terapêutica e as medidas de controle.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Indicada diante de isolado com resistência incomum ou suspeita de produção de enzimas específicas — por exemplo, carbapenem-resistência em enterobactérias, Pseudomonas ou Acinetobacter. Caracteriza o mecanismo (e não apenas o fenótipo) a partir do isolado em cultura ou de hemocultura positiva.",
      "interp": "Os testes imunocromatográficos (lateral flow) identificam as cinco carbapenemases mais relevantes (KPC, NDM, VIM, IMP e OXA-48-like) em minutos, com sensibilidade e especificidade próximas de 97–99% frente à PCR. Métodos fenotípicos complementam a caracterização: sinergismo com EDTA sugere metalo-β-lactamase (NDM/VIM/IMP); com ácido borônico, sugere KPC; testes de inativação do carbapenêmico (mCIM) e colorimétricos (Carba-NP) confirmam a atividade enzimática. A distinção do mecanismo altera a terapia — inibidores como avibactam atuam sobre KPC e OXA-48, mas não sobre metalo-β-lactamases.",
      "vant": "Vai além do 'resistente ou sensível': ao nomear o mecanismo, direciona a escolha entre os novos β-lactâmicos e inibidores, evita esquemas ineficazes e informa precocemente o controle de infecção — num contexto em que cada hora de terapia inadequada tem impacto.",
      "rec": false,
      "refs": [
        {
          "t": "CLSI. M100 — Performance Standards for Antimicrobial Susceptibility Testing.",
          "u": ""
        },
        {
          "t": "BrCAST — Comitê Brasileiro de Teste de Sensibilidade aos Antimicrobianos.",
          "u": "https://brcast.org.br/"
        },
        {
          "t": "Lateral flow immunoassays para detecção de carbapenemases (KPC, NDM, IMP, VIM, OXA-48).",
          "u": "https://www.ncbi.nlm.nih.gov/pmc/articles/PMC12472453/"
        }
      ]
    }
  },
  {
    "nome": "Antibiograma especializado (MIC, sinergismo e MDR)",
    "grupo": "Resistência antimicrobiana",
    "metodo": "Antibiograma",
    "amostra": "Isolado bacteriano / cultura",
    "desc": "Antibiograma estendido com determinação da concentração inibitória mínima (MIC) por microdiluição, ensaios de sinergismo entre antimicrobianos e avaliação da atividade de drogas alternativas frente a isolados multirresistentes (MDR/XDR). Interpretação segundo CLSI, EUCAST e BrCAST, voltada à decisão terapêutica nos casos difíceis.",
    "triagem": false,
    "notifica": false,
    "sm": {
      "usar": "Indicado em infecções por germes multirresistentes (enterobactérias resistentes a carbapenêmicos, Pseudomonas e Acinetobacter XDR), em falha terapêutica ou quando o antibiograma de rotina não oferece opções claras. Fornece o valor numérico da MIC (não apenas S/I/R), testa combinações e avalia drogas de resgate — colistina, fosfomicina, tigeciclina e associações.",
      "interp": "A MIC quantifica a atividade da droga e orienta dose e via — relevante na 'sensibilidade dependente de dose' e em análises PK/PD. O sinergismo é avaliado pelo índice de FIC (sinergia quando ≤ 0,5), por métodos como time-kill (padrão de referência), checkerboard ou tiras de gradiente em razão fixa: combinações como colistina + meropenem ou meropenem + fosfomicina podem recuperar atividade contra isolados resistentes a cada droga isoladamente. A MIC de colistina exige microdiluição em caldo, pois métodos automatizados são pouco confiáveis.",
      "vant": "Transforma um 'resistente a tudo' em um plano terapêutico: define a melhor droga pela MIC, identifica combinações sinérgicas e ampara o uso racional dos antimicrobianos de última linha — decisão que idealmente envolve o infectologista.",
      "rec": false,
      "refs": [
        {
          "t": "CLSI. M100 — Performance Standards for Antimicrobial Susceptibility Testing.",
          "u": ""
        },
        {
          "t": "EUCAST. Breakpoint tables for interpretation of MICs and zone diameters.",
          "u": "https://www.eucast.org/clinical_breakpoints"
        },
        {
          "t": "BrCAST — Comitê Brasileiro de Teste de Sensibilidade aos Antimicrobianos.",
          "u": "https://brcast.org.br/"
        },
        {
          "t": "Synergy testing (índice de FIC) contra Gram-negativos multirresistentes.",
          "u": "https://www.ncbi.nlm.nih.gov/pmc/articles/PMC12291836/"
        }
      ]
    }
  }
];
