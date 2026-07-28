// mailer.js (ESM, para combinar com seu app)
import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.MAIL_USER, pass: process.env.MAIL_PASS }
});

export async function sendWelcomeEmail({ to, name, login, password }) {
  await transporter.sendMail({
    from: `"InfectoAulas" <${process.env.MAIL_USER}>`,
    to,
    subject: 'Seus dados de acesso ao InfectoAulas',
    text: `Olá ${name},

Seu cadastro foi concluído.

Login: ${login}
Senha: ${password}

Acesse: https://infectoaulas2.onrender.com/login
`,
    html: `<p>Olá <b>${name}</b>,</p>
           <p>Seu cadastro no InfectoAulas foi realizado.</p>
           <p><b>Login:</b> ${login}<br><b>Senha:</b> ${password}</p>
           <p><a href="https://infectoaulas2.onrender.com">Acessar o portal</a></p>`
  });
}


// ──────────────────────────────────────────────────────────────────────────
// Acesso aprovado: envia o link de definição de senha.
//
// O link é uma credencial — vale uma vez e expira. Por isso ele não é registrado
// em log, e o texto diz claramente o prazo e a natureza de uso único.
//
// Esta função é chamada DEPOIS do commit da aprovação. Se o envio falhar, a
// aprovação continua válida e a tela mostra o link para envio manual: e-mail que
// não sai nunca pode desfazer nem esconder uma concessão de acesso já feita.
// ──────────────────────────────────────────────────────────────────────────

export function mailerConfigurado() {
  return Boolean(process.env.MAIL_USER && process.env.MAIL_PASS);
}

export async function sendAcessoAprovadoEmail({ to, nome, modulo, link, dias, aprovadoPor, remetente }) {
  if (!mailerConfigurado()) {
    const e = new Error('MAIL_USER/MAIL_PASS não configurados');
    e.code = 'SEM_CONFIG';
    throw e;
  }
  const de = remetente || process.env.MAIL_FROM_NAME || 'Sistemas — HUSF';
  const primeiroNome = String(nome || '').trim().split(/\s+/)[0] || '';

  await transporter.sendMail({
    from: `"${de}" <${process.env.MAIL_USER}>`,
    to,
    subject: `Acesso liberado: ${modulo}`,
    text:
`Olá${primeiroNome ? ' ' + primeiroNome : ''},

Seu acesso a ${modulo} foi aprovado${aprovadoPor ? ` pela ${aprovadoPor}` : ''}.

Para começar, defina sua senha neste link:
${link}

O link expira em ${dias} dias e funciona uma única vez. Depois de definir a senha,
use seu e-mail (${to}) para entrar.

Se você não solicitou este acesso, ignore esta mensagem e avise a coordenação.`,
    html:
`<div style="font-family:system-ui,Segoe UI,Arial,sans-serif;font-size:15px;line-height:1.6;color:#1f2937;max-width:560px">
  <p>Olá${primeiroNome ? ' <b>' + primeiroNome + '</b>' : ''},</p>
  <p>Seu acesso a <b>${modulo}</b> foi aprovado${aprovadoPor ? ` pela ${aprovadoPor}` : ''}.</p>
  <p style="margin:22px 0">
    <a href="${link}" style="background:#0c447c;color:#fff;text-decoration:none;
       padding:12px 20px;border-radius:8px;display:inline-block">Definir minha senha</a>
  </p>
  <p style="color:#6b7280;font-size:13px">
    O link expira em ${dias} dias e funciona uma única vez.
    Depois de definir a senha, use seu e-mail (${to}) para entrar.
  </p>
  <p style="color:#6b7280;font-size:13px">
    Se o botão não funcionar, copie este endereço:<br>
    <span style="word-break:break-all">${link}</span>
  </p>
  <p style="color:#9ca3af;font-size:12px;border-top:1px solid #e5e7eb;padding-top:12px;margin-top:22px">
    Se você não solicitou este acesso, ignore esta mensagem e avise a coordenação.
  </p>
</div>`
  });
}
