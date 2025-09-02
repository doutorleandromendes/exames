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

Acesse: https://infectoaulas.com/login
`,
    html: `<p>Olá <b>${name}</b>,</p>
           <p>Seu cadastro no InfectoAulas foi realizado.</p>
           <p><b>Login:</b> ${login}<br><b>Senha:</b> ${password}</p>
           <p><a href="https://infectoaulas.com/login">Acessar o portal</a></p>`
  });
}
