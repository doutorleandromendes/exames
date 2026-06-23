// pront-doc-pdf.js — renderiza um documento do gerador para PDF (lado servidor).
// Reaproveita a própria lógica do gerador: recebe o HTML do gerador (com o gancho
// window.__RENDER_FOR_PDF já injetado) + o estado S, re-renderiza headless e imprime.
// Mesmo padrão de puppeteer do lab-pdf.js.

let _browser = null;
async function getBrowser() {
  const puppeteer = (await import("puppeteer")).default;
  if (!_browser || !_browser.connected) {
    _browser = await puppeteer.launch({
      headless: true,
      executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || puppeteer.executablePath(),
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
    });
  }
  return _browser;
}

// htmlGerador: HTML do gerador com o gancho __RENDER_FOR_PDF; state: objeto S do cliente
export async function gerarDocumentoPDF(htmlGerador, state) {
  const browser = await getBrowser();
  const page = await browser.newPage();
  try {
    await page.setContent(htmlGerador, { waitUntil: "networkidle0" });
    // aplica o estado do cliente e re-renderiza com a lógica do próprio gerador
    await page.evaluate((s) => window.__RENDER_FOR_PDF(s), state);
    await page.waitForSelector("#pages .page", { timeout: 8000 });
    // honra o @page que o gerador define (size A4/A5, margin 0) + imprime o fundo (timbrado)
    const pdf = await page.pdf({ printBackground: true, preferCSSPageSize: true });
    return Buffer.from(pdf);
  } finally {
    await page.close().catch(() => {});
  }
}
