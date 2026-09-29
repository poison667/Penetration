/**
 * Minimal, dependency-free PDF 1.4 writer.
 * Produces real PDF documents: A4 pages, Helvetica/Bold, wrapped text,
 * tables, colored severity bars, page footers with page numbers.
 */
const PAGE_W = 595.28, PAGE_H = 841.89;
const MARGIN = 48;

export class PdfBuilder {
  constructor({ title, footer }) {
    this.title = title;
    this.footer = footer || '';
    this.pages = [];       // array of content-stream strings
    this.current = [];
    this.y = PAGE_H - MARGIN;
    this.pageCount = 0;
    this.#newPage();
  }
  #newPage() {
    if (this.current.length) this.pages.push(this.current.join('\n'));
    this.current = [];
    this.pageCount++;
    this.y = PAGE_H - MARGIN;
  }
  get contentHeight() { return PAGE_H - 2 * MARGIN; }

  #esc(s) {
    return String(s ?? '').replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)')
      .replace(/[^\x20-\x7E]/g, (c) => ({ '—': '-', '–': '-', '…': '...', '‘': "'", '’': "'", '“': '"', '”': '"', '\u00a0': ' ' }[c] || '?'));
  }
  #text(x, y, text, { size = 10, bold = false, gray = 0 } = {}) {
    this.current.push(`BT /${bold ? 'F2' : 'F1'} ${size} Tf ${gray} ${gray} ${gray} rg 1 0 0 1 ${x.toFixed(2)} ${y.toFixed(2)} Tm (${this.#esc(text)}) Tj ET`);
  }
  #rect(x, y, w, h, r, g, b) {
    this.current.push(`${r} ${g} ${b} rg ${x.toFixed(2)} ${y.toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)} re f`);
  }

  ensureSpace(h) { if (this.y - h < MARGIN + 24) this.#newPage(); }

  heading(text, { size = 16, space = 14 } = {}) {
    this.ensureSpace(size + space);
    this.y -= size + 6;
    this.#text(MARGIN, this.y, text, { size, bold: true });
    this.y -= space - 6;
  }
  subheading(text) { this.heading(text, { size: 12, space: 10 }); }

  paragraph(text, { size = 9.5, gray = 0.15, indent = 0 } = {}) {
    const lines = this.wrap(String(text ?? ''), size, PAGE_W - 2 * MARGIN - indent);
    for (const line of lines) {
      this.ensureSpace(size + 3);
      this.y -= size + 3;
      this.#text(MARGIN + indent, this.y, line, { size, gray });
    }
    this.y -= 4;
  }

  wrap(text, size, width) {
    // approximate char width: 0.5 * size for Helvetica
    const maxChars = Math.max(20, Math.floor(width / (size * 0.5)));
    const out = [];
    for (const rawLine of String(text).split('\n')) {
      let line = '';
      for (const word of rawLine.split(/\s+/)) {
        if ((line + ' ' + word).trim().length > maxChars) { out.push(line.trim()); line = word; }
        else line += ' ' + word;
      }
      if (line.trim()) out.push(line.trim());
    }
    return out.length ? out : [''];
  }

  keyValue(pairs, { size = 9.5 } = {}) {
    for (const [k, v] of pairs) {
      const lines = this.wrap(String(v ?? '—'), size, PAGE_W - 2 * MARGIN - 140);
      lines.forEach((line, i) => {
        this.ensureSpace(size + 3);
        this.y -= size + 3;
        if (i === 0) this.#text(MARGIN, this.y, String(k), { size, bold: true });
        this.#text(MARGIN + 140, this.y, line, { size, gray: 0.2 });
      });
    }
    this.y -= 4;
  }

  table(headers, rows, { widths = null, size = 8.5 } = {}) {
    const totalW = PAGE_W - 2 * MARGIN;
    const ws = widths || headers.map(() => totalW / headers.length);
    // header row
    this.ensureSpace(20);
    this.y -= 16;
    let x = MARGIN;
    this.#rect(MARGIN, this.y - 3, totalW, 16, 0.93, 0.94, 0.96);
    for (let i = 0; i < headers.length; i++) {
      this.#text(x + 4, this.y + 1, headers[i], { size, bold: true });
      x += ws[i];
    }
    this.y -= 4;
    for (const row of rows) {
      const cellLines = row.map((cell, i) => this.wrap(String(cell ?? ''), size, ws[i] - 8));
      const rowLines = Math.max(...cellLines.map((l) => l.length));
      const rowH = rowLines * (size + 2) + 6;
      if (this.y - rowH < MARGIN + 24) { this.#newPage(); this.y -= 16; let hx = MARGIN; this.#rect(MARGIN, this.y - 3, totalW, 16, 0.93, 0.94, 0.96); for (let i = 0; i < headers.length; i++) { this.#text(hx + 4, this.y + 1, headers[i], { size, bold: true }); hx += ws[i]; } this.y -= 4; }
      this.y -= rowH;
      let cx = MARGIN;
      for (let i = 0; i < row.length; i++) {
        cellLines[i].forEach((line, li) => {
          this.#text(cx + 4, this.y + rowH - 8 - li * (size + 2), line, { size, gray: 0.1 });
        });
        cx += ws[i];
      }
      this.current.push(`0.88 0.89 0.91 RG 0.5 w ${MARGIN} ${(this.y + rowH).toFixed(2)} m ${(MARGIN + totalW).toFixed(2)} ${(this.y + rowH).toFixed(2)} l S`);
    }
    this.y -= 8;
  }

  severityBadge(sev, x, y, size = 8.5) {
    const colors = { critical: [0.82, 0.2, 0.22], high: [0.97, 0.39, 0.05], medium: [0.76, 0.61, 0.0], low: [0.18, 0.49, 0.6], info: [0.38, 0.37, 0.36] };
    const [r, g, b] = colors[sev] || colors.info;
    this.#rect(x, y, 52, 12, r, g, b);
    this.#text(x + 4, y + 3, (sev || 'info').toUpperCase(), { size: 7, bold: true, gray: 1 });
  }

  build() {
    if (this.current.length) this.pages.push(this.current.join('\n'));
    // footers with page numbers
    this.pages = this.pages.map((content, i) => {
      const footer = this.footer ? `${this.#esc(this.footer)}   |   Page ${i + 1} of ${this.pages.length}` : `Page ${i + 1} of ${this.pages.length}`;
      return content + `\nBT /F1 8 Tf 0.45 0.45 0.45 rg 1 0 0 1 ${MARGIN} ${MARGIN - 18} Tm (${footer}) Tj ET`;
    });
    const objects = [];
    const pageObjIds = [];
    const contentObjIds = [];
    // 1: catalog, 2: pages, 3: F1, 4: F2, then page+content pairs
    const firstPage = 5;
    this.pages.forEach((_, i) => { pageObjIds.push(firstPage + i * 2); contentObjIds.push(firstPage + i * 2 + 1); });
    objects.push(`<< /Type /Catalog /Pages 2 0 R >>`);
    objects.push(`<< /Type /Pages /Kids [${pageObjIds.map((id) => `${id} 0 R`).join(' ')}] /Count ${this.pages.length} >>`);
    objects.push(`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>`);
    objects.push(`<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>`);
    this.pages.forEach((content, i) => {
      objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${contentObjIds[i]} 0 R >>`);
      objects.push(`<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}\nendstream`);
    });
    let out = '%PDF-1.4\n';
    const offsets = [];
    objects.forEach((obj, i) => {
      offsets.push(Buffer.byteLength(out));
      out += `${i + 1} 0 obj\n${obj}\nendobj\n`;
    });
    const xrefStart = Buffer.byteLength(out);
    out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
    for (const off of offsets) out += `${String(off).padStart(10, '0')} 00000 n \n`;
    out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF`;
    return Buffer.from(out, 'latin1');
  }
}
