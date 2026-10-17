// contrast.mjs - WCAG 2.1 contrast measurement that understands oklch().
//
// Why this exists: axe-core reads colours through getComputedStyle and parses
// the result itself. Chrome returns `oklch(0.205 0 0)` for a token declared in
// oklch(), and axe's parser only understands rgb()/hex, so it walks up to the
// parent and measures the WRONG background. That produced 18 bogus "serious
// color-contrast" findings - for example #fafafa text on what axe believed was
// #ffffff when the real background was oklch(0.205 0 0), a ratio of 16.9:1.
//
// The fix is to let the BROWSER resolve the colour (it implements oklch) and do
// the luminance arithmetic ourselves. A 1x1 canvas is the standard way to
// normalise any CSS colour to sRGB bytes.

/** Runs in the page. Returns a contrast audit of every text-bearing element. */
export function auditContrastInPage({ minRatio = 4.5, largeTextMinRatio = 3 } = {}) {
  // Normalise any CSS colour to [r,g,b,a] using the browser's own colour engine.
  const canvas = document.createElement("canvas");
  canvas.width = 1;
  canvas.height = 1;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  const cache = new Map();
  function toRgba(value) {
    if (!value) return null;
    const key = String(value).trim();
    if (cache.has(key)) return cache.get(key);
    ctx.clearRect(0, 0, 1, 1);
    // Assigning an unparseable colour leaves fillStyle unchanged, so seed it with
    // a sentinel and treat "unchanged" as unparseable.
    ctx.fillStyle = "#010203";
    ctx.fillStyle = key;
    let rgba = null;
    if (ctx.fillStyle !== "#010203") {
      ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data;
      rgba = [d[0], d[1], d[2], d[3] / 255];
    }
    cache.set(key, rgba);
    return rgba;
  }

  const channel = (c) => {
    const v = c / 255;
    return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
  };
  const luminance = ([r, g, b]) =>
    0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
  const over = (fg, bg) => {
    const a = fg[3];
    return [
      fg[0] * a + bg[0] * (1 - a),
      fg[1] * a + bg[1] * (1 - a),
      fg[2] * a + bg[2] * (1 - a),
      1,
    ];
  };
  const ratio = (a, b) => {
    const l1 = luminance(a);
    const l2 = luminance(b);
    const hi = Math.max(l1, l2);
    const lo = Math.min(l1, l2);
    return (hi + 0.05) / (lo + 0.05);
  };

  // Composite the effective background: walk ancestors, flattening translucent
  // layers over whatever is ultimately behind them.
  function effectiveBackground(el) {
    const layers = [];
    let node = el;
    while (node && node.nodeType === 1) {
      const bg = toRgba(getComputedStyle(node).backgroundColor);
      if (bg && bg[3] > 0) {
        layers.push(bg);
        if (bg[3] === 1) break;
      }
      node = node.parentElement;
    }
    layers.push([255, 255, 255, 1]);
    let base = layers[layers.length - 1];
    for (let i = layers.length - 2; i >= 0; i--) base = over(layers[i], base);
    return base;
  }

  const results = [];
  for (const el of document.querySelectorAll("body *")) {
    // Only elements that directly render text.
    const ownText = Array.from(el.childNodes)
      .filter((n) => n.nodeType === 3)
      .map((n) => n.textContent.trim())
      .join("");
    if (!ownText) continue;

    const style = getComputedStyle(el);
    if (style.visibility === "hidden" || style.display === "none") continue;
    if (Number(style.opacity) === 0) continue;
    const rect = el.getBoundingClientRect();
    if (rect.width < 1 || rect.height < 1) continue;

    const fg = toRgba(style.color);
    if (!fg) continue;
    const bg = effectiveBackground(el);
    const composited = fg[3] < 1 ? over(fg, bg) : fg;
    const measured = ratio(composited, bg);

    const size = parseFloat(style.fontSize) || 0;
    const weight = Number(style.fontWeight) || 400;
    const large = size >= 24 || (size >= 18.66 && weight >= 700);
    const required = large ? largeTextMinRatio : minRatio;

    results.push({
      selector:
        el.tagName.toLowerCase() +
        (el.className && typeof el.className === "string"
          ? "." + el.className.trim().split(/\s+/).join(".")
          : ""),
      text: ownText.slice(0, 60),
      fontSizePx: size,
      fontWeight: weight,
      isLargeText: large,
      foreground: `rgb(${composited[0].toFixed(0)}, ${composited[1].toFixed(0)}, ${composited[2].toFixed(0)})`,
      background: `rgb(${bg[0].toFixed(0)}, ${bg[1].toFixed(0)}, ${bg[2].toFixed(0)})`,
      ratio: Math.round(measured * 100) / 100,
      required,
      passes: measured >= required,
    });
  }
  return results;
}