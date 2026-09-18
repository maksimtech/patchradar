// Runs the real scripts of index.html (inline or <script src="/static/...">)
// against a minimal DOM and a scripted fetch(), then reports what the page
// did. Driven by tests/test_ui_errors.py and tests/test_csp.py:
//   node ui_harness.js <index.html> <scenario.json>
"use strict";
const fs = require("fs");
const vm = require("vm");

const [htmlPath, scenarioPath] = process.argv.slice(2);
const html = fs.readFileSync(htmlPath, "utf8");
const scenario = JSON.parse(fs.readFileSync(scenarioPath, "utf8"));
const path = require("path");
const staticDir = path.join(path.dirname(htmlPath), "..", "static");
const scripts = [...html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)].map(m => {
  const src = /\bsrc="\/static\/([^"]+)"/.exec(m[1]);
  return src ? fs.readFileSync(path.join(staticDir, src[1]), "utf8") : m[2];
});
const requests = [];
const clicked = [];

const errors = [];
const toasts = [];
process.on("unhandledRejection", e => errors.push(String(e && e.stack || e)));

function makeElement(tag, id, attrs = {}) {
  const el = {
    tagName: tag, id, children: [], style: {}, className: attrs.class || "", value: "",
    disabled: false, _text: "", _listeners: {}, attrs,
    dataset: Object.fromEntries(Object.entries(attrs)
      .filter(([k]) => k.startsWith("data-"))
      .map(([k, v]) => [k.slice(5).replace(/-(\w)/g, (_, c) => c.toUpperCase()), v])),
    classList: {
      _set: new Set((attrs.class || "").split(/\s+/).filter(Boolean)),
      add(c) { this._set.add(c); }, remove(c) { this._set.delete(c); },
      contains(c) { return this._set.has(c); },
    },
    appendChild(child) { this.children.push(child); return child; },
    addEventListener(type, fn) { (this._listeners[type] ||= []).push(fn); },
    click() { clicked.push(this.id || this.tagName); dispatch(this, "click"); },
    closest(sel) { return matches(this, sel) ? this : null; },
    set textContent(v) { this._text = String(v); this.children = []; },
    get textContent() {
      return this._text + this.children.map(c => c.textContent).join("");
    },
    set innerHTML(v) { this._text = String(v).replace(/<[^>]*>/g, ""); this.children = []; },
    get innerHTML() { return this._text; },
  };
  return el;
}

// Pre-populate the DOM with the elements the markup declares, so listeners
// bound to them by the script are really attached (and inline on*= handlers,
// which a CSP without 'unsafe-inline' refuses to run, are really not).
const byId = {};
const parsed = [];
for (const m of html.matchAll(/<(\w+)((?:\s+[\w-]+(?:="[^"]*")?)*)\s*\/?>/g)) {
  const attrs = {};
  for (const a of m[2].matchAll(/([\w-]+)(?:="([^"]*)")?/g)) attrs[a[1]] = a[2] ?? "";
  if (!attrs.id && !attrs.class && !Object.keys(attrs).some(k => k.startsWith("data-"))) continue;
  const el = makeElement(m[1], attrs.id, attrs);
  parsed.push(el);
  if (attrs.id) byId[attrs.id] = el;
}

function matches(el, sel) {
  if (sel.startsWith(".")) return el.classList.contains(sel.slice(1));
  if (sel.startsWith("#")) return el.id === sel.slice(1);
  const attr = /^\[([\w-]+)(?:="([^"]*)")?\]$/.exec(sel);
  if (attr) return attr[1] in el.attrs && (attr[2] === undefined || el.attrs[attr[1]] === attr[2]);
  return false;
}

const docListeners = {};
function dispatch(el, type, props = {}) {
  const event = { type, target: el, currentTarget: el, defaultPrevented: false,
                  preventDefault() { this.defaultPrevented = true; }, ...props };
  const pending = [];
  for (const fn of (el._listeners[type] || [])) pending.push(fn.call(el, event));
  for (const fn of (docListeners[type] || [])) pending.push(fn(event));
  return Promise.all(pending).then(() => event);
}

const document = {
  getElementById(id) { return byId[id] ||= makeElement("div", id); },
  createElement(tag) { return makeElement(tag); },
  querySelector(sel) { return parsed.find(el => matches(el, sel)) || null; },
  querySelectorAll(sel) { return parsed.filter(el => matches(el, sel)); },
  addEventListener(type, fn) { (docListeners[type] ||= []).push(fn); },
};

const storage = {};
const context = {
  document, console,
  setTimeout: () => 0,
  localStorage: {
    getItem: k => (k in storage ? storage[k] : null),
    setItem: (k, v) => { storage[k] = String(v); },
  },
  prompt: () => scenario.promptAnswer ?? null,
  Number, Math, Object, JSON, String, Promise, Error, Array,
  // fire("#id" | ".cls" | "[data-x=\"y\"]", "click", {key: "Enter"}) from actions
  fire: (sel, type, props) => {
    const el = document.querySelector(sel);
    if (!el) throw new Error(`no element matches ${sel}`);
    return dispatch(el, type, props);
  },
  async fetch(path, opts) {
    requests.push({ path, method: (opts && opts.method) || "GET" });
    const route = Object.keys(scenario.routes || {})
      .find(prefix => path.startsWith(prefix));
    const spec = route ? scenario.routes[route] : scenario.fallback;
    if (!spec || spec.networkError) throw new TypeError("Failed to fetch");
    return {
      ok: spec.status >= 200 && spec.status < 300,
      status: spec.status,
      statusText: spec.statusText || "",
      async json() {
        if (spec.rawBody !== undefined) return JSON.parse(spec.rawBody);
        return spec.json ?? {};
      },
    };
  },
};
vm.createContext(context);

// Capture toasts: the page writes the message into #toast.textContent.
const toastEl = document.getElementById("toast");
Object.defineProperty(toastEl, "textContent", {
  set(v) { toasts.push(String(v)); this._text = String(v); },
  get() { return this._text; },
});

(async () => {
  try {
    for (const src of scripts) vm.runInContext(src, context);
    // init() is fire-and-forget in the page; let it settle.
    await new Promise(r => setImmediate(r));
    await vm.runInContext("init()", context).catch(e => errors.push(String(e.stack || e)));
    for (const [k, v] of Object.entries(scenario.inputs || {})) document.getElementById(k).value = v;
    if (scenario.routesAfterInit) scenario.routes = scenario.routesAfterInit;
    for (const action of scenario.actions || []) {
      await vm.runInContext(`(async () => { ${action} })()`, context)
        .catch(e => errors.push(String(e.stack || e)));
    }
    await new Promise(r => setImmediate(r));
  } catch (e) {
    errors.push(String(e.stack || e));
  }
  const elements = {};
  for (const [id, el] of Object.entries(byId)) {
    elements[id] = { text: el.textContent, className: el.className,
                     active: el.classList.contains("active") };
  }
  const filters = Object.fromEntries(parsed.filter(el => "data-filter" in el.attrs)
    .map(el => [el.attrs["data-filter"], el.classList.contains("active")]));
  process.stdout.write(JSON.stringify({ errors, toasts, elements, requests, clicked, filters }));
})();
