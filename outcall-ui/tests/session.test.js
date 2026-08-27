const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

class FakeElement {
  constructor(tagName = "div") {
    this.tagName = tagName.toUpperCase();
    this.id = "";
    this.className = "";
    this.textContent = "";
    this.hidden = false;
    this.dataset = {};
    this.children = [];
  }

  append(...children) {
    this.children.push(...children);
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  replaceChildren(...children) {
    this.children = children;
  }
}

function dashboardHarness() {
  const elements = new Map();
  const bindReplacement = (element, id) => {
    element.id = id;
    element.replaceWith = (replacement) => {
      bindReplacement(replacement, id);
      elements.set(id, replacement);
    };
    return element;
  };
  for (const id of ["page-alert", "overall-status", "last-refresh"]) {
    const element = bindReplacement(new FakeElement(), id);
    elements.set(id, element);
  }

  const events = new Map();
  const fetchCalls = [];
  const intervals = [];
  const location = { hash: "", pathname: "/ui/", search: "" };
  const history = {
    replaceState(_state, _title, url) {
      const next = new URL(url, "http://127.0.0.1");
      location.pathname = next.pathname;
      location.search = next.search;
      location.hash = next.hash;
    },
  };
  const document = {
    addEventListener() {},
    createElement: (tagName) => new FakeElement(tagName),
    getElementById: (id) => elements.get(id) || null,
    querySelectorAll: () => [],
  };
  const window = {
    addEventListener: (name, callback) => events.set(name, callback),
    confirm: () => false,
    history,
    location,
    prompt: () => null,
    setInterval(callback, delay) {
      intervals.push({ callback, delay });
      return intervals.length;
    },
  };
  const fetch = (url, options) => {
    fetchCalls.push({ url, options });
    return new Promise(() => {});
  };

  const context = vm.createContext({
    Element: FakeElement,
    URL,
    URLSearchParams,
    document,
    fetch,
    history,
    window,
  });
  const script = fs.readFileSync(path.join(__dirname, "../assets/app.js"), "utf8");
  vm.runInContext(script, context, { filename: "app.js" });

  return { elements, events, fetchCalls, intervals, location };
}

test("a token fragment added after initial load activates one dashboard session", () => {
  const harness = dashboardHarness();

  assert.equal(harness.elements.get("overall-status").textContent, "Session required");
  assert.equal(harness.fetchCalls.length, 0);
  assert.equal(harness.intervals.length, 0);

  harness.location.hash = "#token=later-session-token";
  harness.events.get("hashchange")();

  assert.equal(harness.location.hash, "");
  assert.equal(harness.elements.get("overall-status").textContent, "Connecting");
  assert.equal(harness.elements.get("page-alert").hidden, true);
  assert.equal(harness.intervals.length, 1);
  assert.equal(harness.intervals[0].delay, 5000);
  assert.equal(harness.fetchCalls.length, 9);
  for (const call of harness.fetchCalls) {
    assert.equal(call.options.headers["X-Outcall-Token"], "later-session-token");
  }

  harness.location.hash = "#token=replacement-token";
  harness.events.get("hashchange")();

  assert.equal(harness.location.hash, "");
  assert.equal(harness.intervals.length, 1);
});
