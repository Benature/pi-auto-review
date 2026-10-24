import assert from "node:assert/strict";
import { after, test } from "node:test";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

// Capture the extension's diagnostic path under a temporary HOME. Hook tests
// must not write real user logs, contact a model, or execute shell commands.
const testHome = mkdtempSync(path.join(tmpdir(), "pi-auto-review-test-"));
mkdirSync(path.join(testHome, ".pi/agent/extensions"), { recursive: true });
const originalHome = process.env.HOME;
process.env.HOME = testHome;
let registerExtension;
let parseReview;
try {
  ({ default: registerExtension, parseReview } = await import("../src/pi-auto-review.ts"));
} finally {
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
}
after(() => rmSync(testHome, { recursive: true, force: true }));

const reportedVerdict = {
  safe: true,
  risk: "low",
  reason: "Unknown tool 'ego-browser' runs a short script that appears to finalize a task; no obvious destructive, exfiltration, or privilege-escalation behavior, but semantics of finish({keep:[]}) are unverifiable.",
};

const validCases = [
  ["reported reason containing finish({keep:[]})", reportedVerdict],
  ["safe verdict", { safe: true, risk: "none", reason: "Read-only inspection." }],
  ["unsafe verdict", { safe: false, risk: "high", reason: "Deletes project files." }],
  ["nested braces inside reason", { safe: true, risk: "low", reason: 'Reads {"outer":{"items":[]}} and prints it.' }],
  ["unbalanced braces inside a JSON string", { safe: true, risk: "low", reason: "Prints } first, then {; both are literal text." }],
  ["escaped quotes, backslashes and braces", { safe: true, risk: "low", reason: 'Prints "quoted {text}" at C:\\tmp\\; no mutation.' }],
  ["Unicode and newlines", { safe: true, risk: "low", reason: "只读查询 {keep:[]}\n不修改文件。" }],
  ["different property order", { reason: "Inspects metadata.", risk: "none", safe: true }],
];

for (const [name, verdict] of validCases) {
  test(`parseReview accepts ${name}`, () => {
    assert.deepEqual(parseReview(JSON.stringify(verdict)), verdict);
  });
}

const plainJson = JSON.stringify(reportedVerdict);
for (const [name, response] of [
  ["surrounding whitespace", ` \n\t${plainJson}\r\n `],
  ["json fence", `\`\`\`json\n${plainJson}\n\`\`\``],
  ["plain fence", `\`\`\`\n${plainJson}\n\`\`\``],
  ["uppercase fence with CRLF", `\`\`\`JSON\r\n${plainJson}\r\n\`\`\``],
  ["pretty-printed fenced JSON", `\`\`\`json\n${JSON.stringify(reportedVerdict, null, 2)}\n\`\`\``],
]) {
  test(`parseReview accepts ${name}`, () => {
    assert.deepEqual(parseReview(response), reportedVerdict);
  });
}

test("parseReview returns only the validated verdict fields", () => {
  assert.deepEqual(parseReview(JSON.stringify({ ...reportedVerdict, extra: { debug: "ignored" } })), reportedVerdict);
});

const invalidCases = [
  ["empty output", ""],
  ["whitespace only", " \n\t"],
  ["null", "null"],
  ["array of verdicts", `[${plainJson}]`],
  ["JSON string containing a verdict", JSON.stringify(plainJson)],
  ["primitive", "true"],
  ["missing safe", JSON.stringify({ risk: "low", reason: "Unknown operation." })],
  ["string safe", JSON.stringify({ safe: "true", risk: "low", reason: "Unknown operation." })],
  ["numeric safe", JSON.stringify({ safe: 1, risk: "low", reason: "Unknown operation." })],
  ["missing risk", JSON.stringify({ safe: true, reason: "Unknown operation." })],
  ["invalid risk", JSON.stringify({ safe: true, risk: "medium", reason: "Unknown operation." })],
  ["non-string risk", JSON.stringify({ safe: true, risk: 0, reason: "Unknown operation." })],
  ["missing reason", JSON.stringify({ safe: true, risk: "low" })],
  ["blank reason", JSON.stringify({ safe: true, risk: "low", reason: " \n\t" })],
  ["non-string reason", JSON.stringify({ safe: true, risk: "low", reason: {} })],
  ["truncated object", plainJson.slice(0, -1)],
  ["truncated reason", '{"safe":true,"risk":"low","reason":"Unfinished {'],
  ["trailing comma", '{"safe":true,"risk":"low","reason":"Inspect.",}'],
  ["two verdicts", `${plainJson}\n${JSON.stringify({ safe: false, risk: "high", reason: "Unsafe." })}`],
  ["leading prose", `Candidate answer: ${plainJson}`],
  ["trailing prose", `${plainJson}\nBut I cannot confirm this is safe.`],
  ["embedded verdict in another object", JSON.stringify({ candidate: reportedVerdict })],
  ["unclosed fence", `\`\`\`json\n${plainJson}`],
  ["multiple fences", `\`\`\`json\n${plainJson}\n\`\`\`\n\`\`\`json\n${plainJson}\n\`\`\``],
];

for (const [name, response] of invalidCases) {
  test(`parseReview rejects ${name}`, () => {
    assert.equal(parseReview(response), undefined);
  });
}

async function withReviewEnvironment(overrides, callback) {
  const values = {
    PI_AUTO_REVIEW_MODE: "llm",
    PI_AUTO_REVIEW_MODEL: undefined,
    PI_AUTO_REVIEW_STRICT: "0",
    ...overrides,
  };
  const saved = Object.fromEntries(Object.keys(values).map((key) => [key, process.env[key]]));
  for (const [key, value] of Object.entries(values)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    return await callback();
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

function createHarness({ content, hasUI = true, confirm = async () => false }) {
  const handlers = new Map();
  const events = [];
  const notifications = [];
  const confirmations = [];
  let completions = 0;
  const model = { provider: "test-provider", id: "test-model", cost: { input: 1, output: 1 } };
  registerExtension({
    on(name, handler) { handlers.set(name, handler); },
    events: { emit(name, data) { events.push({ name, data }); } },
  });
  const ctx = {
    hasUI,
    ui: {
      notify(message, level) { notifications.push({ message, level }); },
      async confirm(title, message) {
        confirmations.push({ title, message });
        return await confirm();
      },
    },
    model,
    modelRegistry: {
      getAvailable() { return [model]; },
      hasConfiguredAuth() { return true; },
      async complete() {
        completions += 1;
        return { stopReason: "stop", content };
      },
    },
  };
  return {
    events,
    notifications,
    confirmations,
    get completions() { return completions; },
    review(command = "fixture-tool inspect") {
      return handlers.get("tool_call")({ toolName: "bash", input: { command } }, ctx);
    },
  };
}

test("hook accepts the reported valid JSON without a confirmation and reuses its verdict", async () => {
  await withReviewEnvironment({}, async () => {
    const harness = createHarness({ content: [
      { type: "thinking", thinking: "Candidate reasoning with finish({keep:[]}); not a JSON verdict." },
      { type: "text", text: plainJson },
    ] });
    assert.equal(await harness.review(), undefined);
    assert.equal(await harness.review(), undefined);
    assert.equal(harness.completions, 1);
    assert.equal(harness.confirmations.length, 0);
    assert.equal(harness.events.length, 0);
    assert.ok(harness.notifications.some(({ message }) => message.startsWith("shell-review ✓ low")));
  });
});

test("hook still confirms a valid unsafe verdict and restores herdr state on rejection", async () => {
  await withReviewEnvironment({}, async () => {
    const harness = createHarness({ content: [
      { type: "text", text: JSON.stringify({ safe: false, risk: "high", reason: "Might discard task state with finish({keep:[]})." }) },
    ] });
    const result = await harness.review();
    assert.equal(result.block, true);
    assert.match(result.reason, /User rejected after LLM warning/);
    assert.equal(harness.confirmations.length, 1);
    assert.deepEqual(harness.events.map(({ name, data }) => [name, data.active]), [
      ["herdr:blocked", true], ["herdr:blocked", false],
    ]);
  });
});

test("hook blocks an unsafe verdict in STRICT mode without asking", async () => {
  await withReviewEnvironment({ PI_AUTO_REVIEW_STRICT: "1" }, async () => {
    const harness = createHarness({ content: [
      { type: "text", text: JSON.stringify({ safe: false, risk: "high", reason: "Unsafe operation." }) },
    ] });
    const result = await harness.review();
    assert.equal(result.block, true);
    assert.match(result.reason, /LLM blocked/);
    assert.equal(harness.confirmations.length, 0);
  });
});

test("hook falls back to manual confirmation for invalid verdict fields", async () => {
  await withReviewEnvironment({}, async () => {
    const harness = createHarness({ content: [{ type: "text", text: '{"safe":true}' }] });
    const result = await harness.review();
    assert.equal(result.block, true);
    assert.equal(harness.confirmations.length, 1);
    assert.match(harness.confirmations[0].message, /LLM 返回无法解析/);
    assert.deepEqual(harness.events.map(({ data }) => data.active), [true, false]);
  });
});

test("hook blocks truncated output without UI", async () => {
  await withReviewEnvironment({}, async () => {
    const harness = createHarness({ content: [{ type: "text", text: plainJson.slice(0, -1) }], hasUI: false });
    const result = await harness.review();
    assert.equal(result.block, true);
    assert.match(result.reason, /LLM review unavailable/);
    assert.equal(harness.confirmations.length, 0);
  });
});

test("hook keeps the existing complete thinking-JSON fallback", async () => {
  await withReviewEnvironment({}, async () => {
    const harness = createHarness({ content: [{ type: "thinking", thinking: plainJson }] });
    assert.equal(await harness.review(), undefined);
    assert.equal(harness.confirmations.length, 0);
  });
});

test("hook clears herdr blocked state even when the confirmation throws", async () => {
  await withReviewEnvironment({}, async () => {
    const harness = createHarness({
      content: [{ type: "text", text: "invalid response" }],
      confirm: async () => { throw new Error("Dialog cancelled"); },
    });
    await assert.rejects(harness.review(), /Dialog cancelled/);
    assert.deepEqual(harness.events.map(({ data }) => data.active), [true, false]);
  });
});
