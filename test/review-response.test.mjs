import assert from "node:assert/strict";
import { after, test } from "node:test";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

// Isolate diagnostics and mock all provider calls. No reviewed command executes.
const testHome = mkdtempSync(path.join(tmpdir(), "pi-auto-review-response-test-"));
mkdirSync(path.join(testHome, ".pi/agent/extensions"), { recursive: true });
const originalHome = process.env.HOME;
process.env.HOME = testHome;
let registerExtension;
try {
  ({ default: registerExtension } = await import("../src/pi-auto-review.ts"));
} finally {
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
}
after(() => rmSync(testHome, { recursive: true, force: true }));

const approval = JSON.stringify({ safe: true, risk: "low", reason: "Inspects fixture data." });

async function withReviewEnvironment(callback) {
  const values = { PI_AUTO_REVIEW_MODE: "llm", PI_AUTO_REVIEW_MODEL: undefined, PI_AUTO_REVIEW_STRICT: "0", PI_AUTO_REVIEW_SCRIPT_PREVIEW: "0" };
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

function createHarness({ response, responseFactory, hasUI = true, signal, modelAvailable = true }) {
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
    signal,
    ui: {
      notify(message, level) { notifications.push({ message, level }); },
      async confirm(title, message) {
        confirmations.push({ title, message });
        return false;
      },
    },
    model: modelAvailable ? model : undefined,
    modelRegistry: {
      getAvailable() { return modelAvailable ? [model] : []; },
      hasConfiguredAuth() { return true; },
      async complete() {
        completions += 1;
        return responseFactory ? await responseFactory(completions) : response;
      },
    },
  };
  return {
    ctx,
    events,
    notifications,
    confirmations,
    get completions() { return completions; },
    review(command = "fixture-tool inspect") {
      return handlers.get("tool_call")({ toolName: "bash", input: { command } }, ctx);
    },
  };
}

for (const detail of ["HTTP 429: review quota exceeded", "HTTP 401: authentication failed", "Connection timed out"]) {
  test(`hook preserves returned provider error: ${detail}`, async () => {
    await withReviewEnvironment(async () => {
      const harness = createHarness({ response: { stopReason: "error", errorMessage: detail, content: [] } });
      const result = await harness.review();
      assert.equal(result.block, true);
      assert.equal(harness.confirmations.length, 1);
      const message = harness.confirmations[0].message;
      assert.ok(message.includes(detail));
      assert.match(message, /LLM 请求失败.*test-provider\/test-model.*stopReason=error/);
      assert.doesNotMatch(message, /LLM 返回无法解析/);
      assert.deepEqual(harness.events.map(({ data }) => data.active), [true, false]);
    });
  });
}

test("hook explains returned errors without provider details", async () => {
  await withReviewEnvironment(async () => {
    const harness = createHarness({ response: { stopReason: "error", content: [] } });
    assert.equal((await harness.review()).block, true);
    assert.match(harness.confirmations[0].message, /provider 未提供错误详情/);
    assert.doesNotMatch(harness.confirmations[0].message, /LLM 返回无法解析/);
  });
});

test("hook never approves or caches valid-looking JSON from an error response", async () => {
  await withReviewEnvironment(async () => {
    const harness = createHarness({ response: { stopReason: "error", errorMessage: "Interrupted stream", content: [{ type: "text", text: approval }] } });
    assert.equal((await harness.review()).block, true);
    assert.equal((await harness.review()).block, true);
    assert.equal(harness.completions, 2);
    assert.equal(harness.confirmations.length, 2);
    assert.ok(!harness.notifications.some(({ message }) => message.startsWith("shell-review ✓")));
  });
});

test("hook preserves returned provider errors without UI", async () => {
  await withReviewEnvironment(async () => {
    const harness = createHarness({ response: { stopReason: "error", errorMessage: "HTTP 503: temporarily unavailable", content: [] }, hasUI: false });
    const result = await harness.review();
    assert.equal(result.block, true);
    assert.match(result.reason, /HTTP 503/);
    assert.match(result.reason, /LLM 请求失败/);
    assert.equal(harness.confirmations.length, 0);
  });
});

for (const stopReason of ["length", "toolUse", "deferred", "pending"]) {
  test(`hook does not accept a verdict from an unfinished ${stopReason} response`, async () => {
    await withReviewEnvironment(async () => {
      const harness = createHarness({ response: { stopReason, content: [{ type: "text", text: approval }] } });
      assert.equal((await harness.review()).block, true);
      assert.equal((await harness.review()).block, true);
      assert.equal(harness.completions, 2);
      assert.match(harness.confirmations[0].message, /LLM 审查未完成/);
      assert.ok(harness.confirmations[0].message.includes(`stopReason=${stopReason}`));
      assert.ok(!harness.notifications.some(({ message }) => message.startsWith("shell-review ✓")));
    });
  });
}

test("hook blocks an aborted response without asking, even with valid-looking JSON", async () => {
  await withReviewEnvironment(async () => {
    const harness = createHarness({ response: { stopReason: "aborted", content: [{ type: "text", text: approval }] } });
    const result = await harness.review();
    assert.equal(result.block, true);
    assert.match(result.reason, /LLM 审查已取消/);
    assert.equal(harness.confirmations.length, 0);
    assert.equal(harness.events.length, 0);
  });
});

test("hook ignores successful-looking output when the agent signal is aborted", async () => {
  await withReviewEnvironment(async () => {
    const controller = new AbortController();
    controller.abort();
    const harness = createHarness({ response: { stopReason: "stop", content: [{ type: "text", text: approval }] }, signal: controller.signal });
    const result = await harness.review();
    assert.equal(result.block, true);
    assert.match(result.reason, /LLM 审查已取消/);
    assert.equal(harness.confirmations.length, 0);
  });
});

test("hook does not open a confirmation for an abort exception", async () => {
  await withReviewEnvironment(async () => {
    const controller = new AbortController();
    const harness = createHarness({ signal: controller.signal, responseFactory: async () => {
      controller.abort();
      throw new Error("Request aborted");
    } });
    const result = await harness.review();
    assert.equal(result.block, true);
    assert.match(result.reason, /LLM 审查已取消/);
    assert.equal(harness.confirmations.length, 0);
  });
});

test("hook still reports thrown non-abort provider errors", async () => {
  await withReviewEnvironment(async () => {
    const harness = createHarness({ responseFactory: async () => { throw new Error("Provider socket failed"); } });
    assert.equal((await harness.review()).block, true);
    assert.match(harness.confirmations[0].message, /Provider socket failed/);
  });
});

test("hook reports the actual missing-model condition without UI", async () => {
  await withReviewEnvironment(async () => {
    const harness = createHarness({ modelAvailable: false, hasUI: false });
    const result = await harness.review();
    assert.equal(result.block, true);
    assert.match(result.reason, /无可用审核模型/);
    assert.equal(harness.completions, 0);
  });
});

test("failure details are isolated between concurrent review calls", async () => {
  await withReviewEnvironment(async () => {
    const resolvers = [];
    const harness = createHarness({ responseFactory: () => new Promise(resolve => { resolvers.push(resolve); }) });
    const first = harness.review("fixture-tool first");
    const second = harness.review("fixture-tool second");
    assert.equal(resolvers.length, 2);
    resolvers[1]({ stopReason: "error", errorMessage: "Second review failed", content: [] });
    assert.equal((await second).block, true);
    resolvers[0]({ stopReason: "error", errorMessage: "First review failed", content: [] });
    assert.equal((await first).block, true);
    const firstMessage = harness.confirmations.find(({ message }) => message.includes("fixture-tool first"))?.message;
    const secondMessage = harness.confirmations.find(({ message }) => message.includes("fixture-tool second"))?.message;
    assert.match(firstMessage, /First review failed/);
    assert.doesNotMatch(firstMessage, /Second review failed/);
    assert.match(secondMessage, /Second review failed/);
    assert.doesNotMatch(secondMessage, /First review failed/);
  });
});

test("a cached approval cannot bypass a cancelled review", async () => {
  await withReviewEnvironment(async () => {
    const controller = new AbortController();
    const harness = createHarness({ response: { stopReason: "stop", content: [{ type: "text", text: approval }] }, signal: controller.signal });
    assert.equal(await harness.review(), undefined);
    controller.abort();
    const result = await harness.review();
    assert.equal(result.block, true);
    assert.match(result.reason, /LLM 审查已取消/);
    assert.equal(harness.completions, 1);
    assert.equal(harness.confirmations.length, 0);
  });
});
