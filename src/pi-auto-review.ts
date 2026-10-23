/**
 * Shell Auto-Review Extension
 *
 * 在每条 bash 命令执行前做三级审查：
 *
 * 1. 危险正则（DENY_PATTERNS）→ 弹确认 / 拒绝
 * 2. 安全正则（SAFE_PATTERNS）→ 直接放行，不消耗 LLM
 * 3. 其余命令 → 用便宜的小模型做 LLM 审查，返回 JSON 判定
 *
 * 配置（环境变量）：
 *   PI_AUTO_REVIEW_MODE       off | regex | llm   （默认 llm）
 *   PI_AUTO_REVIEW_MODEL      provider/model，审查用模型（最高优先级）
 *   PI_AUTO_REVIEW_FALLBACK   逗号分隔的 provider/model 回落列表
 *                             （默认 anthropic/claude-haiku-4-5,google/gemini-2.5-flash,openai/gpt-4.1-mini）
 *   PI_AUTO_REVIEW_STRICT     1 = LLM 判定不安全时直接 block，0 = 弹确认（默认 0）
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { Api, Model } from "@earendil-works/pi-ai";

type AnyModel = Model<Api>;

/** 诊断日志：审查过程和错误写入文件，便于直接排查 */
import { appendFileSync } from "node:fs";
const DEBUG_LOG = `${process.env.HOME}/.pi/agent/extensions/pi-auto-review.log`;
function dbg(msg: string): void {
	try {
		appendFileSync(DEBUG_LOG, `[${new Date().toISOString()}] ${msg}\n`);
	} catch { /* ignore */ }
}

/** 本地生成 v7 风格 sessionId，避免运行时依赖 @earendil-works/pi-ai */
function newSessionId(): string {
	return "xxxxxxxx-xxxx-7xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
		const r = (Math.random() * 16) | 0;
		return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
	});
}

// ─── 1. 危险命令正则：命中即视为高风险 ─────────────────────────────
const DENY_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
	{ pattern: /\brm\s+(-[a-z]*[rf][a-z]*\s+)?(--recursive|--force)?.*(\/\s*$|\/\s|;|\*|~|\/Users\/)/i, reason: "删除操作可能波及大范围文件" },
	{ pattern: /\brm\s+(-[a-z]*rf[a-z]*|--recursive)/i, reason: "递归强制删除 (rm -rf)" },
	{ pattern: /\bsudo\b/i, reason: "提权操作 (sudo)" },
	{ pattern: /\b(chmod|chown)\b.*\b777\b/i, reason: "宽松权限修改 (777)" },
	{ pattern: /:\(\)\s*\{\s*:\|:\s*&\s*\}\s*;:/, reason: "fork bomb" },
	{ pattern: /\bmkfs\b|\bdd\s+.*\bof=\/dev\//i, reason: "磁盘格式化/覆写" },
	{ pattern: />\s*\/dev\/(sd[a-z]|disk|nvme)/, reason: "写块设备" },
	{ pattern: /\bshutdown\b|\breboot\b|\bhalt\b/i, reason: "系统关机/重启" },
	{ pattern: /\bgit\s+(reset\s+--hard|clean\s+-[a-z]*f|push\s+.*--force)/i, reason: "git 破坏性操作" },
	{ pattern: /\b(npm|pnpm|yarn|pip|brew)\s+.*\b(remove|uninstall)\b/i, reason: "包卸载" },
	{ pattern: /\b(kill|pkill|killall)\s+-?9/i, reason: "强制杀死进程 (SIGKILL)" },
	{ pattern: /\b(curl|wget)\b[^|;]*\|\s*(ba)?sh/i, reason: "管道执行远程脚本" },
	{ pattern: /\b(eval|exec)\b.*\$\(/, reason: "动态执行子命令输出" },
	{ pattern: /\b(export|set)\b.*KEY.*=/i, reason: "导出 API key 可能泄露" },
];

// ─── 2. 安全命令正则：整条命令若能被安全模式覆盖则放行 ─────────────
const SAFE_PREFIXES = [
	// 只读查看类
	"ls", "pwd", "cd", "echo", "printf", "cat", "head", "tail", "less", "more",
	"find", "which", "whereis", "type", "file", "stat", "tree",
	"grep", "rg", "ag", "ack", "fd", "awk", "sed -n", "sort", "uniq", "wc", "diff",
	"du", "df", "free", "uname", "date", "whoami", "hostname", "env", "printenv", "history",
	"ps", "top", "htop", "lsof", "jobs",
	// 版本控制只读
	"git status", "git log", "git diff", "git show", "git branch", "git blame",
	"git ls-files", "git rev-parse", "git remote -v", "git stash list", "git fetch",
	// 语言/工具只读
	"node -e", "node --version", "python --version", "python3 --version",
	"npm list", "npm ls", "npm info", "npm view", "pnpm list", "pip list", "pip show",
	"xcodebuild -list", "swift --version",
];

function isSafeByRegex(command: string): boolean {
	const trimmed = command.trim();
	// 多命令拼接一律不算安全
	if (/[;&|`]|>\s*[^>|]/.test(trimmed) && !/\|\s*(grep|head|tail|wc|sort|less)\b/.test(trimmed)) {
		return false;
	}
	return SAFE_PREFIXES.some(
		(prefix) => trimmed === prefix || trimmed.startsWith(prefix + " "),
	);
}

// ─── 3. LLM 审查 ──────────────────────────────────────────────────
const REVIEW_PROMPT = `You are a strict shell command safety reviewer. Evaluate the command below for the relevant risks:
- data destruction or irreversible changes
- exfiltration of secrets, credentials, or personal data
- privilege escalation, persistence, or system damage
- network exfiltration / remote code execution
- excessive scope (wildcards, recursive deletes, broad globs)

Reply with ONLY a JSON object on one line, no markdown fences:
{"safe": true|false, "risk": "none"|"low"|"high", "reason": "one short sentence"}

Command to review:
---
%s
---`;

interface ReviewResult {
	safe: boolean;
	risk: "none" | "low" | "high";
	reason: string;
}

function parseReview(text: string): ReviewResult | undefined {
	const match = text.match(/\{[^}]*"safe"[^}]*\}/);
	if (!match) return undefined;
	try {
		const obj = JSON.parse(match[0]) as ReviewResult;
		if (typeof obj.safe === "boolean") return obj;
	} catch { /* fall through */ }
	return undefined;
}

export default function (pi: ExtensionAPI) {
	const mode = (process.env.PI_AUTO_REVIEW_MODE ?? "llm").toLowerCase();
	const strict = process.env.PI_AUTO_REVIEW_STRICT === "1";

	if (mode === "off") return;

	// 启动自检通知：能看到这条说明扩展已加载
	pi.on("session_start", (_event, ctx) => {
		ctx.ui.notify(`pi-auto-review 已加载 (mode=${mode}, strict=${strict})`, "info");
	});

	// 结果缓存：同一命令字符串只审一次
	const verdictCache = new Map<string, ReviewResult>();
	let reviewModel: AnyModel | undefined;
	let lastError: string | undefined;

	/** 向 herdr 汇报提问状态（herdr-agent-state 扩展监听 herdr:blocked 事件） */
	function herdrBlocked(active: boolean, label?: string): void {
		try {
			pi.events.emit("herdr:blocked", { active, label });
		} catch { /* herdr 未安装时忽略 */ }
	}

	/** 弹确认框，同时给 herdr 反馈“等待用户回答”状态 */
	async function confirmWithHerdr(ctx: Parameters<Parameters<typeof pi.on>[1]>[1], message: string): Promise<boolean> {
		if (!ctx.hasUI) return false;
		herdrBlocked(true, "pi-auto-review: 等待确认 shell 命令");
		try {
			return await ctx.ui.confirm("pi-auto-review", message);
		} finally {
			herdrBlocked(false);
		}
	}

	function resolveModel(ctx: Parameters<Parameters<typeof pi.on>[1]>[1]): AnyModel | undefined {
		if (reviewModel) return reviewModel;
		const explicit = process.env.PI_AUTO_REVIEW_MODEL;
		if (explicit) {
			const [provider, ...rest] = explicit.split("/");
			reviewModel = ctx.modelRegistry.find(provider, rest.join("/")) ?? undefined;
			if (!reviewModel) ctx.ui.notify(`shell-review: 找不到模型 ${explicit}，退回会话模型`, "warning");
		}
		if (!reviewModel) {
			// 回落列表可通过 PI_AUTO_REVIEW_FALLBACK 配置，逗号分隔 "provider/model"
			const fallbackEnv = process.env.PI_AUTO_REVIEW_FALLBACK;
			const fallbackList: Array<readonly [string, string]> = fallbackEnv
				? fallbackEnv.split(",").map((entry) => {
						const [provider = "", id = ""] = entry.trim().split("/");
						return [provider, id] as const;
					})
				: ([
					["anthropic", "claude-haiku-4-5"],
					["google", "gemini-2.5-flash"],
					["openai", "gpt-4.1-mini"],
				] as const);
			for (const [provider, id] of fallbackList) {
				reviewModel = ctx.modelRegistry.find(provider, id) ?? undefined;
				if (reviewModel) break;
			}
		}
		if (!reviewModel) reviewModel = ctx.model ?? undefined;
		return reviewModel;
	}

	pi.on("tool_call", async (event, ctx) => {
		if (event.toolName !== "bash") return undefined;
		const command = (event.input.command as string | undefined) ?? "";
		if (!command.trim()) return undefined;
		dbg(`tool_call: ${JSON.stringify(command)}`);

		// 一级：危险正则
		for (const { pattern, reason } of DENY_PATTERNS) {
			if (!pattern.test(command)) continue;
			const msg = `⚠️ 危险命令（${reason}）:\n\n  ${command}\n\n允许执行?`;
			if (!ctx.hasUI) {
				return { block: true, reason: `Blocked by pi-auto-review: ${reason}` };
			}
			const ok = await confirmWithHerdr(ctx, msg);
			if (!ok) {
				ctx.ui.notify("已阻止危险命令", "warning");
				return { block: true, reason: `User rejected: ${reason}` };
			}
			return undefined; // 用户明确放行
		}

		// 二级：安全正则，或 regex-only 模式
		if (isSafeByRegex(command)) return undefined;
		if (mode === "regex") {
			// 纯正则模式下，非安全即确认
			if (!ctx.hasUI) return { block: true, reason: "Not in safe allowlist" };
			const ok = await confirmWithHerdr(ctx, `命令不在安全白名单中:\n\n  ${command}\n\n允许?`);
			if (!ok) return { block: true, reason: "User rejected non-allowlisted command" };
			return undefined;
		}

		// 三级：LLM 审查
		const cached = verdictCache.get(command);
		let result: ReviewResult | undefined = cached;

		if (!result) {
			const model = resolveModel(ctx);
			if (!model) {
				ctx.ui.notify("shell-review: 无可用模型，退回人工确认", "warning");
			} else if (!ctx.modelRegistry.hasConfiguredAuth(model)) {
				lastError = `模型 ${model.provider}/${model.id} 没有已配置的 API key`;
				ctx.ui.notify(`shell-review: ${lastError}`, "warning");
			} else {
				try {
					const response = await ctx.modelRegistry.complete(
						model,
						{
							messages: [{
								role: "user",
								content: [{ type: "text", text: REVIEW_PROMPT.replace("%s", command) }],
								timestamp: Date.now(),
							}],
						},
						{ maxTokens: 4096, signal: ctx.signal, cacheRetention: "none", sessionId: newSessionId(),
							samplingParams: { reasoning_effort: "low" } as Record<string, unknown> },
					);
					const text = response.content
						.filter((c): c is { type: "text"; text: string } => c.type === "text")
						.map((c) => c.text)
						.join("");
					// 推理模型可能只在 thinking 块里产出 JSON，兜底解析
					const thinking = response.content
						.filter((c): c is { type: "thinking"; thinking: string } => c.type === "thinking")
						.map((c) => c.thinking)
						.join("\n");
					result = parseReview(text) ?? parseReview(thinking);
					if (!result) {
						const meta = {
							stopReason: (response as { stopReason?: unknown }).stopReason,
							blockTypes: response.content.map((c) => c.type),
							rawText: text.slice(0, 300),
							rawThinking: thinking.slice(0, 300),
						};
						lastError = `LLM 返回无法解析: ${JSON.stringify(meta)}`;
						dbg(lastError);
					}
				} catch (err) {
					lastError = err instanceof Error ? err.message : String(err);
					dbg(`LLM exception: ${lastError}`);
					ctx.ui.notify(`shell-review LLM 调用失败: ${lastError}`, "error");
				}
			}
		}

		if (!result) {
			// LLM 失败 → 人工确认兜底，并带上真实原因
			const detail = lastError ? `\n\n原因: ${lastError}` : "";
			if (!ctx.hasUI) return { block: true, reason: `LLM review unavailable: ${lastError ?? "unknown"}` };
			const ok = await confirmWithHerdr(ctx, `LLM 审查不可用，请人工确认:${detail}\n\n  ${command}`);
			if (!ok) return { block: true, reason: "User rejected (LLM unavailable)" };
			return undefined;
		}

		verdictCache.set(command, result);

		if (result.safe) {
			dbg(`PASS: ${result.risk} — ${result.reason}`);
			ctx.ui.notify(`shell-review ✓ ${result.risk} — ${result.reason}`, "info");
			return undefined;
		}

		const warning = `⚠️ LLM 判定有风险 (${result.risk}): ${result.reason}\n\n  ${command}`;
		if (strict || !ctx.hasUI) {
			ctx.ui.notify(`shell-review ✗ 已阻止: ${result.reason}`, "warning");
			return { block: true, reason: `LLM blocked: ${result.reason}` };
		}
		const ok = await confirmWithHerdr(ctx, `${warning}\n\n仍要执行?`);
		if (!ok) return { block: true, reason: `User rejected after LLM warning: ${result.reason}` };
		dbg(`user-overrode LLM warning: ${result.reason}`);
		return undefined;
	});
}
