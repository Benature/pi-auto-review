# pi-auto-review

Regex + optional LLM review for [Pi](https://pi.dev)'s `bash` tool calls.

在 Agent 执行 shell 命令前进行正则检查和可选的 LLM 审查：常见低风险命令直接放行，疑似危险命令要求确认，其余命令交给审核模型判断。

> **这是启发式审核工具，不是 sandbox 或完整的安全边界。** 正则与 LLM 都可能漏判。处理不可信代码、敏感数据或无人值守任务时，仍应使用隔离环境和最小权限。

## 安装

需要已安装的 Pi；本项目使用 `@earendil-works/pi-coding-agent` 的扩展 API，已在 Pi **1.4.0** 上使用。当前 Pi 要求 Node.js **22.19+**。

直接从 GitHub 安装，无需发布到 npm：

```bash
pi install git:github.com/Benature/pi-auto-review
```

安装后在 Pi 中执行 `/reload`，或重新启动 Pi。扩展启用时会显示：

```text
pi-auto-review 已加载 (mode=llm, strict=false)
```

更新与卸载：

```bash
pi update git:github.com/Benature/pi-auto-review
pi remove git:github.com/Benature/pi-auto-review
```

本地开发或单次试用：

```bash
git clone https://github.com/Benature/pi-auto-review.git
cd pi-auto-review
pi --extension ./src/pi-auto-review.ts
```

Pi 直接加载 TypeScript，无需构建。**只使用一种加载方式**，不要同时通过 package 安装和复制文件／软链接加载同一扩展，否则可能重复审核、重复弹窗。

## 默认行为

`PI_AUTO_REVIEW_MODE` 默认为 `llm`，按以下顺序处理：

| 阶段 | 命中条件 | 行为 |
| --- | --- | --- |
| 危险正则 | 匹配预置风险模式 | 要求人工确认；没有 UI 时阻止 |
| 放行白名单 | 匹配命令前缀及简易组合规则 | 直接执行，不调用审核 LLM |
| LLM 审查 | 未命中前两层 | `safe: true` 放行；否则要求确认 |
| 审核不可用 | 没有模型／凭证、请求失败或结果无法解析 | 要求人工确认；没有 UI 时阻止 |

- 危险正则覆盖部分递归删除、`sudo`、宽松权限、磁盘覆写、破坏性 Git 操作、远程脚本管道执行等模式，**不是完整清单**。
- 白名单包含 `ls`、`pwd`、`grep`、`git status` 等，也包含可能带副作用参数的命令；不能把“命中白名单”等同于“证明只读”。
- `regex` 模式不调用审核 LLM，未命中危险规则或白名单的命令也要求确认。
- `off` 模式不注册审核处理器，所有上述检查和通知均关闭。
- LLM verdict 以完整命令字符串为 key 缓存在扩展内存中；重复命令复用结果，危险／未通过结果仍需按策略确认。缓存不落盘，重载后清空。

## 配置

所有扩展配置通过 Pi **进程环境变量**传入，不在仓库中保存个人端点或凭证。

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PI_AUTO_REVIEW_MODE` | `llm` | `llm`：正则 + LLM；`regex`：仅正则和人工确认；`off`：禁用 |
| `PI_AUTO_REVIEW_MODEL` | 未设置 | 指定 Pi 已注册的 `provider/model-id`；未设置时自动选择 |
| `PI_AUTO_REVIEW_STRICT` | `0` | 设为 `1` 时，LLM 判为不安全直接阻止，不允许人工覆盖该 verdict |

**`STRICT` 只影响 LLM 不安全判定**：不会禁止人工批准危险正则命中的命令，也不会禁止审核不可用时的人工确认。它不是“所有风险一律禁止”的总开关。

一次启动时指定审核模型：

```bash
PI_AUTO_REVIEW_MODEL='your-provider/your-model-id' pi
```

只使用正则：

```bash
PI_AUTO_REVIEW_MODE=regex pi
```

固定模型并禁止覆盖 LLM 不安全判定：

```bash
PI_AUTO_REVIEW_MODEL='your-provider/your-model-id' PI_AUTO_REVIEW_STRICT=1 pi
```

需要持久配置时，将 `export PI_AUTO_REVIEW_MODEL='your-provider/your-model-id'` 写入启动 Pi 的 shell 配置或启动脚本，再从更新后的 shell 启动 Pi。

### 未指定模型时如何选择

不硬编码任何 provider 或 model name：

1. 优先使用 `PI_AUTO_REVIEW_MODEL` 指定且能在 registry 中找到的模型。
2. 未指定或找不到时，从 `ctx.modelRegistry.getAvailable()` 返回的模型中选择 `cost.input + cost.output` 最低的一个。
3. 价格相同时保留 **registry 返回顺序中的第一个**，不自行按名字排序。
4. 可用列表为空时尝试当前会话模型；仍无模型或没有已配置的认证，则进入人工确认兜底。

这是基于 Pi 价格元数据的粗略比较，**不代表实际账单一定最低**。自定义模型没有填写价格时可能被 Pi 赋值为 `0`，从而优先选中；这不意味着免费。请填入真实价格，或显式指定审核模型。

模型首次选定后在当前扩展 runtime 中复用；切换会话模型不会自动重新选取。指定模型存在但认证／请求失败时，也不会自动轮流尝试其他模型。

### Base URL、API token 和 model ID 在哪填

扩展复用 Pi 的 provider 配置，不另设 Base URL 或 token 环境变量。自定义兼容端点在 **`~/.pi/agent/models.json`** 中配置；如果设置了 `PI_CODING_AGENT_DIR`，使用该目录下的 `models.json`。

以下仅为占位示例，请合并到已有 `providers`，不要覆盖其他配置：

```json
{
  "providers": {
    "your-provider": {
      "baseUrl": "https://api.example.com/v1",
      "api": "openai-completions",
      "apiKey": "$REVIEW_API_TOKEN",
      "models": [
        { "id": "your-model-id" }
      ]
    }
  }
}
```

- `baseUrl`：服务的 API 地址。
- `apiKey`：推荐引用本机环境变量或安全的凭证来源；不要提交真实 token。
- `models[].id`：服务接受的模型 ID。
- `api`：选择端点实际支持的协议，而不是统一假设为 OpenAI-compatible。

内置 provider 也可以通过 Pi 的 `/login` 配置认证。更多字段见 [Pi 模型配置文档](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/models.md)。

### 审核请求与思考

当前请求使用 `maxTokens: 4096`，并对适用的 OpenAI-compatible API 发送 `reasoning_effort: "low"`。**这不是关闭 thinking**，provider 的支持情况也不同。

扩展先尝试解析 text 中的完整 `{ "safe": ..., "risk": ..., "reason": ... }`，再尝试 thinking 块中的 JSON。解析器兼容完整的 JSON 代码围栏，正确处理理由中的花括号、引号与转义；要求 `safe` 为布尔值、`risk` 为 `none`／`low`／`high`、`reason` 为非空字符串。

不从解释性文字中截取局部 JSON，也不接受多个 verdict 或截断的对象；解析失败进入人工确认。thinking 兜底仍不能视为可靠的最终 verdict 验证。

## 验证

请**用自然语言让 Agent 调用 `bash` 工具执行**，不要用 `!`／`!!` 直接运行命令来验证审核：

| 示例命令 | 预期路径 |
| --- | --- |
| `ls -la` | 原始命令命中白名单，静默放行 |
| `sudo --version` | 命中危险正则，要求确认；可选择拒绝，不执行 |
| `curl -s https://example.com -o /tmp/pi-auto-review-example.html` | 默认走 LLM 审查，结果取决于模型 |

LLM 放行时会显示类似 `shell-review ✓ low — ...` 的通知。命令没有 stdout **不代表未审核**。

其他扩展（如命令包装器）可能先改写命令，导致原本命中白名单的命令改走 LLM 审查。处理顺序取决于 Pi 的扩展注册顺序。

## herdr 集成

安装了兼容的 herdr Agent 状态集成时，所有确认弹窗会通过 Pi event bus 汇报等待回答状态：

```ts
// 弹窗前
pi.events.emit("herdr:blocked", {
  active: true,
  label: "pi-auto-review: 等待确认 shell 命令"
});

// 回答、取消或弹窗抛错后（finally）
pi.events.emit("herdr:blocked", { active: false });
```

herdr 负责展示 blocked 状态和恢复工作状态。没有监听此事件的集成时，这些事件不产生界面效果，也不需要安装额外依赖。

## 日志与隐私

启用审核时，扩展会尝试追加诊断日志到：

```text
~/.pi/agent/extensions/pi-auto-review.log
```

日志包含**完整命令字符串**、LLM 放行理由、错误和部分无法解析的模型输出，**不脱敏、不自动轮转**。命令中若包含 token、路径或个人信息，也会进入日志。分享前必须检查；不要将本机日志提交到仓库。

- 该日志路径目前固定，不跟随 `PI_CODING_AGENT_DIR`。
- 目录不存在或没有写权限时，日志写入会被静默跳过。
- 当前没有独立日志开关；`MODE=off` 会同时关闭整个审核扩展。
- LLM 审查会把待审命令发送给所选 provider。使用 `regex` 模式可避免这笔额外的审核请求，但不改变 Pi 主对话模型的数据处理方式。

## 排障与安全边界

- **修改源码**：`/reload` 会重载扩展。**修改 shell 环境变量**：需从已加载新环境的 shell 重新启动 Pi；`/reload` 不会重新读取 `.zshrc`，在子进程里 `export` 也不会修改 Pi 父进程的环境。
- **审核不可用**：检查弹窗原因、模型是否在 Pi registry 中、认证是否配置、服务是否可达，以及返回是否只有 thinking 或被 token 上限截断。
- **只拦截名为 `bash` 的 `tool_call`**，不覆盖用户直接输入的 `!`／`!!` 命令、`powershell`、`edit`／`write`、扩展直接启动的进程或全部 MCP 工具。
- **不是完整 shell parser**：前缀、管道、子命令、参数、脚本和间接调用都可能导致误判或漏判。
- **不是系统权限约束**：LLM 可能误判或受 prompt injection 影响；缓存也不跟踪文件和环境变化。需要强安全保证时，应使用容器／VM／OS sandbox 和最小权限。

## 本地测试

在仓库目录运行 `npm test`（Node.js 22.19+，无需安装额外依赖）。测试覆盖 JSON 理由中的花括号／转义、代码围栏、无效字段与截断输出，以及模拟 LLM 返回值的审核 hook；不会请求真实模型或执行被审核的 shell 命令。

## npm 发布

**npm 不是安装这个扩展的前提。** 目前推荐上面的 GitHub 安装方式，本项目尚未发布 npm 包。

`package.json` 已声明 `pi.extensions`，让 Pi 能发现 `src/pi-auto-review.ts`，并保留 `pi-package` keyword。为避免误发布，目前设置了 `private: true`，且尚未指定开源许可（`UNLICENSED`）。

若以后决定发布 npm，应先确定可用的包名或 scope、license、版本策略及发布检查，再移除 `private`。届时用户可以使用 `pi install npm:<实际包名>`；在正式发布前，不应将该命令当作可用安装入口。
