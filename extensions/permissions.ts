import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import {
	CONFIG_DIR_NAME,
	isToolCallEventType,
	type ExtensionAPI,
} from "@earendil-works/pi-coding-agent";

type Decision = "allow" | "ask" | "deny";
type Rule = [string, Decision];
type Policy = { tools: Record<string, Decision>; bash: Rule[] };

const emptyPolicy = (): Policy => ({ tools: {}, bash: [] });
const isDecision = (value: unknown): value is Decision =>
	value === "allow" || value === "ask" || value === "deny";

function parsePolicy(value: unknown, path: string): Policy {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new Error(`${path}: expected a JSON object`);
	}
	const permission = (value as { permission?: unknown }).permission;
	if (!permission || typeof permission !== "object" || Array.isArray(permission)) {
		throw new Error(`${path}: expected a "permission" object`);
	}

	const policy = emptyPolicy();
	for (const [tool, setting] of Object.entries(permission)) {
		if (tool === "bash" && setting && typeof setting === "object" && !Array.isArray(setting)) {
			for (const [pattern, decision] of Object.entries(setting)) {
				if (!isDecision(decision)) throw new Error(`${path}: invalid decision for bash.${pattern}`);
				policy.bash.push([pattern, decision]);
			}
		} else {
			if (!isDecision(setting)) throw new Error(`${path}: invalid decision for ${tool}`);
			policy.tools[tool] = setting;
		}
	}
	return policy;
}

async function readPolicy(path: string): Promise<Policy | undefined> {
	try {
		return parsePolicy(JSON.parse(await readFile(path, "utf8")), path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw error;
	}
}

function mergePolicy(base: Policy, override?: Policy): Policy {
	if (!override) return base;
	return {
		tools: { ...base.tools, ...override.tools },
		bash: override.tools.bash === undefined
			? [...base.bash, ...override.bash]
			: override.bash,
	};
}

function matches(pattern: string, value: string): boolean {
	if (pattern === "*") return true;
	return pattern.endsWith("*") ? value.startsWith(pattern.slice(0, -1)) : value === pattern;
}

function needsShellReview(command: string): boolean {
	return /[<>`]|\$\(/.test(command) ||
		(/^find(?:\s|$)/.test(command) &&
			/-(?:exec|execdir|ok|okdir|delete|fls|fprint|fprint0|fprintf)\b/.test(command));
}

function splitShellCommands(command: string): string[] | undefined {
	const commands: string[] = [];
	let start = 0;
	let quote: "'" | '"' | undefined;
	let escaped = false;

	const push = (end: number) => {
		const part = command.slice(start, end).trim();
		if (part) commands.push(part);
	};

	for (let i = 0; i < command.length; i++) {
		const char = command[i];
		const next = command[i + 1];

		if (escaped) {
			escaped = false;
			continue;
		}
		if (char === "\\" && quote !== "'") {
			escaped = true;
			continue;
		}
		if (quote) {
			if (char === quote) quote = undefined;
			else if (char === "`" || (char === "$" && next === "(")) return undefined;
			continue;
		}
		if (char === "'" || char === '"') {
			quote = char;
			continue;
		}
		if (char === "`" || (char === "$" && next === "(") || char === "<" || char === ">" || char === "(" || char === ")") {
			return undefined;
		}
		if (char === "\n" || char === "\r" || char === ";" || char === "|" || char === "&") {
			push(i);
			if ((char === "|" || char === "&") && next === char) i++;
			start = i + 1;
		}
	}
	if (quote) return undefined;
	push(command.length);
	return commands.length ? commands : [command.trim()];
}

function toolDecision(toolName: string, policy: Policy): Decision {
	if (policy.tools[toolName] !== undefined) return policy.tools[toolName];
	if (toolName === "write" && policy.tools.edit !== undefined) return policy.tools.edit;
	if ((toolName === "lsp" || toolName.startsWith("lsp_")) && policy.tools.lsp !== undefined) {
		return policy.tools.lsp;
	}
	return policy.tools["*"] ?? "ask";
}

function bashPermission(command: string, policy: Policy): { decision: Decision; sessionKey: string; command: string } {
	const normalized = command.trim();
	let decision = policy.tools.bash ?? policy.tools["*"] ?? "ask";
	let matchedPattern: string | undefined;

	for (const [pattern, candidate] of policy.bash) {
		if (matches(pattern, normalized)) {
			decision = candidate;
			matchedPattern = pattern;
		}
	}

	if (decision === "allow" && needsShellReview(normalized)) {
		return { command: normalized, decision: "ask", sessionKey: `bash command: ${normalized}` };
	}
	return {
		command: normalized,
		decision,
		sessionKey: matchedPattern && matchedPattern !== "*"
			? `bash rule: ${matchedPattern}`
			: `bash command: ${normalized}`,
	};
}

function bashPermissions(command: string, policy: Policy): ReturnType<typeof bashPermission>[] {
	const normalized = command.trim();
	const parts = splitShellCommands(normalized);
	if (!parts) {
		const permission = bashPermission(normalized, policy);
		return [{ ...permission, decision: permission.decision === "allow" ? "ask" : permission.decision, sessionKey: `bash command: ${normalized}` }];
	}
	return parts.map((part) => bashPermission(part, policy));
}

const SESSION_PERMISSIONS_KEY = Symbol.for("pi-session-permissions.sessionPermissions");

function getSessionPermissions(): Set<string> {
	const state = globalThis as typeof globalThis & { [SESSION_PERMISSIONS_KEY]?: Set<string> };
	return state[SESSION_PERMISSIONS_KEY] ??= new Set<string>();
}

function shouldClearSessionPermissions(reason: string): boolean {
	return reason !== "reload";
}

const checkPolicy = parsePolicy({ permission: { bash: { "*": "ask", "git commit *": "ask" } } }, "test");
assert.equal(bashPermission("git commit -m test", checkPolicy).sessionKey, "bash rule: git commit *");
assert.deepEqual(splitShellCommands('ls -la | echo "algo"'), ["ls -la", 'echo "algo"']);
assert.equal(splitShellCommands('echo "$(rm -rf /)"'), undefined);
assert.equal(bashPermission('echo "$(rm -rf /)"', parsePolicy({ permission: { bash: { "echo *": "allow" } } }, "test")).decision, "ask");
assert.deepEqual(bashPermissions("ls -la | echo ok", parsePolicy({ permission: { bash: { "ls *": "allow", "echo *": "ask" } } }, "test")).map(({ decision }) => decision), ["allow", "ask"]);
assert.equal(bashPermissions("(cd src && ls)", parsePolicy({ permission: { bash: "allow" } }, "test"))[0]?.decision, "ask");
assert.equal(bashPermission("pwd", mergePolicy(
	parsePolicy({ permission: { bash: { pwd: "allow" } } }, "global test"),
	parsePolicy({ permission: { bash: "deny" } }, "project test"),
)).decision, "deny");
assert.equal(toolDecision("lsp_hover", parsePolicy({
	permission: { lsp: "allow", lsp_hover: "deny" },
}, "test")), "deny");
assert.equal(shouldClearSessionPermissions("reload"), false);
assert.equal(shouldClearSessionPermissions("new"), true);

export default function (pi: ExtensionAPI) {
	let policy = emptyPolicy();
	const sessionPermissions = getSessionPermissions();

	pi.on("session_start", async (_event, ctx) => {
		const agentDir = process.env.PI_CODING_AGENT_DIR ?? join(homedir(), ".pi", "agent");
		const globalPath = join(agentDir, "permissions.json");
		const projectPath = join(ctx.cwd, CONFIG_DIR_NAME, "permissions.json");
		let loaded = emptyPolicy();

		try {
			loaded = mergePolicy(loaded, await readPolicy(globalPath));
		} catch (error) {
			ctx.ui.notify(String(error), "error");
		}
		if (ctx.isProjectTrusted()) {
			try {
				loaded = mergePolicy(loaded, await readPolicy(projectPath));
			} catch (error) {
				ctx.ui.notify(String(error), "error");
			}
		}

		policy = loaded;
		if (shouldClearSessionPermissions(_event.reason)) sessionPermissions.clear();
	});

	pi.on("tool_call", async (event, ctx) => {
		if (isToolCallEventType("bash", event)) {
			const checks = bashPermissions(event.input.command, policy);
			const denied = checks.find(({ decision }) => decision === "deny");
			if (denied) return { block: true, reason: `Blocked by permission policy: ${denied.command}` };

			const pending = checks.filter(({ decision, sessionKey }) => decision === "ask" && !sessionPermissions.has(sessionKey));
			if (pending.length === 0) return;
			if (!ctx.hasUI) {
				return { block: true, reason: `Permission required but no interactive UI is available: ${event.input.command}` };
			}

			const allowed = await ctx.ui.confirm(
				"Allow bash commands for this session?",
				pending.map(({ command, sessionKey }) => `${command}\nScope: ${sessionKey}`).join("\n\n"),
			);
			if (!allowed) return { block: true, reason: "Blocked by user" };
			for (const { sessionKey } of pending) sessionPermissions.add(sessionKey);
			return;
		}

		const decision = toolDecision(event.toolName, policy);
		let sessionKey = `${event.toolName}: ${JSON.stringify(event.input)}`;
		if (event.toolName === "edit" || event.toolName === "write") sessionKey = `tool: ${event.toolName}`;

		if (decision === "allow") return;
		if (decision === "deny") return { block: true, reason: `Blocked by permission policy: ${event.toolName}` };
		if (sessionPermissions.has(sessionKey)) return;
		if (!ctx.hasUI) {
			return { block: true, reason: `Permission required but no interactive UI is available: ${event.toolName}` };
		}

		const allowed = await ctx.ui.confirm(
			`Allow ${event.toolName} for this session?`,
			`${event.toolName}\n\nScope: ${sessionKey}`,
		);
		if (!allowed) return { block: true, reason: "Blocked by user" };
		sessionPermissions.add(sessionKey);
	});
}
