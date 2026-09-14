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
	return override
		? { tools: { ...base.tools, ...override.tools }, bash: [...base.bash, ...override.bash] }
		: base;
}

function matches(pattern: string, value: string): boolean {
	if (pattern === "*") return true;
	return pattern.endsWith("*") ? value.startsWith(pattern.slice(0, -1)) : value === pattern;
}

function needsShellReview(command: string): boolean {
	return /[\n\r;&|<>`]|\$\(/.test(command) ||
		(/^find(?:\s|$)/.test(command) &&
			/-(?:exec|execdir|ok|okdir|delete|fls|fprint|fprint0|fprintf)\b/.test(command));
}

function bashPermission(command: string, policy: Policy): { decision: Decision; sessionKey: string } {
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
		return { decision: "ask", sessionKey: `bash command: ${normalized}` };
	}
	return {
		decision,
		sessionKey: matchedPattern && matchedPattern !== "*"
			? `bash rule: ${matchedPattern}`
			: `bash command: ${normalized}`,
	};
}

const checkPolicy = parsePolicy({ permission: { bash: { "*": "ask", "git commit *": "ask" } } }, "test");
assert.equal(bashPermission("git commit -m test", checkPolicy).sessionKey, "bash rule: git commit *");
assert.equal(bashPermission('echo "$(rm -rf /)"', parsePolicy({ permission: { bash: { "echo *": "allow" } } }, "test")).decision, "ask");

export default function (pi: ExtensionAPI) {
	let policy = emptyPolicy();
	const sessionPermissions = new Set<string>();

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
		sessionPermissions.clear();
	});

	pi.on("tool_call", async (event, ctx) => {
		let decision = policy.tools[event.toolName] ?? policy.tools["*"] ?? "ask";
		let description = event.toolName;
		let sessionKey = `${event.toolName}: ${JSON.stringify(event.input)}`;

		if (event.toolName === "write" && policy.tools.write === undefined) {
			decision = policy.tools.edit ?? decision;
		} else if ((event.toolName === "lsp" || event.toolName.startsWith("lsp_")) && policy.tools.lsp !== undefined) {
			decision = policy.tools.lsp;
		} else if (isToolCallEventType("bash", event)) {
			description = event.input.command;
			({ decision, sessionKey } = bashPermission(description, policy));
		}
		if (event.toolName === "edit" || event.toolName === "write") sessionKey = `tool: ${event.toolName}`;

		if (decision === "allow") return;
		if (decision === "deny") return { block: true, reason: `Blocked by permission policy: ${description}` };
		if (sessionPermissions.has(sessionKey)) return;
		if (!ctx.hasUI) {
			return { block: true, reason: `Permission required but no interactive UI is available: ${description}` };
		}

		const allowed = await ctx.ui.confirm(
			`Allow ${event.toolName} for this session?`,
			`${description}\n\nScope: ${sessionKey}`,
		);
		if (!allowed) return { block: true, reason: "Blocked by user" };
		sessionPermissions.add(sessionKey);
	});
}
