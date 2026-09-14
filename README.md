# pi-session-permissions

OpenCode-style permission rules for [Pi](https://pi.dev), with approvals remembered until the current session ends.

## Install

From a local checkout:

```bash
pi install /absolute/path/to/pi-session-permissions
```

From GitHub:

```bash
pi install https://github.com/USER/pi-session-permissions
```

Restart Pi after installing.

## Configuration

Copy the example policy to Pi's global configuration directory:

```bash
cp permissions.example.json ~/.pi/agent/permissions.json
```

The extension reads, in order:

1. `~/.pi/agent/permissions.json`
2. `.pi/permissions.json` from the current trusted project

Project settings override global tool decisions and append Bash rules. Rules keep their JSON order, and the last matching Bash rule wins. Missing configuration defaults to `ask`; invalid values are reported and ignored.

The schema matches OpenCode-style permission configuration:

```json
{
  "permission": {
    "read": "allow",
    "edit": "ask",
    "bash": {
      "*": "ask",
      "git status*": "allow",
      "git push*": "deny"
    },
    "lsp": "allow"
  }
}
```

Valid decisions are `allow`, `ask`, and `deny`. The `edit` decision also applies to Pi's `write` tool unless `write` is configured explicitly. Run `/reload` after changing either file.

## Behavior

- Tool behavior comes from the JSON policy.
- Approved edit and write permissions are remembered for the session.
- Bash uses ordered rules; the last match wins.
- Explicitly denied commands never prompt.
- Approved Bash rules last for the session.
- Shell composition, substitution, redirection, and mutating `find` actions require approval for the exact command.
- Print and JSON modes deny anything requiring confirmation; RPC can prompt through its UI protocol.

This is a confirmation gate, not an OS sandbox. Use a container or sandbox when commands need hard isolation.
