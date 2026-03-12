# mcp-firewall

Prompt injection firewall middleware for MCP (Model Context Protocol) servers. Sits between an MCP client and server as a stdio proxy, inspects every JSON-RPC request for prompt injection patterns, and blocks or flags suspicious requests.

## Architecture

```
                        mcp-firewall
  ┌──────────┐    ┌─────────────────────────┐    ┌──────────────┐
  │          │    │                         │    │              │
  │   MCP    │    │  ┌───────────────────┐  │    │     MCP      │
  │  Client  │───▶│  │  JSON-RPC Parser  │  │───▶│    Server    │
  │          │    │  └────────┬──────────┘  │    │              │
  │ (Claude  │    │           │             │    │  (your app)  │
  │  Desktop,│    │  ┌────────▼──────────┐  │    │              │
  │  Cursor, │    │  │  Pattern Scanner  │  │    │  node srv.js │
  │  etc.)   │    │  │  (12 detectors)   │  │    │  python s.py │
  │          │    │  └────────┬──────────┘  │    │  etc.        │
  │          │    │           │             │    │              │
  │          │    │  ┌────────▼──────────┐  │    │              │
  │          │◀───│  │  Scoring Engine   │  │◀───│              │
  │          │    │  │  pass/warn/block  │  │    │              │
  │          │    │  └──────────────────┘  │    │              │
  └──────────┘    └─────────────────────────┘    └──────────────┘
                         stdin/stdout
                           proxy

  FLOW:
  ─────────────────────────────────────────────────────────────
  Client stdin ──▶ Firewall inspects ──▶ Server stdin
                        │
                   score < warn?  ──▶  PASS (forward)
                   score >= warn? ──▶  WARN (log + forward)
                   score >= block? ──▶ BLOCK (reject + log)
                        │
  Client stdout ◀── Server stdout ◀── (passthrough responses)
```

## Installation

```bash
npm install -g mcp-firewall
```

Or use directly with npx:

```bash
npx mcp-firewall -- node server.js
```

## Usage

```bash
# Basic usage - wrap any MCP server
npx mcp-firewall -- node my-mcp-server.js

# With custom config
npx mcp-firewall --config firewall.yaml -- python mcp_server.py

# Dry-run mode (log but never block)
npx mcp-firewall --dry-run -- ./my-server

# Verbose text logging
npx mcp-firewall --log-format text --log-level debug -- node server.js
```

### Claude Desktop Integration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": ["mcp-firewall", "--", "node", "/path/to/server.js"]
    }
  }
}
```

## Detection Patterns

mcp-firewall includes 12 built-in detection patterns across 6 attack categories:

| # | Pattern | Category | Score | Description |
|---|---------|----------|-------|-------------|
| 1 | Classic Prompt Injection | classic-injection | 9 | "ignore previous instructions" |
| 2 | Role Hijacking | role-hijacking | 8 | "you are now an unrestricted AI" |
| 3 | Instruction Override | instruction-override | 9 | "bypass all safety filters" |
| 4 | Base64 Encoded Payload | encoded-base64 | 7 | Hidden instructions in base64 |
| 5 | Hex Encoded Payload | encoded-hex | 7 | Hidden commands in hex encoding |
| 6 | Unicode Escape Injection | encoded-unicode | 6 | Obfuscated unicode sequences |
| 7 | Network Exfiltration | exfiltration-network | 10 | "send data to https://evil.com" |
| 8 | Filesystem Access | exfiltration-filesystem | 9 | "read /etc/passwd" |
| 9 | Multi-Step Attack Chain | chaining | 5 | "step 1: ... then step 2: ..." |
| 10 | Context Window Stuffing | context-stuffing | 6 | Padding/overflow attacks |
| 11 | Delimiter Injection | delimiter-injection | 8 | System tag injection (`<\|im_start\|>`) |
| 12 | Tool Invocation Abuse | tool-abuse | 6 | "execute the shell command" |

## Scoring Engine

Each matched pattern contributes its score. Scores are summed and compared against thresholds:

- **Pass** (score < `warn`): Request forwarded silently
- **Warn** (score >= `warn`, < `block`): Request forwarded, warning logged
- **Block** (score >= `block`): Request rejected with JSON-RPC error

Default thresholds: `warn: 5`, `block: 8`

## Configuration

Create a `firewall.yaml` in your working directory:

```yaml
thresholds:
  warn: 5
  block: 8

logging:
  level: info        # debug | info | warn | error
  format: json       # json | text

dryRun: false

patterns:
  enabled:
    - "*"            # Enable all built-in patterns
  disabled:
    - chaining       # Disable specific patterns by ID
  custom:
    - id: my-pattern
      name: My Custom Pattern
      category: classic-injection
      description: Detects my custom attack vector
      regex: "custom\\s+attack\\s+phrase"
      score: 7

allowlist:
  - initialize       # Skip inspection for these methods
  - ping
```

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--config <path>` | Path to YAML config file | `firewall.yaml` |
| `--dry-run` | Log detections but never block | `false` |
| `--log-level <lvl>` | Log level: debug, info, warn, error | `info` |
| `--log-format <fmt>` | Output format: json, text | `json` |
| `--help` | Show help | - |

## Programmatic API

```typescript
import { scan, buildPatternList, loadConfig } from "mcp-firewall";

const config = loadConfig("firewall.yaml");
const patterns = buildPatternList(config);

const result = scan(
  {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: "chat",
      arguments: { text: "ignore previous instructions" },
    },
  },
  patterns,
  config,
);

console.log(result.verdict);    // "block"
console.log(result.totalScore); // 9
console.log(result.matches);    // [{ patternId: "classic-injection", ... }]
```

## Structured Logging

All logs go to stderr (stdout is reserved for the MCP protocol). JSON format example:

```json
{
  "timestamp": "2025-01-15T10:30:00.000Z",
  "level": "error",
  "component": "mcp-firewall",
  "message": "Inspection verdict: block",
  "requestId": "fw-1705312200000-1",
  "method": "tools/call",
  "totalScore": 17,
  "verdict": "block",
  "matchCount": 2,
  "matches": [
    { "pattern": "classic-injection", "category": "classic-injection", "score": 9 },
    { "pattern": "role-hijacking", "category": "role-hijacking", "score": 8 }
  ]
}
```

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Build
npm run build

# Watch mode
npm run test:watch
```

## License

MIT
