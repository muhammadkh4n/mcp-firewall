"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  BUILTIN_PATTERNS: () => BUILTIN_PATTERNS,
  DEFAULT_CONFIG: () => DEFAULT_CONFIG,
  FirewallProxy: () => FirewallProxy,
  Logger: () => Logger,
  buildPatternList: () => buildPatternList,
  loadConfig: () => loadConfig,
  resetCounter: () => resetCounter,
  scan: () => scan
});
module.exports = __toCommonJS(src_exports);

// src/patterns.ts
var BUILTIN_PATTERNS = [
  // 1. Classic prompt injection
  {
    id: "classic-injection",
    name: "Classic Prompt Injection",
    category: "classic-injection",
    description: "Detects classic prompt injection phrases like 'ignore previous instructions'",
    regex: /(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions|prompts|rules|guidelines|context)/i,
    score: 9
  },
  // 2. Role hijacking
  {
    id: "role-hijacking",
    name: "Role Hijacking",
    category: "role-hijacking",
    description: "Detects attempts to reassign the model's identity or role",
    regex: /(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|switch\s+to\s+role|new\s+system\s+prompt|act\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|evil|jailbroken))/i,
    score: 8
  },
  // 3. Instruction override
  {
    id: "instruction-override",
    name: "Instruction Override",
    category: "instruction-override",
    description: "Detects attempts to bypass safety mechanisms or override instructions",
    regex: /(?:bypass\s+(?:all\s+)?(?:safety|security|filter|restriction|guard)|disable\s+(?:all\s+)?(?:safety|filter|content|restriction)|ignore\s+(?:all\s+)?(?:safety|ethical|content)\s+(?:guidelines|policies|rules|filters))/i,
    score: 9
  },
  // 4. Base64 encoded payloads
  {
    id: "encoded-base64",
    name: "Base64 Encoded Payload",
    category: "encoded-base64",
    description: "Detects base64-encoded strings that may contain hidden instructions",
    regex: /(?:decode|execute|run|eval)\s+(?:this\s+)?(?:base64|b64)[:\s]+[A-Za-z0-9+/]{20,}={0,2}/i,
    score: 7
  },
  // 5. Hex encoded payloads
  {
    id: "encoded-hex",
    name: "Hex Encoded Payload",
    category: "encoded-hex",
    description: "Detects hex-encoded strings that may contain hidden commands",
    regex: /(?:decode|execute|run|eval)\s+(?:this\s+)?hex[:\s]+(?:0x)?[0-9a-fA-F]{20,}/i,
    score: 7
  },
  // 6. Unicode escape sequences
  {
    id: "encoded-unicode",
    name: "Unicode Escape Injection",
    category: "encoded-unicode",
    description: "Detects suspicious unicode escape sequences used to hide instructions",
    regex: /(?:\\u[0-9a-fA-F]{4}){5,}/,
    score: 6
  },
  // 7. Network exfiltration
  {
    id: "exfiltration-network",
    name: "Network Exfiltration",
    category: "exfiltration-network",
    description: "Detects attempts to exfiltrate data over network connections",
    regex: /(?:send|post|upload|transmit|exfiltrate|forward)\s+(?:all\s+)?(?:data|information|content|results|output|credentials|secrets|tokens|keys|passwords)\s+(?:to|via|through|using)\s+(?:https?:\/\/|ftp:\/\/|wss?:\/\/)/i,
    score: 10
  },
  // 8. Filesystem exfiltration
  {
    id: "exfiltration-filesystem",
    name: "Filesystem Access",
    category: "exfiltration-filesystem",
    description: "Detects attempts to access sensitive filesystem paths or credentials",
    regex: /(?:read|cat|access|dump|show|display|print)\s+(?:the\s+)?(?:\/etc\/(?:passwd|shadow|hosts)|~\/\.ssh|~\/\.aws|~\/\.env|credentials|\.git\/config|\.npmrc|\.netrc)/i,
    score: 9
  },
  // 9. Chaining / multi-step attacks
  {
    id: "chaining",
    name: "Multi-Step Attack Chain",
    category: "chaining",
    description: "Detects attempts to chain multiple actions as a coordinated attack",
    regex: /(?:step\s*[1-9][:\s].*(?:then|next|after\s+that|step\s*[2-9]))/is,
    score: 5
  },
  // 10. Context stuffing
  {
    id: "context-stuffing",
    name: "Context Window Stuffing",
    category: "context-stuffing",
    description: "Detects padding attacks that attempt to overflow the context window",
    regex: /(.{1,10})\1{50,}/,
    score: 6
  },
  // 11. Delimiter injection
  {
    id: "delimiter-injection",
    name: "Delimiter Injection",
    category: "delimiter-injection",
    description: "Detects injection of system-level delimiters to escape prompt boundaries",
    regex: /(?:<\|(?:im_start|im_end|system|endoftext)\|>|<\/?(?:system|instruction|tool_call)>|\[INST\]|\[\/INST\]|<<\s*SYS\s*>>)/i,
    score: 8
  },
  // 12. Tool abuse
  {
    id: "tool-abuse",
    name: "Tool Invocation Abuse",
    category: "tool-abuse",
    description: "Detects attempts to invoke tools or execute commands directly",
    regex: /(?:call\s+(?:the\s+)?tool|execute\s+(?:the\s+)?(?:function|command|shell)|run\s+(?:the\s+)?(?:shell|bash|cmd|powershell|exec)|invoke\s+(?:the\s+)?(?:function|method|api))\s+/i,
    score: 6
  }
];

// src/scanner.ts
var counter = 0;
function nextRequestId() {
  return `fw-${Date.now()}-${++counter}`;
}
function buildPatternList(config) {
  const patterns = [];
  const { enabled, disabled } = config.patterns;
  const enableAll = enabled.includes("*");
  for (const p of BUILTIN_PATTERNS) {
    if (disabled.includes(p.id)) continue;
    if (enableAll || enabled.includes(p.id)) {
      patterns.push(p);
    }
  }
  for (const custom of config.patterns.custom) {
    if (disabled.includes(custom.id)) continue;
    if (enableAll || enabled.includes(custom.id)) {
      patterns.push({
        ...custom,
        regex: new RegExp(custom.regex, "i")
      });
    }
  }
  return patterns;
}
function extractTextFields(obj, path2 = "") {
  const fields = [];
  if (typeof obj === "string") {
    fields.push({ text: obj, location: path2 || "root" });
  } else if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      fields.push(...extractTextFields(obj[i], `${path2}[${i}]`));
    }
  } else if (obj !== null && typeof obj === "object") {
    for (const [key, value] of Object.entries(obj)) {
      fields.push(...extractTextFields(value, path2 ? `${path2}.${key}` : key));
    }
  }
  return fields;
}
function scan(request, patterns, config) {
  const requestId = nextRequestId();
  const matches = [];
  if (config.allowlist.includes(request.method)) {
    return {
      verdict: "pass",
      totalScore: 0,
      matches: [],
      requestId,
      method: request.method,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
  const fields = extractTextFields(request.params, "params");
  for (const field of fields) {
    for (const pattern of patterns) {
      const match = field.text.match(pattern.regex);
      if (match) {
        matches.push({
          patternId: pattern.id,
          patternName: pattern.name,
          category: pattern.category,
          score: pattern.score,
          matched: match[0].slice(0, 200),
          location: field.location
        });
      }
    }
  }
  const totalScore = matches.reduce((sum, m) => sum + m.score, 0);
  let verdict = "pass";
  if (totalScore >= config.thresholds.block) {
    verdict = "block";
  } else if (totalScore >= config.thresholds.warn) {
    verdict = "warn";
  }
  return {
    verdict,
    totalScore,
    matches,
    requestId,
    method: request.method,
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  };
}
function resetCounter() {
  counter = 0;
}

// src/config.ts
var fs = __toESM(require("fs"));
var path = __toESM(require("path"));
var yaml = __toESM(require("js-yaml"));
var DEFAULT_CONFIG = {
  thresholds: {
    warn: 5,
    block: 8
  },
  logging: {
    level: "info",
    format: "json"
  },
  dryRun: false,
  patterns: {
    enabled: ["*"],
    disabled: [],
    custom: []
  },
  allowlist: []
};
function loadConfig(configPath) {
  if (!configPath) {
    const candidates = ["firewall.yaml", "firewall.yml", "mcp-firewall.yaml"];
    for (const candidate of candidates) {
      const resolved2 = path.resolve(candidate);
      if (fs.existsSync(resolved2)) {
        configPath = resolved2;
        break;
      }
    }
  }
  if (!configPath) {
    return { ...DEFAULT_CONFIG };
  }
  const resolved = path.resolve(configPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Config file not found: ${resolved}`);
  }
  const raw = fs.readFileSync(resolved, "utf-8");
  const parsed = yaml.load(raw);
  if (!parsed || typeof parsed !== "object") {
    throw new Error(`Invalid config file: ${resolved}`);
  }
  return mergeConfig(DEFAULT_CONFIG, parsed);
}
function mergeConfig(defaults, overrides) {
  return {
    thresholds: { ...defaults.thresholds, ...overrides.thresholds },
    logging: { ...defaults.logging, ...overrides.logging },
    dryRun: overrides.dryRun ?? defaults.dryRun,
    patterns: {
      enabled: overrides.patterns?.enabled ?? defaults.patterns.enabled,
      disabled: overrides.patterns?.disabled ?? defaults.patterns.disabled,
      custom: overrides.patterns?.custom ?? defaults.patterns.custom
    },
    allowlist: overrides.allowlist ?? defaults.allowlist
  };
}

// src/logger.ts
var LEVEL_ORDER = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3
};
var Logger = class {
  level;
  format;
  output;
  constructor(config, output) {
    this.level = config.level;
    this.format = config.format;
    this.output = output ?? ((msg) => process.stderr.write(msg + "\n"));
  }
  shouldLog(level) {
    return LEVEL_ORDER[level] >= LEVEL_ORDER[this.level];
  }
  write(level, message, data) {
    if (!this.shouldLog(level)) return;
    if (this.format === "json") {
      this.output(
        JSON.stringify({
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          level,
          component: "mcp-firewall",
          message,
          ...data
        })
      );
    } else {
      const ts = (/* @__PURE__ */ new Date()).toISOString();
      const prefix = `[${ts}] [${level.toUpperCase().padEnd(5)}] [mcp-firewall]`;
      const extra = data ? ` ${JSON.stringify(data)}` : "";
      this.output(`${prefix} ${message}${extra}`);
    }
  }
  debug(message, data) {
    this.write("debug", message, data);
  }
  info(message, data) {
    this.write("info", message, data);
  }
  warn(message, data) {
    this.write("warn", message, data);
  }
  error(message, data) {
    this.write("error", message, data);
  }
  inspection(result) {
    const level = result.verdict === "pass" ? "debug" : result.verdict === "warn" ? "warn" : "error";
    this.write(level, `Inspection verdict: ${result.verdict}`, {
      requestId: result.requestId,
      method: result.method,
      totalScore: result.totalScore,
      verdict: result.verdict,
      matchCount: result.matches.length,
      matches: result.matches.map((m) => ({
        pattern: m.patternId,
        category: m.category,
        score: m.score,
        text: m.matched.slice(0, 100)
      }))
    });
  }
};

// src/proxy.ts
var import_node_child_process = require("child_process");
var FirewallProxy = class {
  child = null;
  patterns;
  config;
  logger;
  inputBuffer = "";
  constructor(patterns, config, logger) {
    this.patterns = patterns;
    this.config = config;
    this.logger = logger;
  }
  start(command, args) {
    this.logger.info("Starting MCP server", { command, args });
    this.child = (0, import_node_child_process.spawn)(command, args, {
      stdio: ["pipe", "pipe", "inherit"]
    });
    this.child.on("error", (err) => {
      this.logger.error("Failed to start server process", {
        error: err.message
      });
      process.exit(1);
    });
    this.child.on("exit", (code) => {
      this.logger.info("Server process exited", { code });
      process.exit(code ?? 0);
    });
    this.child.stdout?.on("data", (chunk) => {
      process.stdout.write(chunk);
    });
    process.stdin.on("data", (chunk) => {
      this.handleInput(chunk);
    });
    process.stdin.on("end", () => {
      this.child?.stdin?.end();
    });
  }
  handleInput(chunk) {
    this.inputBuffer += chunk.toString();
    const lines = this.inputBuffer.split("\n");
    this.inputBuffer = lines.pop() ?? "";
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) {
        this.child?.stdin?.write("\n");
        continue;
      }
      this.processLine(trimmed);
    }
  }
  processLine(line) {
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      this.child?.stdin?.write(line + "\n");
      return;
    }
    if (!isJsonRpcRequest(parsed)) {
      this.child?.stdin?.write(line + "\n");
      return;
    }
    const request = parsed;
    const result = scan(request, this.patterns, this.config);
    this.logger.inspection(result);
    if (result.verdict === "block" && !this.config.dryRun) {
      this.logger.warn("Blocked request", {
        method: request.method,
        requestId: result.requestId,
        totalScore: result.totalScore
      });
      if (request.id !== void 0) {
        const errorResponse = {
          jsonrpc: "2.0",
          id: request.id,
          error: {
            code: -32001,
            message: "Request blocked by mcp-firewall: prompt injection detected",
            data: {
              verdict: result.verdict,
              totalScore: result.totalScore,
              matchCount: result.matches.length
            }
          }
        };
        process.stdout.write(JSON.stringify(errorResponse) + "\n");
      }
      return;
    }
    this.child?.stdin?.write(line + "\n");
  }
  stop() {
    if (this.child) {
      this.child.kill("SIGTERM");
      this.child = null;
    }
  }
};
function isJsonRpcRequest(obj) {
  return typeof obj === "object" && obj !== null && "jsonrpc" in obj && obj.jsonrpc === "2.0" && "method" in obj && typeof obj.method === "string";
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  BUILTIN_PATTERNS,
  DEFAULT_CONFIG,
  FirewallProxy,
  Logger,
  buildPatternList,
  loadConfig,
  resetCounter,
  scan
});
//# sourceMappingURL=index.js.map