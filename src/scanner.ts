import type {
  FirewallConfig,
  JsonRpcRequest,
  Pattern,
  ScanMatch,
  ScanResult,
  Verdict,
} from "./types.js";
import { BUILTIN_PATTERNS } from "./patterns.js";

let counter = 0;

function nextRequestId(): string {
  return `fw-${Date.now()}-${++counter}`;
}

export function buildPatternList(config: FirewallConfig): Pattern[] {
  const patterns: Pattern[] = [];
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
        regex: new RegExp(custom.regex, "i"),
      });
    }
  }

  return patterns;
}

function extractTextFields(obj: unknown, path: string = ""): Array<{ text: string; location: string }> {
  const fields: Array<{ text: string; location: string }> = [];

  if (typeof obj === "string") {
    fields.push({ text: obj, location: path || "root" });
  } else if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      fields.push(...extractTextFields(obj[i], `${path}[${i}]`));
    }
  } else if (obj !== null && typeof obj === "object") {
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      fields.push(...extractTextFields(value, path ? `${path}.${key}` : key));
    }
  }

  return fields;
}

export function scan(
  request: JsonRpcRequest,
  patterns: Pattern[],
  config: FirewallConfig,
): ScanResult {
  const requestId = nextRequestId();
  const matches: ScanMatch[] = [];

  if (config.allowlist.includes(request.method)) {
    return {
      verdict: "pass",
      totalScore: 0,
      matches: [],
      requestId,
      method: request.method,
      timestamp: new Date().toISOString(),
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
          location: field.location,
        });
      }
    }
  }

  const totalScore = matches.reduce((sum, m) => sum + m.score, 0);
  let verdict: Verdict = "pass";

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
    timestamp: new Date().toISOString(),
  };
}

export function resetCounter(): void {
  counter = 0;
}
