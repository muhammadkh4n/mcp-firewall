export interface Pattern {
  id: string;
  name: string;
  category: PatternCategory;
  description: string;
  regex: RegExp;
  score: number;
}

export type PatternCategory =
  | "classic-injection"
  | "role-hijacking"
  | "instruction-override"
  | "encoded-base64"
  | "encoded-hex"
  | "encoded-unicode"
  | "exfiltration-network"
  | "exfiltration-filesystem"
  | "chaining"
  | "context-stuffing"
  | "delimiter-injection"
  | "tool-abuse";

export type Verdict = "pass" | "warn" | "block";

export interface ScanMatch {
  patternId: string;
  patternName: string;
  category: PatternCategory;
  score: number;
  matched: string;
  location: string;
}

export interface ScanResult {
  verdict: Verdict;
  totalScore: number;
  matches: ScanMatch[];
  requestId: string | number | null;
  method: string | undefined;
  timestamp: string;
}

export interface Thresholds {
  warn: number;
  block: number;
}

export interface LoggingConfig {
  level: "debug" | "info" | "warn" | "error";
  format: "json" | "text";
}

export interface FirewallConfig {
  thresholds: Thresholds;
  logging: LoggingConfig;
  dryRun: boolean;
  patterns: {
    enabled: string[];
    disabled: string[];
    custom: Array<{
      id: string;
      name: string;
      category: PatternCategory;
      description: string;
      regex: string;
      score: number;
    }>;
  };
  allowlist: string[];
}

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number;
  method: string;
  params?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id?: string | number;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}
