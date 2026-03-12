export { scan, buildPatternList, resetCounter } from "./scanner.js";
export { loadConfig, DEFAULT_CONFIG } from "./config.js";
export { Logger } from "./logger.js";
export { FirewallProxy } from "./proxy.js";
export { BUILTIN_PATTERNS } from "./patterns.js";
export type {
  Pattern,
  PatternCategory,
  Verdict,
  ScanMatch,
  ScanResult,
  Thresholds,
  LoggingConfig,
  FirewallConfig,
  JsonRpcRequest,
  JsonRpcResponse,
} from "./types.js";
