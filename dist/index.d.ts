interface Pattern {
    id: string;
    name: string;
    category: PatternCategory;
    description: string;
    regex: RegExp;
    score: number;
}
type PatternCategory = "classic-injection" | "role-hijacking" | "instruction-override" | "encoded-base64" | "encoded-hex" | "encoded-unicode" | "exfiltration-network" | "exfiltration-filesystem" | "chaining" | "context-stuffing" | "delimiter-injection" | "tool-abuse";
type Verdict = "pass" | "warn" | "block";
interface ScanMatch {
    patternId: string;
    patternName: string;
    category: PatternCategory;
    score: number;
    matched: string;
    location: string;
}
interface ScanResult {
    verdict: Verdict;
    totalScore: number;
    matches: ScanMatch[];
    requestId: string | number | null;
    method: string | undefined;
    timestamp: string;
}
interface Thresholds {
    warn: number;
    block: number;
}
interface LoggingConfig {
    level: "debug" | "info" | "warn" | "error";
    format: "json" | "text";
}
interface FirewallConfig {
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
interface JsonRpcRequest {
    jsonrpc: "2.0";
    id?: string | number;
    method: string;
    params?: unknown;
}
interface JsonRpcResponse {
    jsonrpc: "2.0";
    id?: string | number;
    result?: unknown;
    error?: {
        code: number;
        message: string;
        data?: unknown;
    };
}

declare function buildPatternList(config: FirewallConfig): Pattern[];
declare function scan(request: JsonRpcRequest, patterns: Pattern[], config: FirewallConfig): ScanResult;
declare function resetCounter(): void;

declare const DEFAULT_CONFIG: FirewallConfig;
declare function loadConfig(configPath?: string): FirewallConfig;

declare class Logger {
    private level;
    private format;
    private output;
    constructor(config: LoggingConfig, output?: (msg: string) => void);
    private shouldLog;
    private write;
    debug(message: string, data?: object): void;
    info(message: string, data?: object): void;
    warn(message: string, data?: object): void;
    error(message: string, data?: object): void;
    inspection(result: ScanResult): void;
}

declare class FirewallProxy {
    private child;
    private patterns;
    private config;
    private logger;
    private inputBuffer;
    constructor(patterns: Pattern[], config: FirewallConfig, logger: Logger);
    start(command: string, args: string[]): void;
    private handleInput;
    private processLine;
    stop(): void;
}

declare const BUILTIN_PATTERNS: Pattern[];

export { BUILTIN_PATTERNS, DEFAULT_CONFIG, type FirewallConfig, FirewallProxy, type JsonRpcRequest, type JsonRpcResponse, Logger, type LoggingConfig, type Pattern, type PatternCategory, type ScanMatch, type ScanResult, type Thresholds, type Verdict, buildPatternList, loadConfig, resetCounter, scan };
