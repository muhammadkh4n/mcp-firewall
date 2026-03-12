import type { LoggingConfig, ScanResult } from "./types.js";

export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

export class Logger {
  private level: LogLevel;
  private format: "json" | "text";
  private output: (msg: string) => void;

  constructor(config: LoggingConfig, output?: (msg: string) => void) {
    this.level = config.level;
    this.format = config.format;
    this.output = output ?? ((msg) => process.stderr.write(msg + "\n"));
  }

  private shouldLog(level: LogLevel): boolean {
    return LEVEL_ORDER[level] >= LEVEL_ORDER[this.level];
  }

  private write(level: LogLevel, message: string, data?: object): void {
    if (!this.shouldLog(level)) return;

    if (this.format === "json") {
      this.output(
        JSON.stringify({
          timestamp: new Date().toISOString(),
          level,
          component: "mcp-firewall",
          message,
          ...data,
        }),
      );
    } else {
      const ts = new Date().toISOString();
      const prefix = `[${ts}] [${level.toUpperCase().padEnd(5)}] [mcp-firewall]`;
      const extra = data ? ` ${JSON.stringify(data)}` : "";
      this.output(`${prefix} ${message}${extra}`);
    }
  }

  debug(message: string, data?: object): void {
    this.write("debug", message, data);
  }

  info(message: string, data?: object): void {
    this.write("info", message, data);
  }

  warn(message: string, data?: object): void {
    this.write("warn", message, data);
  }

  error(message: string, data?: object): void {
    this.write("error", message, data);
  }

  inspection(result: ScanResult): void {
    const level: LogLevel =
      result.verdict === "pass" ? "debug" : result.verdict === "warn" ? "warn" : "error";
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
        text: m.matched.slice(0, 100),
      })),
    });
  }
}
