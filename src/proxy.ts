import { spawn, type ChildProcess } from "node:child_process";
import type { FirewallConfig, JsonRpcRequest, JsonRpcResponse, Pattern } from "./types.js";
import { scan } from "./scanner.js";
import { Logger } from "./logger.js";

export class FirewallProxy {
  private child: ChildProcess | null = null;
  private patterns: Pattern[];
  private config: FirewallConfig;
  private logger: Logger;
  private inputBuffer = "";

  constructor(patterns: Pattern[], config: FirewallConfig, logger: Logger) {
    this.patterns = patterns;
    this.config = config;
    this.logger = logger;
  }

  start(command: string, args: string[]): void {
    this.logger.info("Starting MCP server", { command, args });

    this.child = spawn(command, args, {
      stdio: ["pipe", "pipe", "inherit"],
    });

    this.child.on("error", (err) => {
      this.logger.error("Failed to start server process", {
        error: err.message,
      });
      process.exit(1);
    });

    this.child.on("exit", (code) => {
      this.logger.info("Server process exited", { code });
      process.exit(code ?? 0);
    });

    // Server stdout → Client stdout (passthrough)
    this.child.stdout?.on("data", (chunk: Buffer) => {
      process.stdout.write(chunk);
    });

    // Client stdin → Firewall inspection → Server stdin
    process.stdin.on("data", (chunk: Buffer) => {
      this.handleInput(chunk);
    });

    process.stdin.on("end", () => {
      this.child?.stdin?.end();
    });
  }

  private handleInput(chunk: Buffer): void {
    this.inputBuffer += chunk.toString();

    // JSON-RPC messages are newline-delimited
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

  private processLine(line: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      // Not JSON — pass through as-is
      this.child?.stdin?.write(line + "\n");
      return;
    }

    if (!isJsonRpcRequest(parsed)) {
      // JSON-RPC response or notification without method — pass through
      this.child?.stdin?.write(line + "\n");
      return;
    }

    const request = parsed as JsonRpcRequest;
    const result = scan(request, this.patterns, this.config);
    this.logger.inspection(result);

    if (result.verdict === "block" && !this.config.dryRun) {
      this.logger.warn("Blocked request", {
        method: request.method,
        requestId: result.requestId,
        totalScore: result.totalScore,
      });

      // Send JSON-RPC error response back to client
      if (request.id !== undefined) {
        const errorResponse: JsonRpcResponse = {
          jsonrpc: "2.0",
          id: request.id,
          error: {
            code: -32001,
            message: "Request blocked by mcp-firewall: prompt injection detected",
            data: {
              verdict: result.verdict,
              totalScore: result.totalScore,
              matchCount: result.matches.length,
            },
          },
        };
        process.stdout.write(JSON.stringify(errorResponse) + "\n");
      }
      return;
    }

    // Pass through (pass or warn or dry-run block)
    this.child?.stdin?.write(line + "\n");
  }

  stop(): void {
    if (this.child) {
      this.child.kill("SIGTERM");
      this.child = null;
    }
  }
}

function isJsonRpcRequest(obj: unknown): obj is JsonRpcRequest {
  return (
    typeof obj === "object" &&
    obj !== null &&
    "jsonrpc" in obj &&
    (obj as Record<string, unknown>).jsonrpc === "2.0" &&
    "method" in obj &&
    typeof (obj as Record<string, unknown>).method === "string"
  );
}
