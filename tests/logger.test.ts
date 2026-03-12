import { describe, it, expect, vi } from "vitest";
import { Logger } from "../src/logger.js";
import type { ScanResult } from "../src/types.js";

describe("Logger", () => {
  it("outputs JSON format by default", () => {
    const messages: string[] = [];
    const logger = new Logger(
      { level: "info", format: "json" },
      (msg) => messages.push(msg),
    );

    logger.info("test message", { key: "value" });

    expect(messages).toHaveLength(1);
    const parsed = JSON.parse(messages[0]);
    expect(parsed.level).toBe("info");
    expect(parsed.message).toBe("test message");
    expect(parsed.key).toBe("value");
    expect(parsed.component).toBe("mcp-firewall");
    expect(parsed.timestamp).toBeTruthy();
  });

  it("outputs text format", () => {
    const messages: string[] = [];
    const logger = new Logger(
      { level: "info", format: "text" },
      (msg) => messages.push(msg),
    );

    logger.info("test message");

    expect(messages).toHaveLength(1);
    expect(messages[0]).toContain("[INFO ]");
    expect(messages[0]).toContain("[mcp-firewall]");
    expect(messages[0]).toContain("test message");
  });

  it("respects log level filtering", () => {
    const messages: string[] = [];
    const logger = new Logger(
      { level: "warn", format: "json" },
      (msg) => messages.push(msg),
    );

    logger.debug("should not appear");
    logger.info("should not appear");
    logger.warn("should appear");
    logger.error("should appear");

    expect(messages).toHaveLength(2);
  });

  it("logs inspection results", () => {
    const messages: string[] = [];
    const logger = new Logger(
      { level: "debug", format: "json" },
      (msg) => messages.push(msg),
    );

    const result: ScanResult = {
      verdict: "block",
      totalScore: 15,
      matches: [
        {
          patternId: "classic-injection",
          patternName: "Classic Prompt Injection",
          category: "classic-injection",
          score: 9,
          matched: "ignore previous instructions",
          location: "params.arguments.text",
        },
      ],
      requestId: "fw-test-1",
      method: "tools/call",
      timestamp: new Date().toISOString(),
    };

    logger.inspection(result);

    expect(messages).toHaveLength(1);
    const parsed = JSON.parse(messages[0]);
    expect(parsed.verdict).toBe("block");
    expect(parsed.totalScore).toBe(15);
    expect(parsed.matchCount).toBe(1);
  });

  it("logs pass verdicts at debug level", () => {
    const messages: string[] = [];
    const logger = new Logger(
      { level: "info", format: "json" },
      (msg) => messages.push(msg),
    );

    const result: ScanResult = {
      verdict: "pass",
      totalScore: 0,
      matches: [],
      requestId: "fw-test-2",
      method: "tools/call",
      timestamp: new Date().toISOString(),
    };

    logger.inspection(result);

    // Pass verdicts are debug level, logger is at info - should not appear
    expect(messages).toHaveLength(0);
  });
});
