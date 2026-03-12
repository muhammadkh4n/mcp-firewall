import { describe, it, expect } from "vitest";
import { loadConfig, DEFAULT_CONFIG } from "../src/config.js";
import * as path from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";

describe("Config Loader", () => {
  it("throws when explicit config file not found", () => {
    expect(() => loadConfig("/nonexistent/path/firewall.yaml")).toThrow(
      "Config file not found",
    );
  });

  it("returns default config when no config path given", () => {
    // When called with no path and no default files exist, returns defaults
    const config = loadConfig();
    expect(config.thresholds.warn).toBe(DEFAULT_CONFIG.thresholds.warn);
    expect(config.thresholds.block).toBe(DEFAULT_CONFIG.thresholds.block);
  });

  it("has correct default thresholds", () => {
    expect(DEFAULT_CONFIG.thresholds.warn).toBe(5);
    expect(DEFAULT_CONFIG.thresholds.block).toBe(8);
  });

  it("has correct default logging", () => {
    expect(DEFAULT_CONFIG.logging.level).toBe("info");
    expect(DEFAULT_CONFIG.logging.format).toBe("json");
  });

  it("has correct default pattern config", () => {
    expect(DEFAULT_CONFIG.patterns.enabled).toEqual(["*"]);
    expect(DEFAULT_CONFIG.patterns.disabled).toEqual([]);
    expect(DEFAULT_CONFIG.patterns.custom).toEqual([]);
  });

  it("defaults dryRun to false", () => {
    expect(DEFAULT_CONFIG.dryRun).toBe(false);
  });

  it("loads and merges YAML config", () => {
    const tmpDir = os.tmpdir();
    const tmpFile = path.join(tmpDir, `test-firewall-${Date.now()}.yaml`);

    fs.writeFileSync(
      tmpFile,
      `
thresholds:
  warn: 3
  block: 6
logging:
  level: debug
  format: text
dryRun: true
`,
    );

    try {
      const config = loadConfig(tmpFile);
      expect(config.thresholds.warn).toBe(3);
      expect(config.thresholds.block).toBe(6);
      expect(config.logging.level).toBe("debug");
      expect(config.logging.format).toBe("text");
      expect(config.dryRun).toBe(true);
      // Defaults should still be present for unspecified fields
      expect(config.patterns.enabled).toEqual(["*"]);
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });

  it("throws on invalid config file content", () => {
    const tmpDir = os.tmpdir();
    const tmpFile = path.join(tmpDir, `test-firewall-invalid-${Date.now()}.yaml`);

    fs.writeFileSync(tmpFile, "just a plain string");

    try {
      // A plain string is technically valid YAML but not an object
      expect(() => loadConfig(tmpFile)).toThrow("Invalid config file");
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });
});
