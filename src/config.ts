import * as fs from "node:fs";
import * as path from "node:path";
import * as yaml from "js-yaml";
import type { FirewallConfig } from "./types.js";

export const DEFAULT_CONFIG: FirewallConfig = {
  thresholds: {
    warn: 5,
    block: 8,
  },
  logging: {
    level: "info",
    format: "json",
  },
  dryRun: false,
  patterns: {
    enabled: ["*"],
    disabled: [],
    custom: [],
  },
  allowlist: [],
};

export function loadConfig(configPath?: string): FirewallConfig {
  if (!configPath) {
    const candidates = ["firewall.yaml", "firewall.yml", "mcp-firewall.yaml"];
    for (const candidate of candidates) {
      const resolved = path.resolve(candidate);
      if (fs.existsSync(resolved)) {
        configPath = resolved;
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
  const parsed = yaml.load(raw) as Partial<FirewallConfig> | null;

  if (!parsed || typeof parsed !== "object") {
    throw new Error(`Invalid config file: ${resolved}`);
  }

  return mergeConfig(DEFAULT_CONFIG, parsed);
}

function mergeConfig(
  defaults: FirewallConfig,
  overrides: Partial<FirewallConfig>,
): FirewallConfig {
  return {
    thresholds: { ...defaults.thresholds, ...overrides.thresholds },
    logging: { ...defaults.logging, ...overrides.logging },
    dryRun: overrides.dryRun ?? defaults.dryRun,
    patterns: {
      enabled: overrides.patterns?.enabled ?? defaults.patterns.enabled,
      disabled: overrides.patterns?.disabled ?? defaults.patterns.disabled,
      custom: overrides.patterns?.custom ?? defaults.patterns.custom,
    },
    allowlist: overrides.allowlist ?? defaults.allowlist,
  };
}
