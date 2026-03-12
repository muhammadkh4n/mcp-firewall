import { loadConfig } from "./config.js";
import { buildPatternList } from "./scanner.js";
import { Logger } from "./logger.js";
import { FirewallProxy } from "./proxy.js";

function printUsage(): void {
  console.error(`
mcp-firewall - Prompt injection firewall for MCP servers

USAGE:
  npx mcp-firewall [options] -- <command> [args...]

OPTIONS:
  --config <path>   Path to YAML config file (default: firewall.yaml)
  --dry-run         Log detections but never block requests
  --log-level <lvl> Set log level: debug, info, warn, error
  --log-format <f>  Set log format: json, text
  --help            Show this help message

EXAMPLES:
  npx mcp-firewall -- node server.js
  npx mcp-firewall --dry-run --config firewall.yaml -- python mcp_server.py
  npx mcp-firewall --log-format text --log-level debug -- ./my-mcp-server
`);
}

function parseArgs(argv: string[]): {
  configPath?: string;
  dryRun: boolean;
  logLevel?: string;
  logFormat?: string;
  command: string[];
} {
  const result: ReturnType<typeof parseArgs> = {
    dryRun: false,
    command: [],
  };

  let i = 0;
  while (i < argv.length) {
    const arg = argv[i];

    if (arg === "--") {
      result.command = argv.slice(i + 1);
      break;
    }

    switch (arg) {
      case "--help":
      case "-h":
        printUsage();
        process.exit(0);
        break;
      case "--config":
        result.configPath = argv[++i];
        break;
      case "--dry-run":
        result.dryRun = true;
        break;
      case "--log-level":
        result.logLevel = argv[++i];
        break;
      case "--log-format":
        result.logFormat = argv[++i];
        break;
      default:
        // Assume everything from an unknown arg onward is the command
        result.command = argv.slice(i);
        i = argv.length;
        break;
    }
    i++;
  }

  return result;
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));

  if (args.command.length === 0) {
    console.error("Error: No command specified.\n");
    printUsage();
    process.exit(1);
  }

  const config = loadConfig(args.configPath);

  if (args.dryRun) {
    config.dryRun = true;
  }
  if (args.logLevel) {
    config.logging.level = args.logLevel as typeof config.logging.level;
  }
  if (args.logFormat) {
    config.logging.format = args.logFormat as typeof config.logging.format;
  }

  const logger = new Logger(config.logging);
  const patterns = buildPatternList(config);

  logger.info("mcp-firewall started", {
    dryRun: config.dryRun,
    patternCount: patterns.length,
    thresholds: config.thresholds,
  });

  const proxy = new FirewallProxy(patterns, config, logger);
  const [command, ...commandArgs] = args.command;
  proxy.start(command, commandArgs);

  process.on("SIGINT", () => {
    logger.info("Received SIGINT, shutting down");
    proxy.stop();
    process.exit(0);
  });

  process.on("SIGTERM", () => {
    logger.info("Received SIGTERM, shutting down");
    proxy.stop();
    process.exit(0);
  });
}

main();
