import type { Pattern } from "./types.js";

export const BUILTIN_PATTERNS: Pattern[] = [
  // 1. Classic prompt injection
  {
    id: "classic-injection",
    name: "Classic Prompt Injection",
    category: "classic-injection",
    description:
      "Detects classic prompt injection phrases like 'ignore previous instructions'",
    regex:
      /(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions|prompts|rules|guidelines|context)/i,
    score: 9,
  },

  // 2. Role hijacking
  {
    id: "role-hijacking",
    name: "Role Hijacking",
    category: "role-hijacking",
    description:
      "Detects attempts to reassign the model's identity or role",
    regex:
      /(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|switch\s+to\s+role|new\s+system\s+prompt|act\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|evil|jailbroken))/i,
    score: 8,
  },

  // 3. Instruction override
  {
    id: "instruction-override",
    name: "Instruction Override",
    category: "instruction-override",
    description:
      "Detects attempts to bypass safety mechanisms or override instructions",
    regex:
      /(?:bypass\s+(?:all\s+)?(?:safety|security|filter|restriction|guard)|disable\s+(?:all\s+)?(?:safety|filter|content|restriction)|ignore\s+(?:all\s+)?(?:safety|ethical|content)\s+(?:guidelines|policies|rules|filters))/i,
    score: 9,
  },

  // 4. Base64 encoded payloads
  {
    id: "encoded-base64",
    name: "Base64 Encoded Payload",
    category: "encoded-base64",
    description:
      "Detects base64-encoded strings that may contain hidden instructions",
    regex:
      /(?:decode|execute|run|eval)\s+(?:this\s+)?(?:base64|b64)[:\s]+[A-Za-z0-9+/]{20,}={0,2}/i,
    score: 7,
  },

  // 5. Hex encoded payloads
  {
    id: "encoded-hex",
    name: "Hex Encoded Payload",
    category: "encoded-hex",
    description: "Detects hex-encoded strings that may contain hidden commands",
    regex:
      /(?:decode|execute|run|eval)\s+(?:this\s+)?hex[:\s]+(?:0x)?[0-9a-fA-F]{20,}/i,
    score: 7,
  },

  // 6. Unicode escape sequences
  {
    id: "encoded-unicode",
    name: "Unicode Escape Injection",
    category: "encoded-unicode",
    description:
      "Detects suspicious unicode escape sequences used to hide instructions",
    regex: /(?:\\u[0-9a-fA-F]{4}){5,}/,
    score: 6,
  },

  // 7. Network exfiltration
  {
    id: "exfiltration-network",
    name: "Network Exfiltration",
    category: "exfiltration-network",
    description:
      "Detects attempts to exfiltrate data over network connections",
    regex:
      /(?:send|post|upload|transmit|exfiltrate|forward)\s+(?:all\s+)?(?:data|information|content|results|output|credentials|secrets|tokens|keys|passwords)\s+(?:to|via|through|using)\s+(?:https?:\/\/|ftp:\/\/|wss?:\/\/)/i,
    score: 10,
  },

  // 8. Filesystem exfiltration
  {
    id: "exfiltration-filesystem",
    name: "Filesystem Access",
    category: "exfiltration-filesystem",
    description:
      "Detects attempts to access sensitive filesystem paths or credentials",
    regex:
      /(?:read|cat|access|dump|show|display|print)\s+(?:the\s+)?(?:\/etc\/(?:passwd|shadow|hosts)|~\/\.ssh|~\/\.aws|~\/\.env|credentials|\.git\/config|\.npmrc|\.netrc)/i,
    score: 9,
  },

  // 9. Chaining / multi-step attacks
  {
    id: "chaining",
    name: "Multi-Step Attack Chain",
    category: "chaining",
    description:
      "Detects attempts to chain multiple actions as a coordinated attack",
    regex:
      /(?:step\s*[1-9][:\s].*(?:then|next|after\s+that|step\s*[2-9]))/is,
    score: 5,
  },

  // 10. Context stuffing
  {
    id: "context-stuffing",
    name: "Context Window Stuffing",
    category: "context-stuffing",
    description:
      "Detects padding attacks that attempt to overflow the context window",
    regex: /(.{1,10})\1{50,}/,
    score: 6,
  },

  // 11. Delimiter injection
  {
    id: "delimiter-injection",
    name: "Delimiter Injection",
    category: "delimiter-injection",
    description:
      "Detects injection of system-level delimiters to escape prompt boundaries",
    regex:
      /(?:<\|(?:im_start|im_end|system|endoftext)\|>|<\/?(?:system|instruction|tool_call)>|\[INST\]|\[\/INST\]|<<\s*SYS\s*>>)/i,
    score: 8,
  },

  // 12. Tool abuse
  {
    id: "tool-abuse",
    name: "Tool Invocation Abuse",
    category: "tool-abuse",
    description:
      "Detects attempts to invoke tools or execute commands directly",
    regex:
      /(?:call\s+(?:the\s+)?tool|execute\s+(?:the\s+)?(?:function|command|shell)|run\s+(?:the\s+)?(?:shell|bash|cmd|powershell|exec)|invoke\s+(?:the\s+)?(?:function|method|api))\s+/i,
    score: 6,
  },
];
