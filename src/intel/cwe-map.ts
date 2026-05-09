export type WeaknessMapping = {
  cweId: string;
  name: string;
  primitive: string;
  likelyOutcomes: string[];
  commonPrerequisites: string[];
};

export const weaknessMappings: Record<string, WeaknessMapping> = {
  "CWE-22": {
    cweId: "CWE-22",
    name: "Path Traversal",
    primitive: "arbitrary file path access",
    likelyOutcomes: ["secret theft", "configuration disclosure", "data exposure"],
    commonPrerequisites: ["attacker-controlled path input"],
  },
  "CWE-78": {
    cweId: "CWE-78",
    name: "OS Command Injection",
    primitive: "arbitrary command execution",
    likelyOutcomes: ["remote code execution", "server takeover", "data theft"],
    commonPrerequisites: ["attacker-controlled input reaches command construction"],
  },
  "CWE-79": {
    cweId: "CWE-79",
    name: "Cross-Site Scripting",
    primitive: "browser script execution",
    likelyOutcomes: ["session theft", "account takeover", "user impersonation"],
    commonPrerequisites: ["attacker-controlled content is rendered to a user"],
  },
  "CWE-89": {
    cweId: "CWE-89",
    name: "SQL Injection",
    primitive: "database query manipulation",
    likelyOutcomes: ["data exfiltration", "data modification", "auth bypass"],
    commonPrerequisites: ["attacker-controlled input reaches a database query"],
  },
  "CWE-287": {
    cweId: "CWE-287",
    name: "Improper Authentication",
    primitive: "authentication bypass",
    likelyOutcomes: ["unauthorized access", "account takeover", "privilege escalation"],
    commonPrerequisites: ["reachable authentication flow"],
  },
  "CWE-400": {
    cweId: "CWE-400",
    name: "Uncontrolled Resource Consumption",
    primitive: "resource exhaustion",
    likelyOutcomes: ["denial of service", "service degradation"],
    commonPrerequisites: ["repeatable attacker-controlled request or input"],
  },
  "CWE-502": {
    cweId: "CWE-502",
    name: "Deserialization of Untrusted Data",
    primitive: "object graph manipulation",
    likelyOutcomes: ["remote code execution", "auth bypass", "denial of service"],
    commonPrerequisites: ["application deserializes attacker-controlled data"],
  },
  "CWE-787": {
    cweId: "CWE-787",
    name: "Out-of-bounds Write",
    primitive: "memory corruption",
    likelyOutcomes: ["remote code execution", "process crash", "sandbox escape"],
    commonPrerequisites: ["attacker-controlled input reaches vulnerable memory operation"],
  },
  "CWE-862": {
    cweId: "CWE-862",
    name: "Missing Authorization",
    primitive: "authorization bypass",
    likelyOutcomes: ["data exposure", "unauthorized action", "privilege escalation"],
    commonPrerequisites: ["reachable object or action lacks authorization check"],
  },
  "CWE-918": {
    cweId: "CWE-918",
    name: "Server-Side Request Forgery",
    primitive: "server-side request forgery",
    likelyOutcomes: ["internal service access", "cloud credential theft", "network pivot"],
    commonPrerequisites: ["attacker can influence server-side URL or request target"],
  },
};

export function getWeaknessMapping(cweId: string): WeaknessMapping | undefined {
  return weaknessMappings[cweId.toUpperCase()];
}

