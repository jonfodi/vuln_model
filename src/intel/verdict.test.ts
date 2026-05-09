import { describe, expect, test } from "bun:test";
import { calculateVerdict } from "./verdict";

describe("calculateVerdict", () => {
  test("promotes known exploited critical vulnerabilities", () => {
    const result = calculateVerdict({
      cisaKev: true,
      epssPercentile: 0.99,
      cvssScore: 10,
      publicExploit: true,
      networkExploitable: true,
      privilegesRequired: "none",
      userInteractionRequired: false,
      fixAvailable: true,
    });

    expect(result.verdict).toBe("Act Now");
    expect(result.reasons).toContain("listed in CISA KEV");
  });

  test("keeps weak-signal vulnerabilities low by default", () => {
    const result = calculateVerdict({
      cisaKev: false,
      epssPercentile: 0.1,
      cvssScore: 4,
      publicExploit: false,
      networkExploitable: false,
      privilegesRequired: "unknown",
      userInteractionRequired: true,
      fixAvailable: false,
    });

    expect(result.verdict).toBe("Low Signal");
  });
});

