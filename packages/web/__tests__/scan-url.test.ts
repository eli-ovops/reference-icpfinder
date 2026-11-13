// SPDX-License-Identifier: MIT

import { describe, expect, it } from "vitest";
import { isPrivateIp, scanUrl } from "../lib/scan-url";

describe("isPrivateIp — SSRF guard", () => {
  it("rejects IPv4 loopback / private / link-local / CGNAT / reserved", () => {
    for (const addr of [
      "127.0.0.1",
      "[REDACTED_HOST]",
      "[REDACTED_HOST]",
      "[REDACTED_HOST]",
      "[REDACTED_HOST]",
      "[REDACTED_HOST]",
      "[REDACTED_HOST]",
      "[REDACTED_HOST]", // AWS / GCP metadata
      "[REDACTED_HOST]", // CGNAT
      "[REDACTED_HOST]", // CGNAT end
      "0.0.0.0",
      "[REDACTED_HOST]", // multicast
      "[REDACTED_HOST]", // reserved
      "255.255.255.255", // broadcast
    ]) {
      expect(isPrivateIp(addr), `should reject ${addr}`).toBe(true);
    }
  });

  it("allows IPv4 public addresses", () => {
    for (const addr of ["[REDACTED_HOST]", "[REDACTED_HOST]", "[REDACTED_HOST]", "[REDACTED_HOST]"]) {
      expect(isPrivateIp(addr), `should allow ${addr}`).toBe(false);
    }
  });

  it("rejects IPv6 loopback / unspecified / link-local / unique-local / multicast", () => {
    for (const addr of [
      "::1",
      "::",
      "fe80::1",
      "FE80:0000:0000:0000:0000:0000:0000:0001",
      "fc00::1",
      "fd00::abcd",
      "ff02::1",
    ]) {
      expect(isPrivateIp(addr), `should reject ${addr}`).toBe(true);
    }
  });

  it("rejects IPv4-mapped IPv6 loopback", () => {
    expect(isPrivateIp("::ffff:127.0.0.1")).toBe(true);
    expect(isPrivateIp("::ffff:[REDACTED_HOST]")).toBe(true);
  });

  it("allows public IPv6", () => {
    expect(isPrivateIp("2606:4700:4700::1111")).toBe(false); // [REDACTED_HOST]
    expect(isPrivateIp("2001:4860:4860::8888")).toBe(false); // Google DNS
  });
});

describe("scanUrl — refuses private addresses", () => {
  it("refuses an explicit loopback URL without issuing a fetch", async () => {
    const result = await scanUrl("http://127.0.0.1:6379/");
    expect(result.error).toBeDefined();
    expect(result.error).toMatch(/private|reserved|Refused/i);
    expect(result.scan).toBeUndefined();
  });

  it("refuses cloud metadata endpoint", async () => {
    const result = await scanUrl("http://[REDACTED_HOST]/latest/meta-data/");
    expect(result.error).toBeDefined();
    expect(result.error).toMatch(/private|reserved|Refused/i);
    expect(result.scan).toBeUndefined();
  });

  it("refuses non-http(s) protocols", async () => {
    const result = await scanUrl("file:///etc/passwd");
    expect(result.error).toMatch(/Only http\(s\)/i);
  });

  it("refuses malformed URLs cleanly", async () => {
    const result = await scanUrl("not a url");
    expect(result.error).toMatch(/Invalid URL/i);
  });
});
