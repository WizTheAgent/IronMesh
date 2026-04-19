import { describe, expect, it } from "vitest";

import {
  validateChannelConfig,
  resolveChannelAccount,
  listChannelAccountIds,
  ChannelConfigSchema,
} from "../src/config-schema.js";

const goodCfg = {
  channels: {
    ironmesh: {
      default: {
        url: "ws://127.0.0.1:8765",
        passphrase: "twelve-or-more",
        name: "agent",
      },
    },
  },
};

describe("validateChannelConfig", () => {
  it("accepts a known-good config", () => {
    expect(validateChannelConfig(goodCfg)).toEqual([]);
  });

  it("accepts a config with no channels.ironmesh section (no errors)", () => {
    expect(validateChannelConfig({})).toEqual([]);
    expect(validateChannelConfig({ channels: {} })).toEqual([]);
  });

  it("rejects a config that is not an object", () => {
    const errs = validateChannelConfig("nope");
    expect(errs.some((e) => /must be an object/.test(e.message))).toBe(true);
  });

  it("rejects a missing url field", () => {
    const cfg = {
      channels: { ironmesh: { default: { passphrase: "twelve-or-more", name: "x" } } },
    };
    const errs = validateChannelConfig(cfg);
    expect(errs.find((e) => e.path.endsWith(".url"))).toBeTruthy();
  });

  it("rejects a passphrase shorter than 12 chars", () => {
    const cfg = {
      channels: { ironmesh: { default: { url: "ws://x", passphrase: "short", name: "x" } } },
    };
    const errs = validateChannelConfig(cfg);
    expect(errs.find((e) => /minimum 12/.test(e.message))).toBeTruthy();
  });

  it("rejects a non-ws URL scheme", () => {
    const cfg = {
      channels: { ironmesh: { default: { url: "http://x", passphrase: "twelve-or-more", name: "x" } } },
    };
    const errs = validateChannelConfig(cfg);
    expect(errs.find((e) => /ws:\/\/ or wss:\/\//.test(e.message))).toBeTruthy();
  });
});

describe("resolveChannelAccount", () => {
  it("returns the only account when none is named", () => {
    const acc = resolveChannelAccount(goodCfg);
    expect(acc.accountId).toBe("default");
    expect(acc.url).toBe("ws://127.0.0.1:8765");
  });

  it("returns the named account when accountId is given", () => {
    const cfg = {
      channels: {
        ironmesh: {
          alpha: { url: "ws://a", passphrase: "twelve-or-more", name: "a" },
          beta: { url: "ws://b", passphrase: "twelve-or-more", name: "b" },
        },
      },
    };
    const acc = resolveChannelAccount(cfg, "beta");
    expect(acc.accountId).toBe("beta");
    expect(acc.url).toBe("ws://b");
  });

  it("throws on a config that fails validation", () => {
    const bad = { channels: { ironmesh: { x: { url: "ws://x", passphrase: "short", name: "x" } } } };
    expect(() => resolveChannelAccount(bad)).toThrow(/invalid config/);
  });

  it("throws when the named accountId does not exist", () => {
    expect(() => resolveChannelAccount(goodCfg, "nope")).toThrow(/no account "nope"/);
  });

  it("throws when no accounts are configured", () => {
    expect(() => resolveChannelAccount({ channels: { ironmesh: {} } })).toThrow(/no accounts configured/);
  });
});

describe("listChannelAccountIds", () => {
  it("returns the account names in declaration order", () => {
    const cfg = {
      channels: {
        ironmesh: {
          one: { url: "ws://x", passphrase: "twelve-or-more", name: "1" },
          two: { url: "ws://y", passphrase: "twelve-or-more", name: "2" },
        },
      },
    };
    expect(listChannelAccountIds(cfg)).toEqual(["one", "two"]);
  });

  it("returns [] when no IronMesh section is present", () => {
    expect(listChannelAccountIds({})).toEqual([]);
  });
});

describe("ChannelConfigSchema", () => {
  it("declares required fields and valid types in a JSON-Schema-shaped descriptor", () => {
    const accountSchema =
      ChannelConfigSchema.properties.channels.properties.ironmesh.additionalProperties;
    expect(accountSchema.required).toEqual(["url", "passphrase", "name"]);
    expect(accountSchema.properties.passphrase.minLength).toBe(12);
    expect(accountSchema.properties.url.pattern).toBe("^wss?://");
  });
});
