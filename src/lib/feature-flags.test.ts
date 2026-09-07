import { afterEach, describe, expect, it } from "vitest";
import { getFeatureFlags } from "./feature-flags";

const originalSourceUploads = process.env.ENABLE_SOURCE_UPLOADS;

afterEach(() => {
  if (originalSourceUploads === undefined) delete process.env.ENABLE_SOURCE_UPLOADS;
  else process.env.ENABLE_SOURCE_UPLOADS = originalSourceUploads;
});

describe("source upload feature flag", () => {
  it("can explicitly disable source transmission for a deployment", () => {
    process.env.ENABLE_SOURCE_UPLOADS = "false";
    expect(getFeatureFlags().sourceUploads).toBe(false);
  });

  it("can explicitly enable source analysis for a trusted private deployment", () => {
    process.env.ENABLE_SOURCE_UPLOADS = "true";
    expect(getFeatureFlags().sourceUploads).toBe(true);
  });
});
