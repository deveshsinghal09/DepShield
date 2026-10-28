import { describe, expect, it } from "vitest";
import { selectUploadFiles } from "./scan-upload";

function file(path: string, size = 10) {
  return { name: path.split("/").at(-1), webkitRelativePath: path.includes("/") ? path : "", size } as File;
}
describe("scan upload selection", () => {
  it("accepts a single manifest for staged selection", () => {
    expect(selectUploadFiles([file("package.json")], false).lock).toBeUndefined();
  });
  it("pairs only files in the selected folder root", () => {
    const selected = selectUploadFiles([file("app/package.json"), file("app/child/package-lock.json")], true);
    expect(selected.lock).toBeUndefined();
  });
  it("rejects a parent folder instead of silently picking a nested project", () => {
    expect(() => selectUploadFiles([file("parent/app/package.json")], true)).toThrow("directly contains");
  });
  it("ignores generated source and installed packages", () => {
    const selected = selectUploadFiles([file("app/package.json"), file("app/package-lock.json"), file("app/node_modules/x/index.js"), file("app/.next/app.js"), file("app/src/app.ts")], true);
    expect(selected.sources.map(f => f.name)).toEqual(["app.ts"]);
    expect(selected.lock?.name).toBe("package-lock.json");
  });
  it("rejects unrelated JSON and oversized manifests", () => {
    expect(() => selectUploadFiles([file("config.json")], false)).toThrow("not other JSON");
    expect(() => selectUploadFiles([file("package.json", 1024 * 1024 + 1)], false)).toThrow("1 MB");
  });
});
