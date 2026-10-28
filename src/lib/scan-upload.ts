const EXCLUDED = /(^|\/)(?:node_modules|\.next|\.git|dist|build|coverage)(\/|$)/i;
export function uploadPath(file: File) {
  return (file.webkitRelativePath || file.name).replaceAll("\\", "/");
}
export function selectUploadFiles(files: File[], folder: boolean) {
  const candidates = files.filter(file => !EXCLUDED.test(uploadPath(file)));
  let root = "";
  if (folder) {
    root = uploadPath(files[0]).split("/")[0] + "/";
    if (!candidates.some(file => uploadPath(file) === root + "package.json")) throw new Error("Choose the project folder that directly contains package.json and package-lock.json.");
  } else if (candidates.some(file => !["package.json", "package-lock.json"].includes(file.name))) {
    throw new Error("Choose package.json and package-lock.json, not other JSON files.");
  }
  const manifest = candidates.find(file => uploadPath(file) === root + "package.json");
  const lock = candidates.find(file => uploadPath(file) === root + "package-lock.json");
  if (manifest && manifest.size > 1024 * 1024) throw new Error("package.json exceeds the 1 MB limit.");
  if (lock && lock.size > 16 * 1024 * 1024) throw new Error("package-lock.json exceeds the 16 MB limit.");
  const sources = candidates.filter(file => uploadPath(file).startsWith(root) && /\.(?:js|jsx|ts|tsx|mjs|cjs|mts|cts)$/i.test(file.name) && file.size <= 512 * 1024).slice(0, 750);
  return { manifest, lock, root, sources };
}
