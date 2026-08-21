import Database from "better-sqlite3";
import fs from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { RawAdvisory, Scan } from "@/lib/types";

const directory = process.env.DEPSHIELD_DATA_DIR??(process.env.VERCEL?path.join(tmpdir(),"depshield"):path.join(process.cwd(),"data"));
fs.mkdirSync(directory, { recursive: true });
const db = new Database(path.join(directory, "depshield.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    project TEXT NOT NULL,
    score INTEGER NOT NULL,
    grade TEXT NOT NULL,
    payload TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS vulnerability_cache (
    ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL,
    version TEXT NOT NULL,
    payload TEXT NOT NULL,
    fetched_at INTEGER NOT NULL,
    PRIMARY KEY (ecosystem, package_name, version)
  );
`);

export function saveScan(scan: Scan) {
  const transaction = db.transaction((value: Scan) => {
    db.prepare(`INSERT OR REPLACE INTO scans(id,created_at,project,score,grade,payload) VALUES(?,?,?,?,?,?)`)
      .run(value.id, value.createdAt, value.project, value.score, value.grade, JSON.stringify(value));
  });
  transaction(scan);
  return scan;
}

export function listScans(limit = 50): Scan[] {
  return db.prepare(`SELECT payload FROM scans ORDER BY created_at DESC LIMIT ?`).all(limit)
    .map(row => JSON.parse((row as { payload: string }).payload) as Scan);
}

export function getScan(id: string): Scan | null {
  const row = db.prepare(`SELECT payload FROM scans WHERE id = ?`).get(id) as { payload: string } | undefined;
  return row ? JSON.parse(row.payload) as Scan : null;
}

export function getCachedAdvisories(name: string, version: string, maxAgeMs: number): RawAdvisory[] | null {
  const row = db.prepare(`SELECT payload, fetched_at FROM vulnerability_cache WHERE ecosystem='npm' AND package_name=? AND version=?`)
    .get(name, version) as { payload: string; fetched_at: number } | undefined;
  if (!row || Date.now() - row.fetched_at > maxAgeMs) return null;
  return JSON.parse(row.payload) as RawAdvisory[];
}

export function setCachedAdvisories(name: string, version: string, advisories: RawAdvisory[]) {
  db.prepare(`INSERT OR REPLACE INTO vulnerability_cache(ecosystem,package_name,version,payload,fetched_at) VALUES('npm',?,?,?,?)`)
    .run(name, version, JSON.stringify(advisories), Date.now());
}

export function clearExpiredVulnerabilityCache(maxAgeMs: number) {
  return db.prepare(`DELETE FROM vulnerability_cache WHERE fetched_at < ?`).run(Date.now() - maxAgeMs).changes;
}
