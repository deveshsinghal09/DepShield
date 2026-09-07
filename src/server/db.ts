import Database from "better-sqlite3";
import fs from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { RawAdvisory, Scan } from "@/lib/types";
import type { SecurityPolicy } from "@/lib/policy";
import type { ReplayEvidenceInput } from "@/lib/security-exports";

const directory = process.env.DEPSHIELD_DATA_DIR ?? (
  process.env.VERCEL ? path.join(tmpdir(), "depshield") : path.join(process.cwd(), "data")
);
fs.mkdirSync(directory, { recursive: true });
const db = new Database(path.join(directory, "depshield.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`);
const migrations = [
  {
    version: 1,
    sql: `
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
    `,
  },
  {
    version: 2,
    sql: `
      CREATE TABLE IF NOT EXISTS security_policies (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        payload TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS scan_artifacts (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('sbom','evidence-pack','security-diff')),
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS scan_artifacts_scan_kind ON scan_artifacts(scan_id, kind);
      CREATE TABLE IF NOT EXISTS replay_evidence (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        dependency TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
      );
    `,
  },
] as const;

const migrate = db.transaction(() => {
  const applied = new Set(
    db.prepare(`SELECT version FROM schema_migrations`).all().map((row) => (row as { version: number }).version),
  );
  for (const migration of migrations) {
    if (applied.has(migration.version)) continue;
    db.exec(migration.sql);
    db.prepare(`INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)`)
      .run(migration.version, new Date().toISOString());
  }
});
migrate();

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
    .flatMap((row) => {
      const value = parseStoredJson<Scan>((row as { payload: string }).payload, "scan");
      return value ? [value] : [];
    });
}

export function getScan(id: string): Scan | null {
  const row = db.prepare(`SELECT payload FROM scans WHERE id = ?`).get(id) as { payload: string } | undefined;
  return row ? parseStoredJson<Scan>(row.payload, `scan ${id}`) : null;
}

export function getCachedAdvisories(name: string, version: string, maxAgeMs: number): RawAdvisory[] | null {
  const row = db.prepare(`SELECT payload, fetched_at FROM vulnerability_cache WHERE ecosystem='npm' AND package_name=? AND version=?`)
    .get(name, version) as { payload: string; fetched_at: number } | undefined;
  if (!row || Date.now() - row.fetched_at > maxAgeMs) return null;
  const value = parseStoredJson<RawAdvisory[]>(row.payload, `vulnerability cache ${name}@${version}`);
  if (value) return value;
  db.prepare(`DELETE FROM vulnerability_cache WHERE ecosystem='npm' AND package_name=? AND version=?`).run(name, version);
  return null;
}

export function setCachedAdvisories(name: string, version: string, advisories: RawAdvisory[]) {
  db.prepare(`INSERT OR REPLACE INTO vulnerability_cache(ecosystem,package_name,version,payload,fetched_at) VALUES('npm',?,?,?,?)`)
    .run(name, version, JSON.stringify(advisories), Date.now());
}

export function clearExpiredVulnerabilityCache(maxAgeMs: number) {
  return db.prepare(`DELETE FROM vulnerability_cache WHERE fetched_at < ?`).run(Date.now() - maxAgeMs).changes;
}

export function saveSecurityPolicy(policy: SecurityPolicy) {
  const updatedAt = new Date().toISOString();
  db.prepare(`INSERT OR REPLACE INTO security_policies(id,name,payload,updated_at) VALUES(?,?,?,?)`)
    .run(policy.id, policy.name, JSON.stringify(policy), updatedAt);
  return policy;
}

export function listSecurityPolicies(): SecurityPolicy[] {
  return db.prepare(`SELECT payload FROM security_policies ORDER BY updated_at DESC`).all()
    .flatMap((row) => {
      const value = parseStoredJson<SecurityPolicy>((row as { payload: string }).payload, "security policy");
      return value ? [value] : [];
    });
}

export function saveReplayEvidence(scanId: string, evidence: ReplayEvidenceInput) {
  const id = `replay:${scanId}:${evidence.executedAt}:${evidence.dependency}`;
  db.prepare(`INSERT OR REPLACE INTO replay_evidence(id,scan_id,dependency,payload,created_at) VALUES(?,?,?,?,?)`)
    .run(id, scanId, evidence.dependency, JSON.stringify(evidence), evidence.executedAt);
  return evidence;
}

export function listReplayEvidence(scanId: string): ReplayEvidenceInput[] {
  return db.prepare(`SELECT payload FROM replay_evidence WHERE scan_id=? ORDER BY created_at DESC`).all(scanId)
    .flatMap((row) => {
      const value = parseStoredJson<ReplayEvidenceInput>((row as { payload: string }).payload, "replay evidence");
      return value ? [value] : [];
    });
}

function parseStoredJson<T>(payload: string, label: string): T | null {
  try {
    return JSON.parse(payload) as T;
  } catch {
    console.warn(`DepShield ignored an invalid ${label} JSON record.`);
    return null;
  }
}
