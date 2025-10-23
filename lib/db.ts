import { Database } from 'bun:sqlite'

type Key = {
  did: string
  version: number
  public_key: string
  private_key: string
  created_at: string
  revoked_at: string | null
  status: 'active' | 'revoked' | 'rotated'
}

type Group = {
  id: string
  version: number
  owner_did: string
  secret_key: string
  created_at: string
  revoked_at: string | null
  status: 'active' | 'revoked'
}

type GroupMember = {
  group_id: string
  member_did: string
}

type KeyAccessLog = {
  id: number
  did: string
  version: number
  accessed_at: string
  ip: string | null
  user_agent: string | null
}

export type DBSchema = {
  keys: Key
  groups: Group
  group_members: GroupMember
  key_access_log: KeyAccessLog
}

// Initialize SQLite database
const db = new Database('keyserver.db')
// enable WAL mode: https://bun.com/docs/runtime/sqlite#wal-mode
db.run('PRAGMA journal_mode = WAL;')

// Check if we need to migrate the schema
const tablesExist = db
  .query(`SELECT name FROM sqlite_master WHERE type='table' AND name='keys'`)
  .get() as { name: string } | null

if (!tablesExist) {
  // Fresh install - create new schema with versioning
  db.run(`
    CREATE TABLE keys (
      did TEXT NOT NULL,
      version INTEGER NOT NULL DEFAULT 1,
      public_key TEXT NOT NULL,
      private_key TEXT NOT NULL,
      created_at TEXT NOT NULL,
      revoked_at TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      PRIMARY KEY (did, version)
    );
    CREATE INDEX idx_keys_did_status ON keys(did, status);

    CREATE TABLE groups (
      id TEXT NOT NULL,
      version INTEGER NOT NULL DEFAULT 1,
      owner_did TEXT NOT NULL,
      secret_key TEXT NOT NULL,
      created_at TEXT NOT NULL,
      revoked_at TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      PRIMARY KEY (id, version)
    );
    CREATE INDEX idx_groups_id_status ON groups(id, status);

    CREATE TABLE group_members (
      group_id TEXT NOT NULL,
      member_did TEXT NOT NULL,
      FOREIGN KEY (group_id) REFERENCES groups(id)
    );

    CREATE TABLE key_access_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      did TEXT NOT NULL,
      version INTEGER NOT NULL,
      accessed_at TEXT NOT NULL,
      ip TEXT,
      user_agent TEXT
    );
  `)
}

export default db
