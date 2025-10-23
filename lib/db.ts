import { Database } from 'bun:sqlite'

type Key = {
  did: string
  public_key: string
  private_key: string
}

type Group = {
  id: string
  owner_did: string
  secret_key: string
}

type GroupMember = {
  group_id: string
  member_did: string
}

export type DBSchema = {
  keys: Key
  groups: Group
  group_members: GroupMember
}

// Initialize SQLite database
const db = new Database('keyserver.db')
// enable WAL mode: https://bun.com/docs/runtime/sqlite#wal-mode
db.run('PRAGMA journal_mode = WAL;')
// the most basic table setup
db.run(`
  CREATE TABLE IF NOT EXISTS keys (
    did TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    owner_did TEXT NOT NULL,
    secret_key TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL,
    member_did TEXT NOT NULL,
    FOREIGN KEY (group_id) REFERENCES groups(id)
  );
`)

export default db
