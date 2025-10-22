import { Database } from 'bun:sqlite'

// Initialize SQLite database
const db = new Database('keyserver.db')
db.run(`
  CREATE TABLE IF NOT EXISTS keys (
    did TEXT PRIMARY KEY,
    public_key BLOB NOT NULL,
    private_key BLOB NOT NULL
  )
`)

export default db
