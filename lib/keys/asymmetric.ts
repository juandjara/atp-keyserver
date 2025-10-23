import db, { DBSchema } from '../db'
import * as ed25519 from '@noble/ed25519'

const bytesToHex = ed25519.etc.bytesToHex

export type Keypair = {
  publicKey: string
  privateKey: string
  version: number
}

type KeyVersionInfo = {
  version: number
  status: 'active' | 'revoked' | 'rotated'
  created_at: string
  revoked_at: string | null
}

export async function createKeypair(): Promise<Omit<Keypair, 'version'>> {
  const privateKey = ed25519.utils.randomPrivateKey()
  const publicKey = await ed25519.getPublicKeyAsync(privateKey)
  return {
    publicKey: bytesToHex(publicKey),
    privateKey: bytesToHex(privateKey),
  }
}

export async function getKeypair(did: string): Promise<Keypair> {
  // Try to retrieve active keypair from SQLite
  const query = db.query<DBSchema['keys'], [string]>(
    'SELECT version, public_key, private_key FROM keys WHERE did = ? AND status = "active" ORDER BY version DESC LIMIT 1',
  )

  const result = query.get(did)

  if (result) {
    return {
      publicKey: result.public_key,
      privateKey: result.private_key,
      version: result.version,
    }
  }

  // Create a new keypair if it doesn't exist
  const newKeypair = await createKeypair()
  const insert = db.query<
    void,
    [string, number, string, string, string, string]
  >(
    'INSERT INTO keys (did, version, public_key, private_key, created_at, status) VALUES (?, ?, ?, ?, ?, ?)',
  )

  insert.run(
    did,
    1,
    newKeypair.publicKey,
    newKeypair.privateKey,
    new Date().toISOString(),
    'active',
  )

  return {
    ...newKeypair,
    version: 1,
  }
}

export async function getKeypairVersion(
  did: string,
  version: number,
): Promise<Keypair | null> {
  // Retrieve specific version (even if revoked) for decryption
  const query = db.query<DBSchema['keys'], [string, number]>(
    'SELECT version, public_key, private_key FROM keys WHERE did = ? AND version = ?',
  )

  const result = query.get(did, version)

  if (!result) {
    return null
  }

  return {
    publicKey: result.public_key,
    privateKey: result.private_key,
    version: result.version,
  }
}

export async function rotateKeypair(
  did: string,
  reason: string,
): Promise<{ oldVersion: number; newVersion: number; rotatedAt: string }> {
  // Get current active key
  const current = await getKeypair(did)

  // Mark current as revoked
  const updateQuery = db.query<void, [string, string, number]>(
    'UPDATE keys SET status = "revoked", revoked_at = ? WHERE did = ? AND version = ?',
  )

  const now = new Date().toISOString()
  updateQuery.run(now, did, current.version)

  // Create new key
  const newKeypair = await createKeypair()
  const newVersion = current.version + 1

  const insertQuery = db.query<
    void,
    [string, number, string, string, string, string]
  >(
    'INSERT INTO keys (did, version, public_key, private_key, created_at, status) VALUES (?, ?, ?, ?, ?, ?)',
  )

  insertQuery.run(
    did,
    newVersion,
    newKeypair.publicKey,
    newKeypair.privateKey,
    now,
    'active',
  )

  return {
    oldVersion: current.version,
    newVersion,
    rotatedAt: now,
  }
}

export function listKeypairVersions(did: string): KeyVersionInfo[] {
  const query = db.query<DBSchema['keys'], [string]>(
    'SELECT version, status, created_at, revoked_at FROM keys WHERE did = ? ORDER BY version DESC',
  )

  return query.all(did).map((row) => ({
    version: row.version,
    status: row.status,
    created_at: row.created_at,
    revoked_at: row.revoked_at,
  }))
}

export async function getPublicKey(
  did: string,
  version?: number,
): Promise<string> {
  if (version !== undefined) {
    const keypair = await getKeypairVersion(did, version)
    if (!keypair) {
      throw new Error(`Key version ${version} not found for DID ${did}`)
    }
    return keypair.publicKey
  }

  const keypair = await getKeypair(did)
  return keypair.publicKey
}
