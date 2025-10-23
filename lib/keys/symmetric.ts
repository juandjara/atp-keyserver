import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import {
  bytesToHex,
  hexToBytes,
  randomBytes,
  utf8ToBytes,
} from '@noble/ciphers/utils.js'
import db, { DBSchema } from '../db'
import { error } from 'itty-router'

/**
 * Create a new secret key for symmetric encryption.
 * @returns A hex-encoded string containing the secret key.
 */
export function createSecretKey() {
  return bytesToHex(randomBytes(32))
}

const NONCE_LENGTH = 24

/**
 * Encrypts a plaintext string using a symmetric key and an ID.
 * @param id - The ID to use for encryption. This can be any utf8 text identifying the message. For example, an user ID.
 * @param key - hex-encoded secret key
 * @param plaintext - The plaintext string to encrypt.
 * @returns A hex-encoded string containing the nonce and the encrypted message.
 */
export function encryptMessage(id: string, key: string, plaintext: string) {
  // nonce is a fixed-length 24-byte string
  // it must be different for every encrypted message
  const nonce = randomBytes(NONCE_LENGTH)
  const cipher = xchacha20poly1305(hexToBytes(key), nonce, utf8ToBytes(id))
  const data = new TextEncoder().encode(plaintext)
  const ciphertext = cipher.encrypt(data)

  return bytesToHex(nonce).concat(bytesToHex(ciphertext))
}

/**
 * Decrypts a ciphertext string using a symmetric key, nonce, and ID.
 * @param id - The ID used for encryption (utf8 text)
 * @param key - hex-encoded secret key.
 * @param ciphertext - The hex-encoded string containing the nonce and the encrypted message.
 * @returns the decrypted plaintext string.
 */
export function decryptMessage(id: string, key: string, ciphertext: string) {
  const nonce = ciphertext.slice(0, NONCE_LENGTH * 2)
  const message = ciphertext.slice(NONCE_LENGTH * 2)
  const cipher = xchacha20poly1305(
    hexToBytes(key),
    hexToBytes(nonce),
    utf8ToBytes(id),
  )
  const data = cipher.decrypt(hexToBytes(message))
  return new TextDecoder().decode(data)
}

type GroupKeyVersionInfo = {
  version: number
  status: 'active' | 'revoked'
  created_at: string
  revoked_at: string | null
}

function getGroup(group_id: string, version?: number) {
  if (version !== undefined) {
    // Get specific version
    return db
      .query<DBSchema['groups'], [string, number]>(
        'SELECT id, version, owner_did, secret_key, created_at, revoked_at, status FROM groups WHERE id = ? AND version = ?',
      )
      .get(group_id, version)
  }

  // Get active version
  return db
    .query<DBSchema['groups'], [string]>(
      'SELECT id, version, owner_did, secret_key, created_at, revoked_at, status FROM groups WHERE id = ? AND status = "active" ORDER BY version DESC LIMIT 1',
    )
    .get(group_id)
}

function checkMembership(group_id: string, member_did: string) {
  const memberQuery = db
    .query<
      { count: number },
      [string, string]
    >('SELECT count(*) as count FROM group_members WHERE group_id = ? AND member_did = ?')
    .get(group_id, member_did)
  const isMember = (memberQuery?.count ?? 0) > 0
  return isMember
}

function createGroup(group_id: string, owner_did: string) {
  const secret_key = createSecretKey()
  db.query<void, [string, number, string, string, string, string]>(
    'INSERT INTO groups (id, version, owner_did, secret_key, created_at, status) VALUES (?, ?, ?, ?, ?, ?)',
  ).run(group_id, 1, owner_did, secret_key, new Date().toISOString(), 'active')
  return secret_key
}

export function getGroupKey(
  group_id: string,
  authed_did: string,
  version?: number,
): string {
  const [owner_did] = group_id.split('#')
  const group = getGroup(group_id, version)

  if (!group) {
    if (owner_did === authed_did && version === undefined) {
      // Create new group (only if not requesting specific version)
      return createGroup(group_id, owner_did)
    }
    throw error(404, 'Group not found')
  }

  // return fast if authenticated user is the group owner
  if (group.owner_did === authed_did) {
    return group.secret_key
  }

  const isMember = checkMembership(group_id, authed_did)

  if (isMember) {
    return group.secret_key
  } else {
    throw error(403, 'Cannot access this group key')
  }
}

export function rotateGroupKey(
  group_id: string,
  authed_did: string,
  reason: string,
): { oldVersion: number; newVersion: number; rotatedAt: string } {
  const group = getGroup(group_id)
  if (!group) {
    throw error(404, 'Group not found')
  }

  if (group.owner_did !== authed_did) {
    throw error(403, 'Only group owner can rotate keys')
  }

  // Mark current as revoked
  const now = new Date().toISOString()
  db.query<void, [string, string, number]>(
    'UPDATE groups SET status = "revoked", revoked_at = ? WHERE id = ? AND version = ?',
  ).run(now, group_id, group.version)

  // Create new version
  const newVersion = group.version + 1
  const newKey = createSecretKey()

  db.query<void, [string, number, string, string, string, string]>(
    'INSERT INTO groups (id, version, owner_did, secret_key, created_at, status) VALUES (?, ?, ?, ?, ?, ?)',
  ).run(group_id, newVersion, group.owner_did, newKey, now, 'active')

  return {
    oldVersion: group.version,
    newVersion,
    rotatedAt: now,
  }
}

export function listGroupKeyVersions(
  group_id: string,
  authed_did: string,
): GroupKeyVersionInfo[] {
  const group = getGroup(group_id)
  if (!group) {
    throw error(404, 'Group not found')
  }

  // Check authorization
  if (group.owner_did !== authed_did && !checkMembership(group_id, authed_did)) {
    throw error(403, 'Cannot access this group')
  }

  const query = db.query<
    DBSchema['groups'],
    [string]
  >('SELECT version, status, created_at, revoked_at FROM groups WHERE id = ? ORDER BY version DESC')

  return query.all(group_id).map((row) => ({
    version: row.version,
    status: row.status,
    created_at: row.created_at,
    revoked_at: row.revoked_at,
  }))
}

export function addMember(
  group_id: string,
  member_did: string,
  authed_did: string,
) {
  const group = getGroup(group_id)
  if (!group) {
    throw error(404, 'Group not found')
  }

  if (group.owner_did !== authed_did) {
    throw error(403, 'Cannot add member to group')
  }

  const isMember = checkMembership(group_id, member_did)

  if (isMember) {
    throw error(409, 'Member already in group')
  }

  db.query<void, [string, string]>(
    'INSERT INTO group_members (group_id, member_did) VALUES (?, ?)',
  ).run(group_id, member_did)
}

export function removeMember(
  group_id: string,
  member_did: string,
  authed_did: string,
) {
  const group = getGroup(group_id)
  if (!group) {
    throw error(404, 'Group not found')
  }

  if (group.owner_did !== authed_did) {
    throw error(403, 'Cannot remove member from group')
  }

  const isMember = checkMembership(group_id, member_did)

  if (!isMember) {
    throw error(404, 'Member not found in group')
  }

  db.query<void, [string, string]>(
    'DELETE FROM group_members WHERE group_id = ? AND member_did = ?',
  ).run(group_id, member_did)
}
