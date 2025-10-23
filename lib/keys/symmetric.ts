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
 * @returns A base64-encoded string containing the secret key.
 */
export function createSecretKey() {
  return bytesToHex(randomBytes(32))
}

const NONCE_LENGTH = 24

/**
 * Encrypts a plaintext string using a symmetric key and an ID.
 * @param id - The ID to use for encryption. This can be any utf8 text identifying the message. For example, an user ID.
 * @param key - base64-encoded secret key
 * @param plaintext - The plaintext string to encrypt.
 * @returns A base64-encoded string containing the nonce and the encrypted message.
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
 * @param key - base64-encoded secret key.
 * @param ciphertext - The base64-encoded string containing the nonce and the encrypted message.
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

function getGroup(group_id: string) {
  return db
    .query<
      DBSchema['groups'],
      [string]
    >('SELECT id, owner_did, secret_key FROM groups WHERE id = ?')
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
  db.query<void, [string, string, string]>(
    'INSERT INTO groups (id, owner_did, secret_key) VALUES (?, ?, ?)',
  ).run(group_id, owner_did, secret_key)
  return secret_key
}

export function getGroupKey(group_id: string, authed_did: string) {
  const [owner_did] = group_id.split('#')
  const group = getGroup(group_id)
  if (!group) {
    if (owner_did === authed_did) {
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
    return group?.secret_key
  } else {
    throw error(403, 'Cannot access this group key')
  }
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
