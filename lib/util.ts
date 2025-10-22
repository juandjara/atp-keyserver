import { IdResolver } from '@atproto/identity'
import * as ed25519 from '@noble/ed25519'
import encodeBase32 from 'base32-encode'
import db from './db'

type Keypair = { publicKey: Uint8Array; privateKey: Uint8Array }
const encodeKey = (key: Uint8Array) =>
  encodeBase32(key, 'Crockford').toLowerCase()

// TODO: add a DID cache using SQLite
const idResolver = new IdResolver()
export async function getSigningKey(
  did: string,
  forceRefresh: boolean,
): Promise<string> {
  const atprotoData = await idResolver.did.resolveAtprotoData(did, forceRefresh)
  return atprotoData.signingKey
}

export async function generateKeypair(): Promise<Keypair> {
  const privateKey = ed25519.utils.randomPrivateKey()
  const publicKey = await ed25519.getPublicKeyAsync(privateKey)
  return {
    publicKey,
    privateKey,
  }
}

export async function getKeypair(did: string): Promise<Keypair> {
  // Try to retrieve existing keypair from SQLite
  const query = db.query(
    'SELECT public_key, private_key FROM keys WHERE did = ?',
  )
  const result = query.get(did) as {
    public_key: Uint8Array
    private_key: Uint8Array
  } | null

  if (result) {
    return {
      publicKey: result.public_key,
      privateKey: result.private_key,
    }
  }

  // Generate new keypair if it doesn't exist
  const newKeypair = await generateKeypair()
  const insert = db.query(
    'INSERT INTO keys (did, public_key, private_key) VALUES (?, ?, ?)',
  )
  insert.run(did, newKeypair.publicKey, newKeypair.privateKey)

  return newKeypair
}

export async function getPublicKey(did: string): Promise<string> {
  const keypair = await getKeypair(did)
  return encodeKey(keypair.publicKey)
}

export async function getEncodedKeypair(
  did: string,
): Promise<{ publicKey: string; privateKey: string }> {
  const keypair = await getKeypair(did)
  return {
    publicKey: encodeKey(keypair.publicKey),
    privateKey: encodeKey(keypair.privateKey),
  }
}
