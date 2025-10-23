import db from '../db'
import * as ed25519 from '@noble/ed25519'

const bytesToHex = ed25519.etc.bytesToHex

type Keypair = {
  publicKey: string
  privateKey: string
}

export async function createKeypair(): Promise<Keypair> {
  const privateKey = ed25519.utils.randomPrivateKey()
  const publicKey = await ed25519.getPublicKeyAsync(privateKey)
  return {
    publicKey: bytesToHex(publicKey),
    privateKey: bytesToHex(privateKey),
  }
}

export async function getKeypair(did: string): Promise<Keypair> {
  // Try to retrieve existing keypair from SQLite
  const query = db.query(
    'SELECT public_key, private_key FROM keys WHERE did = ?',
  )
  const result = query.get(did) as {
    public_key: string
    private_key: string
  } | null

  if (result) {
    return {
      publicKey: result.public_key,
      privateKey: result.private_key,
    }
  }

  // Create a new keypair if it doesn't exist
  const newKeypair = await createKeypair()
  const insert = db.query(
    'INSERT INTO keys (did, public_key, private_key) VALUES (?, ?, ?)',
  )
  insert.run(did, newKeypair.publicKey, newKeypair.privateKey)

  return newKeypair
}

export async function getPublicKey(did: string): Promise<string> {
  const keypair = await getKeypair(did)
  return keypair.publicKey
}
