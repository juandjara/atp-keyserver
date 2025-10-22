import { AutoRouter, cors, error } from 'itty-router'
import { verifyJwt } from '@atproto/xrpc-server'
import { isDid, extractDidMethod } from '@atproto/did'
import pkg from './package.json'
import { getEncodedKeypair, getPublicKey, getSigningKey } from './lib/util'
import authMiddleware from './lib/authMiddleware'

const { preflight, corsify } = cors()
const router = AutoRouter({
  before: [preflight],
  finally: [corsify],
})

const serviceDid = process.env.DID

if (!serviceDid) {
  throw new Error(
    'Must set DID environment variable to the DID of this deployed service.',
  )
}

router.get('/', () => ({
  name: pkg.name,
  version: pkg.version,
}))

// Return the service DID
router.get('/.well-known/did.json', ({ url }) => ({
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: serviceDid,
  service: [
    {
      id: '#atp_keyserver',
      type: 'AtpKeyserver',
      serviceEndpoint: (() => {
        const u = new URL(url)
        u.pathname = '/'
        return u.href
      })(),
    },
  ],
}))

type JwtPayload = Awaited<ReturnType<typeof verifyJwt>>
type AuthCtx = {
  jwtPayload: JwtPayload
  did: string
}

type Ctx = Request & AuthCtx

// Get a user's public key
router.get('/xrpc/chat.roomy.v0.key.public', async ({ query }) => {
  let { did } = query
  if (typeof did !== 'string' || !did) {
    return error(400, 'DID query parameter required')
  }

  did = decodeURIComponent(did)
  if (!isDid(did)) {
    return error(400, 'Invalid DID')
  }

  const didMethod = extractDidMethod(did)
  if (didMethod !== 'web' && didMethod !== 'plc') {
    return error(
      400,
      `Invalid DID method: '${did}'. Expected either 'web' or 'plc'`,
    )
  }

  return {
    publicKey: await getPublicKey(did),
  }
})

//
// AUTH WALL
//
// ALL REQUESTS PAST THIS POINT REQUIRE AUTH
//
router.all('*', (ctx) => authMiddleware(serviceDid, ctx))

// Get the user's personal keypair
router.get('/xrpc/chat.roomy.v0.key', ({ did }: Ctx) => {
  return getEncodedKeypair(did)
})

const port = process.env.PORT ? parseInt(process.env.PORT) : 4000

Bun.serve({
  port,
  fetch: router.fetch,
})

console.log(`🔑 Keyserver running on http://localhost:${port}`)
