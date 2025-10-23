import { AutoRouter, cors, error, IRequest } from 'itty-router'
import { verifyJwt } from '@atproto/xrpc-server'
import { isDid, extractDidMethod } from '@atproto/did'
import authMiddleware from './lib/authMiddleware'
import pkg from './package.json'
import {
  getKeypair,
  getPublicKey,
  getKeypairVersion,
  rotateKeypair,
  listKeypairVersions,
  Keypair,
} from './lib/keys/asymmetric'
import {
  getGroupKey,
  rotateGroupKey,
  listGroupKeyVersions,
  addMember,
  removeMember,
} from './lib/keys/symmetric'
import { logKeyAccess } from './lib/keys/access-log'

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

type Ctx = IRequest & AuthCtx

// Get a user's public key
router.get(
  '/xrpc/dev.atpkeyserver.alpha.key.public',
  async ({ query, headers }) => {
    let { did, version } = query
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

    // Parse version if provided
    const keyVersion = version ? parseInt(version as string, 10) : undefined

    try {
      const publicKey = await getPublicKey(did, keyVersion)

      // Log access (no auth required for public keys, so IP tracking is minimal)
      const ip = headers.get('x-forwarded-for') || headers.get('x-real-ip')
      logKeyAccess(did, keyVersion ?? 1, ip, headers.get('user-agent'))

      return {
        publicKey,
        version: keyVersion ?? 1,
      }
    } catch (err) {
      return error(404, (err as Error).message)
    }
  },
)

//
// AUTH WALL
//
// ALL REQUESTS PAST THIS POINT REQUIRE AUTH
//
router.all('*', (ctx) => authMiddleware(serviceDid, ctx))

// Get the user's personal keypair
router.get('/xrpc/dev.atpkeyserver.alpha.key', async (ctx: Ctx) => {
  const { version } = ctx.query

  try {
    let keypair: Keypair | null = null
    if (version) {
      const keyVersion = parseInt(version as string, 10)
      keypair = await getKeypairVersion(ctx.did, keyVersion)
      if (!keypair) {
        return error(404, `Key version ${keyVersion} not found`)
      }
    } else {
      keypair = await getKeypair(ctx.did)
    }

    // Log access
    logKeyAccess(
      ctx.did,
      keypair.version,
      ctx.headers.get('x-forwarded-for') || ctx.headers.get('x-real-ip'),
      ctx.headers.get('user-agent'),
    )

    return keypair
  } catch (err) {
    return error(500, (err as Error).message)
  }
})

// Rotate the user's personal keypair
router.post('/xrpc/dev.atpkeyserver.alpha.key.rotate', async (ctx: Ctx) => {
  try {
    const body = await ctx.json().catch(() => ({}))
    const reason = body.reason || 'user_requested'

    const result = await rotateKeypair(ctx.did, reason)

    return {
      oldVersion: result.oldVersion,
      newVersion: result.newVersion,
      rotatedAt: result.rotatedAt,
    }
  } catch (err) {
    return error(500, (err as Error).message)
  }
})

// List all versions of the user's keypair
router.get('/xrpc/dev.atpkeyserver.alpha.key.versions', (ctx: Ctx) => {
  try {
    const versions = listKeypairVersions(ctx.did)
    return { versions }
  } catch (err) {
    return error(500, (err as Error).message)
  }
})

// Get a group's symmetric key
router.get('/xrpc/dev.atpkeyserver.alpha.group.key', (ctx: Ctx) => {
  const { group_id, version } = ctx.query

  if (typeof group_id !== 'string' || !group_id) {
    return error(400, 'group_id query parameter required')
  }

  try {
    const keyVersion = version ? parseInt(version as string, 10) : undefined
    const secretKey = getGroupKey(group_id, ctx.did, keyVersion)

    // Log access
    const ip =
      ctx.headers.get('x-forwarded-for') || ctx.headers.get('x-real-ip')
    logKeyAccess(group_id, keyVersion ?? 1, ip, ctx.headers.get('user-agent'))

    return {
      groupId: group_id,
      secretKey,
      version: keyVersion ?? 1,
    }
  } catch (err) {
    // Error thrown by getGroupKey (already formatted)
    throw err
  }
})

// Rotate a group's symmetric key
router.post(
  '/xrpc/dev.atpkeyserver.alpha.group.key.rotate',
  async (ctx: Ctx) => {
    try {
      const body = await ctx.json().catch(() => ({}))
      const { group_id, reason } = body

      if (typeof group_id !== 'string' || !group_id) {
        return error(400, 'group_id is required in request body')
      }

      const result = rotateGroupKey(
        group_id,
        ctx.did,
        reason || 'user_requested',
      )

      return {
        groupId: group_id,
        oldVersion: result.oldVersion,
        newVersion: result.newVersion,
        rotatedAt: result.rotatedAt,
      }
    } catch (err) {
      // Error thrown by rotateGroupKey (already formatted)
      throw err
    }
  },
)

// List all versions of a group key
router.get('/xrpc/dev.atpkeyserver.alpha.group.key.versions', (ctx: Ctx) => {
  const { group_id } = ctx.query

  if (typeof group_id !== 'string' || !group_id) {
    return error(400, 'group_id query parameter required')
  }

  try {
    const versions = listGroupKeyVersions(group_id, ctx.did)
    return {
      groupId: group_id,
      versions,
    }
  } catch (err) {
    // Error thrown by listGroupKeyVersions (already formatted)
    throw err
  }
})

// Add a member to a group
router.post(
  '/xrpc/dev.atpkeyserver.alpha.group.member.add',
  async (ctx: Ctx) => {
    try {
      const body = await ctx.json().catch(() => ({}))
      const { group_id, member_did } = body

      if (typeof group_id !== 'string' || !group_id) {
        return error(400, 'group_id is required in request body')
      }

      if (typeof member_did !== 'string' || !member_did) {
        return error(400, 'member_did is required in request body')
      }

      addMember(group_id, member_did, ctx.did)

      return {
        groupId: group_id,
        memberDid: member_did,
        status: 'added',
      }
    } catch (err) {
      // Error thrown by addMember (already formatted)
      throw err
    }
  },
)

// Remove a member from a group
router.post(
  '/xrpc/dev.atpkeyserver.alpha.group.member.remove',
  async (ctx: Ctx) => {
    try {
      const body = await ctx.json().catch(() => ({}))
      const { group_id, member_did } = body

      if (typeof group_id !== 'string' || !group_id) {
        return error(400, 'group_id is required in request body')
      }

      if (typeof member_did !== 'string' || !member_did) {
        return error(400, 'member_did is required in request body')
      }

      removeMember(group_id, member_did, ctx.did)

      return {
        groupId: group_id,
        memberDid: member_did,
        status: 'removed',
      }
    } catch (err) {
      // Error thrown by removeMember (already formatted)
      throw err
    }
  },
)

const port = process.env.PORT ? parseInt(process.env.PORT) : 4000

Bun.serve({
  port,
  fetch: router.fetch,
})

console.log(`🔑 Keyserver running on http://localhost:${port}`)
