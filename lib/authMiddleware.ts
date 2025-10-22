import { error, IRequest } from 'itty-router'
import { verifyJwt } from '@atproto/xrpc-server'
import { getSigningKey } from './util'

type JwtPayload = Awaited<ReturnType<typeof verifyJwt>>

export default async function authMiddleware(
  serviceDid: string,
  ctx: IRequest,
) {
  const url = new URL(ctx.url)
  if (!url.pathname.startsWith('/xrpc/')) {
    return error(404)
  }
  const lxm = url.pathname.split('/xrpc/')[1]

  const authorization = ctx.headers.get('authorization')
  if (!authorization) {
    return error(403, 'Authorization token required.')
  }
  if (!authorization.startsWith('Bearer ')) {
    return error(403, 'Bearer token required')
  }

  const jwt = authorization.split('Bearer ')[1]
  let jwtPayload: JwtPayload
  try {
    jwtPayload = await verifyJwt(jwt, serviceDid, lxm, getSigningKey)
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('Error validating JWT:', e)
    return error(403, 'Could not validate authorization JWT.')
  }

  ctx.jwtPayload = jwtPayload
  ctx.did = jwtPayload.iss

  return undefined
}
