import db from '../db'

/**
 * Log key access for auditing and security monitoring
 */
export function logKeyAccess(
  did: string,
  version: number,
  ip: string | null = null,
  userAgent: string | null = null,
): void {
  const query = db.query<
    void,
    [string, number, string, string | null, string | null]
  >('INSERT INTO key_access_log (did, version, accessed_at, ip, user_agent) VALUES (?, ?, ?, ?, ?)')

  query.run(did, version, new Date().toISOString(), ip, userAgent)
}

/**
 * Get recent key access logs for a specific DID
 */
export function getAccessLogs(
  did: string,
  limit: number = 50,
): Array<{
  version: number
  accessed_at: string
  ip: string | null
  user_agent: string | null
}> {
  const query = db.query<
    {
      version: number
      accessed_at: string
      ip: string | null
      user_agent: string | null
    },
    [string, number]
  >('SELECT version, accessed_at, ip, user_agent FROM key_access_log WHERE did = ? ORDER BY accessed_at DESC LIMIT ?')

  return query.all(did, limit)
}
