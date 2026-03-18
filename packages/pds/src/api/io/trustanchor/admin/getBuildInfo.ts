import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import { validateAdminAuth } from './shared'
import { BUILD_HASH, BUILD_TIME } from '../../../../version'

// Store server start time
const SERVER_START_TIME = new Date()

export default function (server: Server, ctx: AppContext) {
  server.io.trustanchor.admin.getBuildInfo({
    handler: async ({ req }) => {
      // Validate admin authentication
      validateAdminAuth(req, ctx)

      const uptime = Math.floor((Date.now() - SERVER_START_TIME.getTime()) / 1000)

      return {
        encoding: 'application/json',
        body: {
          buildHash: BUILD_HASH || 'unknown',
          buildTime: BUILD_TIME || 'unknown',
          startedAt: SERVER_START_TIME.toISOString(),
          uptime,
          nodeVersion: process.version,
        },
      }
    },
  })
}
