/* eslint-env node */

'use strict'

const dd = require('dd-trace')

dd.tracer.init({ logInjection: true })

// Tracer code above must come before anything else
const assert = require('node:assert')
const { Database, DataPlaneServer, RepoSubscription } = require('@atproto/bsky')

const main = async () => {
  const port = parseInt(process.env.DATAPLANE_PORT || '3001', 10)
  const dbUrl = process.env.DATAPLANE_DB_POSTGRES_URL
  const subscriptionEndpoint = process.env.DATAPLANE_SUBSCRIPTION_ENDPOINT
  const plcUrl =
    process.env.DATAPLANE_DID_PLC_URL || 'https://plc.directory'
  const poolSize = parseInt(process.env.DATAPLANE_DB_POOL_SIZE || '10', 10)
  const runMigrations = process.env.DATAPLANE_DB_MIGRATE !== '0'

  assert(dbUrl, 'DATAPLANE_DB_POSTGRES_URL is required')
  assert(subscriptionEndpoint, 'DATAPLANE_SUBSCRIPTION_ENDPOINT is required')

  if (runMigrations) {
    console.log('dataplane: running db migrations')
    const migrationDb = new Database({ url: dbUrl })
    await migrationDb.migrateToLatestOrThrow()
    await migrationDb.close()
    console.log('dataplane: migrations complete')
  }

  const db = new Database({ url: dbUrl, poolSize })

  const dataplane = await DataPlaneServer.create(db, port, plcUrl)
  console.log(`dataplane: gRPC server listening on port ${port}`)

  const sub = new RepoSubscription({
    service: subscriptionEndpoint,
    db,
    idResolver: dataplane.idResolver,
  })
  sub.start()
  console.log(`dataplane: subscribed to firehose at ${subscriptionEndpoint}`)

  const shutdown = async () => {
    console.log('dataplane: shutting down')
    await sub.destroy()
    await dataplane.destroy()
    await db.close()
    console.log('dataplane: stopped')
    process.exit(0)
  }

  process.on('SIGTERM', shutdown)
  process.on('disconnect', shutdown)
}

main().catch((err) => {
  console.error('dataplane: startup failed', err)
  process.exit(1)
})
