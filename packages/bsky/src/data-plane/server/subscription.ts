import { IdResolver } from '@atproto/identity'
import { WriteOpAction } from '@atproto/repo'
import { Event as FirehoseEvent, Firehose, MemoryRunner } from '@atproto/sync'
import { subLogger as log } from '../../logger'
import { BackgroundQueue } from './background'
import { Database } from './db'
import { IndexingService } from './indexing'

export type RepoSubscriptionOptions = {
  service: string
  db: Database
  idResolver: IdResolver
  /**
   * Cap the number of firehose events held in memory by the runner
   * (queued + in-flight). When set, the firehose consumer loop applies
   * backpressure to the WebSocket whenever this limit is reached,
   * preventing OOM on high-volume relays (e.g. `wss://bsky.network`).
   * If unset, no limit is applied (historical behavior, safe for low-
   * volume sources like a single-tenant PDS).
   */
  maxQueueSize?: number
  /** Resume reading once the queue drains below this count. */
  lowWaterMark?: number
}

/**
 * Pull bounded-queue watermarks from the environment so the dataplane
 * service picks them up without a code change. The dataplane process
 * instantiates `RepoSubscription` directly; callers may also pass the
 * values explicitly, which take precedence.
 *
 * `DATAPLANE_MAX_QUEUE_SIZE`   — hard cap (recommended: 5000 on bsky.network)
 * `DATAPLANE_LOW_WATER_MARK`   — resume threshold (recommended: 1000)
 */
const envQueueLimits = (): {
  maxQueueSize?: number
  lowWaterMark?: number
} => {
  const max = parseInt(process.env.DATAPLANE_MAX_QUEUE_SIZE || '', 10)
  const low = parseInt(process.env.DATAPLANE_LOW_WATER_MARK || '', 10)
  return {
    maxQueueSize: Number.isFinite(max) && max > 0 ? max : undefined,
    lowWaterMark: Number.isFinite(low) && low > 0 ? low : undefined,
  }
}

export class RepoSubscription {
  firehose: Firehose
  runner: MemoryRunner
  background: BackgroundQueue
  indexingSvc: IndexingService

  constructor(public opts: RepoSubscriptionOptions) {
    const { service, db, idResolver } = opts
    this.background = new BackgroundQueue(db)
    this.indexingSvc = new IndexingService(db, idResolver, this.background)

    const env = envQueueLimits()
    const { runner, firehose } = createFirehose({
      idResolver,
      service,
      indexingSvc: this.indexingSvc,
      maxQueueSize: opts.maxQueueSize ?? env.maxQueueSize,
      lowWaterMark: opts.lowWaterMark ?? env.lowWaterMark,
    })
    this.runner = runner
    this.firehose = firehose
  }

  start() {
    this.firehose.start()
  }

  async restart() {
    await this.destroy()
    const env = envQueueLimits()
    const { runner, firehose } = createFirehose({
      idResolver: this.opts.idResolver,
      service: this.opts.service,
      indexingSvc: this.indexingSvc,
      maxQueueSize: this.opts.maxQueueSize ?? env.maxQueueSize,
      lowWaterMark: this.opts.lowWaterMark ?? env.lowWaterMark,
    })
    this.runner = runner
    this.firehose = firehose
    this.start()
  }

  async processAll() {
    await this.runner.processAll()
    await this.background.processAll()
  }

  async destroy() {
    await this.firehose.destroy()
    await this.runner.destroy()
    await this.background.processAll()
  }
}

const createFirehose = (opts: {
  idResolver: IdResolver
  service: string
  indexingSvc: IndexingService
  maxQueueSize?: number
  lowWaterMark?: number
}) => {
  const { idResolver, service, indexingSvc, maxQueueSize, lowWaterMark } = opts
  const runner = new MemoryRunner({
    startCursor: 0,
    maxQueueSize,
    lowWaterMark,
  })
  const firehose = new Firehose({
    idResolver,
    runner,
    service,
    unauthenticatedHandles: true, // indexing service handles these
    unauthenticatedCommits: true, // @TODO there seems to be a very rare issue where the authenticator thinks a block is missing in deletion ops
    onError: (err) => log.error({ err }, 'error in subscription'),
    handleEvent: async (evt: FirehoseEvent) => {
      if (evt.event === 'identity') {
        await indexingSvc.indexHandle(evt.did, evt.time, true)
      } else if (evt.event === 'account') {
        if (evt.active === false && evt.status === 'deleted') {
          await indexingSvc.deleteActor(evt.did)
        } else {
          await indexingSvc.updateActorStatus(evt.did, evt.active, evt.status)
        }
      } else if (evt.event === 'sync') {
        await Promise.all([
          indexingSvc.setCommitLastSeen(evt.did, evt.cid, evt.rev),
          indexingSvc.indexHandle(evt.did, evt.time),
        ])
      } else {
        const indexFn =
          evt.event === 'delete'
            ? indexingSvc.deleteRecord(evt.uri)
            : indexingSvc.indexRecord(
                evt.uri,
                evt.cid,
                evt.record,
                evt.event === 'create'
                  ? WriteOpAction.Create
                  : WriteOpAction.Update,
                evt.time,
              )
        await Promise.all([
          indexFn,
          indexingSvc.setCommitLastSeen(evt.did, evt.commit, evt.rev),
          indexingSvc.indexHandle(evt.did, evt.time),
        ])
      }
    },
  })
  return { firehose, runner }
}
