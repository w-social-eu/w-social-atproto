import PQueue from 'p-queue'
import { ConsecutiveList } from './consecutive-list'
import { EventRunner } from './types'

export type MemoryRunnerOptions = {
  setCursor?: (cursor: number) => Promise<void>
  concurrency?: number
  startCursor?: number
  /**
   * Upper bound on the number of events held in memory (queued + in-flight).
   * When the runner is at or above this watermark, `addTask`/`trackEvent`
   * will await until the in-memory count drops below `lowWaterMark` before
   * enqueueing more work. This lets upstream producers (e.g. a firehose
   * consumer loop) apply backpressure instead of buffering events without
   * bound — which on high-volume relays like `wss://bsky.network` causes
   * OOM because events are produced (~10–20/sec) faster than Postgres can
   * index them.
   *
   * When undefined (default), no backpressure is applied and the runner
   * behaves exactly as it did previously. This preserves compatibility for
   * low-volume producers (e.g. subscribing to a single PDS).
   */
  maxQueueSize?: number
  /**
   * When the in-memory count is at or above `maxQueueSize`, waiters resume
   * only after the count drops below this watermark. Defaults to
   * `Math.max(1, floor(maxQueueSize / 2))`. A gap between the two watermarks
   * prevents thrash — producers drain a bit before being asked to slow down
   * again.
   */
  lowWaterMark?: number
}

// A queue with arbitrarily many partitions, each processing work sequentially.
// Partitions are created lazily and taken out of memory when they go idle.
export class MemoryRunner implements EventRunner {
  consecutive = new ConsecutiveList<number>()
  mainQueue: PQueue
  partitions = new Map<string, PQueue>()
  cursor: number | undefined

  /**
   * Count of tasks currently held in memory by the runner (queued in
   * mainQueue + in-flight across partition queues). Tracked manually rather
   * than derived from `PQueue.size + pending` because with
   * `concurrency: Infinity` everything is `pending` and `size` is always 0,
   * which makes PQueue's built-in `onSizeLessThan` unusable as a gauge.
   */
  private inMemory = 0
  /**
   * Shared deferred that all backpressure waiters await. Resolved once the
   * in-memory count drops below `lowWaterMark`, waking every waiter at
   * once. Each waiter then re-checks `maxQueueSize` before proceeding; if
   * too many race in and overshoot again, they re-arm a new deferred.
   */
  private drainDeferred: {
    promise: Promise<void>
    resolve: () => void
  } | null = null

  constructor(public opts: MemoryRunnerOptions = {}) {
    this.mainQueue = new PQueue({ concurrency: opts.concurrency ?? Infinity })
    this.cursor = opts.startCursor
  }

  getCursor() {
    return this.cursor
  }

  private get lowWaterMark(): number {
    const max = this.opts.maxQueueSize
    if (max === undefined) return 0
    return this.opts.lowWaterMark ?? Math.max(1, Math.floor(max / 2))
  }

  private async waitForRoom(): Promise<void> {
    const max = this.opts.maxQueueSize
    if (max === undefined) return
    // Re-check in a loop: many waiters can be woken simultaneously, but they
    // all compete for slots. If a waiter finds we're still above max after
    // waking, it waits again on a freshly armed deferred.
    while (!this.mainQueue.isPaused && this.inMemory >= max) {
      if (!this.drainDeferred) {
        let resolve!: () => void
        const promise = new Promise<void>((r) => {
          resolve = r
        })
        this.drainDeferred = { promise, resolve }
      }
      await this.drainDeferred.promise
    }
  }

  private notifyDrain() {
    if (!this.drainDeferred) return
    if (this.inMemory < this.lowWaterMark || this.mainQueue.isPaused) {
      const d = this.drainDeferred
      this.drainDeferred = null
      d.resolve()
    }
  }

  async addTask(partitionId: string, task: () => Promise<void>) {
    if (this.mainQueue.isPaused) return

    if (this.opts.maxQueueSize !== undefined) {
      // Bounded mode: apply backpressure, then enqueue and return.
      // The returned promise resolves once there was room to enqueue — NOT
      // once the task completes. That is deliberate: if a producer (like a
      // firehose consumer loop) awaits this, it pauses only long enough to
      // respect the queue depth, letting partitions still process in
      // parallel. Waiting for completion here would serialize processing
      // to one event at a time.
      await this.waitForRoom()
      if (this.mainQueue.isPaused) return
      this.inMemory++
      void this.mainQueue
        .add(async () => {
          try {
            await this.getPartition(partitionId).add(task)
          } finally {
            this.inMemory--
            this.notifyDrain()
          }
        })
        // Swallow: errors surface via `task`/`handler` wrappers; this float
        // exists only because we intentionally don't await completion here.
        .catch(() => {})
      return
    }

    // Unbounded mode: preserve historical behavior — the returned promise
    // resolves when the task completes. Internal callers (`trackEvent`)
    // and existing tests rely on this.
    this.inMemory++
    return this.mainQueue.add(async () => {
      try {
        await this.getPartition(partitionId).add(task)
      } finally {
        this.inMemory--
        this.notifyDrain()
      }
    })
  }

  private getPartition(partitionId: string) {
    let partition = this.partitions.get(partitionId)
    if (!partition) {
      partition = new PQueue({ concurrency: 1 })
      partition.once('idle', () => this.partitions.delete(partitionId))
      this.partitions.set(partitionId, partition)
    }
    return partition
  }

  async trackEvent(did: string, seq: number, handler: () => Promise<void>) {
    if (this.mainQueue.isPaused) return
    const item = this.consecutive.push(seq)
    // When bounded, `addTask` returns once there is room to enqueue (not
    // after the task completes). That lets us propagate backpressure up to
    // the firehose consumer — which should `await trackEvent` — while still
    // letting partitions process in parallel. When unbounded, `addTask`
    // resolves on task completion, matching the previous behavior.
    await this.addTask(did, async () => {
      await handler()
      const latest = item.complete().at(-1)
      if (latest !== undefined) {
        this.cursor = latest
        if (this.opts.setCursor) {
          await this.opts.setCursor(this.cursor)
        }
      }
    })
  }

  async processAll() {
    await this.mainQueue.onIdle()
  }

  async destroy() {
    this.mainQueue.pause()
    this.mainQueue.clear()
    this.partitions.forEach((p) => p.clear())
    // Wake any backpressure waiters so they stop blocking upstream.
    this.notifyDrain()
    await this.mainQueue.onIdle()
  }
}
