import { wait } from '@atproto/common'
import { ConsecutiveList, MemoryRunner } from '..'

describe('EventRunner utils', () => {
  describe('ConsecutiveList', () => {
    it('tracks consecutive complete items.', () => {
      const consecutive = new ConsecutiveList<number>()
      // add items
      const item1 = consecutive.push(1)
      const item2 = consecutive.push(2)
      const item3 = consecutive.push(3)
      expect(item1.isComplete).toEqual(false)
      expect(item2.isComplete).toEqual(false)
      expect(item3.isComplete).toEqual(false)
      // complete items out of order
      expect(consecutive.list.length).toBe(3)
      expect(item2.complete()).toEqual([])
      expect(item2.isComplete).toEqual(true)
      expect(consecutive.list.length).toBe(3)
      expect(item1.complete()).toEqual([1, 2])
      expect(item1.isComplete).toEqual(true)
      expect(consecutive.list.length).toBe(1)
      expect(item3.complete()).toEqual([3])
      expect(consecutive.list.length).toBe(0)
      expect(item3.isComplete).toEqual(true)
    })
  })

  describe('MemoryRunner', () => {
    it('performs work in parallel across partitions, serial within a partition.', async () => {
      const runner = new MemoryRunner({ concurrency: Infinity })
      const complete: number[] = []
      // partition 1 items start slow but get faster: slow should still complete first.
      runner.addTask('1', async () => {
        await wait(30)
        complete.push(11)
      })
      runner.addTask('1', async () => {
        await wait(20)
        complete.push(12)
      })
      runner.addTask('1', async () => {
        await wait(1)
        complete.push(13)
      })
      expect(runner.partitions.size).toEqual(1)
      // partition 2 items complete quickly except the last, which is slowest of all events.
      runner.addTask('2', async () => {
        await wait(1)
        complete.push(21)
      })
      runner.addTask('2', async () => {
        await wait(1)
        complete.push(22)
      })
      runner.addTask('2', async () => {
        await wait(1)
        complete.push(23)
      })
      runner.addTask('2', async () => {
        await wait(60)
        complete.push(24)
      })
      expect(runner.partitions.size).toEqual(2)
      await runner.mainQueue.onIdle()
      expect(complete).toEqual([21, 22, 23, 11, 12, 13, 24])
      expect(runner.partitions.size).toEqual(0)
    })

    it('limits overall concurrency.', async () => {
      const runner = new MemoryRunner({ concurrency: 1 })
      const complete: number[] = []
      // if concurrency were not constrained, partition 1 would complete all items
      // before any items from partition 2. since it is constrained, the work is complete in the order added.
      runner.addTask('1', async () => {
        await wait(1)
        complete.push(11)
      })
      runner.addTask('2', async () => {
        await wait(10)
        complete.push(21)
      })
      runner.addTask('1', async () => {
        await wait(1)
        complete.push(12)
      })
      runner.addTask('2', async () => {
        await wait(10)
        complete.push(22)
      })
      // only partition 1 exists so far due to the concurrency
      expect(runner.partitions.size).toEqual(1)
      await runner.mainQueue.onIdle()
      expect(complete).toEqual([11, 21, 12, 22])
      expect(runner.partitions.size).toEqual(0)
    })

    it('settles with many items.', async () => {
      const runner = new MemoryRunner({ concurrency: 100 })
      const complete: { partition: string; id: number }[] = []
      const partitions = new Set<string>()
      for (let i = 0; i < 500; ++i) {
        const partition = Math.floor(Math.random() * 16).toString(10)
        partitions.add(partition)
        runner.addTask(partition, async () => {
          await wait((i % 2) * 2)
          complete.push({ partition, id: i })
        })
      }
      expect(runner.partitions.size).toBeLessThanOrEqual(partitions.size)
      await runner.mainQueue.onIdle()
      expect(complete.length).toEqual(500)
      for (const partition of partitions) {
        const ids = complete
          .filter((item) => item.partition === partition)
          .map((item) => item.id)
        expect(ids).toEqual([...ids].sort((a, b) => a - b))
      }
      expect(runner.partitions.size).toEqual(0)
    })

    it('applies backpressure when bounded, preventing unbounded memory growth.', async () => {
      // Simulates a fast firehose producer (500 events enqueued back-to-back)
      // with slow consumers (each task waits 5ms). Without backpressure, all
      // 500 closures would be held in memory at once. With a 20/10 watermark
      // pair, the producer's enqueue loop is expected to stall — so the
      // runner never buffers more than ~20 events at a time.
      const runner = new MemoryRunner({
        concurrency: 10,
        maxQueueSize: 20,
        lowWaterMark: 10,
      })
      let maxObserved = 0
      const producer = (async () => {
        for (let i = 0; i < 500; ++i) {
          await runner.trackEvent(
            (i % 4).toString(10), // 4 partitions to allow some parallelism
            i,
            async () => {
              await wait(5)
            },
          )
          // Sample the high-water mark as seen by the producer; with
          // backpressure working, this should never exceed maxQueueSize by
          // more than a couple in transit.
          const inMemory = runner['inMemory'] as number
          if (inMemory > maxObserved) maxObserved = inMemory
        }
      })()
      await producer
      await runner.mainQueue.onIdle()
      // Small fudge for in-flight tasks racing past the watermark while a
      // new enqueue resolves — should stay well under 2× the limit.
      expect(maxObserved).toBeLessThanOrEqual(40)
      expect(runner.getCursor()).toEqual(499)
    })

    it('bounded trackEvent returns after enqueue, not after completion.', async () => {
      // Critical property for the firehose consumer: awaiting `trackEvent`
      // must not block per-task processing, otherwise indexing serializes
      // to one event at a time and the AppView falls hopelessly behind.
      const runner = new MemoryRunner({
        concurrency: 10,
        maxQueueSize: 100,
        lowWaterMark: 50,
      })
      let handlerStarted = false
      let release: (() => void) | null = null
      const p = runner.trackEvent('a', 1, async () => {
        handlerStarted = true
        await new Promise<void>((r) => {
          release = r
        })
      })
      // `await p` must resolve even though the handler is still awaiting
      // `release` — i.e. trackEvent must not block on task completion in
      // bounded mode. A stuck `await p` here would time out the test.
      await p
      // Give the partition queue a tick to start the task.
      await wait(10)
      expect(handlerStarted).toBe(true)
      expect(release).not.toBeNull()
      ;(release as unknown as () => void)()
      await runner.mainQueue.onIdle()
    })
  })
})
