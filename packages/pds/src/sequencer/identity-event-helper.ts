import { BackgroundQueue } from '../background'
import { Sequencer } from './sequencer'

/**
 * Helper to send identity events with defensive error handling and delayed retry.
 *
 * This addresses a timing/race condition where AppView may process account creation
 * events before the identity event is fully propagated. The delayed retry ensures
 * the AppView receives a clean identity event after everything has settled.
 *
 * @param sequencer - The sequencer instance
 * @param backgroundQueue - The background queue for delayed tasks
 * @param did - The DID of the account
 * @param handle - The handle of the account
 * @param logger - Logger instance with info/error methods
 * @param flowIdentifier - Identifier for the flow (e.g., "OAuth flow", "QuickLogin flow")
 * @param delayMs - Delay in milliseconds before retry (default: 3000)
 */
export async function sendIdentityEventWithRetry(
  sequencer: Sequencer,
  backgroundQueue: BackgroundQueue,
  did: string,
  handle: string,
  logger: {
    info: (obj: any, msg: string) => void
    error: (obj: any, msg: string) => void
  },
  flowIdentifier: string,
  delayMs: number = 3000,
): Promise<void> {
  // Send initial identity event with defensive error handling
  try {
    await sequencer.sequenceIdentityEvt(did, handle)
    logger.info(
      { did, handle },
      `initial identity event sent (${flowIdentifier})`,
    )
  } catch (err) {
    logger.error(
      { err, did, handle },
      `failed to send initial identity event (${flowIdentifier}) - will retry with delay`,
    )
  }

  // Schedule a delayed re-broadcast of the identity event to ensure AppView processes it
  backgroundQueue.add(async () => {
    await new Promise((resolve) => setTimeout(resolve, delayMs))
    try {
      await sequencer.sequenceIdentityEvt(did, handle)
      logger.info(
        { did, handle },
        `delayed identity event sent (${flowIdentifier})`,
      )
    } catch (err) {
      logger.error(
        { err, did, handle },
        `failed to send delayed identity event (${flowIdentifier})`,
      )
    }
  })
}
