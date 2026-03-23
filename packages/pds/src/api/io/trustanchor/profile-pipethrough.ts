import type express from 'express'
import { jsonToLex } from '@atproto/lexicon'
import { HandlerPipeThrough, parseReqNsid } from '@atproto/xrpc-server'
import type { AppContext } from '../../../context'
import { lexicons } from '../../../lexicon/lexicons'
import type { ProfileViewDetailed } from '../../../lexicon/types/app/bsky/actor/defs'
import {
  asPipeThroughBuffer,
  isJsonContentType,
  pipethrough,
} from '../../../pipethrough'
import type { HandlerResponse } from '../../../read-after-write/types'
import { addWSocialExtensions } from './profile-extensions'

type ProfileMungeFn<T> = (profile: T) => Promise<T>

/**
 * Pipethrough handler for profile endpoints that always applies W Social extensions.
 * Unlike pipethroughReadAfterWrite, this always buffers and munges the response.
 */
export const pipethroughWithWSocialExtensions = async <T>(
  ctx: AppContext,
  reqCtx: { req: express.Request; auth: { credentials: { did: string } } },
  munge: ProfileMungeFn<T>,
): Promise<HandlerResponse<T> | HandlerPipeThrough> => {
  const { req, auth } = reqCtx
  const requester = auth.credentials.did

  const streamRes = await pipethrough(ctx, req, { iss: requester })

  if (isJsonContentType(streamRes.headers['content-type']) === false) {
    // content-type is present but not JSON, we can't munge this
    return streamRes
  }

  try {
    const lxm = parseReqNsid(req)

    // Always buffer the response to apply W Social extensions
    const { buffer } = await asPipeThroughBuffer(streamRes)
    const lex = jsonToLex(JSON.parse(buffer.toString('utf8')))
    const parsedRes = lexicons.assertValidXrpcOutput(lxm, lex) as T

    // Apply W Social extensions
    const data = await munge(parsedRes)

    return {
      encoding: 'application/json',
      body: data,
    }
  } catch (err) {
    console.error('Error in profile pipethrough with W Social extensions:', err)
    // On error, try to return the stream if still readable
    if (streamRes.stream.readable) {
      return streamRes
    }
    throw err
  }
}

/**
 * Helper to add W Social extensions to a single profile
 */
export const mungeProfileWithWSocial =
  (ctx: AppContext) =>
  async (profile: ProfileViewDetailed): Promise<ProfileViewDetailed> => {
    return addWSocialExtensions(ctx, profile)
  }

/**
 * Helper to add W Social extensions to multiple profiles
 */
export const mungeProfilesWithWSocial =
  (ctx: AppContext) =>
  async (result: {
    profiles: ProfileViewDetailed[]
  }): Promise<{
    profiles: ProfileViewDetailed[]
  }> => {
    const profiles = await Promise.all(
      result.profiles.map((prof) => addWSocialExtensions(ctx, prof)),
    )
    return { ...result, profiles }
  }
