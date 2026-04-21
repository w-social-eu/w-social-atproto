import { Server } from '@atproto/xrpc-server'
import { AppContext } from '../context'
import appBsky from './app/bsky'
import comAtproto from './com/atproto'
import ioTrustanchor from './io'

export default function (server: Server, ctx: AppContext) {
  comAtproto(server, ctx)
  appBsky(server, ctx)
  ioTrustanchor(server, ctx)

  return server
}
