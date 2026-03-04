import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import listInvitations from './listInvitations'
import getInvitationStats from './getInvitationStats'
import deleteInvitation from './deleteInvitation'
import purgeInvitations from './purgeInvitations'
import createInvitation from './createInvitation'

export default function (server: Server, ctx: AppContext) {
  createInvitation(server, ctx)
  listInvitations(server, ctx)
  getInvitationStats(server, ctx)
  deleteInvitation(server, ctx)
  purgeInvitations(server, ctx)
}
