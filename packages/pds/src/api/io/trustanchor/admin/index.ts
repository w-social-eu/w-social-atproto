import { AppContext } from '../../../../context'
import { Server } from '../../../../lexicon'
import clearInventory from './clearInventory'
import createBotAccount from './createBotAccount'
import createInvitation from './createInvitation'
import deleteInvitation from './deleteInvitation'
import getBuildInfo from './getBuildInfo'
import getInventoryStatus from './getInventoryStatus'
import getInvitationStats from './getInvitationStats'
import listInvitations from './listInvitations'
import loadInventory from './loadInventory'
import purgeInvitations from './purgeInvitations'
import setAccountPassword from './setAccountPassword'
import setThreadViewPreferences from './setThreadViewPreferences'
import subscribeToLists from './subscribeToLists'
import updateInvitationEmailStatus from './updateInvitationEmailStatus'

export default function (server: Server, ctx: AppContext) {
  createInvitation(server, ctx)
  listInvitations(server, ctx)
  getInvitationStats(server, ctx)
  deleteInvitation(server, ctx)
  purgeInvitations(server, ctx)
  createBotAccount(server, ctx)
  setAccountPassword(server, ctx)
  subscribeToLists(server, ctx)
  setThreadViewPreferences(server, ctx)
  getInventoryStatus(server, ctx)
  loadInventory(server, ctx)
  clearInventory(server, ctx)
  updateInvitationEmailStatus(server, ctx)
  getBuildInfo(server, ctx)
}
