import Threat from '../models/Threat.js';
import Asset from '../models/Asset.js';
import ResponseAction from '../models/ResponseAction.js';

export const getKPIs = async (organizationId) => {
  const tenant = organizationId ? { organization: organizationId } : {};
  const activeThreats = await Threat.countDocuments({ ...tenant, status: { $ne: 'resolved' } });
  const systemsMonitored = await Asset.countDocuments(tenant);
  const incidentsResolved = await Threat.countDocuments({ ...tenant, status: 'resolved' });
  const pendingActions = await ResponseAction.countDocuments({ ...tenant, status: 'pending' });
  const totalActions = await ResponseAction.countDocuments(tenant);

  const resolutionRate = totalActions > 0
    ? Math.round((await ResponseAction.countDocuments({ ...tenant, status: 'completed' }) / totalActions) * 100)
    : 0;

  return {
    activeThreats,
    systemsMonitored,
    incidentsResolved,
    pendingActions,
    totalActions,
    resolutionRate,
  };
};
