import Threat from '../models/Threat.js';
import Asset from '../models/Asset.js';
import ResponseAction from '../models/ResponseAction.js';

export const getKPIs = async () => {
  const activeThreats = await Threat.countDocuments({ status: { $ne: 'resolved' } });
  const systemsMonitored = await Asset.countDocuments();
  const incidentsResolved = await Threat.countDocuments({ status: 'resolved' });
  const pendingActions = await ResponseAction.countDocuments({ status: 'pending' });
  const totalActions = await ResponseAction.countDocuments();

  const resolutionRate = totalActions > 0
    ? Math.round((await ResponseAction.countDocuments({ status: 'completed' }) / totalActions) * 100)
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
