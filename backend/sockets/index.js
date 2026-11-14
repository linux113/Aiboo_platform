import { listThreats } from '../services/threat.service.js';
import { listDetections, listCameras } from '../services/camera.service.js';
import User from '../models/User.js';
import Organization from '../models/Organization.js';
import logger from '../utils/logger.js';

const allowedOrganizationStatus = new Set(['active', 'legacy']);
const scopedRoleRoom = (organizationId, role) => `org:${organizationId}:role:${role}`;

export default function (io) {
  io.on('connection', async (socket) => {
    try {
      // A signed token is not enough for a long-lived socket: refresh tenant and
      // role from MongoDB so reassignment/disablement takes effect on reconnect.
      const user = await User.findById(socket.user?.id).select('name email role active organization');
      if (!user || user.active === false || user.role === 'super_admin' || !user.organization) {
        socket.disconnect(true);
        return;
      }
      const organization = await Organization.findById(user.organization).select('_id status isLegacy subscriptionExpiresAt');
      const subscriptionCurrent = organization?.isLegacy
        || (organization?.status === 'active' && organization?.subscriptionExpiresAt instanceof Date && organization.subscriptionExpiresAt.getTime() > Date.now());
      if (!organization || !allowedOrganizationStatus.has(organization.status) || !subscriptionCurrent) {
        socket.disconnect(true);
        return;
      }

      const organizationId = String(organization._id);
      const freshUser = {
        ...socket.user,
        id: String(user._id),
        name: user.name,
        email: user.email,
        role: user.role,
        organization: organizationId,
      };
      socket.user = freshUser;
      socket.organizationId = organizationId;
      socket.join(`org:${organizationId}`);
      logger.info(`Socket connected: ${socket.id} (user: ${user.email}, organization: ${organizationId})`);

      socket.on('init', async () => {
        try {
          const [threats, detections, cameras] = await Promise.all([
            listThreats({}, { organizationId }),
            listDetections({}, 30, organizationId),
            listCameras({}, { organizationId }),
          ]);
          socket.emit('init:data', { threats, detections, cameras });
        } catch (e) {
          logger.error(`socket init error: ${e.message}`);
        }
      });

      // Role-specific rooms are still tenant scoped. No cross-company room
      // joins are accepted from the client.
      socket.on('subscribe:role', (role) => {
        if (role === 'admin' && user.role === 'admin') {
          socket.join(scopedRoleRoom(organizationId, 'admin'));
        }
        if (role === 'analyst' && ['admin', 'analyst'].includes(user.role)) {
          socket.join(scopedRoleRoom(organizationId, 'analyst'));
        }
      });

      socket.on('unsubscribe:role', (role) => {
        if (['admin', 'analyst', 'viewer'].includes(role)) {
          socket.leave(scopedRoleRoom(organizationId, role));
        }
      });

      socket.on('disconnect', () => {
        logger.info(`Socket disconnected: ${socket.id} (user: ${user.email})`);
      });

      socket.on('error', (err) => {
        logger.error(`Socket error: ${err.message}`);
      });
    } catch (e) {
      logger.warn(`Socket tenant verification failed: ${e.message}`);
      socket.disconnect(true);
    }
  });
}
