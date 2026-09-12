import * as svc from '../services/camera.service.js';

export const getCameras = async (req, res, next) => {
  try {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 20, 1), 100);
    res.json(await svc.listCameras({}, { page, limit }));
  } catch (e) { next(e); }
};

export const addCamera = async (req, res, next) => {
  try {
    const { name, streamUrl } = req.body;
    if (!name || !streamUrl) {
      return res.status(400).json({ message: 'name and streamUrl are required' });
    }
    res.status(201).json(await svc.addCamera(req.body, req.user?.id));
  } catch (e) { next(e); }
};

export const updateCamera = async (req, res, next) => {
  try {
    if (!req.params.id) return res.status(400).json({ message: 'Camera ID is required' });
    res.json(await svc.updateCamera(req.params.id, req.body));
  } catch (e) { next(e); }
};

export const deleteCamera = async (req, res, next) => {
  try {
    if (!req.params.id) return res.status(400).json({ message: 'Camera ID is required' });
    await svc.deleteCamera(req.params.id);
    res.json({ success: true });
  } catch (e) { next(e); }
};

export const toggleCamera = async (req, res, next) => {
  try {
    if (!req.params.id) return res.status(400).json({ message: 'Camera ID is required' });
    res.json(await svc.updateCamera(req.params.id, { enabled: req.body.enabled }));
  } catch (e) { next(e); }
};

export const getDetections = async (req, res, next) => {
  try {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 20, 1), 100);
    const filter = req.query.cameraId ? { cameraId: req.query.cameraId } : {};
    res.json(await svc.listDetections(filter, limit));
  } catch (e) { next(e); }
};

export const postDetection = async (req, res, next) => {
  try {
    const { type } = req.body;
    if (!type) return res.status(400).json({ message: 'type is required' });
    res.status(201).json(await svc.createDetection(req.body));
  } catch (e) { next(e); }
};

export const ackDetection = async (req, res, next) => {
  try {
    if (!req.params.id) return res.status(400).json({ message: 'Detection ID is required' });
    res.json(await svc.acknowledgeDetection(req.params.id));
  } catch (e) { next(e); }
};

export const escalateDetection = async (req, res, next) => {
  try {
    if (!req.params.id) return res.status(400).json({ message: 'Detection ID is required' });
    res.json(await svc.escalateDetection(req.params.id));
  } catch (e) { next(e); }
};

export const triggerDetection = async (req, res, next) => {
  try {
    if (!req.params.id) return res.status(400).json({ message: 'Camera ID is required' });
    const result = await svc.runDetection(req.params.id);
    if (!result) return res.status(400).json({ message: 'Camera not found or disabled' });
    res.status(201).json(result);
  } catch (e) { next(e); }
};
