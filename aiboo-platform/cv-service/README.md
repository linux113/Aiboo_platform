# AiBoO CV Service — YOLOv8 + DeepSORT + OpenCV

## Setup

```bash
cd cv_service
pip install -r requirements.txt
python app.py
```

Runs on **http://localhost:5050**

## How it works
1. Frontend POSTs camera details to `/cameras` → CV service opens the stream
2. CV service runs **YOLOv8** object detection every 3 frames
3. **DeepSORT** assigns persistent tracking IDs to each detected object
4. **OpenCV** handles frame capture, annotation, MJPEG encoding
5. Detections are POSTed to Node backend → emitted via WebSocket to frontend
6. Annotated stream served at `/cameras/<id>/stream` as MJPEG

## IP Webcam (Android)
1. Install "IP Webcam" app
2. Start Server → note the IP:port shown
3. Stream URL: `http://192.168.x.x:8080/video`
4. Add this URL in Dashboard → Surveillance → Add Camera
5. Set Type: `ip`

## RTSP Camera
Stream URL format: `rtsp://username:password@192.168.x.x:554/stream`

## What's detected
| Class | Type | Severity |
|-------|------|----------|
| person | person | low |
| knife / scissors | weapon_knife | critical |
| car / truck / bus | vehicle | low |
| backpack / suitcase | bag | low |
| 5+ persons | crowd | medium |
| Motion (fallback) | person | low |

## Fallback mode
If YOLOv8/DeepSORT are not installed, the service falls back to
OpenCV background subtraction for motion detection automatically.
