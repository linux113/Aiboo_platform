"""
AiBoO CV Service — Flask + YOLOv8 + DeepSORT + OpenCV

Full-spectrum detection: objects, animals, faces, motion, fire, smoke,
abandoned objects, fall detection, camera tampering, line crossing,
traffic analysis, night mode, loitering, crowd/gathering, zone breaches.
"""

from __future__ import annotations

import cv2
import numpy as np
import threading
import time
import json
import os
import logging
import signal
import sys
import hmac
import re
import ipaddress
import socket
from urllib.parse import urlparse
from collections import OrderedDict, deque
from datetime import datetime
from typing import Optional
from functools import wraps

import requests
from flask import Flask, Response, request, jsonify, abort
from flask_cors import CORS

# ── Logging Configuration ─────────────────────────────────────────
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt=LOG_DATE_FORMAT,
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("opencv")

# ── Configuration ────────────────────────────────────────────────
class Config:
    HOST = os.environ.get("CV_HOST", "127.0.0.1")
    PORT = int(os.environ.get("CV_PORT", 5050))
    NODE_BACKEND = os.environ.get("NODE_BACKEND", "http://localhost:4000")
    CV_AUTH_TOKEN = os.environ.get("CV_AUTH_TOKEN", "changeme-default-token-change-in-production")
    YOLO_MODEL_PATH = os.environ.get("YOLO_MODEL_PATH", "yolov8n.pt")
    YOLO_CONFIDENCE = float(os.environ.get("YOLO_CONFIDENCE", "0.30"))
    FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "http://localhost:3000")
    DETECTION_COOLDOWN_WEAPON = int(os.environ.get("DETECTION_COOLDOWN_WEAPON", "3"))
    DETECTION_COOLDOWN_CRITICAL = int(os.environ.get("DETECTION_COOLDOWN_CRITICAL", "5"))
    DETECTION_COOLDOWN_DEFAULT = int(os.environ.get("DETECTION_COOLDOWN_DEFAULT", "10"))
    MAX_TRACK_HISTORY = 1000
    ENTRY_STALE_SECONDS = 60
    CLEANUP_INTERVAL = 30
    RATE_LIMIT_REQUESTS = 60
    RATE_LIMIT_WINDOW = 60
    DETECTION_RETRY_MAX = 3
    DETECTION_RETRY_DELAY = 1.0
    FAILED_DETECTION_BUFFER_MAX = 500
    WORKER_HEALTH_TIMEOUT = 120
    RECONNECT_DELAY_MIN = 2
    RECONNECT_DELAY_MAX = 30
    FRAME_SKIP_INTERVAL = 3
    STREAM_FPS_TARGET = 30
    JPEG_QUALITY = 75
    MIN_TOKEN_LENGTH = 16
    FACE_DETECT_MIN_SIZE = 30
    FACE_DETECT_COOLDOWN = 8
    FACE_DETECT_SCALE_FACTOR = 1.1
    FACE_DETECT_MIN_NEIGHBORS = 4
    MOTION_THRESHOLD = 25
    MOTION_MIN_AREA = 800
    CROWD_THRESHOLD = 5
    GROUP_MIN = 2
    GROUP_MAX = 4
    GROUP_COOLDOWN = 30
    LOITERING_THRESHOLD = 20
    SPEED_COOLDOWN = 15
    SPEED_STANDING = 15
    SPEED_WALKING = 60
    SPEED_JOGGING = 150
    BREACH_CONFIDENCE_BASE = 75
    CROWD_CONFIDENCE_PER_PERSON = 5
    GROUP_CONFIDENCE = 70
    LOITERING_CONFIDENCE = 75
    FACE_CONFIDENCE = 85
    BREACH_CONFIDENCE_MAX = 95
    CROWD_CONFIDENCE_MAX = 95
    PERSON_CONFIDENCE_BOOST = 5
    PERSON_CONFIDENCE_MAX = 99
    MOTION_CONFIDENCE = 70
    SPEED_JOGGING_ALERT = 82
    FACE_WIDTH_WEIGHT = 20

    ANIMAL_COOLDOWN = int(os.environ.get("ANIMAL_COOLDOWN", "15"))
    ANIMAL_CONFIDENCE = int(os.environ.get("ANIMAL_CONFIDENCE", "78"))
    FIRE_CONFIDENCE = int(os.environ.get("FIRE_CONFIDENCE", "82"))
    FIRE_COOLDOWN = int(os.environ.get("FIRE_COOLDOWN", "10"))
    FIRE_MIN_RED_INTENSITY = int(os.environ.get("FIRE_MIN_RED_INTENSITY", "160"))
    SMOKE_CONFIDENCE = int(os.environ.get("SMOKE_CONFIDENCE", "75"))
    SMOKE_COOLDOWN = int(os.environ.get("SMOKE_COOLDOWN", "15"))
    ABANDONED_OBJECT_TIMEOUT = int(os.environ.get("ABANDONED_OBJECT_TIMEOUT", "30"))
    ABANDONED_CONFIDENCE = int(os.environ.get("ABANDONED_CONFIDENCE", "75"))
    ABANDONED_COOLDOWN = int(os.environ.get("ABANDONED_COOLDOWN", "20"))
    FALL_DETECT_COOLDOWN = int(os.environ.get("FALL_DETECT_COOLDOWN", "10"))
    FALL_ASPECT_RATIO_THRESHOLD = float(os.environ.get("FALL_ASPECT_RATIO_THRESHOLD", "0.55"))
    FALL_CONFIDENCE = int(os.environ.get("FALL_CONFIDENCE", "88"))
    TAMPER_FRAME_CONSISTENT_THRESHOLD = int(os.environ.get("TAMPER_FRAME_CONSISTENT_THRESHOLD", "40"))
    TAMPER_COOLDOWN = int(os.environ.get("TAMPER_COOLDOWN", "30"))
    TAMPER_CONFIDENCE = int(os.environ.get("TAMPER_CONFIDENCE", "90"))
    TRIPWIRE_COOLDOWN = int(os.environ.get("TRIPWIRE_COOLDOWN", "10"))
    TRIPWIRE_CONFIDENCE = int(os.environ.get("TRIPWIRE_CONFIDENCE", "82"))
    NIGHT_MODE_THRESHOLD = int(os.environ.get("NIGHT_MODE_THRESHOLD", "40"))
    NIGHT_COOLDOWN = int(os.environ.get("NIGHT_COOLDOWN", "30"))
    TRAFFIC_COOLDOWN = int(os.environ.get("TRAFFIC_COOLDOWN", "20"))

# ── Rate Limiter ──────────────────────────────────────────────────
class RateLimiter:
    def __init__(self, limit: int = Config.RATE_LIMIT_REQUESTS, window: int = Config.RATE_LIMIT_WINDOW):
        self.limit = limit
        self.window = window
        self._requests: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self.window
        with self._lock:
            if key not in self._requests:
                self._requests[key] = []
            entries = self._requests[key]
            entries[:] = [t for t in entries if t > cutoff]
            if len(entries) >= self.limit:
                return False
            entries.append(now)
            if len(self._requests) > 10000:
                self._requests.clear()
            return True

limiter = RateLimiter()

# ── URL / SSRF Validation ────────────────────────────────────────
_PRIVATE_IPV4_RANGES = [
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("169.254.0.0/16"),
]

_ALLOWED_SCHEMES = {"http", "https", "rtsp"}

def is_private_ip(hostname: str) -> bool:
    try:
        addr = ipaddress.ip_address(hostname)
        return any(addr in net for net in _PRIVATE_IPV4_RANGES)
    except ValueError:
        return False

def resolve_hostname(hostname: str) -> list[str]:
    try:
        return [info[4][0] for info in socket.getaddrinfo(hostname, None)]
    except OSError:
        return []

def validate_stream_url(url: str) -> Optional[str]:
    if not url or not url.strip():
        return "URL is empty"
    url = url.strip()
    if url == "string":
        return "URL is a placeholder value"
    parsed = urlparse(url)
    if not parsed.scheme:
        return f"URL has no scheme: {url}"
    if parsed.scheme not in _ALLOWED_SCHEMES:
        return f"URL scheme '{parsed.scheme}' is not allowed (must be http, https, or rtsp)"
    if not parsed.netloc and parsed.scheme in ("http", "https"):
        return f"URL has no host: {url}"
    if parsed.scheme in ("http", "https", "rtsp"):
        hostname = parsed.hostname
        if not hostname:
            return f"Could not parse hostname from URL: {url}"
        if is_private_ip(hostname):
            return f"URL points to a private/internal IP address: {hostname}"
        resolved = resolve_hostname(hostname)
        if not resolved:
            return f"Could not resolve hostname: {hostname}"
        for ip_addr in resolved:
            if is_private_ip(ip_addr):
                return f"URL resolves to private IP: {ip_addr}"
        if "/demo/stream" in parsed.path:
            return "Demo stream URL is not allowed"
    return None

# ── Authentication Decorator ─────────────────────────────────────
_NODE_TOKEN = ""
_node_token_lock = threading.Lock()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header. Use: Bearer <token>"}), 401
        token = auth_header[len("Bearer "):].strip()
        if not token:
            return jsonify({"error": "Token is empty"}), 401
        if not _verify_cv_token(token):
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

def _verify_cv_token(token: str) -> bool:
    return hmac.compare_digest(token, Config.CV_AUTH_TOKEN)


def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if not limiter.is_allowed(client_ip):
            return jsonify({"error": "Rate limit exceeded"}), 429
        return f(*args, **kwargs)
    return decorated

# ── Retry helper ───────────────────────────────────────────────────
def _post_with_retry(url: str, payload: dict, headers: dict, max_retries: int = Config.DETECTION_RETRY_MAX):
    last_exc = None
    for attempt in range(max_retries):
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=2)
            if resp.ok:
                return True
            last_exc = RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        except requests.RequestException as exc:
            last_exc = exc
        if attempt < max_retries - 1:
            time.sleep(Config.DETECTION_RETRY_DELAY * (2 ** attempt))
    log.error("Failed to POST detection after %d retries: %s", max_retries, last_exc)
    return False

# ── LRU Cache (thread-safe) ──────────────────────────────────────
class LRUCache:
    def __init__(self, maxsize: int = Config.MAX_TRACK_HISTORY):
        self._maxsize = maxsize
        self._cache: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key, default=None):
        with self._lock:
            if key not in self._cache:
                return default
            self._cache.move_to_end(key)
            return self._cache[key]

    def put(self, key, value):
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = value
            if len(self._cache) > self._maxsize:
                self._cache.popitem(last=False)

    def __contains__(self, key):
        with self._lock:
            return key in self._cache

    def __len__(self):
        with self._lock:
            return len(self._cache)

    def keys(self):
        with self._lock:
            return list(self._cache.keys())

    def pop(self, key, default=None):
        with self._lock:
            return self._cache.pop(key, default)

    def items(self):
        with self._lock:
            return list(self._cache.items())

# ── Comprehensive COCO Class Map ──────────────────────────────────
# Maps all 80 YOLOv8 COCO classes into security-relevant categories

COCO_PERSON = {"person"}
COCO_VEHICLE = {"car", "truck", "bus", "motorcycle", "bicycle"}
COCO_ANIMAL = {"dog", "cat", "bird", "horse", "sheep", "cow", "elephant",
               "bear", "zebra", "giraffe"}
COCO_BAG = {"backpack", "handbag", "suitcase"}
COCO_DEVICE = {"cell phone", "laptop", "tv", "remote"}
COCO_WEAPON_LIKE = {"knife", "scissors"}
COCO_SPORTS = {"frisbee", "skis", "snowboard", "sports ball", "kite",
               "baseball bat", "baseball glove", "skateboard", "surfboard",
               "tennis racket"}
COCO_FOOD = {"bottle", "cup", "fork", "knife", "spoon", "bowl",
             "banana", "apple", "sandwich", "orange", "broccoli",
             "carrot", "hot dog", "pizza", "donut", "cake"}
COCO_INDOOR = {"chair", "couch", "potted plant", "bed", "dining table",
               "toilet", "sink", "refrigerator", "book", "vase",
               "clock", "hair drier", "toothbrush"}
COCO_OUTDOOR = {"bench", "umbrella", "traffic light", "stop sign",
                "parking meter", "fire hydrant", "tie"}
COCO_ELECTRONICS = {"keyboard", "mouse", "monitor", "microwave", "oven",
                    "toaster"}

# Combined map: class_name -> detection_type
COCO_TO_DETECTION: dict[str, str] = {}
for cls in COCO_PERSON:
    COCO_TO_DETECTION[cls] = "person"
for cls in COCO_VEHICLE:
    COCO_TO_DETECTION[cls] = "vehicle"
for cls in COCO_ANIMAL:
    COCO_TO_DETECTION[cls] = "animal"
for cls in COCO_BAG:
    COCO_TO_DETECTION[cls] = "bag"
for cls in COCO_DEVICE:
    COCO_TO_DETECTION[cls] = "device"
for cls in COCO_WEAPON_LIKE:
    COCO_TO_DETECTION[cls] = "weapon_knife"
for cls in COCO_SPORTS:
    COCO_TO_DETECTION[cls] = "sports_equipment"
for cls in COCO_FOOD:
    COCO_TO_DETECTION[cls] = "food_item"
for cls in COCO_INDOOR:
    COCO_TO_DETECTION[cls] = "indoor_object"
for cls in COCO_OUTDOOR:
    COCO_TO_DETECTION[cls] = "outdoor_object"
for cls in COCO_ELECTRONICS:
    COCO_TO_DETECTION[cls] = "electronics"

def get_severity(det_type: str) -> str:
    if det_type in ("weapon_knife", "face_watchlist", "fire", "tamper"):
        return "critical"
    if det_type in ("face_unknown", "behavior_anomaly", "smoke", "fall"):
        return "high"
    if det_type in ("crowd", "breach", "device", "animal", "line_cross",
                    "abandoned_object", "traffic_anomaly"):
        return "medium"
    return "low"

# ── YOLOv8 ─────────────────────────────────────────────────────────
yolo = None
YOLO_AVAILABLE = False
try:
    from ultralytics import YOLO as _YOLO
    model_path = Config.YOLO_MODEL_PATH
    if os.path.exists(model_path):
        yolo = _YOLO(model_path)
        YOLO_AVAILABLE = True
        log.info("YOLOv8 loaded from %s", model_path)
    else:
        log.warning("YOLO model not found at %s, trying default yolov8n.pt", model_path)
        yolo = _YOLO("yolov8n.pt")
        YOLO_AVAILABLE = True
        log.info("YOLOv8 loaded (default)")
except Exception as exc:
    YOLO_AVAILABLE = False
    log.warning("YOLOv8 not available (%s) — using OpenCV motion detection fallback", exc)

# ── DeepSORT ───────────────────────────────────────────────────────
DEEPSORT_AVAILABLE = False
DeepSort = None
try:
    from deep_sort_realtime.deepsort_tracker import DeepSort
    DEEPSORT_AVAILABLE = True
    log.info("DeepSORT loaded")
except Exception as exc:
    DEEPSORT_AVAILABLE = False
    log.warning("DeepSORT not available (%s) — tracking disabled", exc)

# ── Flask App ──────────────────────────────────────────────────────
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
CORS(app, origins=[Config.FRONTEND_ORIGIN], supports_credentials=True)

# ── Failed detection buffer ────────────────────────────────────────
_failed_detections: deque = deque()
_failed_detections_lock = threading.Lock()

# ── Color names for clothing detection ─────────────────────────────
_COLOR_NAMES = [
    ("Red", (0, 0, 200)),
    ("Blue", (200, 0, 0)),
    ("Green", (0, 150, 0)),
    ("White", (200, 200, 200)),
    ("Black", (30, 30, 30)),
    ("Gray", (120, 120, 120)),
    ("Brown", (60, 120, 190)),
    ("Yellow", (0, 220, 220)),
]

# ── Per-Camera Worker with Full-Spectrum Detection ─────────────────
class CameraWorker:
    def __init__(self, camera_id: str, name: str, url: str, location: str):
        self.camera_id = camera_id
        self.name = name
        self.url = url
        self.location = location
        self.running = False
        self.frame: Optional[np.ndarray] = None
        self.annotated: Optional[np.ndarray] = None
        self.lock = threading.Lock()
        self.cap: Optional[cv2.VideoCapture] = None
        self.last_alert: dict[str, float] = {}
        self._last_alert_lock = threading.Lock()
        self.frame_count = 0
        self.fps = 0
        self._thread: Optional[threading.Thread] = None
        self._motion_bg: Optional[np.ndarray] = None
        self._face_cascade: Optional[cv2.CascadeClassifier] = None
        self._face_cascade_loaded = False

        self._person_entries: dict[int, float] = {}
        self._person_entries_lock = threading.Lock()
        self._loitering_reported: set[int] = set()
        self._loitering_lock = threading.Lock()
        self._track_history = LRUCache(maxsize=Config.MAX_TRACK_HISTORY)
        self._zone_breach_reported: set[int] = set()
        self._zone_breach_lock = threading.Lock()
        self._group_reported = False
        self._last_frame_time = 0.0
        self._cap_lock = threading.Lock()
        self.tracker = DeepSort(max_age=30) if DeepSort else None

        # -- Abandoned object detection --
        self._static_objects: dict[str, dict] = {}
        self._static_lock = threading.Lock()
        self._prev_frame_gray: Optional[np.ndarray] = None

        # -- Tamper detection --
        self._tamper_frame_buffer: deque = deque(maxlen=5)
        self._tamper_lock = threading.Lock()

        # -- Night mode tracking --
        self._night_reported = False
        self._night_lock = threading.Lock()

        # -- Traffic analysis --
        self._vehicle_count = 0
        self._vehicle_lock = threading.Lock()
        self._vehicle_tracks: dict[int, tuple[float, int, int]] = {}

        # -- Line crossing / tripwire (vertical line at 50% width) --
        self._tripwire_x: Optional[int] = None
        self._crossed_ids: set[int] = set()
        self._crossing_lock = threading.Lock()

    def _new_track_entry(self) -> dict:
        return {
            "zone": None,
            "last_zone_entry": 0,
            "last_pos_time": 0,
            "positions": [],
            "prev_center": None,
            "prev_time": None,
            "entry_side": None,
            "color": "Unknown",
            "speed": "Standing",
        }

    def cleanup(self):
        now = time.time()
        cutoff = now - Config.ENTRY_STALE_SECONDS
        with self._person_entries_lock:
            stale_person = [tid for tid, t in self._person_entries.items() if t < cutoff]
            for tid in stale_person:
                del self._person_entries[tid]
        with self._loitering_lock:
            stale_loitering = set()
            for tid in list(self._loitering_reported):
                entry = self._person_entries.get(tid)
                if entry is not None and entry < cutoff:
                    stale_loitering.add(tid)
            self._loitering_reported -= stale_loitering
        with self._zone_breach_lock:
            stale_breach = set()
            for tid in list(self._zone_breach_reported):
                entry = self._person_entries.get(tid)
                if entry is not None and entry < cutoff:
                    stale_breach.add(tid)
            self._zone_breach_reported -= stale_breach
        stale_tracks = []
        for tid in self._track_history.keys():
            entry = self._person_entries.get(tid)
            if entry is not None and entry < cutoff:
                stale_tracks.append(tid)
            else:
                hist = self._track_history.get(tid)
                if hist and hist["positions"]:
                    last_pos_time = hist.get("last_pos_time", 0)
                    if last_pos_time and last_pos_time < cutoff:
                        stale_tracks.append(tid)
        for tid in stale_tracks:
            self._track_history.pop(tid)
        with self._static_lock:
            stale_static = [k for k, v in self._static_objects.items()
                           if v.get("first_seen", 0) < cutoff]
            for k in stale_static:
                del self._static_objects[k]

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name=f"cam-{self.camera_id}")
        self._thread.start()

    def stop(self):
        self.running = False
        with self._cap_lock:
            cap = self.cap
            if cap is not None:
                try:
                    cap.release()
                except Exception:
                    pass
            self.cap = None

    def _load_face_cascade(self):
        if self._face_cascade_loaded:
            return
        try:
            cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
            if os.path.exists(cascade_path):
                cc = cv2.CascadeClassifier(cascade_path)
                if not cc.empty():
                    self._face_cascade = cc
                    log.debug("Face cascade loaded for camera %s", self.camera_id)
                else:
                    self._face_cascade = None
                    log.warning("Face cascade classifier is empty for camera %s", self.camera_id)
            else:
                self._face_cascade = None
                log.warning("Haar cascade file not found at %s", cascade_path)
        except Exception as exc:
            self._face_cascade = None
            log.error("Failed to load face cascade for camera %s: %s", self.camera_id, exc)
        self._face_cascade_loaded = True

    def _run(self):
        log.info("Starting camera: %s -> %s", self.name, self.url)
        reconnect_delay = Config.RECONNECT_DELAY_MIN
        while self.running:
            try:
                if self.url.startswith("webcam:"):
                    idx_str = self.url.split(":", 1)[1]
                    try:
                        idx = int(idx_str)
                    except ValueError:
                        log.error("Invalid webcam index '%s' for camera %s", idx_str, self.camera_id)
                        time.sleep(reconnect_delay)
                        continue
                    self.cap = cv2.VideoCapture(idx)
                    if not self.cap.isOpened():
                        log.warning("Cannot open webcam index %d, retrying in %ds...", idx, reconnect_delay)
                        time.sleep(reconnect_delay)
                        reconnect_delay = min(reconnect_delay * 2, Config.RECONNECT_DELAY_MAX)
                        continue
                    self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
                    self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
                else:
                    self.cap = cv2.VideoCapture(self.url)
                if not self.cap.isOpened():
                    log.warning("Cannot open %s, retrying in %ds...", self.url, reconnect_delay)
                    time.sleep(reconnect_delay)
                    reconnect_delay = min(reconnect_delay * 2, Config.RECONNECT_DELAY_MAX)
                    continue
                reconnect_delay = Config.RECONNECT_DELAY_MIN
                t_prev = time.time()
                while self.running:
                    with self._cap_lock:
                        cap = self.cap
                    if cap is None:
                        break
                    ret, frame = cap.read()
                    if not ret:
                        break
                    self.frame_count += 1
                    t_now = time.time()
                    self.fps = round(1.0 / max(t_now - t_prev, 0.001), 1)
                    t_prev = t_now
                    self._last_frame_time = t_now

                    if self.frame_count % Config.FRAME_SKIP_INTERVAL == 0:
                        annotated, detections = self._process_frame(frame)
                        for det in detections:
                            self._post_detection(det)
                    else:
                        annotated = frame.copy()

                    self._overlay_hud(annotated)
                    with self.lock:
                        self.frame = frame.copy()
                        self.annotated = annotated
            except Exception as exc:
                log.error("Camera %s error: %s", self.name, exc, exc_info=True)
            finally:
                with self._cap_lock:
                    cap = self.cap
                    if cap is not None:
                        try:
                            cap.release()
                        except Exception:
                            pass
                    self.cap = None
            if self.running:
                time.sleep(reconnect_delay)

    def _get_color_name(self, frame: np.ndarray, x1: int, y1: int, x2: int, y2: int) -> str:
        try:
            h, w = frame.shape[:2]
            y1c = max(0, y1)
            y2c = min(y2, h)
            x1c = max(0, x1)
            x2c = min(x2, w)
            roi = frame[y1c:y2c, x1c:x2c]
            if roi.size == 0:
                return "Unknown"
            avg = roi.mean(axis=(0, 1))
            b, g, r = float(avg[0]), float(avg[1]), float(avg[2])
            best = min(_COLOR_NAMES, key=lambda c: (r - c[1][2]) ** 2 + (g - c[1][1]) ** 2 + (b - c[1][0]) ** 2)
            return best[0]
        except Exception as exc:
            log.debug("Color detection failed: %s", exc)
            return "Unknown"

    @staticmethod
    def _get_zone(cy: int, h: int) -> str:
        if cy < h * 0.33:
            return "Restricted"
        if cy < h * 0.66:
            return "Sensitive"
        return "Public"

    @staticmethod
    def _classify_speed(displacement: float, dt: float) -> str:
        if dt < 0.01:
            return "Standing"
        speed = displacement / dt
        if speed < Config.SPEED_STANDING:
            return "Standing"
        if speed < Config.SPEED_WALKING:
            return "Walking"
        if speed < Config.SPEED_JOGGING:
            return "Jogging"
        return "Running"

    @staticmethod
    def _get_entry_side(cx: int, w: int, prev_cx: Optional[int], prev_cy: Optional[int]) -> str:
        if prev_cx is None:
            return "entered_frame"
        dx = cx - prev_cx
        if abs(dx) > w * 0.08:
            return "moving_right" if dx > 0 else "moving_left"
        return "stationary"

    # ── Fire Detection ─────────────────────────────────────────────
    def _detect_fire(self, frame: np.ndarray) -> list[dict]:
        dets = []
        h, w = frame.shape[:2]
        hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
        lower_fire = np.array([0, 60, Config.FIRE_MIN_RED_INTENSITY])
        upper_fire = np.array([35, 255, 255])
        mask1 = cv2.inRange(hsv, lower_fire, upper_fire)
        lower_fire2 = np.array([165, 60, Config.FIRE_MIN_RED_INTENSITY])
        upper_fire2 = np.array([179, 255, 255])
        mask2 = cv2.inRange(hsv, lower_fire2, upper_fire2)
        mask = cv2.bitwise_or(mask1, mask2)
        mask = cv2.GaussianBlur(mask, (15, 15), 0)
        mask = cv2.erode(mask, None, iterations=1)
        mask = cv2.dilate(mask, None, iterations=2)
        cnts, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        for c in cnts:
            area = cv2.contourArea(c)
            if area < 200:
                continue
            x, y, cw, ch = cv2.boundingRect(c)
            dets.append({
                "type": "fire",
                "confidence": Config.FIRE_CONFIDENCE,
                "box": [x, y, x + cw, y + ch],
                "label": f"Fire Detected — area {int(area)}px, zone {self._get_zone(y + ch//2, h)}",
            })
            cv2.rectangle(frame, (x, y), (x + cw, y + ch), (0, 0, 255), 3)
            cv2.putText(frame, "FIRE", (x, y - 8), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 255), 2)
        return dets

    # ── Smoke Detection ────────────────────────────────────────────
    def _detect_smoke(self, frame: np.ndarray) -> list[dict]:
        dets = []
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        blurred = cv2.GaussianBlur(gray, (21, 21), 0)
        if self._prev_frame_gray is not None:
            diff = cv2.absdiff(self._prev_frame_gray, blurred)
            _, thresh = cv2.threshold(diff, 15, 255, cv2.THRESH_BINARY)
            thresh = cv2.dilate(thresh, None, iterations=2)
            cnts, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            for c in cnts:
                area = cv2.contourArea(c)
                if area < 400:
                    continue
                x, y, cw, ch = cv2.boundingRect(c)
                roi = frame[y:y+ch, x:x+cw]
                if roi.size == 0:
                    continue
                gray_roi = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)
                mean_intensity = gray_roi.mean()
                if 60 < mean_intensity < 180:
                    dets.append({
                        "type": "smoke",
                        "confidence": Config.SMOKE_CONFIDENCE,
                        "box": [x, y, x + cw, y + ch],
                        "label": f"Smoke Detected — area {int(area)}px, zone {self._get_zone(y + ch//2, frame.shape[0])}",
                    })
                    cv2.rectangle(frame, (x, y), (x + cw, y + ch), (100, 100, 100), 2)
                    cv2.putText(frame, "SMOKE", (x, y - 6), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (100, 100, 100), 2)
        self._prev_frame_gray = blurred
        return dets

    # ── Abandoned Object Detection ─────────────────────────────────
    def _detect_abandoned_objects(self, frame: np.ndarray, yolo_dets: list[dict]) -> list[dict]:
        dets = []
        now = time.time()
        h, w = frame.shape[:2]
        bag_boxes = [d for d in yolo_dets if d.get("_cls") in COCO_BAG]
        person_boxes = [d for d in yolo_dets if d.get("_cls") in COCO_PERSON]
        with self._static_lock:
            for bag in bag_boxes:
                bx1, by1, bx2, by2 = bag["box"]
                bcx, bcy = (bx1 + bx2) // 2, (by1 + by2) // 2
                is_near_person = False
                for p in person_boxes:
                    px1, py1, px2, py2 = p["box"]
                    pcx, pcy = (px1 + px2) // 2, (py1 + py2) // 2
                    dist = ((bcx - pcx) ** 2 + (bcy - pcy) ** 2) ** 0.5
                    if dist < max(w, h) * 0.25:
                        is_near_person = True
                        break
                key = f"bag_{bx1}_{by1}_{bx2}_{by2}"
                if not is_near_person:
                    if key not in self._static_objects:
                        self._static_objects[key] = {"first_seen": now, "alerted": False}
                    elapsed = now - self._static_objects[key]["first_seen"]
                    if elapsed > Config.ABANDONED_OBJECT_TIMEOUT and not self._static_objects[key]["alerted"]:
                        self._static_objects[key]["alerted"] = True
                        dets.append({
                            "type": "abandoned_object",
                            "confidence": Config.ABANDONED_CONFIDENCE,
                            "box": [bx1, by1, bx2, by2],
                            "label": f"Abandoned {bag.get('label', 'object')} — unattended for {int(elapsed)}s",
                        })
                        cv2.rectangle(frame, (bx1, by1), (bx2, by2), (0, 165, 255), 3)
                        cv2.putText(frame, "ABANDONED", (bx1, by1 - 6),
                                    cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 165, 255), 2)
                else:
                    self._static_objects.pop(key, None)
        return dets

    # ── Fall Detection ─────────────────────────────────────────────
    def _detect_falls(self, tracks: list, frame: np.ndarray, now: float) -> list[dict]:
        dets = []
        for track in tracks:
            if not track.is_confirmed():
                continue
            ltrb = track.to_ltrb()
            tx1, ty1, tx2, ty2 = map(int, ltrb)
            box_w = tx2 - tx1
            box_h = ty2 - ty1
            if box_h <= 0:
                continue
            aspect = box_w / box_h
            if aspect > (1.0 / Config.FALL_ASPECT_RATIO_THRESHOLD) and box_h > Config.FACE_DETECT_MIN_SIZE * 3:
                tid = track.track_id
                cooldown_key = f"fall_{tid}"
                with self._last_alert_lock:
                    last_fall = self.last_alert.get(cooldown_key, 0.0)
                    if now - last_fall > Config.FALL_DETECT_COOLDOWN:
                        self.last_alert[cooldown_key] = now
                        dets.append({
                            "type": "fall",
                            "confidence": Config.FALL_CONFIDENCE,
                            "box": [tx1, ty1, tx2, ty2],
                            "label": f"Fall Detected — person ID {tid} horizontal (aspect {aspect:.2f})",
                        })
                        cv2.rectangle(frame, (tx1, ty1), (tx2, ty2), (0, 0, 255), 3)
                        cv2.putText(frame, "FALL", (tx1, ty1 - 6),
                                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 255), 2)
        return dets

    # ── Camera Tamper Detection ────────────────────────────────────
    def _detect_tamper(self, frame: np.ndarray, now: float) -> list[dict]:
        dets = []
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        mean_val = gray.mean()
        std_val = gray.std()
        with self._tamper_lock:
            self._tamper_frame_buffer.append((mean_val, std_val))
            if len(self._tamper_frame_buffer) >= 3:
                means = [m for m, _ in self._tamper_frame_buffer]
                stds = [s for _, s in self._tamper_frame_buffer]
                mean_range = max(means) - min(means)
                std_range = max(stds) - min(stds)
                if mean_range < Config.TAMPER_FRAME_CONSISTENT_THRESHOLD and std_range < 10:
                    cooldown_key = "tamper"
                    with self._last_alert_lock:
                        last_tamper = self.last_alert.get(cooldown_key, 0.0)
                        if now - last_tamper > Config.TAMPER_COOLDOWN:
                            self.last_alert[cooldown_key] = now
                            reason = "covered" if mean_val < Config.TAMPER_FRAME_CONSISTENT_THRESHOLD * 2 else "consistent_unexpected"
                            dets.append({
                                "type": "tamper",
                                "confidence": Config.TAMPER_CONFIDENCE,
                                "box": [0, 0, frame.shape[1], frame.shape[0]],
                                "label": f"Camera Tamper — possible {reason} lens (global mean={mean_val:.0f})",
                            })
                            cv2.putText(frame, "TAMPER DETECTED", (30, 60),
                                        cv2.FONT_HERSHEY_SIMPLEX, 1.0, (0, 0, 255), 3)
        return dets

    # ── Tripwire / Line Crossing Detection ─────────────────────────
    def _detect_line_crossing(self, tracks: list, frame: np.ndarray, now: float, w: int) -> list[dict]:
        dets = []
        if self._tripwire_x is None:
            self._tripwire_x = w // 2
        tw_x = self._tripwire_x
        cv2.line(frame, (tw_x, 0), (tw_x, frame.shape[0]), (0, 255, 255), 2)
        cv2.putText(frame, "TRIPWIRE", (tw_x + 4, 20), cv2.FONT_HERSHEY_SIMPLEX, 0.4, (0, 255, 255), 1)
        for track in tracks:
            if not track.is_confirmed():
                continue
            tid = track.track_id
            ltrb = track.to_ltrb()
            tx1, _, tx2, _ = map(int, ltrb)
            cx = (tx1 + tx2) // 2
            prev_cx = None
            hist = self._track_history.get(tid)
            if hist and hist["positions"]:
                prev_cx = hist["positions"][-1][0]
            if prev_cx is not None:
                crossed_before = (prev_cx - tw_x) * (cx - tw_x) < 0
                with self._crossing_lock:
                    if crossed_before and tid not in self._crossed_ids:
                        self._crossed_ids.add(tid)
                        direction = "L→R" if cx > tw_x else "R→L"
                        cooldown_key = f"cross_{tid}"
                        with self._last_alert_lock:
                            last_cross = self.last_alert.get(cooldown_key, 0.0)
                            if now - last_cross > Config.TRIPWIRE_COOLDOWN:
                                self.last_alert[cooldown_key] = now
                                dets.append({
                                    "type": "line_cross",
                                    "confidence": Config.TRIPWIRE_CONFIDENCE,
                                    "box": [tx1, int(frame.shape[0] * 0.4), tx2, int(frame.shape[0] * 0.6)],
                                    "label": f"Line Crossed — ID {tid} {direction} at tripwire",
                                })
                                cv2.putText(frame, f"CROSS {direction}", (tw_x - 80, frame.shape[0] // 2),
                                            cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 255), 2)
        return dets

    # ── Traffic Analysis ───────────────────────────────────────────
    def _detect_traffic(self, tracks: list, frame: np.ndarray, now: float) -> list[dict]:
        dets = []
        with self._vehicle_lock:
            for track in tracks:
                if not track.is_confirmed():
                    continue
                tid = track.track_id
                ltrb = track.to_ltrb()
                tx1, ty1, tx2, ty2 = map(int, ltrb)
                cx = (tx1 + tx2) // 2
                if tid in self._vehicle_tracks:
                    prev_x, prev_count, _ = self._vehicle_tracks[tid]
                    if abs(cx - prev_x) > 20:
                        self._vehicle_count += 1
                        self._vehicle_tracks[tid] = (cx, self._vehicle_count, now)
                        if self._vehicle_count % 10 == 0:
                            cooldown_key = "traffic"
                            with self._last_alert_lock:
                                last_traffic = self.last_alert.get(cooldown_key, 0.0)
                                if now - last_traffic > Config.TRAFFIC_COOLDOWN:
                                    self.last_alert[cooldown_key] = now
                                    dets.append({
                                        "type": "traffic_anomaly",
                                        "confidence": Config.LOITERING_CONFIDENCE,
                                        "box": [tx1, ty1, tx2, ty2],
                                        "label": f"Traffic Alert — {self._vehicle_count} vehicles tracked",
                                    })
                else:
                    self._vehicle_tracks[tid] = (cx, self._vehicle_count, now)
        return dets

    # ── Night Mode Detection ───────────────────────────────────────
    def _detect_night(self, frame: np.ndarray, now: float) -> list[dict]:
        dets = []
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        mean_brightness = gray.mean()
        with self._night_lock:
            if mean_brightness < Config.NIGHT_MODE_THRESHOLD and not self._night_reported:
                self._night_reported = True
                cooldown_key = "night"
                with self._last_alert_lock:
                    last_night = self.last_alert.get(cooldown_key, 0.0)
                    if now - last_night > Config.NIGHT_COOLDOWN:
                        self.last_alert[cooldown_key] = now
                        dets.append({
                            "type": "behavior_anomaly",
                            "confidence": Config.MOTION_CONFIDENCE,
                            "box": [0, 0, frame.shape[1], frame.shape[0]],
                            "label": f"Low Light / Night Mode — brightness {mean_brightness:.0f}/255",
                        })
            elif mean_brightness >= Config.NIGHT_MODE_THRESHOLD and self._night_reported:
                self._night_reported = False
        return dets

    # ── Main Frame Processing Pipeline ─────────────────────────────
    def _process_frame(self, frame: np.ndarray):
        detections: list[dict] = []
        annotated = frame.copy()
        h, w = frame.shape[:2]
        now = time.time()

        # ── Zone overlays ──────────────────────────────────────────
        zone_config = [
            ("Restricted", (0, 0, 180, 0.08)),
            ("Sensitive", (0, 120, 255, 0.05)),
            ("Public", (180, 0, 0, 0.05)),
        ]
        for zi, (zname, (zr, zg, zb, za)) in enumerate(zone_config):
            y0 = int(h * zi / 3)
            y1 = int(h * (zi + 1) / 3)
            overlay = annotated.copy()
            cv2.rectangle(overlay, (0, y0), (w, y1), (zb, zg, zr), -1)
            cv2.addWeighted(overlay, za, annotated, 1 - za, 0, annotated)
            cv2.putText(annotated, zname.upper(), (8, y0 + 20),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.4, (180, 180, 180), 1)

        # ── Ambient detection (always runs) ────────────────────────
        tamper_dets = self._detect_tamper(annotated, now)
        detections.extend(tamper_dets)
        night_dets = self._detect_night(annotated, now)
        detections.extend(night_dets)

        if YOLO_AVAILABLE:
            try:
                results = yolo(frame, verbose=False, conf=Config.YOLO_CONFIDENCE)[0]
            except Exception as exc:
                log.error("YOLO inference failed: %s", exc)
                return annotated, []
            raw_dets: list = []
            yolo_detections: list[dict] = []

            for box in results.boxes:
                cls_id = int(box.cls[0])
                cls_name = yolo.names[cls_id].lower()
                confidence = float(box.conf[0])
                x1, y1, x2, y2 = map(int, box.xyxy[0])

                det_type: Optional[str] = COCO_TO_DETECTION.get(cls_name)

                if det_type:
                    raw_dets.append(([x1, y1, x2 - x1, y2 - y1], confidence, det_type))
                    det_entry = {
                        "type": det_type,
                        "confidence": round(confidence * 100),
                        "box": [x1, y1, x2, y2],
                        "label": cls_name.replace("_", " ").title(),
                        "_cls": cls_name,
                    }
                    yolo_detections.append(det_entry)
                    detections.append(det_entry)

                if det_type == "weapon_knife":
                    color = (0, 0, 255)
                elif det_type == "animal":
                    color = (0, 200, 255)
                elif det_type in ("vehicle", "device", "electronics"):
                    color = (255, 200, 0)
                elif det_type:
                    color = (0, 255, 180)
                else:
                    color = (100, 100, 100)
                cv2.rectangle(annotated, (x1, y1), (x2, y2), color, 2)
                label_txt = f"{cls_name} {confidence:.0%}"
                cv2.putText(annotated, label_txt, (x1, y1 - 6),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.45, color, 1)

            # ── Specialized detections from YOLO findings ──────────
            fire_dets = self._detect_fire(annotated)
            detections.extend(fire_dets)
            smoke_dets = self._detect_smoke(annotated)
            detections.extend(smoke_dets)
            abandon_dets = self._detect_abandoned_objects(annotated, yolo_detections)
            detections.extend(abandon_dets)

            tracks = []
            if DEEPSORT_AVAILABLE and raw_dets:
                try:
                    tracks = self.tracker.update_tracks(raw_dets, frame=frame)
                except Exception as exc:
                    log.error("DeepSORT update failed: %s", exc)
                    tracks = []

                for track in tracks:
                    if not track.is_confirmed():
                        continue
                    tid = track.track_id
                    ltrb = track.to_ltrb()
                    tx1, ty1, tx2, ty2 = map(int, ltrb)
                    cx, cy = (tx1 + tx2) // 2, (ty1 + ty2) // 2
                    cv2.putText(annotated, f"ID:{tid}", (tx1, ty2 + 14),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.4, (100, 255, 255), 1)

                    hist = self._track_history.get(tid)
                    if hist is None:
                        hist = self._new_track_entry()
                        self._track_history.put(tid, hist)

                    hist["positions"].append((cx, cy))
                    if len(hist["positions"]) > 60:
                        hist["positions"].pop(0)
                    hist["last_pos_time"] = now

                    current_zone = self._get_zone(cy, h)
                    if hist["zone"] != current_zone:
                        hist["last_zone_entry"] = now
                    hist["zone"] = current_zone

                    prev = hist["prev_center"]
                    prev_t = hist["prev_time"]
                    if prev and prev_t:
                        dx = cx - prev[0]
                        dy = cy - prev[1]
                        disp = (dx ** 2 + dy ** 2) ** 0.5
                        dt = now - prev_t
                        hist["speed"] = self._classify_speed(disp, dt)
                    hist["prev_center"] = (cx, cy)
                    hist["prev_time"] = now

                    if hist["color"] == "Unknown" and (ty2 - ty1) > 40:
                        hist["color"] = self._get_color_name(frame, tx1, ty1 + (ty2 - ty1) // 3, tx2, ty2)

                    movement = self._get_entry_side(cx, w, prev[0] if prev else None, cy)
                    if hist["entry_side"] is None and movement == "entered_frame":
                        side = "left" if cx < w * 0.3 else "right" if cx > w * 0.7 else "center"
                        hist["entry_side"] = side

                    with self._zone_breach_lock:
                        if current_zone == "Restricted" and tid not in self._zone_breach_reported:
                            self._zone_breach_reported.add(tid)
                            breach_conf = min(Config.BREACH_CONFIDENCE_MAX,
                                              Config.BREACH_CONFIDENCE_BASE + int(abs(cx - w // 2) * Config.FACE_WIDTH_WEIGHT / w))
                            detections.append({
                                "type": "breach",
                                "confidence": breach_conf,
                                "box": [tx1, ty1, tx2, ty2],
                                "label": f"Zone Breach — {hist['color']} subject entered Restricted Zone",
                            })
                            cv2.rectangle(annotated, (tx1, ty1), (tx2, ty2), (0, 0, 255), 3)
                            cv2.putText(annotated, "BREACH", (tx1, ty1 - 20),
                                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 255), 2)

                    high_speed = hist["speed"]
                    cooldown_key = f"speed_{tid}"
                    with self._last_alert_lock:
                        last = self.last_alert.get(cooldown_key, 0.0)
                        if high_speed in ("Running", "Jogging") and now - last > Config.SPEED_COOLDOWN:
                            self.last_alert[cooldown_key] = now
                            detections.append({
                                "type": "behavior_anomaly",
                                "confidence": Config.SPEED_JOGGING_ALERT,
                                "box": [tx1, ty1, tx2, ty2],
                                "label": f"{high_speed} — {hist['color']} subject moving at high speed",
                            })

                    self._load_face_cascade()
                    with self._last_alert_lock:
                        face_last = self.last_alert.get(f"face_{tid}", 0.0)
                        if self._face_cascade is not None and now - face_last > Config.FACE_DETECT_COOLDOWN:
                            y1_clamped = max(0, ty1)
                            y2_clamped = min(ty2, h)
                            x1_clamped = max(0, tx1)
                            x2_clamped = min(tx2, w)
                            if y2_clamped > y1_clamped and x2_clamped > x1_clamped:
                                roi_gray = cv2.cvtColor(
                                    frame[y1_clamped:y2_clamped, x1_clamped:x2_clamped],
                                    cv2.COLOR_BGR2GRAY,
                                )
                                if roi_gray.size > 0:
                                    try:
                                        faces = self._face_cascade.detectMultiScale(
                                            roi_gray,
                                            scaleFactor=Config.FACE_DETECT_SCALE_FACTOR,
                                            minNeighbors=Config.FACE_DETECT_MIN_NEIGHBORS,
                                            minSize=(Config.FACE_DETECT_MIN_SIZE, Config.FACE_DETECT_MIN_SIZE),
                                        )
                                    except Exception as exc:
                                        log.debug("Face detection error: %s", exc)
                                        faces = []
                                    for (fx, fy, fw, fh) in faces:
                                        fx_abs = fx + tx1
                                        fy_abs = fy + ty1
                                        cv2.rectangle(annotated, (fx_abs, fy_abs),
                                                      (fx_abs + fw, fy_abs + fh), (255, 200, 0), 2)
                                        cv2.putText(annotated, "FACE", (fx_abs, fy_abs - 6),
                                                    cv2.FONT_HERSHEY_SIMPLEX, 0.4, (255, 200, 0), 1)
                                        self.last_alert[f"face_{tid}"] = now
                                        face_dir = "looking at camera" if fy < (ty2 - ty1) * 0.4 else "looking away"
                                        detections.append({
                                            "type": "face_unknown",
                                            "confidence": Config.FACE_CONFIDENCE,
                                            "box": [fx_abs, fy_abs, fx_abs + fw, fy_abs + fh],
                                            "label": f"Unknown Face — {hist['color']} subject, {face_dir}",
                                        })

                    cv2.putText(annotated, f"{hist['speed']} | {hist['color']} | {current_zone[0]}",
                                (tx1, ty2 + 30), cv2.FONT_HERSHEY_SIMPLEX, 0.35, (150, 200, 255), 1)

                # ── Fall detection ─────────────────────────────────
                fall_dets = self._detect_falls(tracks, annotated, now)
                detections.extend(fall_dets)
                # ── Tripwire ───────────────────────────────────────
                cross_dets = self._detect_line_crossing(tracks, annotated, now, w)
                detections.extend(cross_dets)

            # ── Crowd / Group analysis ─────────────────────────────
            persons = [d for d in detections if d["type"] == "person"]
            person_count = len(persons)
            if person_count >= Config.CROWD_THRESHOLD:
                detections.append({
                    "type": "crowd",
                    "confidence": min(Config.CROWD_CONFIDENCE_MAX, 70 + person_count * Config.CROWD_CONFIDENCE_PER_PERSON),
                    "box": [0, 0, w, h],
                    "label": f"High Crowd Density — {person_count} persons in frame",
                })
                cv2.putText(annotated, f"CROWD: {person_count} persons", (10, h - 20),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 100, 255), 2)
            elif Config.GROUP_MIN <= person_count <= Config.GROUP_MAX:
                with self._last_alert_lock:
                    last_group = self.last_alert.get("group", 0.0)
                    if now - last_group > Config.GROUP_COOLDOWN:
                        self.last_alert["group"] = now
                        detections.append({
                            "type": "behavior_anomaly",
                            "confidence": Config.GROUP_CONFIDENCE,
                            "box": [0, 0, w, h],
                            "label": f"Gathering Detected — {person_count} persons in proximity",
                        })

            if DEEPSORT_AVAILABLE and tracks:
                for track in tracks:
                    if not track.is_confirmed():
                        continue
                    tid = track.track_id
                    with self._person_entries_lock:
                        if tid not in self._person_entries:
                            self._person_entries[tid] = now
                        elapsed = now - self._person_entries[tid]
                    hist = self._track_history.get(tid)
                    if hist is None:
                        continue
                    with self._loitering_lock:
                        if elapsed > Config.LOITERING_THRESHOLD and tid not in self._loitering_reported and hist["speed"] == "Standing":
                            self._loitering_reported.add(tid)
                            detections.append({
                                "type": "behavior_anomaly",
                                "confidence": Config.LOITERING_CONFIDENCE,
                                "box": [0, 0, w, h],
                                "label": f"Loitering — {hist['color']} subject stationary for {int(elapsed)}s",
                            })
                            cv2.putText(annotated, f"LOITERING {int(elapsed)}s", (10, h - 40),
                                        cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 100, 255), 2)

                # ── Traffic analysis from tracked vehicles ─────────
                traffic_dets = self._detect_traffic(tracks, annotated, now)
                detections.extend(traffic_dets)

            for det in detections:
                if det["type"] == "person":
                    x1, y1, x2, y2 = det["box"]
                    cy = (y1 + y2) // 2
                    zone = self._get_zone(cy, h)
                    color_name = self._get_color_name(frame, x1, y1 + (y2 - y1) // 3, x2, y2)
                    det["label"] = f"Person — {color_name} · {zone} Zone"
                    det["confidence"] = min(Config.PERSON_CONFIDENCE_MAX, det["confidence"] + Config.PERSON_CONFIDENCE_BOOST)

            # ── Annotate detection count per category ──────────────
            type_counts: dict[str, int] = {}
            for d in detections:
                t = d["type"]
                type_counts[t] = type_counts.get(t, 0) + 1
            y_offset = h - 80
            cv2.putText(annotated, "Detections:", (6, y_offset),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.35, (200, 200, 100), 1)
            for i, (dtype, count) in enumerate(sorted(type_counts.items())[:5]):
                cv2.putText(annotated, f"  {dtype}: {count}", (6, y_offset + 14 * (i + 1)),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.35, (180, 180, 100), 1)

        else:
            # ── OpenCV fallback: motion detection ──────────────────
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            gray = cv2.GaussianBlur(gray, (21, 21), 0)
            if self._motion_bg is None:
                self._motion_bg = gray.copy().astype("float")
            cv2.accumulateWeighted(gray, self._motion_bg, 0.5)
            delta = cv2.absdiff(gray, cv2.convertScaleAbs(self._motion_bg))
            thresh = cv2.threshold(delta, Config.MOTION_THRESHOLD, 255, cv2.THRESH_BINARY)[1]
            thresh = cv2.dilate(thresh, None, iterations=2)
            cnts, _ = cv2.findContours(thresh.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            for c in cnts:
                if cv2.contourArea(c) < Config.MOTION_MIN_AREA:
                    continue
                (x, y, cw, ch) = cv2.boundingRect(c)
                cv2.rectangle(annotated, (x, y), (x + cw, y + ch), (0, 255, 180), 2)
                detections.append({
                    "type": "person",
                    "confidence": Config.MOTION_CONFIDENCE,
                    "box": [x, y, x + cw, y + ch],
                    "label": "Motion Detected",
                })
                break

        return annotated, detections

    def _overlay_hud(self, frame: np.ndarray):
        h, w = frame.shape[:2]
        overlay = frame.copy()
        cv2.rectangle(overlay, (0, 0), (w, 28), (10, 15, 25), -1)
        cv2.addWeighted(overlay, 0.6, frame, 0.4, 0, frame)
        ts = datetime.now().strftime("%H:%M:%S")
        engine = "YOLOv8" if YOLO_AVAILABLE else "OpenCV"
        cv2.putText(frame, f"AiBoO CAM | {self.name} | {ts} | {self.fps}fps | {engine}",
                    (6, 18), cv2.FONT_HERSHEY_SIMPLEX, 0.42, (0, 220, 200), 1)
        cv2.circle(frame, (w - 14, 14), 5, (0, 0, 255), -1)

    def _post_detection(self, det: dict):
        det_type = det["type"]
        now = time.time()
        if "weapon" in det_type:
            cooldown = Config.DETECTION_COOLDOWN_WEAPON
        elif det_type in ("fire", "tamper", "fall"):
            cooldown = Config.DETECTION_COOLDOWN_CRITICAL
        else:
            cooldown = Config.DETECTION_COOLDOWN_DEFAULT
        with self._last_alert_lock:
            last = self.last_alert.get(det_type, 0.0)
            if now - last < cooldown:
                return
            self.last_alert[det_type] = now

        with _node_token_lock:
            node_token = _NODE_TOKEN

        payload = {
            "cameraId": self.camera_id,
            "cameraName": self.name,
            "location": self.location,
            "type": det_type,
            "severity": get_severity(det_type),
            "confidence": det["confidence"],
            "label": det["label"],
            "metadata": {"source": "cv_service", "engine": "YOLOv8" if YOLO_AVAILABLE else "OpenCV"},
        }
        headers = {"Content-Type": "application/json"}
        if node_token:
            headers["Authorization"] = f"Bearer {node_token}"

        success = _post_with_retry(
            f"{Config.NODE_BACKEND}/api/cameras/detections",
            payload,
            headers,
        )
        if not success:
            with _failed_detections_lock:
                if len(_failed_detections) < Config.FAILED_DETECTION_BUFFER_MAX:
                    payload["_retry_count"] = 0
                    _failed_detections.append(payload)
                else:
                    log.warning("Failed detection buffer full, dropping detection: %s", det_type)

    def get_jpeg(self) -> Optional[bytes]:
        with self.lock:
            frame = self.annotated
        if frame is None:
            return None
        success, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, Config.JPEG_QUALITY])
        if not success:
            return None
        return buf.tobytes()

# ── Global Camera Registry ────────────────────────────────────────
workers: dict[str, CameraWorker] = {}
workers_lock = threading.Lock()

# ── Periodic Cleanup ──────────────────────────────────────────────
def _cleanup_loop():
    while True:
        time.sleep(Config.CLEANUP_INTERVAL)
        try:
            now = time.time()
            with workers_lock:
                stale_workers = []
                for cid, w in workers.items():
                    try:
                        w.cleanup()
                    except Exception as exc:
                        log.error("Cleanup error for camera %s: %s", cid, exc)
                    if w.running and w._last_frame_time > 0 and now - w._last_frame_time > Config.WORKER_HEALTH_TIMEOUT:
                        log.warning("Camera %s has not sent frames for %.0fs, marking stale", cid, now - w._last_frame_time)
                        stale_workers.append(cid)
                for cid in stale_workers:
                    try:
                        workers[cid].stop()
                        workers.pop(cid, None)
                        log.info("Removed stale worker %s", cid)
                    except Exception as exc:
                        log.error("Error removing stale worker %s: %s", cid, exc)
        except Exception as exc:
            log.error("Cleanup loop error: %s", exc)

# ── Failed Detection Retry Loop ───────────────────────────────────
def _retry_failed_detections():
    while True:
        time.sleep(10)
        payload = None
        with _failed_detections_lock:
            if _failed_detections:
                payload = _failed_detections.popleft()
        if payload is not None:
            retry_count = payload.pop("_retry_count", 0) + 1
            headers = {"Content-Type": "application/json"}
            with _node_token_lock:
                if _NODE_TOKEN:
                    headers["Authorization"] = f"Bearer {_NODE_TOKEN}"
            try:
                resp = requests.post(
                    f"{Config.NODE_BACKEND}/api/cameras/detections",
                    json=payload,
                    headers=headers,
                    timeout=2,
                )
                if not resp.ok:
                    raise RuntimeError(f"HTTP {resp.status_code}")
            except Exception as exc:
                if retry_count < Config.DETECTION_RETRY_MAX:
                    payload["_retry_count"] = retry_count
                    with _failed_detections_lock:
                        if len(_failed_detections) >= Config.FAILED_DETECTION_BUFFER_MAX:
                            _failed_detections.popleft()
                            log.warning("Failed detection buffer full, dropping oldest for retry")
                        _failed_detections.append(payload)
                else:
                    log.error("Failed to retry detection after %d attempts: %s", retry_count, exc)

# ── Routes ─────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "yolo": YOLO_AVAILABLE,
        "deepsort": DEEPSORT_AVAILABLE,
        "cameras": len(workers),
    })

@app.route("/cameras", methods=["POST"])
@require_auth
@rate_limit
def add_camera():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    cam_id = str(data.get("cameraId", ""))
    name = str(data.get("name", "Camera"))
    url = str(data.get("streamUrl", ""))
    location = str(data.get("location", ""))

    cam_id = cam_id.strip()[:64]
    name = re.sub(r'[<>&"\'/]', '', name).strip()[:64]
    location = re.sub(r'[<>&"\'/]', '', location).strip()[:128]

    if not cam_id:
        cam_id = str(time.time())

    err = validate_stream_url(url)
    if err:
        return jsonify({"error": f"Invalid streamUrl: {err}"}), 400

    with workers_lock:
        if cam_id in workers:
            workers[cam_id].stop()
            workers[cam_id] = CameraWorker(cam_id, name, url, location)
        else:
            w = CameraWorker(cam_id, name, url, location)
            workers[cam_id] = w
        workers[cam_id].start()

    log.info("Camera added: %s (%s)", cam_id, name)
    return jsonify({"ok": True, "cameraId": cam_id}), 201

@app.route("/cameras/webcam", methods=["POST"])
@require_auth
@rate_limit
def add_webcam():
    with workers_lock:
        if "webcam_0" in workers:
            return jsonify({"ok": True, "cameraId": "webcam_0", "message": "Webcam already active"})

    cam_id = "webcam_0"
    body = request.get_json(silent=True) or {}
    name = str(body.get("name", "Built-in Webcam"))
    location = str(body.get("location", "Local Workstation"))
    name = re.sub(r'[<>&"\'/]', '', name).strip()[:64]
    location = re.sub(r'[<>&"\'/]', '', location).strip()[:128]
    webcam_url = "webcam:0"

    with workers_lock:
        if cam_id in workers:
            workers[cam_id].stop()
        w = CameraWorker(cam_id, name, webcam_url, location)
        w.start()
        workers[cam_id] = w

    log.info("Webcam activated")
    return jsonify({"ok": True, "cameraId": cam_id, "name": name, "message": "Webcam activated — full-spectrum detection running"})

@app.route("/cameras", methods=["GET"])
@require_auth
@rate_limit
def list_cameras():
    with workers_lock:
        result = [
            {
                "id": cid,
                "cameraId": cid,
                "name": w.name,
                "location": w.location,
                "streamUrl": w.url,
                "running": w.running,
                "fps": w.fps,
                "frames": w.frame_count,
            }
            for cid, w in workers.items()
        ]
    return jsonify(result)

@app.route("/cameras/<cam_id>", methods=["DELETE"])
@require_auth
@rate_limit
def remove_camera(cam_id):
    with workers_lock:
        w = workers.pop(cam_id, None)
        if w:
            w.stop()
            log.info("Camera removed: %s", cam_id)
    return jsonify({"ok": True})

@app.route("/cameras/<cam_id>/stream")
@require_auth
@rate_limit
def stream(cam_id):
    def generate():
        try:
            while True:
                w = workers.get(cam_id)
                if w:
                    try:
                        frame_bytes = w.get_jpeg()
                        if frame_bytes:
                            yield (b"--frame\r\n"
                                   b"Content-Type: image/jpeg\r\n\r\n" + frame_bytes + b"\r\n")
                    except GeneratorExit:
                        break
                    except Exception as exc:
                        log.error("Stream error for camera %s: %s", cam_id, exc)
                try:
                    time.sleep(1.0 / Config.STREAM_FPS_TARGET)
                except KeyboardInterrupt:
                    break
        finally:
            log.debug("Stream client disconnected from camera %s", cam_id)

    return Response(generate(), mimetype="multipart/x-mixed-replace; boundary=frame")

@app.route("/cameras/<cam_id>/snapshot")
@require_auth
@rate_limit
def snapshot(cam_id):
    w = workers.get(cam_id)
    if not w:
        return jsonify({"error": "Camera not found"}), 404
    try:
        frame_bytes = w.get_jpeg()
    except Exception as exc:
        log.error("Snapshot error for camera %s: %s", cam_id, exc)
        return jsonify({"error": "Failed to capture snapshot"}), 500
    if not frame_bytes:
        return jsonify({"error": "No frame available yet"}), 503
    return Response(frame_bytes, mimetype="image/jpeg")

@app.route("/cameras/<cam_id>/status")
@require_auth
@rate_limit
def cam_status(cam_id):
    w = workers.get(cam_id)
    if not w:
        return jsonify({"status": "not_found"}), 404
    return jsonify({
        "status": "running" if w.running else "stopped",
        "fps": w.fps,
        "frames": w.frame_count,
        "yolo": YOLO_AVAILABLE,
    })

@app.route("/token", methods=["POST"])
@require_auth
@rate_limit
def set_token():
    global _NODE_TOKEN
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be valid JSON"}), 400
    token = data.get("token", "")
    if not token or not isinstance(token, str):
        return jsonify({"error": "token must be a non-empty string"}), 400
    token = token.strip()
    if len(token) < Config.MIN_TOKEN_LENGTH:
        return jsonify({"error": f"token must be at least {Config.MIN_TOKEN_LENGTH} characters long"}), 400
    with _node_token_lock:
        _NODE_TOKEN = token
    log.info("Node backend token updated")
    return jsonify({"ok": True})

# ── Error Handlers ────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def internal_error(e):
    log.error("Internal server error: %s", e)
    return jsonify({"error": "Internal server error"}), 500

# ── Signal Handlers & Graceful Shutdown ────────────────────────────
_shutdown_event = threading.Event()

def _signal_handler(signum, frame):
    sig_name = signal.Signals(signum).name
    log.warning("Received signal %s, shutting down...", sig_name)
    _shutdown_event.set()

def _register_signal_handlers():
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _signal_handler)
        except (ValueError, OSError):
            pass

def _shutdown():
    log.info("Shutting down all camera workers...")
    with workers_lock:
        for cid, w in list(workers.items()):
            try:
                w.stop()
                log.debug("Stopped worker %s", cid)
            except Exception as exc:
                log.error("Error stopping worker %s: %s", cid, exc)
        workers.clear()
    log.info("Shutdown complete.")

# ── Main ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    _register_signal_handlers()

    cleanup_thread = threading.Thread(target=_cleanup_loop, daemon=True, name="cleanup")
    cleanup_thread.start()

    retry_thread = threading.Thread(target=_retry_failed_detections, daemon=True, name="retry-detections")
    retry_thread.start()

    log.info("=" * 50)
    log.info("AiBoO CV Service starting on %s:%d", Config.HOST, Config.PORT)
    log.info("  YOLOv8:    %s", "enabled" if YOLO_AVAILABLE else "disabled (using OpenCV fallback)")
    log.info("  DeepSORT:  %s", "enabled" if DEEPSORT_AVAILABLE else "disabled")
    log.info("  Detection: full-spectrum (objects/animals/fire/smoke/faces/motion/falls/tamper/tripwire/traffic)")
    log.info("  Auth:      %s", "enabled" if Config.CV_AUTH_TOKEN != "changeme-default-token-change-in-production" else "using default token (CHANGE IN PRODUCTION)")
    log.info("  CORS:      %s", Config.FRONTEND_ORIGIN)
    log.info("=" * 50)

    try:
        app.run(host=Config.HOST, port=Config.PORT, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        pass
    finally:
        _shutdown()
