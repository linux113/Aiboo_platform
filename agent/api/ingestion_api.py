from __future__ import annotations
import logging
import time
import uvicorn
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from cachetools import TTLCache

from pydantic import BaseModel, Field, field_validator

from fastapi import FastAPI, HTTPException, status, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware          # <-- ADDED CORS
from starlette.middleware.base import BaseHTTPMiddleware

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.event_bus import EventBus
from core.events import (
    ThreatEvent, ThreatType, Severity,
    AccessRequest, ZeroTrustDecision, RiskLevel,
    ResponseAction, AgentFinding,
)

# Try to import config; if missing, use defaults
try:
    from core.config import config
except ImportError:
    class DefaultConfig:
        rate_limit = 100
        api_key = "dev-key-change-in-production"
        internal_key = "internal-dev-key"
        log_level = "INFO"
        api_host = "0.0.0.0"
        api_port = 8000
    config = DefaultConfig()
    logging.warning("core.config not found – using default config")

log = logging.getLogger("api.ingestion")

# ---- Global shared event bus ----
_shared_event_bus: Optional[EventBus] = None

def set_event_bus(bus: EventBus) -> None:
    global _shared_event_bus
    _shared_event_bus = bus
    log.info("EventBus shared with API server")

def get_event_bus() -> EventBus:
    global _shared_event_bus
    if _shared_event_bus is None:
        _shared_event_bus = EventBus()
        log.info("Created new EventBus for API server (standalone mode)")
    return _shared_event_bus

# -------------------------------------------------------------

request_counts: TTLCache[str, list[float]] = TTLCache(maxsize=10000, ttl=60)


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window = 60.0
        key = f"{client_ip}:{request.url.path}"
        if key not in request_counts:
            request_counts[key] = []
        timestamps = request_counts[key]
        cutoff = now - window
        request_counts[key] = [t for t in timestamps if t > cutoff]
        if len(request_counts[key]) >= config.rate_limit:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"type": "https://httpstatuses.io/429", "title": "Too Many Requests", "detail": "Rate limit exceeded", "status": 429, "instance": str(request.url)}
            )
        request_counts[key].append(now)
        response = await call_next(request)
        return response


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Allow public endpoints and WebSocket handshake
        if request.url.path in ("/health", "/", "/docs", "/openapi.json", "/ws/alerts"):
            return await call_next(request)
        api_key = request.headers.get("X-API-Key", "")
        internal_key = request.headers.get("X-Internal-Key", "")
        if api_key == config.api_key or internal_key == config.internal_key:
            return await call_next(request)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"type": "https://httpstatuses.io/401", "title": "Unauthorized", "detail": "Invalid or missing API key", "status": 401, "instance": str(request.url)}
        )


# ============================================
# WebSocket Connection Manager
# ============================================

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass

# ============================================
# Pydantic Models
# ============================================

class IngestEventRequest(BaseModel):
    timestamp: str = Field(..., description="ISO format timestamp of the event")
    source: str = Field(..., description="Source identifier", min_length=1, max_length=255)
    event_type: str = Field(..., description="Type of event")
    message: str = Field(..., description="Human-readable event description", max_length=10000)
    payload: Optional[dict] = Field(default_factory=dict)
    severity: Optional[str] = Field(default="medium")

    @field_validator('timestamp')
    @classmethod
    def validate_timestamp(cls, v):
        try:
            datetime.fromisoformat(v.replace('Z', '+00:00'))
            return v
        except ValueError:
            raise ValueError(f"Invalid timestamp format: {v}")

    @field_validator('event_type')
    @classmethod
    def validate_event_type(cls, v):
        valid_types = [t.value for t in ThreatType]
        if v not in valid_types:
            raise ValueError(f"Invalid event_type: {v}. Valid types: {valid_types}")
        return v

    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v):
        valid_severities = ['low', 'medium', 'high', 'critical']
        if v and v.lower() not in valid_severities:
            raise ValueError(f"Invalid severity: {v}")
        return v.lower() if v else 'medium'


class IngestEventResponse(BaseModel):
    status: str
    event_id: str
    message: str
    timestamp: str


class AccessRequestModel(BaseModel):
    user_id: str = Field(..., description="User identifier", min_length=1, max_length=255)
    device_id: str = Field(..., description="Device identifier", min_length=1, max_length=255)
    resource: str = Field(..., description="Resource being accessed", min_length=1, max_length=512)
    timestamp: str = Field(..., description="ISO format timestamp")
    location: Optional[str] = Field(default="", max_length=255)
    network: Optional[str] = Field(default="", max_length=255)
    behavior_context: Optional[Dict[str, Any]] = Field(default_factory=dict)
    source: Optional[str] = Field(default="api", max_length=255)

    @field_validator('timestamp')
    @classmethod
    def validate_timestamp(cls, v):
        try:
            datetime.fromisoformat(v.replace('Z', '+00:00'))
            return v
        except ValueError:
            raise ValueError(f"Invalid timestamp format: {v}")

    def to_access_request(self) -> AccessRequest:
        timestamp = datetime.fromisoformat(self.timestamp.replace('Z', '+00:00'))
        return AccessRequest(
            user_id=self.user_id,
            device_id=self.device_id,
            resource=self.resource,
            timestamp=timestamp,
            location=self.location or "",
            network=self.network or "",
            behavior_context=self.behavior_context or {},
            source=self.source or "api"
        )


class AccessRequestResponse(BaseModel):
    status: str
    request_id: str
    allowed: bool
    risk_level: str
    required_actions: List[str]
    message: str
    confidence: float
    timestamp: str


class DeviceTrustRequest(BaseModel):
    device_id: str = Field(..., description="Device identifier", min_length=1, max_length=255)
    user_id: Optional[str] = Field(default="", max_length=255)
    device_info: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(..., description="ISO format timestamp")


class DeviceTrustResponse(BaseModel):
    status: str
    device_id: str
    is_trusted: bool
    is_quarantined: bool
    trust_score: float
    health_score: float
    message: str
    timestamp: str


class ErrorResponse(BaseModel):
    type: str
    title: str
    detail: str
    status: int
    instance: str


def create_app(event_bus: EventBus = None) -> FastAPI:
    app = FastAPI(
        title="AiBoO Threat Ingestion & Zero Trust API",
        description="Receives security events and access requests, forwards to AiBoO pipeline",
        version="1.0.0",
    )

    # ---- CORS Middleware (for frontend on port 3000) ----
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:8000", "*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(AuthMiddleware)

    if event_bus is None:
        event_bus = get_event_bus()
    app.state.event_bus = event_bus
    app.state.pending_decisions = {}

    # ---- WebSocket Manager ----
    manager = ConnectionManager()

    # ---- WebSocket Endpoint ----
    @app.websocket("/ws/alerts")
    async def websocket_endpoint(websocket: WebSocket):
        await manager.connect(websocket)
        log.info(f"WebSocket client connected: {websocket.client}")
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            manager.disconnect(websocket)
            log.info(f"WebSocket client disconnected: {websocket.client}")

    # ---- Forward AgentFinding events to WebSocket ----
    async def forward_finding(finding: AgentFinding):
        if finding.severity not in (Severity.HIGH, Severity.CRITICAL):
            return
        message = {
            "type": "agent_finding",
            "id": finding.event_id,
            "timestamp": finding.timestamp.isoformat(),
            "severity": finding.severity.value,
            "agent_name": finding.agent_name,
            "threat_type": finding.threat_type.value,
            "summary": finding.summary,
            "confidence": finding.confidence,
            "actions": [a.value for a in finding.actions],
            "metadata": finding.metadata,
        }
        await manager.broadcast(json.dumps(message))

    @app.on_event("startup")
    async def startup_event():
        bus = app.state.event_bus
        bus.subscribe(AgentFinding, forward_finding)
        log.info("WebSocket forwarder subscribed to AgentFinding events")

    # ---- Exception Handlers ----
    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError):
        log.warning("Validation error on %s: %s", request.url.path, exc)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"type": "https://httpstatuses.io/400", "title": "Bad Request", "detail": str(exc), "status": 400, "instance": str(request.url)}
        )

    @app.exception_handler(Exception)
    async def general_error_handler(request: Request, exc: Exception):
        log.exception("Unhandled error on %s", request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"type": "https://httpstatuses.io/500", "title": "Internal Server Error", "detail": "An unexpected error occurred", "status": 500, "instance": str(request.url)}
        )

    # ---- REST Endpoints ----
    @app.post("/events", response_model=IngestEventResponse, status_code=status.HTTP_202_ACCEPTED)
    async def ingest_event(request: IngestEventRequest):
        # ... (same as before, unchanged)
        log.info("Received event from %s: %s", request.source, request.event_type)
        try:
            timestamp = datetime.fromisoformat(request.timestamp.replace('Z', '+00:00'))
            severity_map = {'low': Severity.LOW, 'medium': Severity.MEDIUM, 'high': Severity.HIGH, 'critical': Severity.CRITICAL}
            severity = severity_map.get(request.severity, Severity.MEDIUM)
            threat_type = ThreatType(request.event_type)
            payload = {"message": request.message}
            if request.payload:
                payload.update(request.payload)
            threat_event = ThreatEvent(
                source=request.source,
                threat_type=threat_type,
                severity=severity,
                payload=payload,
                timestamp=timestamp
            )
            log.info("Event received: %s source=%s type=%s severity=%s", threat_event.event_id, threat_event.source, threat_event.threat_type.value, threat_event.severity.value)
            await app.state.event_bus.publish(threat_event)
            return IngestEventResponse(
                status="accepted",
                event_id=threat_event.event_id,
                message="Event successfully ingested and forwarded to agents",
                timestamp=datetime.now().isoformat()
            )
        except ValueError as e:
            log.error("Validation error: %s", e)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            log.exception("Unexpected error")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    @app.post("/access/request", response_model=AccessRequestResponse, status_code=status.HTTP_202_ACCEPTED)
    async def request_access(access_request: AccessRequestModel):
        # ... (same as before)
        log.info("Access request from %s -> %s", access_request.user_id, access_request.resource)
        try:
            request = access_request.to_access_request()
            log.info("Access request: user=%s device=%s resource=%s location=%s network=%s", request.user_id, request.device_id, request.resource, request.location or 'unknown', request.network or 'unknown')
            await app.state.event_bus.publish(request)
            risk_level = RiskLevel.MEDIUM
            required_actions = ["step_up_auth"]
            if request.location == "office" and request.network == "corporate":
                risk_level = RiskLevel.LOW
                required_actions = []
            elif request.location == "unknown" or request.network == "public":
                risk_level = RiskLevel.HIGH
                required_actions = ["challenge_mfa", "step_up_auth"]
            sensitive = {"database", "server_room", "data_vault", "admin_console"}
            if request.resource in sensitive:
                if "challenge_mfa" not in required_actions:
                    required_actions.append("challenge_mfa")
                if risk_level == RiskLevel.LOW:
                    risk_level = RiskLevel.MEDIUM
            return AccessRequestResponse(
                status="pending",
                request_id=request.session_id or f"req_{request.user_id}_{int(datetime.now().timestamp())}",
                allowed=False,
                risk_level=risk_level.value,
                required_actions=required_actions,
                message=f"Access request submitted for {request.user_id} -> {request.resource}.",
                confidence=0.5,
                timestamp=datetime.now().isoformat()
            )
        except ValueError as e:
            log.error("Validation error: %s", e)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            log.exception("Unexpected error")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    @app.post("/device/trust", response_model=DeviceTrustResponse, status_code=status.HTTP_200_OK)
    async def verify_device_trust(device_request: DeviceTrustRequest):
        # ... (same as before)
        log.info("Device trust verification for %s", device_request.device_id)
        try:
            device_id = device_request.device_id
            health_info = device_request.device_info.get("health", {})
            is_healthy = (
                health_info.get("antivirus_active", True) and
                health_info.get("disk_encrypted", True) and
                health_info.get("firewall_active", True) and
                not health_info.get("root_detected", False)
            )
            trust_score = 0.85 if is_healthy else 0.3
            is_trusted = trust_score > 0.6
            is_quarantined = trust_score < 0.3
            log.info("Device %s: trust=%.2f trusted=%s quarantined=%s healthy=%s", device_id, trust_score, is_trusted, is_quarantined, is_healthy)
            return DeviceTrustResponse(
                status="verified",
                device_id=device_id,
                is_trusted=is_trusted,
                is_quarantined=is_quarantined,
                trust_score=trust_score,
                health_score=0.9 if is_healthy else 0.4,
                message=f"Device {'trusted' if is_trusted else 'not trusted'}" + (" (quarantined)" if is_quarantined else ""),
                timestamp=datetime.now().isoformat()
            )
        except Exception as e:
            log.exception("Error in device trust verification")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    @app.post("/device/register", status_code=status.HTTP_201_CREATED)
    async def register_device(device_info: Dict[str, Any]):
        # ... (same as before)
        try:
            device_id = device_info.get("device_id")
            user_id = device_info.get("user_id", "unknown")
            if not device_id:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="device_id is required")
            log.info("Device registration: %s for user %s", device_id, user_id)
            return {
                "status": "registered",
                "device_id": device_id,
                "user_id": user_id,
                "message": f"Device {device_id} registered successfully",
                "timestamp": datetime.now().isoformat()
            }
        except HTTPException:
            raise
        except Exception as e:
            log.exception("Error in device registration")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    @app.get("/decisions/{request_id}")
    async def get_decision(request_id: str):
        return {
            "request_id": request_id,
            "status": "pending",
            "message": "Decision still being processed",
            "timestamp": datetime.now().isoformat()
        }

    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "service": "AiBoO Ingestion & Zero Trust API", "timestamp": datetime.now().isoformat()}

    @app.get("/metrics")
    async def metrics():
        return {"active_endpoints": len([r for r in app.routes if hasattr(r, 'methods')]), "uptime": "running"}

    @app.get("/")
    async def root():
        return {
            "service": "AiBoO Threat Ingestion & Zero Trust API",
            "version": "1.0.0",
            "endpoints": {
                "POST /events": "Ingest a threat event",
                "POST /access/request": "Submit a Zero Trust access request",
                "POST /device/trust": "Verify device trust status",
                "POST /device/register": "Register a new device",
                "GET /decisions/{request_id}": "Get decision status",
                "GET /health": "Health check",
                "GET /metrics": "Metrics",
                "GET /docs": "Interactive API documentation",
                "WS /ws/alerts": "WebSocket for live alert stream"
            }
        }

    return app


# ---- Standalone execution ----
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s \u2014 %(message)s",
        datefmt="%H:%M:%S",
    )

    bus = get_event_bus()

    print("\n" + "="*60)
    print("  AiBoO Threat Ingestion & Zero Trust API")
    print("="*60)
    print("  POST   /events            - Send threat events")
    print("  POST   /access/request    - Zero Trust access request")
    print("  POST   /device/trust      - Verify device trust")
    print("  POST   /device/register   - Register new device")
    print("  GET    /decisions/{id}    - Get decision status")
    print("  GET    /health            - Health check")
    print("  GET    /metrics           - Metrics")
    print("  GET    /docs              - API documentation")
    print("  WS     /ws/alerts         - Live alert WebSocket")
    print("="*60 + "\n")

    uvicorn.run(create_app(bus), host="0.0.0.0", port=8000, log_level="info")