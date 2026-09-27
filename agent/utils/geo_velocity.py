"""
utils/geo_velocity.py — Geo-Velocity Detection Utilities

Detects impossible travel scenarios based on login locations and timestamps.
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Tuple, Dict
from dataclasses import dataclass

EARTH_RADIUS_KM = 6371.0
MAX_TRAVEL_SPEED_KPH = 900


@dataclass
class GeoLocation:
    latitude: float
    longitude: float
    timestamp: datetime
    location_name: str = ""
    
    def is_valid(self) -> bool:
        return -90 <= self.latitude <= 90 and -180 <= self.longitude <= 180


class GeoVelocityDetector:
    def __init__(self, max_speed_kph: float = MAX_TRAVEL_SPEED_KPH):
        self.max_speed_kph = max_speed_kph
    
    def calculate_distance(self, loc1: GeoLocation, loc2: GeoLocation) -> float:
        if not loc1.is_valid() or not loc2.is_valid():
            return 0.0
        lat1, lon1 = math.radians(loc1.latitude), math.radians(loc1.longitude)
        lat2, lon2 = math.radians(loc2.latitude), math.radians(loc2.longitude)
        dlat, dlon = lat2 - lat1, lon2 - lon1
        a = math.sin(dlat/2)**2 + math.cos(lat1)*math.cos(lat2)*math.sin(dlon/2)**2
        return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))
    
    def calculate_required_speed(self, loc1: GeoLocation, loc2: GeoLocation) -> float:
        distance = self.calculate_distance(loc1, loc2)
        if distance == 0:
            return 0.0
        hours = abs((loc2.timestamp - loc1.timestamp).total_seconds()) / 3600
        return distance / hours if hours > 0 else float('inf')
    
    def detect_impossible_travel(self, loc1: GeoLocation, loc2: GeoLocation) -> Tuple[bool, float, str]:
        if not loc1.is_valid() or not loc2.is_valid():
            return False, 0.0, "Invalid location"
        distance = self.calculate_distance(loc1, loc2)
        required = self.calculate_required_speed(loc1, loc2)
        if distance < 1.0:
            return False, 0.0, "Same location"
        hours = abs((loc2.timestamp - loc1.timestamp).total_seconds()) / 3600
        if required > self.max_speed_kph:
            return True, min(required / self.max_speed_kph, 1.0), f"Impossible: {distance:.0f}km in {hours:.1f}h (speed {required:.0f}km/h)"
        if required > self.max_speed_kph * 0.5:
            return True, 0.5, f"Suspicious: {distance:.0f}km in {hours:.1f}h"
        return False, max(0.0, required / self.max_speed_kph), "Normal travel"