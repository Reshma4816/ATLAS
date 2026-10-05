"""
Business Context Registry
Stores asset importance, exposure levels, and data classifications.
"""

from typing import Dict, Any

ASSET_REGISTRY: Dict[str, Dict[str, Any]] = {
    "127.0.0.1": {
        "asset_name": "Local Development Server",
        "asset_criticality": 3.0,
        "exposure_level": 5.0,  # Internal
        "data_classification": "Internal"
    },
    "192.168.1.1": {
        "asset_name": "Production API Gateway",
        "asset_criticality": 9.5,
        "exposure_level": 10.0, # External
        "data_classification": "Confidential"
    },
    "default": {
        "asset_name": "Unregistered Asset Host",
        "asset_criticality": 5.0,
        "exposure_level": 5.0,
        "data_classification": "Restricted"
    }
}


def get_asset_context(host: str) -> Dict[str, Any]:
    return ASSET_REGISTRY.get(host, ASSET_REGISTRY["default"])