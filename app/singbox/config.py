import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Dict, List, Optional, Union

import commentjson

from app.models.proxy import ProxyTypes


class SingBoxConfig(dict):
    """
    Sing-box configuration manager.
    Handles parsing, validation, and user management for Hysteria2, TUIC, and WireGuard protocols.
    """

    SUPPORTED_PROTOCOLS = {"hysteria2", "tuic", "wireguard"}

    def __init__(
        self,
        config: Union[dict, str],
        inbounds_by_tag: Optional[Dict[str, dict]] = None,
        inbounds_by_protocol: Optional[Dict[ProxyTypes, List[dict]]] = None,
    ):
        if isinstance(config, str):
            if config.startswith("{"):
                config = commentjson.loads(config)
            else:
                with open(config, "r") as f:
                    config = commentjson.load(f)

        super().__init__(deepcopy(config))

        if inbounds_by_tag is None or inbounds_by_protocol is None:
            inbounds_by_tag, inbounds_by_protocol = self._resolve_inbounds()

        self.inbounds_by_tag = inbounds_by_tag
        self.inbounds_by_protocol = inbounds_by_protocol

    def _resolve_inbounds(self):
        """Parse inbounds and group them by tag and protocol."""
        inbounds_by_tag = {}
        inbounds_by_protocol = {}

        for inbound in self.get("inbounds", []):
            tag = inbound.get("tag")
            protocol = inbound.get("type")

            if not tag or protocol not in self.SUPPORTED_PROTOCOLS:
                continue

            settings = {
                "tag": tag,
                "protocol": protocol,
                "port": inbound.get("listen_port") or inbound.get("port"),
                "listen": inbound.get("listen", "::"),
            }

            # Protocol-specific settings
            if protocol == "hysteria2":
                settings.update(self._parse_hysteria2_settings(inbound))
            elif protocol == "tuic":
                settings.update(self._parse_tuic_settings(inbound))
            elif protocol == "wireguard":
                settings.update(self._parse_wireguard_settings(inbound))

            inbounds_by_tag[tag] = settings

            # Map to ProxyTypes
            proxy_type = self._protocol_to_proxy_type(protocol)
            if proxy_type:
                if proxy_type not in inbounds_by_protocol:
                    inbounds_by_protocol[proxy_type] = []
                inbounds_by_protocol[proxy_type].append(settings)

        return inbounds_by_tag, inbounds_by_protocol

    def _protocol_to_proxy_type(self, protocol: str) -> Optional[ProxyTypes]:
        """Map sing-box protocol name to ProxyTypes enum."""
        mapping = {
            "hysteria2": ProxyTypes.Hysteria2,
            "tuic": ProxyTypes.TUIC,
            "wireguard": ProxyTypes.WireGuard,
        }
        return mapping.get(protocol)

    def _parse_hysteria2_settings(self, inbound: dict) -> dict:
        """Parse Hysteria2 specific settings."""
        settings = {
            "tls": "tls" if inbound.get("tls", {}).get("enabled") else "none",
            "obfs_type": "",
            "obfs_password": "",
        }

        # TLS settings
        tls = inbound.get("tls", {})
        if tls.get("enabled"):
            settings["sni"] = tls.get("server_name", "")
            settings["alpn"] = tls.get("alpn", [])

        # Obfuscation
        obfs = inbound.get("obfs", {})
        if obfs:
            settings["obfs_type"] = obfs.get("type", "")
            settings["obfs_password"] = obfs.get("password", "")

        # Masquerade
        masquerade = inbound.get("masquerade")
        if masquerade:
            settings["masquerade"] = masquerade

        return settings

    def _parse_tuic_settings(self, inbound: dict) -> dict:
        """Parse TUIC specific settings."""
        settings = {
            "tls": "tls" if inbound.get("tls", {}).get("enabled") else "none",
            "congestion_control": inbound.get("congestion_control", "bbr"),
        }

        # TLS settings
        tls = inbound.get("tls", {})
        if tls.get("enabled"):
            settings["sni"] = tls.get("server_name", "")
            settings["alpn"] = tls.get("alpn", [])

        return settings

    def _parse_wireguard_settings(self, inbound: dict) -> dict:
        """Parse WireGuard specific settings."""
        return {
            "private_key": inbound.get("private_key", ""),
            "mtu": inbound.get("mtu", 1280),
            "address": inbound.get("local_address", ["10.0.0.1/24"]),
        }

    def to_json(self, **kwargs) -> str:
        """Serialize configuration to JSON string."""
        return json.dumps(self, **kwargs)

    def copy(self) -> "SingBoxConfig":
        """Create a deep copy of the configuration."""
        return SingBoxConfig(
            deepcopy(dict(self)),
            inbounds_by_tag=deepcopy(self.inbounds_by_tag),
            inbounds_by_protocol=deepcopy(self.inbounds_by_protocol),
        )

    def include_db_users(self) -> "SingBoxConfig":
        """
        Include users from database into the configuration.
        This method is called before starting/reloading sing-box.
        """
        from app.db import GetDB
        from app.db.models import User
        from app.models.user import UserStatus

        config = self.copy()

        with GetDB() as db:
            users = (
                db.query(User)
                .filter(User.status.in_([UserStatus.active, UserStatus.on_hold]))
                .all()
            )

            for inbound in config.get("inbounds", []):
                tag = inbound.get("tag")
                protocol = inbound.get("type")

                if protocol not in self.SUPPORTED_PROTOCOLS:
                    continue

                proxy_type = self._protocol_to_proxy_type(protocol)
                if not proxy_type:
                    continue

                if protocol == "hysteria2":
                    inbound["users"] = []
                    for user in users:
                        if proxy_type in user.inbounds and tag in user.inbounds.get(
                            proxy_type, []
                        ):
                            proxy_settings = user.proxies.get(proxy_type, {})
                            if proxy_settings:
                                inbound["users"].append(
                                    {
                                        "name": f"{user.id}.{user.username}",
                                        "password": proxy_settings.get("password", ""),
                                    }
                                )

                elif protocol == "tuic":
                    inbound["users"] = []
                    for user in users:
                        if proxy_type in user.inbounds and tag in user.inbounds.get(
                            proxy_type, []
                        ):
                            proxy_settings = user.proxies.get(proxy_type, {})
                            if proxy_settings:
                                inbound["users"].append(
                                    {
                                        "name": f"{user.id}.{user.username}",
                                        "uuid": str(proxy_settings.get("uuid", "")),
                                        "password": proxy_settings.get("password", ""),
                                    }
                                )

                elif protocol == "wireguard":
                    inbound["peers"] = []
                    for user in users:
                        if proxy_type in user.inbounds and tag in user.inbounds.get(
                            proxy_type, []
                        ):
                            proxy_settings = user.proxies.get(proxy_type, {})
                            if proxy_settings:
                                inbound["peers"].append(
                                    {
                                        "public_key": proxy_settings.get(
                                            "public_key", ""
                                        ),
                                        "allowed_ips": [
                                            proxy_settings.get(
                                                "address", "10.0.0.2/32"
                                            )
                                        ],
                                    }
                                )

        return config
