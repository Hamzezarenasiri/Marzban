from typing import TYPE_CHECKING, Sequence

from app.models.proxy import ProxyHostSecurity
from app.utils.store import DictStorage
from config import (
    SINGBOX_ENABLED,
    SINGBOX_EXECUTABLE_PATH,
    SINGBOX_ASSETS_PATH,
    SINGBOX_JSON,
)

if TYPE_CHECKING:
    from app.db.models import ProxyHost

if SINGBOX_ENABLED:
    from app.singbox.core import SingBoxCore
    from app.singbox.config import SingBoxConfig

    core = SingBoxCore(
        executable_path=SINGBOX_EXECUTABLE_PATH,
        assets_path=SINGBOX_ASSETS_PATH,
    )
    config = SingBoxConfig(SINGBOX_JSON)

    @DictStorage
    def hosts(storage: dict):
        from app.db import GetDB, crud

        storage.clear()
        with GetDB() as db:
            for inbound_tag in config.inbounds_by_tag:
                inbound_hosts: Sequence[ProxyHost] = crud.get_hosts(db, inbound_tag)

                storage[inbound_tag] = [
                    {
                        "remark": host.remark,
                        "address": [i.strip() for i in host.address.split(',')] if host.address else [],
                        "port": host.port,
                        "path": host.path if host.path else None,
                        "sni": [i.strip() for i in host.sni.split(',')] if host.sni else [],
                        "host": [i.strip() for i in host.host.split(',')] if host.host else [],
                        "alpn": host.alpn.value,
                        "fingerprint": host.fingerprint.value,
                        "tls": None
                        if host.security == ProxyHostSecurity.inbound_default
                        else host.security.value,
                        "allowinsecure": host.allowinsecure,
                        "mux_enable": host.mux_enable,
                        "fragment_setting": host.fragment_setting,
                        "noise_setting": host.noise_setting,
                        "random_user_agent": host.random_user_agent,
                        "use_sni_as_host": host.use_sni_as_host,
                    } for host in inbound_hosts if not host.is_disabled
                ]
else:
    core = None
    config = None
    hosts = None
