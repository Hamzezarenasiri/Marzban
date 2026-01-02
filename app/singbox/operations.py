"""
Sing-box user operations.
Handles adding, removing, and updating users for Hysteria2, TUIC, and WireGuard protocols.
"""
from typing import TYPE_CHECKING, List

from app import logger
from app.models.proxy import ProxyTypes

if TYPE_CHECKING:
    from app.db.models import User as DBUser
    from app.models.user import UserResponse


SINGBOX_PROTOCOLS = {ProxyTypes.Hysteria2, ProxyTypes.TUIC, ProxyTypes.WireGuard}


def is_singbox_protocol(proxy_type: ProxyTypes) -> bool:
    """Check if a protocol is handled by sing-box."""
    return proxy_type in SINGBOX_PROTOCOLS


def add_user(dbuser: "DBUser"):
    """
    Add a user to sing-box configuration.
    Since sing-box doesn't have a dynamic user API like Xray,
    we need to reload the configuration.
    """
    from app.models.user import UserResponse

    user = UserResponse.model_validate(dbuser)

    for proxy_type, inbound_tags in user.inbounds.items():
        if not is_singbox_protocol(proxy_type):
            continue

        if not inbound_tags:
            continue

        logger.info(
            f"User '{user.username}' added to sing-box inbounds: {inbound_tags}"
        )

    # Trigger config reload
    _reload_singbox()


def remove_user(dbuser: "DBUser"):
    """
    Remove a user from sing-box configuration.
    """
    from app.models.user import UserResponse

    user = UserResponse.model_validate(dbuser)

    for proxy_type, inbound_tags in user.inbounds.items():
        if not is_singbox_protocol(proxy_type):
            continue

        if not inbound_tags:
            continue

        logger.info(
            f"User '{user.username}' removed from sing-box inbounds: {inbound_tags}"
        )

    # Trigger config reload
    _reload_singbox()


def update_user(dbuser: "DBUser"):
    """
    Update a user in sing-box configuration.
    """
    from app.models.user import UserResponse

    user = UserResponse.model_validate(dbuser)

    for proxy_type in user.inbounds.keys():
        if is_singbox_protocol(proxy_type):
            logger.info(f"User '{user.username}' updated in sing-box")
            break

    # Trigger config reload
    _reload_singbox()


def _reload_singbox():
    """
    Reload sing-box configuration with updated users.
    This is called after any user change.
    """
    from config import SINGBOX_ENABLED

    if not SINGBOX_ENABLED:
        return

    try:
        from app import singbox

        if singbox.core and singbox.core.started:
            # Generate new config with all users
            new_config = singbox.config.include_db_users()
            singbox.core.reload(new_config)
    except Exception as e:
        logger.error(f"Failed to reload sing-box: {e}")


def get_user_inbounds(
    proxy_type: ProxyTypes, inbound_tags: List[str]
) -> List[dict]:
    """
    Get inbound settings for a user's assigned inbounds.
    """
    from config import SINGBOX_ENABLED

    if not SINGBOX_ENABLED:
        return []

    from app import singbox

    if not singbox.config:
        return []

    inbounds = []
    for tag in inbound_tags:
        if tag in singbox.config.inbounds_by_tag:
            inbounds.append(singbox.config.inbounds_by_tag[tag])

    return inbounds
