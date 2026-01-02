from config import (
    SINGBOX_ENABLED,
    SINGBOX_EXECUTABLE_PATH,
    SINGBOX_ASSETS_PATH,
    SINGBOX_JSON,
)

if SINGBOX_ENABLED:
    from app.singbox.core import SingBoxCore
    from app.singbox.config import SingBoxConfig

    core = SingBoxCore(
        executable_path=SINGBOX_EXECUTABLE_PATH,
        assets_path=SINGBOX_ASSETS_PATH,
    )
    config = SingBoxConfig(SINGBOX_JSON)
else:
    core = None
    config = None
