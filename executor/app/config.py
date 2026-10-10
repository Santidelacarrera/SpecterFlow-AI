from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Settings:
    token: str = field(default_factory=lambda: os.getenv("EXECUTOR_TOKEN", ""))
    live: bool = field(default_factory=lambda: os.getenv("EXECUTOR_MODE", "dry-run").lower() == "live")
    connectors: list[str] = field(default_factory=lambda: [c.strip() for c in os.getenv("CONNECTORS", "").split(",") if c.strip()])
    state_dir: str = field(default_factory=lambda: os.getenv("EXECUTOR_STATE_DIR", "/data"))
    # Kong
    kong_admin_url: str = field(default_factory=lambda: os.getenv("KONG_ADMIN_URL", "http://kong:8001"))
    kong_admin_token: str = field(default_factory=lambda: os.getenv("KONG_ADMIN_TOKEN", ""))
    # NGINX
    nginx_dir: str = field(default_factory=lambda: os.getenv("NGINX_CONF_DIR", "/etc/sf-gateway"))
    nginx_reload_cmd: str = field(default_factory=lambda: os.getenv("NGINX_RELOAD_CMD", ""))
    # Vault (KV v2)
    vault_addr: str = field(default_factory=lambda: os.getenv("VAULT_ADDR", "http://vault:8200"))
    vault_token: str = field(default_factory=lambda: os.getenv("VAULT_TOKEN", ""))
    vault_mount: str = field(default_factory=lambda: os.getenv("VAULT_MOUNT", "secret"))
    vault_prefix: str = field(default_factory=lambda: os.getenv("VAULT_PREFIX", "specterflow/agents"))


def get_settings() -> Settings:
    return Settings()
