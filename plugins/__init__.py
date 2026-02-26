from __future__ import annotations

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Type

if TYPE_CHECKING:
    from plugins.base import BaseTool

logger = logging.getLogger("mergen.plugins")

_REGISTRY: Dict[str, "BaseTool"] = {}


def discover_plugins() -> Dict[str, "BaseTool"]:
    pkg_dir = Path(__file__).parent
    for _, module_name, _ in pkgutil.iter_modules([str(pkg_dir)]):
        if module_name.startswith("_"):
            continue
        fqn = f"plugins.{module_name}"
        try:
            importlib.import_module(fqn)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load plugin '%s': %s", module_name, exc)
    return _REGISTRY


def register(cls: Type["BaseTool"]) -> Type["BaseTool"]:
    instance = cls()
    if instance.name in _REGISTRY:
        logger.debug("Re-registering plugin '%s' (hot-reload)", instance.name)
    _REGISTRY[instance.name] = instance
    return cls
