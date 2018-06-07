import os
import importlib.util
from typing import Dict, Type

from pytacacs_plus.authentication_plugins.base import BaseAuthenticationPlugin


def get_authentication_plugins() -> Dict[str, Type[BaseAuthenticationPlugin]]:
    file_dir = os.path.dirname(__file__)
    files = [item for item in os.listdir(file_dir) if item != '__init__.py' and item.endswith('.py')]

    result = {
        BaseAuthenticationPlugin.NAME: BaseAuthenticationPlugin
    }

    for file in files:
        module_name = '.'.join([__name__, file.replace('.py', '')])
        module_path = os.path.join(file_dir, file)

        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

    for subclass in BaseAuthenticationPlugin.__subclasses__():
        result[subclass.NAME] = subclass

    return result
