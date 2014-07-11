import pkgutil

"""Import all parsers as their class name."""

__all__ = []
for loader, module_name, is_pkg in  pkgutil.walk_packages(__path__):
    __all__.append(module_name)
    module = loader.find_module(module_name).load_module(module_name)
    exec('%s = module' % module_name)
    exec('from %s import *' % module_name)