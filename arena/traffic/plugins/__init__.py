import importlib
import pkgutil
from pathlib import Path

for _mod in pkgutil.iter_modules([str(Path(__file__).parent)]):
    if _mod.name != "base":
        importlib.import_module(f".{_mod.name}", package=__name__)
