"""NoiseChat: keys and plaintext belong to the clients."""

from importlib.metadata import PackageNotFoundError, version
import tomllib
from pathlib import Path

try:
    __version__ = version("noisechat")
except PackageNotFoundError:
    __version__ = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())["project"]["version"]
