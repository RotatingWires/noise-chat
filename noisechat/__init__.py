"""NoiseChat: keys and plaintext belong to the clients."""

from importlib.metadata import version
import tomllib
from pathlib import Path

project_file = Path(__file__).parents[1] / "pyproject.toml"
if project_file.is_file():
    __version__ = tomllib.loads(project_file.read_text())["project"]["version"]
else:
    __version__ = version("noisechat")
