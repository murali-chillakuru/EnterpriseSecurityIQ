"""IQForge — template-driven IQ-platform scaffolder."""
__version__ = "1.0.0"

from iqforge.generator import generate_project as create_project
from iqforge.validators import load_and_validate as validate_config
