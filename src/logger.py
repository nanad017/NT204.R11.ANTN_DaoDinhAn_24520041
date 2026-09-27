import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def prepare_output(output_file, truncate=True):
    path = Path(output_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    if truncate:
        path.write_text("", encoding="utf-8")
    elif not path.exists():
        path.touch()
    return path


def write_event(event, output_file):
    path = Path(output_file)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(event.to_dict(), ensure_ascii=False)
        with path.open("a", encoding="utf-8") as output:
            output.write(serialized)
            output.write("\n")
    except OSError:
        logger.exception("Could not write event to %s", path)
        raise
