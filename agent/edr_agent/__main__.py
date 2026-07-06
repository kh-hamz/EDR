import logging
import sys

from .agent import EDRAgent
from .config import AgentSettings


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(threadName)s] %(name)s: %(message)s",
    )
    settings = AgentSettings()
    return EDRAgent(settings).run()


if __name__ == "__main__":
    sys.exit(main())
