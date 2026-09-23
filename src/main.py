"""CLI entry point for managing Cloudflare, Telnyx, and Regery infrastructure."""

from __future__ import annotations

import argparse
import logging
import pathlib
import sys
from typing import Final, cast
import src.cloudflare as cloudflare
import src.configuration as configuration
import src.regery as regery
import src.telnyx as telnyx

PROJECT_DIRECTORY: Final = pathlib.Path(__file__).parent.parent

logger = logging.getLogger(__name__)

CONFIGURATION_DIRECTORY: Final = PROJECT_DIRECTORY / "examples/"


def parseCommands(arguments: list[str]) -> tuple[list[str], bool, bool, str]:
    """Parse the provider reconciliation commands requested by the invoker."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--do",
        action="append",
        choices=("all", "cloudflare", "telnyx", "regery"),
        dest="commands",
        metavar="PROVIDER",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="perform the planned mutations")
    mode.add_argument("--check", action="store_true", help="validate local configuration without network access")
    parser.add_argument("--plan", choices=("json", "text"), default="text", help="select the plan output format")
    parsed = parser.parse_args(arguments)
    if parsed.check:
        return [], False, True, str(parsed.plan)
    if not parsed.commands:
        parser.error("--do is required unless --check is used")
    commands = cast("list[str]", parsed.commands)
    if "all" in commands:
        if len(commands) != 1:
            parser.error("--do all cannot be combined with another provider")
        commands = ["cloudflare", "telnyx", "regery"]
    return commands, bool(parsed.apply), False, str(parsed.plan)


def main() -> None:
    """Run the requested infrastructure reconciliation commands."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    commands, apply, check, planformat = parseCommands(sys.argv[1:])
    zones, telnyxconfig, regeryconfig = configuration.readConfiguration(CONFIGURATION_DIRECTORY)
    if check:
        configuration.checkConfiguration(CONFIGURATION_DIRECTORY, zones, telnyxconfig, regeryconfig)
        return
    if "cloudflare" in commands:
        logger.info("\n=== Cloudflare ===")
        cloudflare.reconcile(CONFIGURATION_DIRECTORY, zones, apply=apply, planformat=planformat)
    if "telnyx" in commands:
        logger.info("\n=== Telnyx ===")
        telnyx.reconcile(telnyxconfig, apply=apply, planformat=planformat)
    if "regery" in commands:
        logger.info("\n=== Regery ===")
        managednames = set(cast("list[str]", regeryconfig["domains"]))
        nameservers = cloudflare.fetchNameservers(managednames)
        regery.reconcile(regeryconfig, nameservers, apply=apply, planformat=planformat)


if __name__ == "__main__":
    main()
