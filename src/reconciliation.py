"""Declarative configuration tree diffing and delta application."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Literal, cast
if TYPE_CHECKING:
    from collections.abc import Callable, Generator

Action = Literal["remove", "push", "replace", "unknown"]

logger = logging.getLogger(__name__)


LeafNode = dict[str, object]
Path = tuple[str, ...]
ConfigTree = dict[Path, LeafNode]
Diff = tuple[Action, Path, LeafNode]
Plan = list[dict[str, object]]
TransitionResult = dict[str, object]
Dependencies = dict[Path, tuple[Path, ...]]
Unknowns = dict[Path, str]


def setValue(tree: ConfigTree, path: Path, value: object) -> None:
    """Set one plain resource value without registering mutation behavior."""
    tree[path] = {"value": value}


def TreeDifferences(
    remote: ConfigTree,
    local: ConfigTree,
) -> Generator[Diff, None, None]:
    """Yield differences between two flat resource maps."""
    remotekeys = set(remote.keys())
    localkeys = set(local.keys())
    for path in sorted(remotekeys - localkeys):
        yield ("remove", path, remote[path])
    for path in sorted(localkeys - remotekeys):
        yield ("push", path, local[path])
    for path in sorted(remotekeys & localkeys):
        if remote[path]["value"] != local[path]["value"]:
            yield ("replace", path, local[path])


def Node(remote: ConfigTree, path: Path) -> LeafNode | None:
    """Retrieve a resource leaf by path."""
    return remote.get(path)


def DictionaryDelta(old: dict[str, object], new: dict[str, object]) -> list[str]:
    """Compute per-key changes between two dicts."""
    changes: list[str] = []
    for key in sorted(set(old.keys()) | set(new.keys())):
        oldvalue = old.get(key)
        newvalue = new.get(key)
        if oldvalue != newvalue:
            changes.append(f"  {key}: {oldvalue!r} -> {newvalue!r}")
    return changes


def printPlan(plan: Plan, planformat: str) -> None:
    """Print a serializable patch plan for review."""
    if planformat == "json":
        logger.info("%s", json.dumps(plan, indent=4, sort_keys=True, default=str))
        return
    for operation in plan:
        action = cast("Action", operation["action"])
        path = cast("Path", operation["path"])
        pathstring = "/".join(path)
        if action == "remove":
            logger.info("remove: %s", pathstring)
        elif action == "push":
            logger.info("push: %s = %s", pathstring, operation["after"])
        elif action == "replace":
            logger.info("replace: %s", pathstring)
            before = operation["before"]
            after = operation["after"]
            if isinstance(before, dict) and isinstance(after, dict):
                for change in DictionaryDelta(before, after):
                    logger.info("%s", change)
        elif action == "unknown":
            logger.warning("unknown: %s: %s", pathstring, operation["reason"])
        else:
            message = f"unknown action: {action}"
            raise ValueError(message)


def PathUnknown(path: Path, unknowns: Unknowns) -> bool:
    """Return whether an observation boundary contains a resource path."""
    return any(path[:len(boundary)] == boundary for boundary in unknowns)


def OrderedPlan(plan: Plan) -> Plan:
    """Return deterministic dependency-respecting operation order."""
    pending = {str(operation["id"]): operation for operation in plan}
    completed: set[str] = set()
    ordered: Plan = []
    while pending:
        ready = [
            operationid
            for operationid, operation in pending.items()
            if set(cast("list[str]", operation["after_operations"])) <= completed
        ]
        if not ready:
            raise ValueError("plan contains a dependency cycle")
        for operationid in sorted(ready):
            ordered.append(pending.pop(operationid))
            completed.add(operationid)
    return ordered


def ReconciliationPlan(remote: ConfigTree, desired: ConfigTree, dependencies: Dependencies, unknowns: Unknowns) -> Plan:
    """Return the deterministic patch plan from observed to desired state."""
    plan: Plan = []
    for action, path, node in TreeDifferences(remote, desired):
        if PathUnknown(path, unknowns):
            continue
        remotenode = Node(remote, path)
        plan.append({
            "id": f"{action}:{'/'.join(path)}",
            "action": action,
            "path": path,
            "before": remotenode["value"] if remotenode is not None else None,
            "after": None if action == "remove" else node["value"],
            "after_operations": [],
        })
    ids = {cast("Path", operation["path"]): str(operation["id"]) for operation in plan}
    for operation in plan:
        if operation["action"] == "remove":
            continue
        path = cast("Path", operation["path"])
        prerequisites = dependencies.get(path, ())
        operation["after_operations"] = [ids[dependency] for dependency in prerequisites if dependency in ids]
    for boundary, reason in sorted(unknowns.items()):
        plan.append({
            "id": f"unknown:{'/'.join(boundary)}",
            "action": "unknown",
            "path": boundary,
            "before": None,
            "after": None,
            "after_operations": [],
            "reason": reason,
        })
    return OrderedPlan(plan)


def executeValues(plan: Plan, executor: Callable[[dict[str, object]], TransitionResult]) -> list[dict[str, object]]:
    """Execute a plan through one provider mutation authority."""
    outcomes: list[dict[str, object]] = []
    failed: set[str] = set()
    for operation in plan:
        operationid = str(operation["id"])
        dependencies = set(cast("list[str]", operation["after_operations"]))
        blocked = sorted(dependencies & failed)
        if blocked:
            outcomes.append({"id": operationid, "status": "skipped", "completed_steps": [], "reason": f"failed dependencies: {', '.join(blocked)}"})
            failed.add(operationid)
            continue
        if operation["action"] == "unknown":
            outcomes.append({"id": operationid, "status": "skipped", "completed_steps": [], "reason": operation["reason"]})
            continue
        try:
            result = executor(operation)
        except Exception as error:
            failed.add(operationid)
            outcomes.append({"id": operationid, "status": "failed", "completed_steps": [], "reason": str(error)})
            continue
        completed = cast("list[str]", result["completed_steps"])
        error = result.get("error")
        if error is not None:
            failed.add(operationid)
            outcomes.append({"id": operationid, "status": "failed", "completed_steps": completed, "reason": str(error)})
            continue
        outcomes.append({"id": operationid, "status": "completed", "completed_steps": completed})
    return outcomes


def printOutcomes(outcomes: list[dict[str, object]]) -> None:
    """Print execution outcomes and reject incomplete application."""
    incomplete = False
    for outcome in outcomes:
        status = str(outcome["status"])
        if status == "completed":
            logger.info("completed: %s", outcome["id"])
            continue
        incomplete = True
        logger.error("%s: %s: %s", status, outcome["id"], outcome["reason"])
    if incomplete:
        raise RuntimeError("plan application incomplete")


def verifyConvergence(observed: ConfigTree, desired: ConfigTree, dependencies: Dependencies, unknowns: Unknowns) -> None:
    """Require re-observed state to produce an empty plan."""
    remaining = ReconciliationPlan(observed, desired, dependencies, unknowns)
    if remaining:
        printPlan(remaining, "text")
        raise RuntimeError("provider did not converge after applying the plan")
    logger.info("converged")


def runValues(
    observed: ConfigTree,
    desired: ConfigTree,
    dependencies: Dependencies,
    unknowns: Unknowns,
    executor: Callable[[dict[str, object]], TransitionResult],
    *,
    apply: bool,
    planformat: str = "text",
) -> bool:
    """Plan plain values and delegate mutations to one provider executor."""
    plan = ReconciliationPlan(observed, desired, dependencies, unknowns)
    if not plan:
        logger.info("no changes")
        return False
    printPlan(plan, planformat)
    if not apply:
        logger.info("\nplan only; rerun with --apply to perform these mutations")
        return False
    outcomes = executeValues(plan, executor)
    printOutcomes(outcomes)
    return True
