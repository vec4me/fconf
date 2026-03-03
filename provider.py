"""Declarative config tree diffing and delta application."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Literal, TypedDict, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

Action = Literal["remove", "push", "update"]

logger = logging.getLogger(__name__)


class LeafNode(TypedDict):
    """A leaf node in the config tree holding a value and push/remove callbacks."""

    value: object
    push: Callable[[], None]
    remove: Callable[[], None]


ConfigTree = dict[str, "ConfigTree | LeafNode"]
Path = tuple[str, ...]
Diff = tuple[Action, Path, LeafNode]


def set_tree(
    tree: ConfigTree,
    path: Path,
    value: object,
    push_fn: Callable[[], None],
    remove_fn: Callable[[], None],
) -> None:
    """Set a leaf node in the config tree at the given path."""
    current: ConfigTree = tree
    for key in path[:-1]:
        if key not in current:
            current[key] = {}
        current = cast(ConfigTree, current[key])
    leaf: LeafNode = {"value": value, "push": push_fn, "remove": remove_fn}
    current[path[-1]] = leaf


def is_leaf(node: ConfigTree | LeafNode) -> bool:
    """Check whether a node is a leaf node."""
    return "value" in node


def as_leaf(node: ConfigTree | LeafNode) -> LeafNode:
    """Narrow a node to LeafNode after checking is_leaf."""
    return cast(LeafNode, node)

def as_tree(node: ConfigTree | LeafNode) -> ConfigTree:
    """Narrow a node to ConfigTree after checking it is not a leaf."""
    return cast(ConfigTree, node)

def diff_one_sided(
    source: ConfigTree,
    action: Literal["remove", "push"],
    keys: set[str],
    path: Path,
) -> Generator[Diff, None, None]:
    """Yield diffs for keys only present on one side."""
    empty: ConfigTree = {}
    for key in keys:
        node = source[key]
        if is_leaf(node):
            yield (action, (*path, key), as_leaf(node))
        elif action == "remove":
            yield from diff_trees(as_tree(node), empty, (*path, key))
        else:
            yield from diff_trees(empty, as_tree(node), (*path, key))


def diff_shared_key(
    remote_node: ConfigTree | LeafNode,
    local_node: ConfigTree | LeafNode,
    key: str,
    path: Path,
) -> Generator[Diff, None, None]:
    """Yield diffs for a key present in both trees."""
    if is_leaf(remote_node) and is_leaf(local_node):
        if remote_node["value"] != local_node["value"]:
            yield ("update", (*path, key), as_leaf(local_node))
    elif not is_leaf(remote_node) and not is_leaf(local_node):
        yield from diff_trees(as_tree(remote_node), as_tree(local_node), (*path, key))
    else:
        if is_leaf(remote_node):
            yield ("remove", (*path, key), as_leaf(remote_node))
        if is_leaf(local_node):
            yield ("push", (*path, key), as_leaf(local_node))


def diff_trees(
    remote: ConfigTree,
    local: ConfigTree,
    path: Path = (),
) -> Generator[Diff, None, None]:
    """Yield diffs between two config trees."""
    remote_keys = set(remote.keys())
    local_keys = set(local.keys())

    yield from diff_one_sided(remote, "remove", remote_keys - local_keys, path)
    yield from diff_one_sided(local, "push", local_keys - remote_keys, path)

    for key in remote_keys & local_keys:
        yield from diff_shared_key(remote[key], local[key], key, path)


def get_node(remote: ConfigTree, path: Path) -> LeafNode | None:
    """Retrieve a leaf node from the remote tree by path."""
    tree = remote
    for key in path[:-1]:
        if key not in tree:
            return None
        tree = as_tree(tree[key])
    if path[-1] not in tree:
        return None
    node = tree[path[-1]]
    return as_leaf(node) if is_leaf(node) else None


def dict_delta(old: dict[str, object], new: dict[str, object]) -> list[str]:
    """Compute per-key changes between two dicts."""
    changes: list[str] = []
    for key in sorted(set(old.keys()) | set(new.keys())):
        old_val = old.get(key)
        new_val = new.get(key)
        if old_val != new_val:
            changes.append(f"  {key}: {old_val!r} -> {new_val!r}")
    return changes


def log_diffs(diffs: list[Diff], remote: ConfigTree) -> None:
    """Log all pending diffs for user review."""
    for action, path, node in diffs:
        path_str = "/".join(path)
        if action == "remove":
            logger.info("remove: %s", path_str)
        elif action == "push":
            logger.info("push: %s = %s", path_str, node["value"])
        elif action == "update":
            remote_node = get_node(remote, path)
            logger.info("update: %s", path_str)
            if remote_node:
                remote_val = cast(dict[str, object], remote_node["value"])
                local_val = cast(dict[str, object], node["value"])
                for change in dict_delta(remote_val, local_val):
                    logger.info("%s", change)
        else:
            msg = f"unknown action: {action}"
            raise ValueError(msg)


def apply_diffs(diffs: list[Diff], remote: ConfigTree) -> None:
    """Apply all diffs by calling push/remove callbacks."""
    for action, path, node in diffs:
        if action == "remove":
            node["remove"]()
        elif action == "push":
            node["push"]()
        elif action == "update":
            remote_node = get_node(remote, path)
            if remote_node:
                remote_node["remove"]()
            node["push"]()
        else:
            msg = f"unknown action: {action}"
            raise ValueError(msg)


def run_deltas(remote: ConfigTree, local: ConfigTree) -> None:
    """Diff two config trees, prompt for confirmation, and apply changes."""
    diffs: list[Diff] = list(diff_trees(remote, local))

    if not diffs:
        logger.info("no changes")
        return

    log_diffs(diffs, remote)

    confirm = input("\nproceed with writes? [y/N] ")
    if confirm.lower() != "y":
        logger.info("aborted")
        return

    apply_diffs(diffs, remote)
