"""Find the TN object that holds an encrypted group when it travels inside another one.

Receipt routes carried groups natively: `Session.receive` and `Session.admit` ask the
received object and every object on the path to a group's holder. These helpers only
read public envelopes, for field hashes and edition selections.
"""


def route(obj, group):
    """`obj`, each object on the breadth-first path to `group`'s holder, and the holder.

    A successor never copies a group its writer could not decrypt. It carries the
    whole source object, so that group stays bound to the source's governance.
    The search is breadth first, the order native receipt resolves holders in.
    """
    pending = [[obj]]
    while pending:
        path = pending.pop(0)
        if group in path[-1].group_names:
            return path
        pending.extend(path + [child] for child in path[-1].carried)
    raise KeyError(group)


def holder(obj, group):
    """Return `obj`, or the nearest whole object it carries, that holds `group`."""
    return route(obj, group)[-1]


def field_hash(obj, group, field):
    """The signed field hash of `field` in `group`, read from the object that holds it."""
    return holder(obj, group).envelope[group]["field_hashes"][field]


def suppliers(obj, groups):
    """The distinct objects that hold `groups` for `obj`, in request order."""
    return _distinct(holder(obj, group) for group in groups)


def _distinct(objects):
    found = {}
    for item in objects:
        found.setdefault(item.id, item)
    return list(found.values())
