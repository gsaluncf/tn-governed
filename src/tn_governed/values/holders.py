"""Find the TN object that holds an encrypted group when it travels inside another one."""


def holder(obj, group):
    """Return `obj`, or the nearest whole object it carries, that holds `group`.

    A successor never copies a group its writer could not decrypt. It carries the
    whole source object, so that group stays bound to the source's governance.
    """
    pending = [obj]
    while pending:
        current = pending.pop(0)
        if group in current.group_names:
            return current
        pending.extend(getattr(current, "carried", ()))
    raise KeyError(group)


def field_hash(obj, group, field):
    """The signed field hash of `field` in `group`, read from the object that holds it."""
    return holder(obj, group).envelope[group]["field_hashes"][field]


def receive_routed(session, obj, *, use, groups, decide, selection=None):
    """Receive `groups`, opening each one from the object that holds it.

    The groups `obj` holds open from it in one admission. A group that travels in a
    carried object opens from that object, admitted under its own governance, and
    joins the working copy as plaintext. `decide(source, groups)` returns the
    admission callback for each object and the groups requested from it.
    """
    own = [group for group in groups if group in obj.group_names]
    if not own:
        # Returning the carried object's data instead would drop `obj` from lineage.
        raise LookupError(
            "every requested group travels in a carried object; "
            "strict admission of an object with no opened group is not available yet")
    data = session.receive(obj, use=use, groups=own, selection=selection, decide=decide(obj, own))
    for group in groups:
        if group not in obj.group_names:
            source = holder(obj, group)
            opened = session.receive(source, use=use, groups=[group], decide=decide(source, [group]))
            data.set(None, opened.get(None, group=group), group=group)
    return data


def bind_manifest(data, group="evidence"):
    """Bind every data group of the next release to `group`, when the SDK supports binding."""
    bind = getattr(data, "bind_manifest", None)
    if bind is not None:
        bind(group)
