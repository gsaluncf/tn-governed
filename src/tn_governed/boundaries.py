"""Required-governed application boundaries validate handles before dispatch."""

from .artifact_types import GovernedArtifact


class BoundaryError(TypeError):
    """An application boundary received a plain or unverifiable value."""


class GovernedBoundary:
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def accept(self, value):
        if isinstance(value, GovernedArtifact):
            self.endpoint.metadata(value)
            return value
        if isinstance(value, dict) and value and all(type(key) is str for key in value):
            return {key: self.accept(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)) and value:
            items = [self.accept(item) for item in value]
            return tuple(items) if isinstance(value, tuple) else items
        raise BoundaryError("this boundary requires governed artifact leaves")

    def dispatch(self, handler, value):
        accepted = self.accept(value)
        result = self.accept(handler(accepted))
        required = {artifact.reference.object_id for artifact in self._leaves(accepted)}
        for artifact in self._leaves(result):
            if not required <= self.endpoint.ancestors(artifact):
                raise BoundaryError("result omits a contributing boundary input")
        return result

    def _leaves(self, value):
        if isinstance(value, GovernedArtifact):
            yield value
        else:
            for item in value.values() if isinstance(value, dict) else value:
                yield from self._leaves(item)
