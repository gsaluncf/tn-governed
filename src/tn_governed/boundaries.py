"""Required-governed application boundaries validate handles before dispatch."""

from .artifact_types import GovernedArtifact
from .artifact_verification import verify_artifact


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
        sources = [verify_artifact(self.endpoint, item) for item in self._leaves(accepted)]
        required_claims = {claim.id for _, _, claims in sources for claim in claims}
        required_actions = {action for _, manifest, _ in sources for action in manifest["action_records"]}
        required_editions = [binding for source, _, _ in sources for binding in source.dataset_bindings]
        disputes = [dispute for _, manifest, _ in sources for dispute in manifest["disputes"]]
        for artifact in self._leaves(result):
            data, manifest, claims = verify_artifact(self.endpoint, artifact)
            if (any(not any(p.matches_contract(q) for q in data.policies)
                    for source, _, _ in sources for p in source.policies)
                    or not required_claims <= {claim.id for claim in claims}
                    or any(binding not in data.dataset_bindings for binding in required_editions)
                    or any(dispute not in manifest["disputes"] for dispute in disputes)
                    or not required_actions <= set(manifest["action_records"])):
                raise BoundaryError("result omits a contributing input's governance")
        return result

    def _leaves(self, value):
        if isinstance(value, GovernedArtifact):
            yield value
        else:
            for item in value.values() if isinstance(value, dict) else value:
                yield from self._leaves(item)
