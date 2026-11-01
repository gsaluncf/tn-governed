"""Immutable expectations for signed tool-completion evidence."""

from dataclasses import dataclass


def _identity(value, field):
    if (not isinstance(value, str) or not value.strip() or value != value.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ValueError(f"{field} must be a nonempty string without surrounding space or controls")
    return value


@dataclass(frozen=True, slots=True)
class ToolEvidenceExpectation:
    """Bind a tool name to its allowed input sections and signed publication type."""

    name: str
    selected_sections: tuple[str, ...]
    object_type: str

    def __post_init__(self):
        _identity(self.name, "tool name")
        _identity(self.object_type, "tool publication type")
        if isinstance(self.selected_sections, str):
            raise TypeError("tool sections must be a sequence of names")
        sections = tuple(self.selected_sections)
        if not sections or len(set(sections)) != len(sections):
            raise ValueError("tool sections must be nonempty and unique")
        for section in sections:
            _identity(section, "tool section")
        object.__setattr__(self, "selected_sections", sections)
