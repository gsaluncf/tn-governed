"""One operation schedule, dispatched through overloaded primitives or explicit callbacks."""


class Operations:
    """Keep the operation schedule equal while varying developer dispatch."""

    def __init__(self, context, mode):
        self.explicit = None
        if mode == "explicit":
            from .explicit import ExplicitOperations
            self.explicit = ExplicitOperations(context)

    def upper(self, value):
        return (self.explicit.execute("upper", (value,), lambda text: text.upper())
                if self.explicit else value.upper())

    def prefix(self, value):
        return (self.explicit.execute("slice", (value,), lambda text: text[:1],
                                      parameters=(None, 1, None))
                if self.explicit else value[:1])

    def add(self, left, right):
        return (self.explicit.execute("add", (left, right), lambda a, b: a + b)
                if self.explicit else left + right)

    def add_literal(self, value, literal):
        return (self.explicit.execute("add", (value,), lambda number: number + literal,
                    parameters=(literal, "right"),
                    literals=({"parameter_index": 0, "position": "right", "claims": []},))
                if self.explicit else value + literal)

    def concat(self, left, right):
        return (self.explicit.execute("concat", (left, right), lambda a, b: a + b)
                if self.explicit else left + right)

    def concat_literal(self, value, literal):
        return (self.explicit.execute("concat", (value,), lambda text: text + literal,
                    parameters=(literal, "right"),
                    literals=({"parameter_index": 0, "position": "right", "claims": []},))
                if self.explicit else value + literal)

    def as_string(self, value):
        return (self.explicit.execute("to_string", (value,), str)
                if self.explicit else value.as_string())
