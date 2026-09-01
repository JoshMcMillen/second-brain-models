"""Typed failures surfaced by the command-line tooling."""


class ModelCatalogError(RuntimeError):
    """A candidate or catalog operation failed closed."""


class DocumentError(ModelCatalogError):
    """JSON, YAML, or schema data was malformed."""


class PolicyError(ModelCatalogError):
    """A repository policy was missing, ambiguous, or violated."""


class SignatureError(ModelCatalogError):
    """A detached Ed25519 signature was absent or invalid."""


class EvaluationError(ModelCatalogError):
    """Synthetic evaluation evidence did not meet the release gate."""
