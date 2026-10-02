"""CF031 JSON profile, NOT a final transport encoding or trust decoder."""

from dataclasses import fields
from enum import Enum
import json

from .models import Digest, Label, MAX_INTEGER, Model, Ref


def primitive(value: object) -> object:
    if isinstance(value, (Ref, Label, Digest)):
        return value.value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Model):
        return {f.name: primitive(getattr(value, f.name)) for f in fields(value)}
    if type(value) is tuple:
        return [primitive(v) for v in value]
    if value is None:
        return None
    if type(value) is int and 0 <= value <= MAX_INTEGER:
        return value
    raise TypeError("Only validated model values can be serialized")


def canonical_json(value: Model) -> bytes:
    if not isinstance(value, Model):
        raise TypeError("Expected a model")
    envelope = {"schema": "CF031", "type": type(value).__name__, "value": primitive(value)}
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def human_log(record: Model) -> str:
    from .models import CFDecisionRecord
    if type(record) is not CFDecisionRecord:
        raise TypeError("Expected CFDecisionRecord")
    o = record.outcome
    effective = "NONE" if o.grant is None else o.grant.scope.capability.value
    return (f"event={record.event_id.value} seq={record.event_sequence} "
            f"decision={o.decision_id.value} state={o.decision.value} "
            f"requested={o.request.scope.capability.value} effective={effective} "
            f"reasons={','.join(r.value for r in o.reasons)} "
            f"enforcement={record.enforcement_result.value}")
