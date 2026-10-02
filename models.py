"""Immutable, validated data contracts. Construction is NOT authentication.

All identifiers are opaque references, not credentials. No wire decoder or
security boundary is provided by Python dataclasses. See docs/ARCHITECTURE.md.
"""

from dataclasses import dataclass, fields
from enum import Enum
import re
import types
from typing import Union, get_args, get_origin, get_type_hints

MAX_INTEGER = (1 << 53) - 1


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def check_type(value: object, expected: object) -> bool:
    origin = get_origin(expected)
    if origin in (Union, types.UnionType):
        return any(check_type(value, t) for t in get_args(expected))
    if origin is tuple:
        args = get_args(expected)
        return (type(value) is tuple and len(args) == 2 and args[1] is Ellipsis
                and all(check_type(item, args[0]) for item in value))
    return type(value) is expected


class Model:
    def __post_init__(self) -> None:
        hints = get_type_hints(type(self))
        for field in fields(self):
            value = getattr(self, field.name)
            require(check_type(value, hints[field.name]),
                    "Invalid type for " + field.name)
            if type(value) is int:
                require(0 <= value <= MAX_INTEGER, "Integer outside wire domain")


@dataclass(frozen=True)
class Ref(Model):
    """128-bit opaque reference rendered as exactly 32 lowercase hex digits."""
    value: str

    def __post_init__(self) -> None:
        super().__post_init__()
        require(re.fullmatch(r"[0-9a-f]{32}", self.value) is not None, "Invalid ref")


# Nominally distinct IDs cannot be substituted at construction time.
class DeviceId(Ref):
    pass


class AppInstanceId(Ref):
    pass


class SessionId(Ref):
    pass


class ResourceId(Ref):
    pass


class RecoveryId(Ref):
    pass


@dataclass(frozen=True)
class Label(Model):
    """Registered non-secret symbolic name, never a free-text user field."""
    value: str

    def __post_init__(self) -> None:
        super().__post_init__()
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}", self.value)
                is not None, "Invalid registered label")


@dataclass(frozen=True)
class Digest(Model):
    """SHA-256 digest of PUBLIC measurements or policy, never of credentials."""
    value: str

    def __post_init__(self) -> None:
        super().__post_init__()
        require(re.fullmatch(r"[0-9a-f]{64}", self.value) is not None, "Invalid digest")


class IdentityStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    VERIFIED = "VERIFIED"
    REVOKED = "REVOKED"


class RootKind(str, Enum):
    TPM = "TPM"
    SECURE_ELEMENT = "SECURE_ELEMENT"
    MOSKO_HARDWARE = "MOSKO_HARDWARE"
    SIMULATED = "SIMULATED"


class AttestationStatus(str, Enum):
    NOT_EVALUATED = "NOT_EVALUATED"
    ACCEPTABLE = "ACCEPTABLE"
    REJECTED = "REJECTED"
    INDETERMINATE = "INDETERMINATE"


class Freshness(str, Enum):
    FRESH = "FRESH"
    STALE = "STALE"
    NOT_YET_VALID = "NOT_YET_VALID"
    UNKNOWN = "UNKNOWN"


class SessionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class ChannelStatus(str, Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    EXHAUSTED = "EXHAUSTED"


class Direction(str, Enum):
    LOCAL_TO_PEER = "LOCAL_TO_PEER"
    PEER_TO_LOCAL = "PEER_TO_LOCAL"


class Liveness(str, Enum):
    UNKNOWN = "UNKNOWN"
    LIVE = "LIVE"
    STALE = "STALE"
    EXPIRED = "EXPIRED"


class CompromiseStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    SUSPECTED = "SUSPECTED"
    CONFIRMED = "CONFIRMED"


class AuthorityDecision(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    RESTRICTED = "RESTRICTED"
    DENIED = "DENIED"


class EnforcementResult(str, Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    BLOCKED = "BLOCKED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


class Operation(str, Enum):
    READ = "READ"
    EXPORT = "EXPORT"
    MODIFY = "MODIFY"
    COMMAND = "COMMAND"
    ISSUE = "ISSUE"
    CREATE = "CREATE"
    DELETE = "DELETE"
    INITIATE = "INITIATE"
    RESTORE = "RESTORE"


class Capability(str, Enum):
    READ_REA_TELEMETRY = "READ_REA_TELEMETRY"
    MODIFY_REA_FIRMWARE = "MODIFY_REA_FIRMWARE"
    COMMAND_NETRUNNER = "COMMAND_NETRUNNER"
    ISSUE_NEW_CAPABILITIES = "ISSUE_NEW_CAPABILITIES"
    MODIFY_CF_POLICY = "MODIFY_CF_POLICY"
    CREATE_ADMINISTRATOR = "CREATE_ADMINISTRATOR"
    DELETE_AUDIT_HISTORY = "DELETE_AUDIT_HISTORY"
    READ_OWNED_DATA = "READ_OWNED_DATA"
    EXPORT_OWNED_DATA = "EXPORT_OWNED_DATA"
    INSPECT_RECOVERY = "INSPECT_RECOVERY"
    INITIATE_CREDENTIAL_RECOVERY = "INITIATE_CREDENTIAL_RECOVERY"
    RESTORE_OWNERSHIP_ACCESS = "RESTORE_OWNERSHIP_ACCESS"


OPERATIONS = {
    Capability.READ_REA_TELEMETRY: Operation.READ,
    Capability.MODIFY_REA_FIRMWARE: Operation.MODIFY,
    Capability.COMMAND_NETRUNNER: Operation.COMMAND,
    Capability.ISSUE_NEW_CAPABILITIES: Operation.ISSUE,
    Capability.MODIFY_CF_POLICY: Operation.MODIFY,
    Capability.CREATE_ADMINISTRATOR: Operation.CREATE,
    Capability.DELETE_AUDIT_HISTORY: Operation.DELETE,
    Capability.READ_OWNED_DATA: Operation.READ,
    Capability.EXPORT_OWNED_DATA: Operation.EXPORT,
    Capability.INSPECT_RECOVERY: Operation.READ,
    Capability.INITIATE_CREDENTIAL_RECOVERY: Operation.INITIATE,
    Capability.RESTORE_OWNERSHIP_ACCESS: Operation.RESTORE,
}

RECOVERY_CAPABILITIES = frozenset({
    Capability.READ_OWNED_DATA, Capability.EXPORT_OWNED_DATA,
    Capability.INSPECT_RECOVERY, Capability.INITIATE_CREDENTIAL_RECOVERY,
    Capability.RESTORE_OWNERSHIP_ACCESS,
})


class Reason(str, Enum):
    EXACT_RULE = "EXACT_RULE"
    EXPLICIT_FALLBACK = "EXPLICIT_FALLBACK"
    NO_RULE = "NO_RULE"
    IDENTITY_UNVERIFIED = "IDENTITY_UNVERIFIED"
    SESSION_INVALID = "SESSION_INVALID"
    APP_BINDING_MISMATCH = "APP_BINDING_MISMATCH"
    ATTESTATION_UNACCEPTABLE = "ATTESTATION_UNACCEPTABLE"
    ATTESTATION_NOT_FRESH = "ATTESTATION_NOT_FRESH"
    POLICY_MISMATCH = "POLICY_MISMATCH"
    CHANNEL_INVALID = "CHANNEL_INVALID"
    LIVENESS_REQUIRED = "LIVENESS_REQUIRED"
    COMPROMISE_HOLD = "COMPROMISE_HOLD"
    RECOVERY_INVALID = "RECOVERY_INVALID"
    RECOVERY_SCOPE = "RECOVERY_SCOPE"
    SCOPE_EXCEEDED = "SCOPE_EXCEEDED"


@dataclass(frozen=True)
class DeviceIdentity(Model):
    device_id: DeviceId
    root_kind: RootKind
    public_root_ref: Ref
    enrollment_ref: Ref
    # Identity status belongs to independent verification state, not this record.


@dataclass(frozen=True)
class AttestationEvidence(Model):
    evidence_ref: Ref
    claimed_device_id: DeviceId
    challenge_ref: Ref
    session_id: SessionId
    format_id: Label
    # Evidence bytes and untrusted claims live in a separate protected store.


@dataclass(frozen=True)
class AttestationResult(Model):
    result_ref: Ref
    evidence_ref: Ref
    device_id: DeviceId
    session_id: SessionId
    challenge_ref: Ref
    status: AttestationStatus
    verifier_id: Label
    verifier_version: Label
    appraisal_policy: Digest
    clock_domain: Ref
    evaluated_at: int
    valid_until: int

    def __post_init__(self) -> None:
        super().__post_init__()
        require(self.evaluated_at < self.valid_until, "Empty attestation interval")

    def freshness(self, now: int) -> Freshness:
        if now < self.evaluated_at:
            return Freshness.NOT_YET_VALID
        return Freshness.FRESH if now < self.valid_until else Freshness.STALE


@dataclass(frozen=True)
class AppPrincipal(Model):
    instance_id: AppInstanceId
    app_id: Label
    publisher: Label
    measurement: Digest
    version: Label
    device_id: DeviceId
    platform_profile: Label


@dataclass(frozen=True)
class PolicyRef(Model):
    version: Label
    digest: Digest


@dataclass(frozen=True)
class CapabilityScope(Model):
    capability: Capability
    operation: Operation
    resource: ResourceId

    def __post_init__(self) -> None:
        super().__post_init__()
        require(OPERATIONS[self.capability] is self.operation,
                "Capability and operation disagree")


@dataclass(frozen=True)
class KeyReference(Model):
    handle: Ref
    epoch: int
    # Handle is a non-secret locator, not a bearer authority or key material.


@dataclass(frozen=True)
class SessionContext(Model):
    session_id: SessionId
    local_device_id: DeviceId
    peer_device_id: DeviceId
    local_attestation_ref: Ref | None
    peer_attestation_ref: Ref | None
    local_app: AppPrincipal | None
    peer_app: AppPrincipal | None
    key: KeyReference
    clock_domain: Ref
    established_at: int
    expires_at: int
    policy: PolicyRef
    status: SessionStatus = SessionStatus.ACTIVE
    granted_scope: tuple[CapabilityScope, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        require(self.established_at < self.expires_at, "Empty session interval")
        require(self.local_device_id != self.peer_device_id, "Peers must differ")
        for app, device in ((self.local_app, self.local_device_id),
                            (self.peer_app, self.peer_device_id)):
            require(app is None or app.device_id == device, "App/device mismatch")
        require(len(set(self.granted_scope)) == len(self.granted_scope),
                "Duplicate granted scope")


@dataclass(frozen=True)
class ChannelState(Model):
    session_id: SessionId
    channel_id: Ref
    direction: Direction
    tx_counter: int = 0
    rx_counter: int = 0
    status: ChannelStatus = ChannelStatus.OPEN
    # In-order high-water mark only. No transport or replay acceptance implemented.


@dataclass(frozen=True)
class SessionHealth(Model):
    session_id: SessionId
    liveness: Liveness = Liveness.UNKNOWN
    compromise: CompromiseStatus = CompromiseStatus.UNKNOWN


@dataclass(frozen=True)
class RecoveryPrincipal(Model):
    recovery_id: RecoveryId
    owner_ref: Ref
    credential_ref: Ref
    # User-controlled RecoveryKey locator. Never a TPM endorsement key.


@dataclass(frozen=True)
class RecoveryContext(Model):
    context_id: Ref
    principal: RecoveryPrincipal
    session_id: SessionId
    app: AppPrincipal
    verification_result_ref: Ref
    identity_status: IdentityStatus
    verifier_version: Label
    clock_domain: Ref
    verified_at: int
    expires_at: int
    policy: PolicyRef
    allowed_scope: tuple[CapabilityScope, ...]
    ownership_binding_ref: Ref

    def __post_init__(self) -> None:
        super().__post_init__()
        require(self.verified_at < self.expires_at, "Empty recovery interval")
        require(all(s.capability in RECOVERY_CAPABILITIES for s in self.allowed_scope),
                "Recovery cannot carry administrative authority")
        require(len(set(self.allowed_scope)) == len(self.allowed_scope), "Duplicate scope")


@dataclass(frozen=True)
class CapabilityRequest(Model):
    request_id: Ref
    requesting_device: DeviceId
    requesting_app: AppPrincipal
    session_id: SessionId
    channel_id: Ref
    scope: CapabilityScope
    recovery_id: RecoveryId | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        require(self.requesting_device == self.requesting_app.device_id,
                "Request app/device mismatch")


@dataclass(frozen=True)
class CapabilityGrant(Model):
    grant_id: Ref
    decision_id: Ref
    request_id: Ref
    session_id: SessionId
    channel_id: Ref
    device_id: DeviceId
    app: AppPrincipal
    scope: CapabilityScope
    policy: PolicyRef
    clock_domain: Ref
    issued_at: int
    expires_at: int
    recovery_id: RecoveryId | None

    def __post_init__(self) -> None:
        super().__post_init__()
        require(self.app.device_id == self.device_id, "Grant app/device mismatch")
        require(self.issued_at < self.expires_at, "Empty grant interval")
        require(self.recovery_id is None or self.scope.capability in RECOVERY_CAPABILITIES,
                "Recovery grant exceeds recovery domain")


@dataclass(frozen=True)
class AuthorityOutcome(Model):
    decision_id: Ref
    request: CapabilityRequest
    decision: AuthorityDecision
    grant: CapabilityGrant | None
    matched_rules: tuple[Label, ...]
    reasons: tuple[Reason, ...]

    def __post_init__(self) -> None:
        super().__post_init__()
        require(bool(self.reasons), "Decision requires reason codes")
        if self.decision is AuthorityDecision.DENIED:
            require(self.grant is None, "Denied decision cannot contain grant")
            return
        g = self.grant
        r = self.request
        require(g is not None and bool(self.matched_rules), "Grant requires matched rule")
        require((g.decision_id, g.request_id, g.session_id, g.channel_id,
                 g.device_id, g.app, g.recovery_id) ==
                (self.decision_id, r.request_id, r.session_id, r.channel_id,
                 r.requesting_device, r.requesting_app, r.recovery_id),
                "Grant binding mismatch")
        if self.decision is AuthorityDecision.AUTHORIZED:
            require(g.scope == r.scope, "Authorized must grant exact request")
        else:
            require(g.scope != r.scope and g.scope.resource == r.scope.resource,
                    "Restricted must describe a distinct operation on same resource")
            require(Reason.EXPLICIT_FALLBACK in self.reasons,
                    "Restricted requires explicit fallback reason")


@dataclass(frozen=True)
class PacketMetadata(Model):
    protocol_version: Label
    session_id: SessionId
    origin: DeviceId
    destination: DeviceId
    channel_id: Ref
    packet_counter: int
    direction: Direction
    key_epoch: int
    message_type: Label

    def __post_init__(self) -> None:
        super().__post_init__()
        require(self.origin != self.destination, "Packet peers must differ")
        require(self.packet_counter > 0, "Counter zero reserved")


@dataclass(frozen=True)
class CFDecisionRecord(Model):
    event_id: Ref
    ledger_epoch: Ref
    event_sequence: int
    timestamp_unix_ms: int
    clock_domain: Ref
    decision_time: int
    outcome: AuthorityOutcome
    peer_device: DeviceId
    local_identity_status: IdentityStatus
    identity_status: IdentityStatus
    local_attestation_status: AttestationStatus
    attestation_status: AttestationStatus
    local_attestation_ref: Ref | None
    attestation_ref: Ref | None
    local_attestation_freshness: Freshness
    attestation_freshness: Freshness
    liveness: Liveness
    compromise: CompromiseStatus
    policy: PolicyRef
    enforcement_point: Label
    enforcement_result: EnforcementResult
    build: Label
    local_verifier_version: Label | None
    verifier_version: Label | None
    recovery_verifier_version: Label | None
    recovery_context_ref: Ref | None

    def __post_init__(self) -> None:
        super().__post_init__()
        require(self.event_sequence > 0, "Sequence starts at one")
        require(not (self.outcome.decision is AuthorityDecision.DENIED and
                     self.enforcement_result is EnforcementResult.EXECUTED),
                "Denied cannot be executed")
        if self.outcome.grant is not None:
            require(self.outcome.grant.policy == self.policy, "Audit policy mismatch")
        # No free-form payload, credentials, evidence bytes, or arbitrary metadata.
