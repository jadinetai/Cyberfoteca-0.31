"""POLICY SIMULATION ONLY. No authentication, cryptography, or enforcement.

TrustedSnapshot and rule tables are fixture inputs, not accepted wire messages.
This module is never a production authorization service. Python object creation
does not establish provenance. A future isolated core must own these records.
"""

from dataclasses import dataclass

from .models import (
    AppPrincipal, AttestationResult, AttestationStatus, AuthorityDecision,
    AuthorityOutcome, CapabilityGrant, CapabilityRequest, CapabilityScope,
    CFDecisionRecord, ChannelState, ChannelStatus, CompromiseStatus,
    DeviceIdentity, Direction, EnforcementResult, Freshness, IdentityStatus,
    Label, Liveness, Model, PolicyRef, Reason, RecoveryContext, RecoveryId,
    Ref, SessionContext, SessionHealth, SessionStatus, require,
)


@dataclass(frozen=True)
class PolicyRule(Model):
    rule_id: Label
    app: AppPrincipal
    requested: CapabilityScope
    effective: CapabilityScope
    recovery_id: RecoveryId | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        require(self.requested.resource == self.effective.resource,
                "Fallback cannot silently change target")
        # A different effective scope is an explicit policy-defined fallback.
        # Policy author is responsible for establishing that it is lower risk.


@dataclass(frozen=True)
class Policy(Model):
    reference: PolicyRef
    rules: tuple[PolicyRule, ...]

    def __post_init__(self) -> None:
        super().__post_init__()
        selectors = [(r.app, r.requested, r.recovery_id) for r in self.rules]
        require(len(set(selectors)) == len(selectors), "Ambiguous rule selectors")
        require(len({r.rule_id for r in self.rules}) == len(self.rules), "Duplicate rule ID")


@dataclass(frozen=True)
class TrustedSnapshot(Model):
    """Immutable fixture snapshot captured by a hypothetical trusted core."""
    local_device: DeviceIdentity
    peer_device: DeviceIdentity
    local_identity: IdentityStatus
    peer_identity: IdentityStatus
    local_attestation: AttestationResult | None
    peer_attestation: AttestationResult | None
    local_challenge: Ref
    peer_challenge: Ref
    session: SessionContext
    channel: ChannelState
    health: SessionHealth
    policy: Policy
    now: int
    clock_domain: Ref
    recovery: RecoveryContext | None = None


def evaluate(request: CapabilityRequest, context: TrustedSnapshot,
             decision_id: Ref, grant_id: Ref) -> AuthorityOutcome:
    """Pure deterministic fixture evaluation. Does not execute an operation."""
    require(type(request) is CapabilityRequest and type(context) is TrustedSnapshot,
            "Validated request and snapshot required")
    s, c, p = context.session, context.channel, context.policy

    def deny(reason: Reason, rules: tuple[Label, ...] = ()) -> AuthorityOutcome:
        return AuthorityOutcome(decision_id, request, AuthorityDecision.DENIED,
                                None, rules, (reason,))

    if (context.local_identity is not IdentityStatus.VERIFIED or
            context.peer_identity is not IdentityStatus.VERIFIED):
        return deny(Reason.IDENTITY_UNVERIFIED)
    if (request.session_id != s.session_id or
            context.local_device.device_id != s.local_device_id or
            context.peer_device.device_id != s.peer_device_id or
            request.requesting_device != s.peer_device_id or
            context.clock_domain != s.clock_domain or
            s.status is not SessionStatus.ACTIVE or
            not s.established_at <= context.now < s.expires_at):
        return deny(Reason.SESSION_INVALID)
    if request.requesting_app != s.peer_app:
        return deny(Reason.APP_BINDING_MISMATCH)
    if s.policy != p.reference:
        return deny(Reason.POLICY_MISMATCH)
    if (c.session_id != s.session_id or request.channel_id != c.channel_id or
            c.direction is not Direction.PEER_TO_LOCAL or
            c.status is not ChannelStatus.OPEN):
        return deny(Reason.CHANNEL_INVALID)

    for att, device, ref, challenge in (
        (context.local_attestation, s.local_device_id,
         s.local_attestation_ref, context.local_challenge),
        (context.peer_attestation, s.peer_device_id,
         s.peer_attestation_ref, context.peer_challenge),
    ):
        if (att is None or att.result_ref != ref or att.device_id != device or
                att.session_id != s.session_id or att.challenge_ref != challenge or
                att.clock_domain != s.clock_domain or
                att.appraisal_policy != p.reference.digest or
                att.status is not AttestationStatus.ACCEPTABLE):
            return deny(Reason.ATTESTATION_UNACCEPTABLE)
        if att.freshness(context.now) is not Freshness.FRESH:
            return deny(Reason.ATTESTATION_NOT_FRESH)
    if context.health.session_id != s.session_id:
        return deny(Reason.SESSION_INVALID)
    if context.health.compromise is not CompromiseStatus.UNKNOWN:
        return deny(Reason.COMPROMISE_HOLD)
    if context.health.liveness is not Liveness.LIVE:
        return deny(Reason.LIVENESS_REQUIRED)

    recovery = context.recovery
    if request.recovery_id is not None:
        if (recovery is None or recovery.principal.recovery_id != request.recovery_id or
                recovery.identity_status is not IdentityStatus.VERIFIED or
                recovery.session_id != s.session_id or recovery.app != s.peer_app or
                recovery.clock_domain != s.clock_domain or
                recovery.policy != p.reference or
                not recovery.verified_at <= context.now < recovery.expires_at):
            return deny(Reason.RECOVERY_INVALID)
    elif recovery is not None:
        # A recovery-only context must not select ordinary app authority.
        return deny(Reason.RECOVERY_INVALID)

    rule = next((r for r in p.rules if r.app == request.requesting_app and
                 r.requested == request.scope and r.recovery_id == request.recovery_id), None)
    if rule is None:
        return deny(Reason.NO_RULE)
    if recovery is not None and rule.effective not in recovery.allowed_scope:
        return deny(Reason.RECOVERY_SCOPE, (rule.rule_id,))

    expires = min(s.expires_at, context.local_attestation.valid_until,
                  context.peer_attestation.valid_until)
    if recovery is not None:
        expires = min(expires, recovery.expires_at)
    grant = CapabilityGrant(
        grant_id, decision_id, request.request_id, s.session_id, c.channel_id,
        request.requesting_device, request.requesting_app, rule.effective,
        p.reference, s.clock_domain, context.now, expires, request.recovery_id,
    )
    exact = rule.requested == rule.effective
    return AuthorityOutcome(
        decision_id, request,
        AuthorityDecision.AUTHORIZED if exact else AuthorityDecision.RESTRICTED,
        grant, (rule.rule_id,),
        (Reason.EXACT_RULE if exact else Reason.EXPLICIT_FALLBACK,),
    )


def record_decision(outcome: AuthorityOutcome, context: TrustedSnapshot,
                    event_id: Ref, ledger_epoch: Ref, sequence: int,
                    timestamp_unix_ms: int) -> CFDecisionRecord:
    """Allowlist projection. This is a decision log, not an execution receipt."""
    expected = evaluate(outcome.request, context, outcome.decision_id,
                        Ref("0" * 32) if outcome.grant is None else outcome.grant.grant_id)
    require(expected == outcome, "Outcome does not belong to this decision snapshot")

    def status(att: AttestationResult | None) -> AttestationStatus:
        return AttestationStatus.NOT_EVALUATED if att is None else att.status

    def freshness(att: AttestationResult | None) -> Freshness:
        if att is None or att.clock_domain != context.clock_domain:
            return Freshness.UNKNOWN
        return att.freshness(context.now)

    local, peer = context.local_attestation, context.peer_attestation
    return CFDecisionRecord(
        event_id=event_id, ledger_epoch=ledger_epoch, event_sequence=sequence,
        timestamp_unix_ms=timestamp_unix_ms, clock_domain=context.clock_domain,
        decision_time=context.now, outcome=outcome,
        peer_device=context.session.local_device_id,
        local_identity_status=context.local_identity, identity_status=context.peer_identity,
        local_attestation_status=status(local), attestation_status=status(peer),
        local_attestation_ref=None if local is None else local.result_ref,
        attestation_ref=None if peer is None else peer.result_ref,
        local_attestation_freshness=freshness(local), attestation_freshness=freshness(peer),
        liveness=context.health.liveness, compromise=context.health.compromise,
        policy=context.policy.reference, enforcement_point=Label("SIMULATION.NONE"),
        enforcement_result=EnforcementResult.NOT_ATTEMPTED,
        build=Label("Cyberforteca.0.3.internal.0.31"),
        local_verifier_version=None if local is None else local.verifier_version,
        verifier_version=None if peer is None else peer.verifier_version,
        recovery_verifier_version=(None if context.recovery is None
                                   else context.recovery.verifier_version),
        recovery_context_ref=None if context.recovery is None else context.recovery.context_id,
    )
