"""Future adapter contracts. No implementations or successful stub verifiers."""

from typing import Protocol

from .models import (
    AppPrincipal, AttestationEvidence, AttestationResult, CapabilityGrant,
    CapabilityRequest, CFDecisionRecord, DeviceIdentity, DeviceId,
    EnforcementResult, IdentityStatus, KeyReference, PacketMetadata,
    RecoveryContext, RecoveryPrincipal, Ref, SessionId,
)


class IdentityVerifier(Protocol):
    def verify(self, identity: DeviceIdentity, proof_ref: Ref,
               challenge_ref: Ref) -> IdentityStatus: ...


class AttestationVerifier(Protocol):
    def verify(self, evidence: AttestationEvidence, expected_device: DeviceId,
               expected_session: SessionId, expected_challenge: Ref) -> AttestationResult: ...


class RecoveryVerifier(Protocol):
    def verify(self, principal: RecoveryPrincipal, evidence_ref: Ref,
               session_id: SessionId, app: AppPrincipal) -> RecoveryContext: ...


class EvidenceCollector(Protocol):
    # HMAI implementation can acquire evidence, never mint a result or grant.
    def collect(self, challenge_ref: Ref) -> Ref: ...


class ProtectedTransport(Protocol):
    # Backend owns keys, nonce allocation, authentication, and replay commit.
    def seal(self, key: KeyReference, metadata: PacketMetadata,
             plaintext: bytes) -> bytes: ...

    def open(self, key: KeyReference, expected_session: SessionId,
             packet: bytes) -> tuple[PacketMetadata, bytes]: ...


class EnforcementPoint(Protocol):
    # Must resolve grant from issuer's protected registry and recheck current
    # session/policy/revocation/resource state. Never trust caller-supplied grants.
    def enforce(self, grant_ref: Ref, request: CapabilityRequest) -> EnforcementResult: ...


class AuditSink(Protocol):
    def append(self, record: CFDecisionRecord) -> None: ...
