"""Synthetic verified-state fixtures. These do not verify any real evidence."""

from dataclasses import replace

from cyberforteca.models import (
    AppInstanceId, AppPrincipal, AttestationResult, AttestationStatus,
    Capability, CapabilityRequest, CapabilityScope, ChannelState, DeviceId,
    DeviceIdentity, Digest, Direction, IdentityStatus, KeyReference, Label,
    Liveness, Operation, PolicyRef, RecoveryContext, RecoveryId,
    RecoveryPrincipal, Ref, ResourceId, RootKind, SessionContext,
    SessionHealth, SessionId,
)
from cyberforteca.simulation import Policy, PolicyRule, TrustedSnapshot


def ref(n: int) -> Ref:
    return Ref(f"{n:032x}")


LOCAL = DeviceId("1" * 32)
PEER = DeviceId("2" * 32)
SESSION = SessionId("3" * 32)
RESOURCE = ResourceId("4" * 32)
RECOVERY = RecoveryId("5" * 32)
CLOCK = ref(10)
POLICY = PolicyRef(Label("CF031.test-policy.v1"), Digest("a" * 64))
APP = AppPrincipal(AppInstanceId("6" * 32), Label("MOSKO.REA.READER"),
                   Label("MOSKO"), Digest("b" * 64), Label("test.1"),
                   PEER, Label("PLATFORM.INDEPENDENT.TEST"))
READ = CapabilityScope(Capability.READ_REA_TELEMETRY, Operation.READ, RESOURCE)
FIRMWARE = CapabilityScope(Capability.MODIFY_REA_FIRMWARE, Operation.MODIFY, RESOURCE)
OWNED_READ = CapabilityScope(Capability.READ_OWNED_DATA, Operation.READ, RESOURCE)
OWNED_EXPORT = CapabilityScope(Capability.EXPORT_OWNED_DATA, Operation.EXPORT, RESOURCE)


def fixture(rules: tuple[PolicyRule, ...] | None = None) -> tuple[CapabilityRequest, TrustedSnapshot]:
    if rules is None:
        rules = (PolicyRule(Label("rea.read"), APP, READ, READ),)
    local = AttestationResult(ref(20), ref(21), LOCAL, SESSION, ref(22),
                              AttestationStatus.ACCEPTABLE, Label("SIMULATED"),
                              Label("fixture.1"), POLICY.digest, CLOCK, 50, 800)
    peer = replace(local, result_ref=ref(23), evidence_ref=ref(24),
                   device_id=PEER, challenge_ref=ref(25))
    session = SessionContext(SESSION, LOCAL, PEER, local.result_ref, peer.result_ref,
                             None, APP, KeyReference(ref(26), 1), CLOCK, 100, 900,
                             POLICY)
    context = TrustedSnapshot(
        DeviceIdentity(LOCAL, RootKind.SIMULATED, ref(27), ref(28)),
        DeviceIdentity(PEER, RootKind.SIMULATED, ref(29), ref(30)),
        IdentityStatus.VERIFIED, IdentityStatus.VERIFIED, local, peer,
        ref(22), ref(25), session,
        ChannelState(SESSION, ref(31), Direction.PEER_TO_LOCAL),
        SessionHealth(SESSION, Liveness.LIVE), Policy(POLICY, rules), 200, CLOCK,
    )
    request = CapabilityRequest(ref(32), PEER, APP, SESSION, ref(31), READ)
    return request, context


def recovery_fixture() -> tuple[CapabilityRequest, TrustedSnapshot]:
    rule = PolicyRule(Label("recovery.owned.read"), APP, OWNED_READ, OWNED_READ, RECOVERY)
    request, context = fixture((rule,))
    recovery = RecoveryContext(
        ref(40), RecoveryPrincipal(RECOVERY, ref(41), ref(42)), SESSION, APP,
        ref(43), IdentityStatus.VERIFIED, Label("recovery.fixture.1"), CLOCK,
        150, 600, POLICY, (OWNED_READ,), ref(44),
    )
    return (replace(request, scope=OWNED_READ, recovery_id=RECOVERY),
            replace(context, recovery=recovery))
