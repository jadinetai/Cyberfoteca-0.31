from dataclasses import FrozenInstanceError, fields, replace
import json
import unittest

from cyberforteca.models import (
    AppPrincipal, AttestationEvidence, AttestationStatus, AuthorityDecision,
    AuthorityOutcome, Capability, CapabilityScope, ChannelStatus,
    CompromiseStatus, DeviceId, DeviceIdentity, Direction, EnforcementResult,
    Freshness, IdentityStatus, Label, Liveness, MAX_INTEGER, Operation,
    PacketMetadata, Reason, Ref, ResourceId, SessionId, SessionStatus,
)
from cyberforteca.serialization import canonical_json, human_log
from cyberforteca.simulation import Policy, PolicyRule, evaluate, record_decision
from tests.fixtures import (
    APP, CLOCK, FIRMWARE, LOCAL, OWNED_EXPORT, OWNED_READ, PEER, POLICY,
    READ, RECOVERY, RESOURCE, SESSION, fixture, recovery_fixture, ref,
)


class BoundaryTests(unittest.TestCase):
    def decide(self, request, context):
        return evaluate(request, context, ref(100), ref(101))

    def assertDenied(self, request, context, reason=None):
        outcome = self.decide(request, context)
        self.assertIs(outcome.decision, AuthorityDecision.DENIED)
        self.assertIsNone(outcome.grant)
        if reason is not None:
            self.assertIn(reason, outcome.reasons)

    def test_01_known_device_does_not_grant_authority(self):
        request, context = fixture(())
        self.assertIs(context.peer_identity, IdentityStatus.VERIFIED)
        self.assertDenied(request, context, Reason.NO_RULE)

    def test_02_acceptable_attestation_does_not_grant_authority(self):
        request, context = fixture(())
        self.assertIs(context.peer_attestation.status, AttestationStatus.ACCEPTABLE)
        self.assertDenied(request, context, Reason.NO_RULE)

    def test_03_known_device_valid_session_unauthorized_app_denied(self):
        request, context = fixture()
        unauthorized = replace(APP, app_id=Label("UNAUTHORIZED.APP"))
        request = replace(request, requesting_app=unauthorized)
        context = replace(context, session=replace(context.session, peer_app=unauthorized))
        self.assertDenied(request, context, Reason.NO_RULE)

    def test_04_authorized_app_gets_exact_capability(self):
        request, context = fixture()
        outcome = self.decide(request, context)
        self.assertIs(outcome.decision, AuthorityDecision.AUTHORIZED)
        self.assertEqual(outcome.grant.scope, READ)
        self.assertEqual(outcome.grant.session_id, SESSION)
        self.assertEqual(outcome.grant.expires_at, 800)
        self.assertEqual(context.session.granted_scope, ())  # no implicit mutation

    def test_05_restriction_requires_explicit_policy_mapping(self):
        request, context = fixture((PolicyRule(Label("owned.read"), APP, OWNED_READ, OWNED_READ),))
        request = replace(request, scope=OWNED_EXPORT)
        self.assertDenied(request, context, Reason.NO_RULE)
        fallback = PolicyRule(Label("owned.export-to-read"), APP, OWNED_EXPORT, OWNED_READ)
        context = replace(context, policy=Policy(POLICY, (fallback,)))
        outcome = self.decide(request, context)
        self.assertIs(outcome.decision, AuthorityDecision.RESTRICTED)
        self.assertEqual(outcome.grant.scope, OWNED_READ)
        self.assertEqual(outcome.request.scope, OWNED_EXPORT)
        self.assertIn(Reason.EXPLICIT_FALLBACK, outcome.reasons)

    def test_06_dangerous_authority_without_fallback_denied(self):
        request, context = fixture()
        for cap, operation in (
            (Capability.MODIFY_REA_FIRMWARE, Operation.MODIFY),
            (Capability.COMMAND_NETRUNNER, Operation.COMMAND),
            (Capability.ISSUE_NEW_CAPABILITIES, Operation.ISSUE),
        ):
            with self.subTest(cap=cap):
                self.assertDenied(replace(request, scope=CapabilityScope(cap, operation, RESOURCE)),
                                  context, Reason.NO_RULE)

    def test_07_recovery_preserves_only_explicit_ownership_scope(self):
        request, context = recovery_fixture()
        outcome = self.decide(request, context)
        self.assertIs(outcome.decision, AuthorityDecision.AUTHORIZED)
        self.assertEqual(outcome.grant.scope, OWNED_READ)
        self.assertEqual(outcome.grant.expires_at, 600)
        for cap, operation in (
            (Capability.MODIFY_REA_FIRMWARE, Operation.MODIFY),
            (Capability.MODIFY_CF_POLICY, Operation.MODIFY),
            (Capability.CREATE_ADMINISTRATOR, Operation.CREATE),
            (Capability.ISSUE_NEW_CAPABILITIES, Operation.ISSUE),
            (Capability.COMMAND_NETRUNNER, Operation.COMMAND),
            (Capability.DELETE_AUDIT_HISTORY, Operation.DELETE),
        ):
            with self.subTest(cap=cap):
                scope = CapabilityScope(cap, operation, RESOURCE)
                self.assertDenied(replace(request, scope=scope), context)
                # Even a mistaken policy rule cannot exceed the verified recovery ceiling.
                rule = PolicyRule(Label("mistaken.recovery"), APP, scope, scope, RECOVERY)
                self.assertDenied(replace(request, scope=scope),
                                  replace(context, policy=Policy(POLICY, (rule,))),
                                  Reason.RECOVERY_SCOPE)
                with self.assertRaises(ValueError):
                    replace(context.recovery, allowed_scope=(scope,))

    def test_08_app_identity_is_distinct_from_device(self):
        self.assertNotEqual(APP.instance_id, PEER)
        with self.assertRaises(ValueError):
            replace(APP, device_id=APP.instance_id)
        request, context = fixture()
        altered = replace(APP, measurement=replace(APP.measurement, value="c" * 64))
        self.assertDenied(replace(request, requesting_app=altered), context,
                          Reason.APP_BINDING_MISMATCH)

    def test_09_session_identity_is_distinct_from_counters(self):
        request, context = fixture()
        advanced = replace(context.channel, tx_counter=10, rx_counter=20)
        self.assertEqual(advanced.session_id, SESSION)
        self.assertEqual(self.decide(request, context),
                         self.decide(request, replace(context, channel=advanced)))
        with self.assertRaises(ValueError):
            replace(context.channel, session_id=20)

    def test_10_audit_explains_all_three_decisions_without_secrets(self):
        cases = [fixture(), fixture(())]
        request, context = fixture((PolicyRule(Label("fallback"), APP, OWNED_EXPORT, OWNED_READ),))
        cases.append((replace(request, scope=OWNED_EXPORT), context))
        states = set()
        for n, (request, context) in enumerate(cases, 1):
            outcome = self.decide(request, context)
            record = record_decision(outcome, context, ref(n), ref(999), n, 1000000)
            serialized = canonical_json(record)
            body = json.loads(serialized)["value"]
            self.assertEqual(body["outcome"]["decision"], outcome.decision.value)
            self.assertTrue(body["outcome"]["reasons"])
            self.assertEqual(body["enforcement_result"], "NOT_ATTEMPTED")
            self.assertIn(outcome.decision.value, human_log(record))
            states.add(outcome.decision)
            keys = set()
            def visit(value):
                if isinstance(value, dict):
                    keys.update(value)
                    for child in value.values():
                        visit(child)
                elif isinstance(value, list):
                    for child in value:
                        visit(child)
            visit(body)
            self.assertFalse(keys & {"password", "private_key", "session_key", "key",
                                     "recovery_key", "biometric", "telemetry", "payload",
                                     "credential_ref", "owner_ref", "evidence_bytes"})
        self.assertEqual(states, set(AuthorityDecision))

    def test_11_unknown_identity_denied_without_malicious_classification(self):
        request, context = fixture()
        context = replace(context, peer_identity=IdentityStatus.UNKNOWN)
        self.assertDenied(request, context, Reason.IDENTITY_UNVERIFIED)
        self.assertIs(context.health.compromise, CompromiseStatus.UNKNOWN)

    def test_12_liveness_independent_from_compromise(self):
        request, context = fixture()
        for live in (Liveness.UNKNOWN, Liveness.STALE, Liveness.EXPIRED):
            health = replace(context.health, liveness=live)
            self.assertIs(health.compromise, CompromiseStatus.UNKNOWN)
            self.assertDenied(request, replace(context, health=health), Reason.LIVENESS_REQUIRED)

    def test_evidence_cannot_be_substituted_for_result(self):
        request, context = fixture()
        evidence = AttestationEvidence(ref(1), PEER, ref(2), SESSION, Label("claim.only"))
        with self.assertRaises(ValueError):
            replace(context, peer_attestation=evidence)
        self.assertDenied(request, replace(context, peer_attestation=None),
                          Reason.ATTESTATION_UNACCEPTABLE)

    def test_attestation_subject_session_challenge_and_policy_binding(self):
        request, context = fixture()
        mutations = {"device_id": LOCAL, "session_id": SessionId("9" * 32),
                     "challenge_ref": ref(555), "result_ref": ref(556),
                     "clock_domain": ref(557),
                     "appraisal_policy": replace(POLICY.digest, value="f" * 64),
                     "status": AttestationStatus.REJECTED}
        for field, value in mutations.items():
            with self.subTest(field=field):
                self.assertDenied(request, replace(context, peer_attestation=
                                  replace(context.peer_attestation, **{field: value})),
                                  Reason.ATTESTATION_UNACCEPTABLE)

    def test_attestation_freshness_is_half_open_and_not_future(self):
        request, context = fixture()
        self.assertDenied(request, replace(context, now=800), Reason.ATTESTATION_NOT_FRESH)
        future = replace(context.peer_attestation, evaluated_at=201)
        self.assertDenied(request, replace(context, peer_attestation=future),
                          Reason.ATTESTATION_NOT_FRESH)
        self.assertIs(future.freshness(200), Freshness.NOT_YET_VALID)

    def test_session_expiration_revocation_and_clock_domain(self):
        request, context = fixture()
        for now in (99, 900):
            self.assertDenied(request, replace(context, now=now), Reason.SESSION_INVALID)
        for status in (SessionStatus.EXPIRED, SessionStatus.REVOKED):
            self.assertDenied(request, replace(context, session=
                              replace(context.session, status=status)), Reason.SESSION_INVALID)
        self.assertDenied(request, replace(context, clock_domain=ref(666)), Reason.SESSION_INVALID)

    def test_old_request_does_not_transfer_to_new_session(self):
        request, context = fixture()
        newer = replace(context.session, session_id=SessionId("7" * 32), granted_scope=())
        self.assertDenied(request, replace(context, session=newer), Reason.SESSION_INVALID)

    def test_channel_session_direction_and_status(self):
        request, context = fixture()
        for channel in (replace(context.channel, session_id=SessionId("8" * 32)),
                        replace(context.channel, direction=Direction.LOCAL_TO_PEER),
                        replace(context.channel, status=ChannelStatus.CLOSED),
                        replace(context.channel, channel_id=ref(888))):
            self.assertDenied(request, replace(context, channel=channel), Reason.CHANNEL_INVALID)

    def test_recovery_is_session_app_owner_resource_and_time_bound(self):
        request, context = recovery_fixture()
        for changes in ({"session_id": SessionId("8" * 32)},
                        {"identity_status": IdentityStatus.UNKNOWN},
                        {"expires_at": 199}, {"verified_at": 201},
                        {"app": replace(APP, version=Label("another"))},
                        {"clock_domain": ref(987)}):
            self.assertDenied(request, replace(context, recovery=
                              replace(context.recovery, **changes)), Reason.RECOVERY_INVALID)
        self.assertDenied(replace(request, recovery_id=None), context, Reason.RECOVERY_INVALID)
        other = replace(OWNED_READ, resource=ResourceId("9" * 32))
        other_rule = PolicyRule(Label("other.resource"), APP, other, other, RECOVERY)
        self.assertDenied(replace(request, scope=other),
                          replace(context, policy=Policy(POLICY, (other_rule,))),
                          Reason.RECOVERY_SCOPE)

    def test_recovery_does_not_require_normal_user_credential(self):
        request, context = recovery_fixture()
        self.assertIs(self.decide(request, context).decision, AuthorityDecision.AUTHORIZED)
        self.assertNotIn("normal_credential", {f.name for f in fields(context.recovery)})

    def test_empty_recovery_scope_has_no_authority(self):
        request, context = recovery_fixture()
        self.assertDenied(request, replace(context, recovery=
                          replace(context.recovery, allowed_scope=())), Reason.RECOVERY_SCOPE)

    def test_policy_version_and_digest_both_must_match(self):
        request, context = fixture()
        for policy in (replace(POLICY, version=Label("next")),
                       replace(POLICY, digest=replace(POLICY.digest, value="c" * 64))):
            self.assertDenied(request, replace(context, policy=replace(context.policy,
                              reference=policy)), Reason.POLICY_MISMATCH)

    def test_no_ambiguous_policy_or_cross_resource_fallback(self):
        _, context = fixture()
        with self.assertRaises(ValueError):
            replace(context.policy, rules=context.policy.rules * 2)
        with self.assertRaises(ValueError):
            PolicyRule(Label("bad"), APP, OWNED_EXPORT,
                       replace(OWNED_READ, resource=ResourceId("a" * 32)))

    def test_contradictory_decision_grant_rejected(self):
        request, context = fixture()
        outcome = self.decide(request, context)
        for changes in ({"decision": AuthorityDecision.DENIED},
                        {"grant": None}, {"matched_rules": ()},
                        {"decision": AuthorityDecision.RESTRICTED},
                        {"grant": replace(outcome.grant, session_id=SessionId("8" * 32))}):
            with self.assertRaises(ValueError):
                replace(outcome, **changes)
        with self.assertRaises(ValueError):
            replace(outcome.grant, scope=FIRMWARE, recovery_id=RECOVERY)

    def test_invalid_scalar_and_mutable_container_inputs_rejected(self):
        request, context = fixture()
        for value in (-1, True, 1.0, "1", MAX_INTEGER + 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                replace(context.channel, rx_counter=value)
        with self.assertRaises(ValueError):
            replace(context.session, granted_scope=[])
        with self.assertRaises(ValueError):
            replace(context, peer_identity="VERIFIED")
        with self.assertRaises(ValueError):
            replace(context.session, expires_at=100)
        with self.assertRaises(FrozenInstanceError):
            request.scope = FIRMWARE

    def test_capability_operation_mismatch_and_app_device_mismatch_rejected(self):
        request, context = fixture()
        with self.assertRaises(ValueError):
            replace(READ, operation=Operation.MODIFY)
        with self.assertRaises(ValueError):
            replace(context.session, peer_app=replace(APP, device_id=LOCAL))
        with self.assertRaises(ValueError):
            replace(request, requesting_device=LOCAL)

    def test_json_has_fixed_order_no_floats_and_schema_discriminator(self):
        self.assertEqual(canonical_json(ref(1)),
                         b'{"schema":"CF031","type":"Ref","value":"00000000000000000000000000000001"}')
        request, context = fixture()
        encoded = canonical_json(context.session)
        self.assertEqual(encoded, canonical_json(replace(context.session)))
        self.assertEqual(json.loads(encoded)["schema"], "CF031")
        for invalid in ({"secret": "value"}, float("nan"), b"secret"):
            with self.assertRaises(TypeError):
                canonical_json(invalid)

    def test_packet_metadata_binds_session_counter_and_direction(self):
        packet = PacketMetadata(Label("CF031"), SESSION, PEER, LOCAL, ref(31),
                                1, Direction.PEER_TO_LOCAL, 1, Label("REQUEST"))
        original = canonical_json(packet)
        for changes in ({"session_id": SessionId("9" * 32)}, {"packet_counter": 2},
                        {"direction": Direction.LOCAL_TO_PEER}, {"key_epoch": 2},
                        {"message_type": Label("HEARTBEAT")}, {"channel_id": ref(90)},
                        {"protocol_version": Label("CF032")},
                        {"origin": DeviceId("a" * 32)},
                        {"destination": DeviceId("b" * 32)}):
            self.assertNotEqual(original, canonical_json(replace(packet, **changes)))
        with self.assertRaises(ValueError):
            replace(packet, packet_counter=0)

    def test_hmai_has_no_implicit_policy_privilege(self):
        request, context = fixture()
        hmai = replace(APP, app_id=Label("MOSKO.HMAI"))
        request = replace(request, requesting_app=hmai)
        context = replace(context, session=replace(context.session, peer_app=hmai))
        self.assertDenied(request, context, Reason.NO_RULE)

    def test_denied_audit_cannot_claim_successful_execution(self):
        request, context = fixture(())
        record = record_decision(self.decide(request, context), context,
                                 ref(1), ref(2), 1, 1000)
        with self.assertRaises(ValueError):
            replace(record, enforcement_result=EnforcementResult.EXECUTED)
        with self.assertRaises(TypeError):
            replace(record, payload="secret")

    def test_compromise_is_separate_policy_hold(self):
        request, context = fixture()
        health = replace(context.health, compromise=CompromiseStatus.CONFIRMED)
        self.assertIs(health.liveness, Liveness.LIVE)
        self.assertDenied(request, replace(context, health=health), Reason.COMPROMISE_HOLD)

    def test_audit_rejects_outcome_from_different_snapshot(self):
        request, context = fixture()
        outcome = self.decide(request, context)
        with self.assertRaises(ValueError):
            record_decision(outcome, replace(context, peer_identity=IdentityStatus.UNKNOWN),
                            ref(1), ref(2), 1, 1000)


if __name__ == "__main__":
    unittest.main()
