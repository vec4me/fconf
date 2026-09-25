"""Regression checks for declarative configuration boundaries."""

from __future__ import annotations

import json
import pathlib
from unittest import mock
import src.cloudflare as cloudflare
import src.reconciliation as reconciliation
import src.regery as regery
import src.telnyx as telnyx
import src.zone_file as zone_file


def keepPlanReadOnly() -> None:
    """Verify plan mode invokes no mutation callback."""
    desired: reconciliation.ConfigTree = {}
    reconciliation.setValue(desired, ("records", "new"), "desired")
    executor = mock.Mock(return_value={"completed_steps": ["push"], "error": None})
    reconciliation.runValues({}, desired, {}, {}, executor, apply=False)
    executor.assert_not_called()


def keepPlanDeterministic() -> None:
    """Verify resource paths have stable lexical ordering."""
    desired: reconciliation.ConfigTree = {}
    reconciliation.setValue(desired, ("records", "z"), "last")
    reconciliation.setValue(desired, ("records", "a"), "first")
    plan = reconciliation.ReconciliationPlan({}, desired, {}, {})
    assert [operation["path"] for operation in plan] == [("records", "a"), ("records", "z")]


def keepPlanSerializable() -> None:
    """Verify plans contain values rather than mutation callbacks."""
    desired: reconciliation.ConfigTree = {}
    reconciliation.setValue(desired, ("records", "www"), {"type": "CNAME"})
    encoded = json.dumps(reconciliation.ReconciliationPlan({}, desired, {}, {}), sort_keys=True)
    assert '"action": "push"' in encoded
    assert '"type": "CNAME"' in encoded


def replaceByRemovingBeforePushing() -> None:
    """Verify replacement is delegated as one provider-owned transition."""
    observed: reconciliation.ConfigTree = {}
    desired: reconciliation.ConfigTree = {}
    reconciliation.setValue(observed, ("records", "same"), "old")
    reconciliation.setValue(desired, ("records", "same"), "new")
    plan = reconciliation.ReconciliationPlan(observed, desired, {}, {})
    executor = mock.Mock(return_value={"completed_steps": ["remove", "push"], "error": None})
    outcomes = reconciliation.executeValues(plan, executor)
    executor.assert_called_once_with(plan[0])
    assert outcomes[0]["completed_steps"] == ["remove", "push"]


def keepUnknownBoundariesUnmanaged() -> None:
    """Verify unknown observation cannot produce a mutation."""
    desired: reconciliation.ConfigTree = {}
    reconciliation.setValue(desired, ("zones", "example.com", "records", "www"), "desired")
    unknowns = {("zones", "example.com", "records"): "authentication failed"}
    plan = reconciliation.ReconciliationPlan({}, desired, {}, unknowns)
    assert [operation["action"] for operation in plan] == ["unknown"]
    executor = mock.Mock(return_value={"completed_steps": [], "error": None})
    reconciliation.executeValues(plan, executor)
    executor.assert_not_called()


def respectPlanDependencies() -> None:
    """Verify dependencies override incidental lexical ordering."""
    desired: reconciliation.ConfigTree = {}
    first = ("resources", "z-prerequisite")
    second = ("resources", "a-dependent")
    reconciliation.setValue(desired, first, "first")
    reconciliation.setValue(desired, second, "second")
    plan = reconciliation.ReconciliationPlan({}, desired, {second: (first,)}, {})
    assert [operation["path"] for operation in plan] == [first, second]


def skipFailedDependents() -> None:
    """Verify operations depending on failure are explicitly skipped."""
    desired: reconciliation.ConfigTree = {}
    prerequisite = ("resources", "prerequisite")
    dependent = ("resources", "dependent")
    reconciliation.setValue(desired, prerequisite, "first")
    reconciliation.setValue(desired, dependent, "second")
    plan = reconciliation.ReconciliationPlan({}, desired, {dependent: (prerequisite,)}, {})

    def execute(operation: dict[str, object]) -> reconciliation.TransitionResult:
        if operation["path"] == prerequisite:
            return {"completed_steps": [], "error": "prerequisite failed"}
        return {"completed_steps": ["push"], "error": None}

    outcomes = reconciliation.executeValues(plan, execute)
    assert [outcome["status"] for outcome in outcomes] == ["failed", "skipped"]


def requireObservedConvergence() -> None:
    """Verify convergence succeeds only when the second plan is empty."""
    desired: reconciliation.ConfigTree = {}
    reconciliation.setValue(desired, ("records", "same"), "value")
    reconciliation.verifyConvergence(desired, desired, {}, {})
    try:
        reconciliation.verifyConvergence({}, desired, {}, {})
    except RuntimeError as error:
        assert str(error) == "provider did not converge after applying the plan"
    else:
        raise AssertionError("non-converged state was accepted")


def letLocalSettingsOverrideIncludedDefaults() -> None:
    """Verify declarations after an include replace included values."""
    path = pathlib.Path(__file__).parent.parent / "examples/" / "hiroshimajobnavi.com.zone"
    configuration = zone_file.readAnnotations(path)
    assert configuration["dnssec"] == "disabled"
    assert configuration["settings"]["ssl"] == "full"


def compileCloudflareDesiredStateBeforeObservation() -> None:
    """Verify desired state is complete before provider identities are available."""
    directory = pathlib.Path(__file__).parent.parent / "examples/"
    configuration = zone_file.readAnnotations(directory / "clarkn.co.jp.zone")
    desired, operations, zones, _destinations, _settingids = cloudflare.compileDesired(
        directory,
        {"clarkn.co.jp": configuration},
    )
    assert all(not any(callable(value) for value in resource.values()) for resource in operations.values())
    assert "id" not in zones["clarkn.co.jp"]
    worker = reconciliation.Node(desired, ("worker_domains", "clarkn.co.jp"))
    assert worker is not None
    assert "zone_id" not in worker["value"]
    cloudflare.bindZoneIdentities(zones, [{"id": "zone-id", "name": "clarkn.co.jp"}])
    setting = ("zones", "clarkn.co.jp", "settings", "ssl")
    with mock.patch.object(cloudflare, "patch") as patch:
        cloudflare.pushResource({}, operations[setting], reconciliation.Node(desired, setting)["value"], zones)
    patch.assert_called_once_with({}, "zones/zone-id/settings/ssl", reconciliation.Node(desired, setting)["value"])


def identifyUnreferencedCloudflareDeployments() -> None:
    """Verify deployment diagnostics derive references from every declaration kind."""
    configurations = {
        "example.com": {
            "worker_domains": ["website:example.com"],
            "routes": ["api.example.com/*=api"],
            "page_domains": ["site:www.example.com"],
        },
    }
    workers, pages = cloudflare.ReferencedDeployments(configurations)
    assert workers == {"website", "api"}
    assert pages == {"site"}


def leaveUndeclaredTelnyxResourcesUntouched() -> None:
    """Verify Telnyx observation retains only exact managed identities."""
    responses: dict[str, list[dict[str, object]]] = {
        "phone_numbers": [
            {"id": "managed-number", "phone_number": "+17752000767"},
            {"id": "foreign-number", "phone_number": "+17752000768"},
        ],
        "messaging_profiles": [
            {"id": "managed-message", "name": "msg-+17752000767"},
            {"id": "foreign-message", "name": "msg-+17752000768"},
        ],
        "outbound_voice_profiles": [
            {"id": "managed-voice", "name": "voice-+17752000767"},
            {"id": "foreign-voice", "name": "voice-+17752000768"},
        ],
        "credential_connections": [
            {"id": "managed-sip", "connection_name": "sip-+17752000767"},
            {"id": "foreign-sip", "connection_name": "sip-+17752000768"},
        ],
    }
    details = {
        "messaging_profiles/managed-message": responses["messaging_profiles"][0],
        "outbound_voice_profiles/managed-voice": responses["outbound_voice_profiles"][0],
        "credential_connections/managed-sip": responses["credential_connections"][0],
        "phone_numbers/managed-number": responses["phone_numbers"][0],
        "phone_numbers/managed-number/messaging": {"messaging_profile_id": "managed-message"},
        "phone_numbers/managed-number/voice": {"connection_id": "managed-sip"},
    }
    with mock.patch.object(telnyx, "paginate", side_effect=lambda _client, endpoint: responses[endpoint]), mock.patch.object(telnyx, "sendRequest", side_effect=lambda _client, _method, endpoint: details[endpoint]):
        observed = telnyx.fetchState({}, {
            "+17752000767": {
                "messaging_profile_name": "msg-+17752000767",
                "outbound_voice_profile_name": "voice-+17752000767",
                "credential_connection_name": "sip-+17752000767",
            },
        })
    assert set(observed["phone_numbers"]) == {"+17752000767"}
    assert [profile["id"] for profile in observed["messaging_profiles"]] == ["managed-message"]
    assert [profile["id"] for profile in observed["voice_profiles"]] == ["managed-voice"]
    assert [profile["id"] for profile in observed["credential_connections"]] == ["managed-sip"]
    assert observed["phone_number_details"]["+17752000767"]["voice"]["connection_id"] == "managed-sip"


def keepRegeryPlanFreeOfMutationCallbacks() -> None:
    """Verify Regery desired state contains values and delegates application once."""
    desired: reconciliation.ConfigTree = {}
    contacts = {"registrant": "contact"}
    regery.declareDomain(desired, "example.com", autorenew=True, nameservers=["ns2.example", "ns1.example"], contacts=contacts)
    executor = mock.Mock(return_value={"completed_steps": ["push"], "error": None})
    reconciliation.runValues({}, desired, {}, {}, executor, apply=False)
    executor.assert_not_called()
    plan = reconciliation.ReconciliationPlan({}, desired, {}, {})
    outcomes = reconciliation.executeValues(plan, executor)
    executor.assert_called_once_with(plan[0])
    assert outcomes[0]["completed_steps"] == ["push"]


def keepTelnyxPlanFreeOfMutationCallbacks() -> None:
    """Verify Telnyx delegates its whole-number transition to one executor."""
    directory = pathlib.Path(__file__).parent.parent / "examples/"
    configuration = json.loads((directory / "telnyx.json").read_text(encoding="utf-8"))
    numberconfiguration = configuration["numbers"]["+17752000767"]
    voice = {**configuration["voice_settings"], "connection_id": "connection-id", "call_forwarding": numberconfiguration["call_forwarding"]}
    connection = {"id": "connection-id", "connection_name": numberconfiguration["credential_connection_name"], "user_name": numberconfiguration["sip_user_name"], **configuration["credential_connection"]}
    connection["outbound"] = {**connection["outbound"], "ani_override": "+17752000767", "outbound_voice_profile_id": "voice-id"}
    profiles: telnyx.TelnyxData = {
        "phone_numbers": {"+17752000767": {"id": "number-id"}},
        "messaging_profiles": [{"id": "message-id", "name": numberconfiguration["messaging_profile_name"], **configuration["messaging_profile"]}],
        "voice_profiles": [{"id": "voice-id", "name": numberconfiguration["outbound_voice_profile_name"], **configuration["outbound_voice_profile"]}],
        "credential_connections": [connection],
        "phone_number_details": {"+17752000767": {"number": configuration["number_settings"], "messaging": {"messaging_profile_id": "message-id"}, "voice": voice}},
    }
    observed, desired, _observedresources, _desiredresources, dependencies = telnyx.ConfigurationTrees(profiles, configuration)
    assert reconciliation.ReconciliationPlan(observed, desired, dependencies, {}) == []


def planTelnyxCleanupAsExplicitRemovals() -> None:
    """Verify stale Telnyx resources become ordinary planned removals."""
    directory = pathlib.Path(__file__).parent.parent / "examples/"
    configuration = json.loads((directory / "telnyx.json").read_text(encoding="utf-8"))
    number = "+17752000767"
    numberconfiguration = configuration["numbers"][number]
    voice = {**configuration["voice_settings"], "connection_id": "connection-id", "call_forwarding": numberconfiguration["call_forwarding"]}
    connection = {"id": "connection-id", "connection_name": numberconfiguration["credential_connection_name"], "user_name": numberconfiguration["sip_user_name"], **configuration["credential_connection"]}
    connection["outbound"] = {**connection["outbound"], "ani_override": number, "outbound_voice_profile_id": "voice-id"}
    profiles: telnyx.TelnyxData = {
        "phone_numbers": {number: {"id": "number-id"}},
        "messaging_profiles": [{"id": "message-id", "name": numberconfiguration["messaging_profile_name"], **configuration["messaging_profile"]}],
        "voice_profiles": [{"id": "voice-id", "name": numberconfiguration["outbound_voice_profile_name"], **configuration["outbound_voice_profile"]}],
        "credential_connections": [connection],
        "phone_number_details": {number: {"number": configuration["number_settings"], "messaging": {"messaging_profile_id": "message-id"}, "voice": voice}},
        "cleanup_resources": [{"kind": "messaging_profiles", "id": "orphan-id", "name": "msg-old"}],
    }
    observed, desired, _observedresources, _desiredresources, dependencies = telnyx.ConfigurationTrees(profiles, configuration)
    plan = reconciliation.ReconciliationPlan(observed, desired, dependencies, {})
    assert [(operation["action"], operation["path"]) for operation in plan] == [("remove", ("cleanup", "messaging_profiles", "orphan-id"))]


def reportPartialCloudflareReplacementFailure() -> None:
    """Verify a failed create preserves the preceding successful removal."""
    path: reconciliation.Path = ("zones", "example.com", "routes", "example.com/*")
    observed: cloudflare.Resources = {path: {"kind": "route", "zone": "example.com", "route_id": "route-id"}}
    desired: cloudflare.Resources = {path: {"kind": "route", "zone": "example.com", "route_id": None}}
    operation = {"action": "replace", "path": path, "after": {"pattern": "example.com/*"}}
    zones: dict[str, cloudflare.Zone] = {"example.com": {"id": "zone-id", "name": "example.com"}}
    with mock.patch.object(cloudflare, "removeResource") as remove, mock.patch.object(cloudflare, "pushResource", side_effect=RuntimeError("create failed")):
        result = cloudflare.execute({}, operation, observed, desired, zones)
    remove.assert_called_once()
    assert result == {"completed_steps": ["remove"], "error": "create failed"}


def replaceCnameRecordInPlace() -> None:
    """Verify changing a CNAME target preserves identity and performs one provider mutation."""
    zone: cloudflare.Zone = {"id": "zone-id", "name": "example.com"}
    observed: reconciliation.ConfigTree = {}
    desired: reconciliation.ConfigTree = {}
    observedresources: cloudflare.Resources = {}
    desiredresources: cloudflare.Resources = {}
    cloudflare.makeRecord(observed, observedresources, zone, remotedata={
        "id": "record-id", "name": "www.example.com", "type": "CNAME", "content": "old.example.net",
        "proxied": True, "ttl": 1, "comment": None, "tags": [], "settings": {"flatten_cname": False},
    })
    cloudflare.makeRecord(desired, desiredresources, zone, "www", "CNAME", "new.example.net", proxied=True, ttl=1)
    plan = reconciliation.ReconciliationPlan(observed, desired, {}, {})
    assert len(plan) == 1
    assert plan[0]["action"] == "replace"
    with mock.patch.object(cloudflare, "put") as put:
        result = cloudflare.execute({}, plan[0], observedresources, desiredresources, {"example.com": zone})
    put.assert_called_once_with({}, "zones/zone-id/dns_records/record-id", plan[0]["after"])
    assert result == {"completed_steps": ["replace"], "error": None}


def projectOnlyDeclaredTelnyxFields() -> None:
    """Verify Telnyx normalization excludes provider-owned response metadata."""
    source = {"name": "profile", "webhook": {"url": "https://example.com", "status": "ready"}, "created_at": "ignored"}
    template = {"name": "", "webhook": {"url": ""}}
    assert telnyx.Project(source, template) == {"name": "profile", "webhook": {"url": "https://example.com"}}
    try:
        telnyx.Project({}, {"required": ""})
    except ValueError as error:
        assert str(error) == "Telnyx observation missing declared field: required"
    else:
        raise AssertionError("missing Telnyx field was accepted")


def rejectMissingProviderCredentials() -> None:
    """Verify provider clients cannot represent absent credentials."""
    with mock.patch.object(cloudflare.os, "getenv", return_value=None):
        try:
            cloudflare.initializeClient()
        except ValueError as error:
            assert str(error) == "CLOUDFLARE_API_TOKEN is required"
        else:
            raise AssertionError("missing Cloudflare credentials were accepted")
    with mock.patch.object(telnyx.os, "getenv", return_value=None):
        try:
            telnyx.initializeClient()
        except ValueError as error:
            assert str(error) == "TELNYX_API_KEY is required"
        else:
            raise AssertionError("missing Telnyx credentials were accepted")
    with mock.patch.object(regery.os, "getenv", return_value=None):
        try:
            regery.initializeClient()
        except ValueError as error:
            assert str(error) == "REGERY_API_KEY is required"
        else:
            raise AssertionError("missing Regery credentials were accepted")


def observeEveryDeclaredCloudflareSetting() -> None:
    """Verify declared settings remain observed regardless of editability or bulk-list omission."""
    remote: reconciliation.ConfigTree = {}
    resources: cloudflare.Resources = {}
    zone: cloudflare.Zone = {
        "id": "zone-id",
        "name": "example.com",
        "settings": {
            "advanced_ddos": {"id": "advanced_ddos", "value": "on", "editable": False},
        },
    }
    missing = {"id": "origin_max_http_version", "value": "1", "editable": True}
    with mock.patch.object(cloudflare, "get", return_value=missing) as get, mock.patch.object(cloudflare, "getRedirectRules", return_value=None):
        cloudflare.fetchZoneSettings({}, remote, resources, zone, {"advanced_ddos", "origin_max_http_version"})
    assert reconciliation.Node(remote, ("zones", "example.com", "settings", "advanced_ddos"))["value"] == {"id": "advanced_ddos", "value": "on"}
    assert reconciliation.Node(remote, ("zones", "example.com", "settings", "origin_max_http_version"))["value"] == {"id": "origin_max_http_version", "value": "1"}
    get.assert_called_once_with({}, "zones/zone-id/settings/origin_max_http_version")


def leaveProviderOwnedDnsRecordsUnmanaged() -> None:
    """Verify read-only provider-generated DNS records never enter the mutation plan."""
    record = {
        "name": "media.example.com",
        "type": "CNAME",
        "content": "public.r2.dev",
        "meta": {"r2_bucket": "bucket-id", "read_only": True},
    }
    assert cloudflare.ManagedRecord(record)


def preserveExplicitEmailForwardingSource() -> None:
    """Verify an explicit source mailbox remains part of the desired resource identity."""
    directory = pathlib.Path(__file__).parent.parent / "examples/"
    configurations = {"tattoocollectivereno.com": zone_file.readAnnotations(directory / "tattoocollectivereno.com.zone")}
    desired, resources, _zones, destinations, _settingids = cloudflare.compileDesired(directory, configurations)
    path = ("zones", "tattoocollectivereno.com", "email_routing_rules", "ink@tattoocollectivereno.com")
    assert reconciliation.Node(desired, path)["value"] == {
        "enabled": True,
        "actions": [{"type": "forward", "value": ["tattoocollectivereno@gmail.com"]}],
        "matchers": [{"type": "literal", "field": "to", "value": "ink@tattoocollectivereno.com"}],
    }
    assert resources[path]["push_after"] == (("email routing destinations", "tattoocollectivereno@gmail.com"),)
    assert destinations == {"tattoocollectivereno@gmail.com"}


def protectEveryEmailRuleWhenObservationFails() -> None:
    """Verify failed Email Routing observation protects every managed rule kind."""
    zones: dict[str, cloudflare.Zone] = {
        "zone-id": {
            "name": "example.com",
            "unavailable": {"email routing": "authentication failed"},
        },
    }
    unknowns = cloudflare.Unknowns(zones)
    assert unknowns == {
        ("zones", "example.com", "email_routing_catch_all"): "authentication failed",
        ("zones", "example.com", "email_routing_rules"): "authentication failed",
    }


def preserveCentralEmailForwardingChain() -> None:
    """Verify default-forwarding zones explicitly route through the je.gy hub."""
    directory = pathlib.Path(__file__).parent.parent / "examples/"
    zones = {
        "2204355.com",
        "hironavi.com",
        "leetforms.com",
        "notatel.com",
        "pyusoft.com",
        "roteni.com",
        "stripemerchant.com",
        "vec4me.com",
    }
    for zone in zones:
        configuration = zone_file.readAnnotations(directory / f"{zone}.zone")
        assert "*=jeff@je.gy" in configuration["email_forwards"]
    configuration = zone_file.readAnnotations(directory / "je.gy.zone")
    assert "*=vec4me@icloud.com" in configuration["email_forwards"]


def giveRegeryExplicitProviderClients() -> None:
    """Verify Regery reconciliation receives Cloudflare observations as input."""
    regeryclient = {"provider": "regery"}
    configuration = {
        "contact_roles": ["registrant"],
        "services": {},
        "disclose": {},
        "domains": ["example.com"],
        "auto_renew": True,
    }
    nameservers = {"example.com": ["ns1.example.com"]}
    with mock.patch.dict(regery.os.environ, {"REGERY_CONTACT_ID": "contact"}), mock.patch.object(regery, "initializeClient", return_value=regeryclient), mock.patch.object(regery, "fetchState", return_value={}) as fetchstate, mock.patch.object(reconciliation, "runValues", return_value=False):
        regery.reconcile(configuration, nameservers, apply=False, planformat="text")
    fetchstate.assert_called_once_with(regeryclient, {"example.com"})


def main() -> None:
    """Run every regression check."""
    keepPlanReadOnly()
    keepPlanDeterministic()
    keepPlanSerializable()
    replaceByRemovingBeforePushing()
    keepUnknownBoundariesUnmanaged()
    respectPlanDependencies()
    skipFailedDependents()
    requireObservedConvergence()
    letLocalSettingsOverrideIncludedDefaults()
    compileCloudflareDesiredStateBeforeObservation()
    identifyUnreferencedCloudflareDeployments()
    leaveUndeclaredTelnyxResourcesUntouched()
    keepRegeryPlanFreeOfMutationCallbacks()
    keepTelnyxPlanFreeOfMutationCallbacks()
    planTelnyxCleanupAsExplicitRemovals()
    reportPartialCloudflareReplacementFailure()
    replaceCnameRecordInPlace()
    projectOnlyDeclaredTelnyxFields()
    rejectMissingProviderCredentials()
    observeEveryDeclaredCloudflareSetting()
    leaveProviderOwnedDnsRecordsUnmanaged()
    preserveExplicitEmailForwardingSource()
    protectEveryEmailRuleWhenObservationFails()
    preserveCentralEmailForwardingChain()
    giveRegeryExplicitProviderClients()


if __name__ == "__main__":
    main()
