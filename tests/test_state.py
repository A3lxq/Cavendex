import pytest
from pydantic import ValidationError

from state import Incident, ProposedAction


def test_incident_defaults():
    incident = Incident(id="abc123", description="test incident")
    assert incident.severity == "medium"
    assert incident.status == "open"
    assert incident.iocs == []
    assert incident.affected_assets == []
    assert incident.source is None


def test_incident_custom_fields():
    incident = Incident(
        id="abc123",
        description="brute force",
        severity="high",
        affected_assets=["DC-01"],
        iocs=["1.2.3.4"],
        source="SIEM",
    )
    assert incident.severity == "high"
    assert incident.affected_assets == ["DC-01"]
    assert incident.iocs == ["1.2.3.4"]
    assert incident.source == "SIEM"


def test_proposed_action_defaults_to_pending():
    action = ProposedAction(action="Block IP", target="1.2.3.4", rationale="malicious")
    assert action.approved is None


def test_proposed_action_approval_does_not_mutate_original():
    action = ProposedAction(action="Block IP", target="1.2.3.4", rationale="malicious")
    approved = action.model_copy(update={"approved": True})
    assert approved.approved is True
    assert action.approved is None


def test_incident_rejects_invalid_severity():
    with pytest.raises(ValidationError):
        Incident(id="abc123", description="test", severity="nuke-everything")


def test_incident_rejects_invalid_status():
    with pytest.raises(ValidationError):
        Incident(id="abc123", description="test", status="not-a-real-status")


def test_incident_rejects_oversized_description():
    with pytest.raises(ValidationError):
        Incident(id="abc123", description="A" * 5000)


def test_incident_rejects_too_many_iocs():
    with pytest.raises(ValidationError):
        Incident(id="abc123", description="test", iocs=[f"ioc{i}" for i in range(51)])


def test_incident_status_assignment_is_validated():
    incident = Incident(id="abc123", description="test")
    with pytest.raises(ValidationError):
        incident.status = "not-a-real-status"
