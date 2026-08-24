from langgraph.graph import END

from graph import route_next


def test_route_next_returns_end_when_no_next_agent():
    assert route_next({"next_agent": None}) == END


def test_route_next_returns_end_when_key_missing():
    assert route_next({}) == END


def test_route_next_returns_named_agent():
    assert route_next({"next_agent": "investigator"}) == "investigator"
    assert route_next({"next_agent": "threat_hunter"}) == "threat_hunter"
    assert route_next({"next_agent": "responder"}) == "responder"
