"""Tests the in-process pub/sub used to push "something changed" events
to the dashboard (see utils/incident_events.py)."""

import queue

from utils.incident_events import publish, reset_for_tests, subscribe, unsubscribe


def setup_function():
    reset_for_tests()


def test_a_subscriber_receives_a_published_event():
    q = subscribe("tenant-a")
    publish("tenant-a", {"type": "incident_updated", "thread_id": "inc-1"})
    assert q.get_nowait() == {"type": "incident_updated", "thread_id": "inc-1"}


def test_a_subscriber_never_sees_another_tenants_events():
    q = subscribe("tenant-a")
    publish("tenant-b", {"type": "incident_updated", "thread_id": "inc-1"})
    assert q.empty()


def test_multiple_subscribers_on_the_same_tenant_all_receive_it():
    q1 = subscribe("tenant-a")
    q2 = subscribe("tenant-a")
    publish("tenant-a", {"type": "incident_updated", "thread_id": "inc-1"})
    assert q1.get_nowait()["thread_id"] == "inc-1"
    assert q2.get_nowait()["thread_id"] == "inc-1"


def test_publishing_with_no_subscribers_does_not_raise():
    publish("tenant-with-nobody-listening", {"type": "incident_updated", "thread_id": "inc-1"})


def test_unsubscribe_stops_further_delivery():
    q = subscribe("tenant-a")
    unsubscribe("tenant-a", q)
    publish("tenant-a", {"type": "incident_updated", "thread_id": "inc-1"})
    assert q.empty()


def test_unsubscribe_of_an_unknown_queue_does_not_raise():
    unsubscribe("tenant-nobody-subscribed-to", queue.Queue())


def test_a_full_queue_drops_new_events_instead_of_blocking_or_raising():
    q = subscribe("tenant-a")
    for i in range(200):
        publish("tenant-a", {"type": "incident_updated", "thread_id": f"inc-{i}"})
    # maxsize=100 -- publish() must never block or raise even once the
    # queue backs up; a stalled subscriber shouldn't affect anyone else.
    assert q.qsize() <= 100
