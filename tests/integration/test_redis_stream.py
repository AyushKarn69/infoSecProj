import asyncio

from services.control_api import app as control_app


def test_connection_hub_appends_events_to_configured_redis_stream(monkeypatch) -> None:
    calls: list[tuple[str, dict[str, str]]] = []

    class FakeRedis:
        async def xadd(self, stream: str, fields: dict[str, str], **kwargs: object) -> str:
            assert kwargs == {"maxlen": 10_000, "approximate": True}
            calls.append((stream, fields))
            return "1-0"

    monkeypatch.setattr(control_app, "_redis_events", FakeRedis())
    event = {"type": "risk.updated", "overall_score": 42}

    asyncio.run(control_app.ConnectionHub().publish(event))

    assert calls == [("riskshare:events", {'json': '{"overall_score":42,"type":"risk.updated"}'})]
