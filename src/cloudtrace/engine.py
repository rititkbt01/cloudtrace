"""The entry point: raw records in, a full decision record out.

    from cloudtrace.engine import analyze
    result = analyze(records, config)

result["verdicts"]     one row per candidate event, with the reason (the decision record)
result["quality"]      what the quality check found in the input
result["key_history"]  who created which key and where it was used
"""
from cloudtrace import check1, lineage, quality
from cloudtrace import config as settings


def analyze(records: list, config: dict | None = None) -> dict:
    cfg = settings.resolve(config)
    events, report = quality.clean(records)
    history = lineage.build(events)
    verdicts = check1.run(events, cfg)
    # Stage 5 adds check2 and check3 here.
    return {
        "verdicts": verdicts,
        "quality": report.as_dict(),
        "key_history": [k.as_dict() for k in history.values()],
        "config": cfg,
    }
