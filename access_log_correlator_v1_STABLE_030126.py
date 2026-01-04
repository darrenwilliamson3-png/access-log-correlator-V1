import argparse
import json
import sys
from datetime import datetime
from datetime import timedelta
from collections import defaultdict

EXIT_OK = 0
EXIT_SCHEMA_ERROR = 2
EXIT_RUNTIME_ERROR = 1

ALERT_SCHEMA = {
    "type": str,
    "user": str,
    "source_ip": str,
    "count": int,
    "window_minutes": int,
    "first_seen": datetime,
    "last_seen": datetime,
}


def parser_args():
    parser = argparse.ArgumentParser(
        description="Access / Log Correlator V1"
    )

    parser.add_argument(
        "--input",
        required=True,
        help= "Path to access log JSON input file"
    )

    parser.add_argument(
        "--output-json",
        dest="output_json",
        help="Write detected alerts to JSON file"
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console output"
    )

    return parser.parse_args()

def load_events(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            events = json.load(f)
    except FileNotFoundError:
        print(f"ERROR: File not found: {path}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(events, list):
        print(f"ERROR: JSON root must be a list", file=sys.stderr)
        sys.exit(1)

    return events

REQUIRED_FIELDS = {
    "timestamp": str,
    "user": str,
    "source_ip": str,
    "action": str,
    "result": str,
}

ALLOWED_RESULTS = {"success", "fail"}

def guard_schema(events):
    if not isinstance(events, list):
        raise ValueError("Input must be a list of events")

    for idx, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise ValueError(f"Event #{idx} is not an object")

        # Required fields and types
        for field, expected_type in REQUIRED_FIELDS.items():
            if field not in event:
                raise ValueError(f"Event #{idx} missing required field '{field}'")

            if not isinstance(event[field], expected_type):
                raise ValueError(
                    f"Event #{idx} field '{field}' must be {expected_type.__name__}"
                )
        # Allowed types
        if event["result"].lower() not in ALLOWED_RESULTS:
            raise ValueError(
                f"Event #{idx} has invalid result '{event['result']}' "
                f"(allowed: {ALLOWED_RESULTS})"
            )

VALID_RESULTS = {"success", "fail"}

def validate_schema(events):
    for idx, event in enumerate(events, start=1):
        for field in REQUIRED_FIELDS:
            if field not in event:
                raise ValueError(f'Event #{idx} missing field {field}')

        if event["result"] not in VALID_RESULTS:
            raise ValueError(
                f"Event #{idx} invalid result '{event['result']}'"
            )

def guard_alert_schema(alerts):
    if not isinstance(alerts, list):
        raise ValueError("Alerts must be a list")

    for idx, alert in enumerate(alerts, start=1):
        if not isinstance(alert, dict):
            raise ValueError(f"Alert #{idx} is not an object")

        for field, expected_type in ALERT_SCHEMA.items():
            if field not in alert:
                raise ValueError(f"Alert #{idx} missing field '{field}'")

            if not isinstance(alert[field], expected_type):
                raise ValueError(
                    f"Alert #{idx} field '{field}' must be {expected_type.__name__}"
                )

        if alert["count"] <= 0:
            raise ValueError(f"Alert #{idx} has invalid count")

        if alert["first_seen"] > alert["last_seen"]:
            raise ValueError(f"Alert #{idx} has invalid time window")


def normalize_events(events):
    normalized = []

    for event in events:
        result = event["result"].lower()

        success = result == "success"

        normalized.append({
            "timestamp": datetime.fromisoformat(event["timestamp"]),
            "user": event["user"],
            "action": event["action"].lower(),
            "success": success,
            "source_ip": event["source_ip"],
        })

    return normalized

def detect_failed_logins(events, threshold=3, window_minutes=5):
    alerts = []
    events = sorted(events, key=lambda e: e["timestamp"])

    # Group failed login attempts by (user, source_ip)
    failures = defaultdict(list)

    for event in events:
        if event["action"] != "login":
            continue

        if event["success"]:
            continue

        key = (event["user"], event["source_ip"])
        failures[key].append(event["timestamp"])

        window_start = event["timestamp"] - timedelta(minutes=window_minutes)

        # Keep only timestamps in window
        failures[key] = [
            ts for ts in failures[key]
            if ts >= window_start
        ]

        if len(failures[key]) >= threshold:
            alerts.append({
                "type": "failed_login_burst",
                "user": event["user"],
                "source_ip": event["source_ip"],
                "count": len(failures[key]),
                "window_minutes": window_minutes,
                "first_seen": failures[key][0],
                "last_seen": failures[key][-1],
            })

            # Prevent duplicate alerts
            failures[key].clear()

    return alerts

def export_json(alerts, total_events, path):
    output = {
        "summary": {
            "total_events": total_events,
            "alerts_detected": len(alerts),
        },
        "alerts": []
    }

    for alert in alerts:
        output["alerts"].append({
            "type": alert["type"],
            "user": alert["user"],
            "source_ip": alert["source_ip"],
            "failed_attempts": alert["count"],
            "window_minutes": alert["window_minutes"],
            "first_seen": alert["first_seen"].isoformat(),
            "last_seen": alert["last_seen"].isoformat()
        })

    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

def print_summary(alerts):
    print("Summary:")
    print(f" Alerts detected: {len(alerts)}")

    for alerts in alerts:
        print(
            f"  - {alerts['user']} from {alerts['source_ip']} "
            f"({alerts["count"]} failures in {alerts['window_minutes']} min)"
        )

def main ():
    try:
        args=parser_args()

        events = load_events(args.input)
        guard_schema(events)

        normalized = normalize_events(events)
        alerts = detect_failed_logins(normalized)

        guard_alert_schema(alerts)

        print(f"loaded events: {len(events)}")
        print(f"Detected {len(alerts)} suspicious login pattern")

        if args.output_json:
            export_json(alerts, len(events), args.output_json)

        if not args.quiet:
            print_summary(alerts)

        return EXIT_OK

    except ValueError as e:
        print(f"SCHEMA ERROR: {e}", file=sys.stderr)
        return EXIT_SCHEMA_ERROR

    except Exception as e:
        print(f"RUNTIME ERROR: {e}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR

if __name__ == "__main__":
    main()