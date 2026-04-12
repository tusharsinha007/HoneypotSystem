"""
LLMPot — Data Ingestion
Import real session data for retraining the ML model.
"""

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from database.db_manager import DatabaseManager
from utils.logger import get_logger

logger = get_logger("ingest")


def ingest_from_csv(csv_path: str):
    """Import session data from a CSV file."""
    db = DatabaseManager()
    count = 0

    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                db.create_session(
                    session_id=row.get("session_id", f"imported-{count}"),
                    attacker_ip=row.get("attacker_ip", "0.0.0.0"),
                    attacker_port=int(row.get("attacker_port", 0)),
                    username=row.get("username", ""),
                    password=row.get("password", ""),
                    auth_success=bool(row.get("auth_success", False)),
                    geo_data={
                        "country": row.get("country", ""),
                        "countryCode": row.get("country_code", ""),
                        "city": row.get("city", ""),
                        "lat": float(row.get("latitude", 0)),
                        "lon": float(row.get("longitude", 0)),
                    },
                )
                count += 1
            except Exception as e:
                logger.warning(f"Skipping row: {e}")

    logger.info(f"Imported {count} sessions from {csv_path}")
    return count


def ingest_from_json(json_path: str):
    """Import session data from a JSON file."""
    db = DatabaseManager()
    count = 0

    with open(json_path, "r") as f:
        data = json.load(f)

    sessions = data if isinstance(data, list) else data.get("sessions", [])

    for session in sessions:
        try:
            db.create_session(
                session_id=session.get("session_id", f"imported-{count}"),
                attacker_ip=session.get("attacker_ip", "0.0.0.0"),
                attacker_port=int(session.get("attacker_port", 0)),
                username=session.get("username", ""),
                password=session.get("password", ""),
                auth_success=bool(session.get("auth_success", False)),
                geo_data=session.get("geo_data", {}),
            )

            # Import commands if present
            for cmd in session.get("commands", []):
                db.log_command(
                    session_id=session["session_id"],
                    command=cmd.get("command", ""),
                    output=cmd.get("output", ""),
                    is_dangerous=bool(cmd.get("is_dangerous", False)),
                    threat_category=cmd.get("category"),
                )

            count += 1
        except Exception as e:
            logger.warning(f"Skipping session: {e}")

    logger.info(f"Imported {count} sessions from {json_path}")
    return count


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Import attack data")
    parser.add_argument("file", help="Path to CSV or JSON file")
    parser.add_argument("--format", choices=["csv", "json"], default="json",
                        help="File format")
    args = parser.parse_args()

    if args.format == "csv":
        ingest_from_csv(args.file)
    else:
        ingest_from_json(args.file)
