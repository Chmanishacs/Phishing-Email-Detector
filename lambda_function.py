"""Optional: analyze .eml files uploaded to an input bucket (S3 trigger)."""
import os
import uuid
from datetime import datetime, timezone
from urllib.parse import unquote_plus

from cloud.s3_upload import upload_report
from detector.parser import parse_email
from detector.rules import analyze

MAX_BYTES = 1_000_000


def lambda_handler(event, context, client=None):
    if client is None:
        import boto3
        client = boto3.client("s3")
    output = os.environ["OUTPUT_BUCKET"]
    keys = []
    for record in event["Records"]:
        bucket = record["s3"]["bucket"]["name"]
        if bucket == output:
            raise ValueError("Input and output buckets must be different.")
        key = unquote_plus(record["s3"]["object"]["key"])
        if record["s3"]["object"].get("size", 0) > MAX_BYTES:
            print("skipped oversized object")
            continue
        raw = client.get_object(Bucket=bucket, Key=key)["Body"].read()
        result = analyze(parse_email(raw))
        report = {
            "analysis_id": uuid.uuid4().hex[:12],
            "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "score": result["score"],
            "verdict": result["verdict"],
            "triggered_rules": [f["rule"] for f in result["findings"]],
        }
        keys.append(upload_report(report, output, client))
        print(f'analyzed id={report["analysis_id"]} score={report["score"]}')
    return {"reports": keys}
