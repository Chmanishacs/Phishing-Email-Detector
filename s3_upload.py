"""Upload one sanitized report to a private S3 bucket."""
import json


def upload_report(report, bucket, client=None):
    if client is None:
        import boto3  # only needed for the cloud feature
        client = boto3.client("s3")
    key = f'reports/{report["analysis_id"]}.json'
    client.put_object(Bucket=bucket, Key=key, Body=json.dumps(report, indent=2).encode(),
                      ContentType="application/json", ServerSideEncryption="AES256")
    return key
