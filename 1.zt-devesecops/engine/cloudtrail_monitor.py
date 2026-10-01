import boto3
from datetime import datetime, timezone, timedelta


BUCKET_NAME = "zt-devsecops-c23e242d8c01c05f03876fddbf"


# Only these S3 operations are allowed by the intent manifest.
ALLOWED_S3_EVENTS = {
    "GetObject",
    "PutObject"
}


def get_recent_events(minutes=10):

    cloudtrail = boto3.client("cloudtrail")

    end_time = datetime.now(timezone.utc)

    start_time = (
        end_time - timedelta(minutes=minutes)
    )

    response = cloudtrail.lookup_events(
        StartTime=start_time,
        EndTime=end_time,
        MaxResults=50
    )

    return response.get("Events", [])


def analyze_events(events):

    suspicious_events = []

    for event in events:

        event_name = event.get(
            "EventName",
            ""
        )

        event_source = event.get(
            "EventSource",
            ""
        )

        # Only inspect S3 API activity.
        if event_source != "s3.amazonaws.com":
            continue

        # Ignore bucket-level infrastructure configuration.
        if event_name in {
            "GetBucketAcl",
            "GetBucketPolicy",
            "PutBucketPolicy",
            "GetBucketPublicAccessBlock",
            "GetBucketEncryption",
            "GetBucketVersioning",
            "GetBucketLogging",
            "GetBucketLifecycle",
            "GetBucketCors",
            "GetBucketWebsite",
            "GetBucketReplication",
            "GetBucketObjectLockConfiguration",
            "GetBucketRequestPayment",
            "GetAccelerateConfiguration",
            "ListBucket",
            "HeadBucket"
        }:
            continue

        # Only GetObject and PutObject are permitted.
        if event_name not in ALLOWED_S3_EVENTS:

            suspicious_events.append({
                "event_name": event_name,
                "event_time": event.get("EventTime"),
                "username": event.get("Username"),
                "source": event_source
            })

    return suspicious_events


def main():

    print("=== CloudTrail Security Monitor ===")

    print(
        "[MONITOR] Deployment bucket:",
        BUCKET_NAME
    )

    print(
        "[MONITOR] Allowed S3 actions:",
        ["GetObject", "PutObject"]
    )

    events = get_recent_events()

    print(
        "[MONITOR] Events received:",
        len(events)
    )

    suspicious_events = analyze_events(
        events
    )

    if suspicious_events:

        print(
            "[ALERT] Out-of-scope S3 activity detected!"
        )

        for event in suspicious_events:

            print(
                "[ALERT]",
                event["event_name"],
                "|",
                event["username"],
                "|",
                event["source"]
            )

        print(
            "[ACTION] Security response should revoke access."
        )

    else:

        print(
            "[MONITOR] No out-of-scope S3 activity detected."
        )


if __name__ == "__main__":

    main()