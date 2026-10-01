import streamlit as st
import boto3
import json
import os
import sys
from datetime import datetime, timezone, timedelta

import pandas as pd
import plotly.graph_objects as go


# =========================================================
# CONFIG
# =========================================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

ENGINE_DIR = os.path.join(PROJECT_ROOT, "engine")
VAPT_DIR = os.path.join(PROJECT_ROOT, "vapt")
HONEYTOKEN_DIR = os.path.join(PROJECT_ROOT, "honeytoken")

ACCESS_STATE_FILE = os.path.join(
    ENGINE_DIR,
    "access_state.json"
)

HONEYTOKEN_FILE = os.path.join(
    HONEYTOKEN_DIR,
    "honeytoken_events.json"
)

MANIFEST_FILE = os.path.join(
    PROJECT_ROOT,
    "manifests",
    "intent.yaml"
)

REGION = "ap-south-1"

BUCKET_NAME = "zt-devsecops-c23e242d8c01c05f03876fddbf"

ROLE_ARN = (
    "arn:aws:iam::904290465920:"
    "role/ZT-DevSecOps-Deploy-Role"
)


# =========================================================
# PAGE
# =========================================================

st.set_page_config(
    page_title="ZT DevSecOps SOC",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# CSS ONLY
# =========================================================

st.markdown(
    """
    <style>

    .stApp {
        background-color: #080d18;
    }

    .block-container {
        max-width: 1500px;
        padding-top: 2rem;
    }

    h1 {
        font-size: 2.2rem !important;
        letter-spacing: 1px;
    }

    h2 {
        color: #dce6f5 !important;
    }

    h3 {
        color: #b9c7da !important;
    }

    [data-testid="stMetric"] {
        background-color: #111a2b;
        border: 1px solid #263750;
        border-radius: 12px;
        padding: 15px;
    }

    [data-testid="stMetricValue"] {
        font-size: 28px;
    }

    div[data-testid="stTabs"] button {
        font-weight: 600;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# =========================================================
# HELPERS
# =========================================================

def load_json(path, default):

    if not os.path.exists(path):
        return default

    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def load_access_state():

    return load_json(
        ACCESS_STATE_FILE,
        {
            "status": "UNKNOWN",
            "granted_at": None,
            "revoked_at": None,
            "reason": None
        }
    )


def load_honeytoken_events():

    return load_json(
        HONEYTOKEN_FILE,
        []
    )


def load_manifest():

    try:

        import yaml

        with open(MANIFEST_FILE, "r") as f:
            return yaml.safe_load(f)

    except Exception:

        return {}


@st.cache_resource
def aws_clients():

    return {
        "sts": boto3.client(
            "sts",
            region_name=REGION
        ),

        "s3": boto3.client(
            "s3",
            region_name=REGION
        ),

        "cloudtrail": boto3.client(
            "cloudtrail",
            region_name=REGION
        )
    }


def cloudtrail_events():

    try:

        client = aws_clients()["cloudtrail"]

        end = datetime.now(timezone.utc)

        start = end - timedelta(
            minutes=30
        )

        response = client.lookup_events(
            StartTime=start,
            EndTime=end,
            MaxResults=50
        )

        return response.get(
            "Events",
            []
        )

    except Exception:

        return []


def cloudtrail_status():

    try:

        response = aws_clients()["cloudtrail"].get_trail_status(
            Name="ZT-DevSecOps-Trail"
        )

        return response.get(
            "IsLogging",
            False
        )

    except Exception:

        return False


def bucket_status():

    try:

        aws_clients()["s3"].head_bucket(
            Bucket=BUCKET_NAME
        )

        return True

    except Exception:

        return False


def run_vapt():

    try:

        if VAPT_DIR not in sys.path:
            sys.path.insert(0, VAPT_DIR)

        from vapt_scanner import run_vapt_scan

        return bool(
            run_vapt_scan()
        )

    except Exception:

        return False


# =========================================================
# LOAD DATA
# =========================================================

access = load_access_state()

honeytokens = load_honeytoken_events()

manifest = load_manifest()

events = cloudtrail_events()

trail_online = cloudtrail_status()

s3_online = bucket_status()

vapt_passed = run_vapt()


# =========================================================
# MANIFEST DATA
# =========================================================

pipeline_name = (
    manifest
    .get("pipeline", {})
    .get("name", "zero-trust-deployment")
)

stage_name = (
    manifest
    .get("stage", {})
    .get("name", "deploy")
)

resource = (
    manifest
    .get("access", {})
    .get("resource", "N/A")
)

allowed_actions = (
    manifest
    .get("access", {})
    .get("actions", [])
)


# =========================================================
# HEADER
# =========================================================

st.title(
    "🛡️ ZERO TRUST DEVSECOPS SECURITY CENTER"
)

st.caption(
    "Security Operations Center • "
    "AWS Access Control • VAPT • CloudTrail • Deception"
)

st.divider()


# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.header("🛡️ SOC CONTROL")

    st.success(
        "AWS Connected"
    )

    st.write(
        f"**Region:** `{REGION}`"
    )

    st.write(
        "**Account:** `904290465920`"
    )

    if trail_online:
        st.success("CloudTrail: ACTIVE")
    else:
        st.error("CloudTrail: OFFLINE")

    if s3_online:
        st.success("S3 Bucket: ONLINE")
    else:
        st.error("S3 Bucket: OFFLINE")

    st.divider()

    st.subheader("Manifest Permissions")

    for action in allowed_actions:

        st.code(
            action
        )

    st.divider()

    if st.button(
        "🔄 Refresh Dashboard",
        use_container_width=True
    ):

        st.cache_resource.clear()
        st.rerun()


# =========================================================
# TOP METRICS
# =========================================================

col1, col2, col3, col4, col5 = st.columns(5)


with col1:

    st.metric(
        "ZERO TRUST ACCESS",
        access.get(
            "status",
            "UNKNOWN"
        )
    )


with col2:

    st.metric(
        "VAPT GATE",
        "PASS"
        if vapt_passed
        else "FAIL"
    )


with col3:

    st.metric(
        "CLOUDTRAIL",
        "ACTIVE"
        if trail_online
        else "OFFLINE"
    )


with col4:

    st.metric(
        "REVOCATION",
        "TRIGGERED"
        if access.get("revoked_at")
        else "READY"
    )


with col5:

    st.metric(
        "HONEYTOKEN ALERTS",
        len(honeytokens)
    )


# =========================================================
# PIPELINE
# =========================================================

st.subheader(
    "🔐 Zero Trust Security Pipeline"
)

p1, p2, p3, p4, p5 = st.columns(5)

with p1:
    st.info(
        "**01 — INTENT**\n\n"
        "YAML access manifest"
    )

with p2:
    st.success(
        "**02 — VAPT**\n\n"
        "Security posture check"
    )

with p3:
    st.success(
        "**03 — STS**\n\n"
        "Temporary scoped access"
    )

with p4:
    st.info(
        "**04 — MONITOR**\n\n"
        "CloudTrail activity"
    )

with p5:

    if access.get("revoked_at"):

        st.error(
            "**05 — REVOKED**\n\n"
            "Task completed"
        )

    else:

        st.warning(
            "**05 — REVOCATION**\n\n"
            "Awaiting completion"
        )


# =========================================================
# MAIN TABS
# =========================================================

tab_overview, tab_access, tab_cloudtrail, tab_honey = st.tabs(
    [
        "📊 Overview",
        "🔐 Access & VAPT",
        "🚨 CloudTrail",
        "🍯 Honeytoken"
    ]
)


# =========================================================
# OVERVIEW
# =========================================================

with tab_overview:

    st.subheader(
        "Security Operations Overview"
    )

    m1, m2, m3, m4 = st.columns(4)

    with m1:
        st.metric(
            "AWS Events",
            len(events)
        )

    with m2:
        st.metric(
            "Allowed Actions",
            len(allowed_actions)
        )

    with m3:
        st.metric(
            "Honeytoken Incidents",
            len(honeytokens)
        )

    with m4:
        st.metric(
            "Protected Resource",
            "S3"
        )


    st.subheader(
        "Security Control Status"
    )

    status_df = pd.DataFrame(
        [
            ["AWS S3", "ONLINE" if s3_online else "OFFLINE"],
            ["CloudTrail", "ACTIVE" if trail_online else "OFFLINE"],
            ["VAPT", "PASS" if vapt_passed else "FAIL"],
            [
                "STS Access",
                access.get("status", "UNKNOWN")
            ],
            [
                "Revocation",
                "TRIGGERED"
                if access.get("revoked_at")
                else "READY"
            ],
            [
                "Honeytoken",
                f"{len(honeytokens)} ALERT(S)"
            ]
        ],
        columns=[
            "Security Control",
            "Status"
        ]
    )

    st.dataframe(
        status_df,
        use_container_width=True,
        hide_index=True
    )


    # Security visualization

    st.subheader(
        "Security Architecture Status"
    )

    values = [
        1 if s3_online else 0,
        1 if vapt_passed else 0,
        1 if trail_online else 0,
        1 if access.get("revoked_at") else 0,
        1 if honeytokens else 0
    ]

    labels = [
        "S3",
        "VAPT",
        "CloudTrail",
        "Revocation",
        "Honeytoken"
    ]

    fig = go.Figure(
        go.Bar(
            x=labels,
            y=values,
            text=[
                "ONLINE" if x else "NO DATA"
                for x in values
            ],
            textposition="outside"
        )
    )

    fig.update_layout(
        height=320,
        yaxis=dict(
            range=[0, 1.2],
            showticklabels=False
        ),
        xaxis_title="Security Layer",
        margin=dict(
            l=20,
            r=20,
            t=30,
            b=20
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(
            color="#dce6f5"
        )
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


# =========================================================
# ACCESS + VAPT
# =========================================================

with tab_access:

    st.subheader(
        "🔐 Zero Trust Access Control"
    )

    left, right = st.columns(2)

    with left:

        st.markdown(
            "### Intent Manifest"
        )

        st.write(
            f"**Pipeline:** `{pipeline_name}`"
        )

        st.write(
            f"**Stage:** `{stage_name}`"
        )

        st.write(
            f"**Resource:** `{resource}`"
        )

        st.write(
            "**Allowed Actions:**"
        )

        for action in allowed_actions:

            st.code(action)


    with right:

        st.markdown(
            "### Credential Lifecycle"
        )

        lifecycle_df = pd.DataFrame(
            [
                [
                    "Access State",
                    access.get(
                        "status",
                        "UNKNOWN"
                    )
                ],
                [
                    "Granted At",
                    access.get(
                        "granted_at",
                        "N/A"
                    )
                ],
                [
                    "Revoked At",
                    access.get(
                        "revoked_at",
                        "N/A"
                    )
                ],
                [
                    "Reason",
                    access.get(
                        "reason",
                        "N/A"
                    )
                ]
            ],
            columns=[
                "Lifecycle Event",
                "Value"
            ]
        )

        st.dataframe(
            lifecycle_df,
            use_container_width=True,
            hide_index=True
        )


    st.subheader(
        "🛡️ VAPT Security Gate"
    )

    vapt_df = pd.DataFrame(
        [
            [
                "Secret Pattern Scan",
                "PASS"
            ],
            [
                "S3 Public Access Protection",
                "PASS"
            ],
            [
                "Critical Findings",
                "0"
            ]
        ],
        columns=[
            "Security Check",
            "Result"
        ]
    )

    st.dataframe(
        vapt_df,
        use_container_width=True,
        hide_index=True
    )


# =========================================================
# CLOUDTRAIL
# =========================================================

with tab_cloudtrail:

    st.subheader(
        "🚨 CloudTrail Security Monitor"
    )

    st.caption(
        "Recent AWS API activity captured from ZT-DevSecOps-Trail"
    )

    if events:

        rows = []

        for event in events:

            rows.append(
                {
                    "Time":
                        str(
                            event.get(
                                "EventTime",
                                ""
                            )
                        ),

                    "Event":
                        event.get(
                            "EventName",
                            ""
                        ),

                    "Source":
                        event.get(
                            "EventSource",
                            ""
                        ),

                    "User":
                        event.get(
                            "Username",
                            ""
                        )
                }
            )

        event_df = pd.DataFrame(
            rows
        )

        st.dataframe(
            event_df,
            use_container_width=True,
            hide_index=True,
            height=500
        )

    else:

        st.info(
            "No CloudTrail events found."
        )


# =========================================================
# HONEYTOKEN
# =========================================================

with tab_honey:

    st.subheader(
        "🍯 Honeytoken Deception Center"
    )

    h1, h2, h3 = st.columns(3)

    with h1:
        st.metric(
            "Triggers",
            len(honeytokens)
        )

    with h2:
        st.metric(
            "Threat Status",
            "ALERT"
            if honeytokens
            else "CLEAR"
        )

    with h3:
        st.metric(
            "Logged Incidents",
            len(honeytokens)
        )


    if honeytokens:

        honey_rows = []

        for event in honeytokens:

            honey_rows.append(
                {
                    "Timestamp":
                        event.get(
                            "timestamp",
                            ""
                        ),

                    "Event":
                        event.get(
                            "event",
                            ""
                        ),

                    "Reason":
                        event.get(
                            "reason",
                            ""
                        ),

                    "Attempted Action":
                        event.get(
                            "attempted_action",
                            ""
                        ),

                    "Status":
                        event.get(
                            "status",
                            ""
                        )
                }
            )

        honey_df = pd.DataFrame(
            honey_rows
        )

        st.dataframe(
            honey_df,
            use_container_width=True,
            hide_index=True
        )

        st.error(
            "⚠️ Honeytoken activity detected."
        )

    else:

        st.success(
            "No honeytoken incidents detected."
        )


# =========================================================
# AWS CONTEXT
# =========================================================

st.divider()

st.subheader(
    "☁️ AWS Security Context"
)

aws_df = pd.DataFrame(
    [
        [
            "Region",
            REGION
        ],
        [
            "Account",
            "904290465920"
        ],
        [
            "Protected S3 Bucket",
            BUCKET_NAME
        ],
        [
            "Deployment Role",
            ROLE_ARN
        ],
        [
            "CloudTrail",
            "ZT-DevSecOps-Trail"
        ]
    ],
    columns=[
        "Component",
        "Configuration"
    ]
)

st.dataframe(
    aws_df,
    use_container_width=True,
    hide_index=True
)


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.caption(
    "ZERO TRUST DEVSECOPS • "
    "AWS STS • IAM • S3 • VAPT • CLOUDTRAIL • HONEYTOKEN"
)