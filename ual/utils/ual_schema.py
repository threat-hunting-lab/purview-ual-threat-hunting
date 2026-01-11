"""
Common UAL column candidates & helpers.

Different exports flatten AuditData differently. These lists help scripts remain portable.
"""

IP_CANDIDATES = [
    "IP_Normalized",
    "ClientIP",
    "ClientIPAddress",
    "AuditData.ClientIP",
    "AuditData.ClientIPAddress",
    "Client_IP",
    "ip",
    "ipaddress",
]

USER_CANDIDATES = [
    "UserId",
    "User",
    "ActorUserId",
    "AuditData.UserId",
    "AuditData.User",
]

OPERATION_CANDIDATES = [
    "Operation",
    "AuditData.Operation",
]

WORKLOAD_CANDIDATES = [
    "Workload",
    "AuditData.Workload",
]

CREATIONDATE_CANDIDATES = [
    "CreationDate",
    "CreationTime",
    "AuditData.CreationDate",
]
