"""Compliance framework constants for security posture management."""

# CIS Benchmark control families mapped to scan rule categories.
CIS_CONTROL_MAP = {
    "iam": "CIS 1.x - Identity and Access Management",
    "logging": "CIS 2.x - Logging",
    "monitoring": "CIS 3.x - Monitoring",
    "networking": "CIS 4.x - Networking",
    "storage": "CIS 5.x - Storage",
}

# Compliance framework identifiers for report tagging.
COMPLIANCE_FRAMEWORKS = {
    "cis_aws_1_5": "CIS Amazon Web Services Foundations Benchmark v1.5",
    "cis_azure_2_0": "CIS Microsoft Azure Foundations Benchmark v2.0",
    "soc2_type2": "SOC 2 Type II",
    "iso_27001": "ISO/IEC 27001:2022",
    "nist_csf": "NIST Cybersecurity Framework v2.0",
    "pci_dss_4": "PCI DSS v4.0",
}

# Auto-remediation risk tiers.
# Only LOW and MEDIUM findings are auto-remediated; HIGH and CRITICAL
# require human approval to avoid breaking production workloads.
REMEDIATION_TIERS = {
    "auto": ["LOW", "MEDIUM"],
    "approval_required": ["HIGH", "CRITICAL"],
}
