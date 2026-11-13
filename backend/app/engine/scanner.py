import uuid
from typing import List, Dict, Any
from app.engine.cvss import calculate_cvss_v31, parse_vector_string

# Known CVE Knowledge Base
VULNERABILITY_KB = [
    {
        "cve_id": "CVE-2021-44228",
        "title": "Apache Log4j Remote Code Execution (Log4Shell)",
        "service": "Tomcat / Java",
        "default_port": 8080,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "description": "JNDI lookup features in Log4j allow unauthenticated remote attackers to execute arbitrary code via LDAP/RMI references.",
        "remediation": "Upgrade org.apache.logging.log4j:log4j-core to 2.17.1+. Alternatively, set env LOG4J_FORMAT_MSG_NO_LOOKUPS=true."
    },
    {
        "cve_id": "CVE-2014-0160",
        "title": "OpenSSL TLS Heartbeat Information Disclosure (Heartbleed)",
        "service": "OpenSSL TLS",
        "default_port": 443,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "description": "Memory boundary validation flaw in OpenSSL heartbeat handling permits reading up to 64KB of server heap memory per request.",
        "remediation": "Update openssl package to >= 1.0.1g, revoke active certificates, and generate fresh RSA/ECDSA key pairs."
    },
    {
        "cve_id": "CVE-2023-38606",
        "title": "Exposed Redis Cache Without Authentication",
        "service": "Redis",
        "default_port": 6379,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Redis instance reachable without password credentials permits arbitrary command execution and database manipulation.",
        "remediation": "Bind Redis listener to 127.0.0.1 or VPC private subnet. Enforce 'requirepass' in redis.conf and disable CONFIG/FLUSHALL."
    },
    {
        "cve_id": "CVE-2020-1472",
        "title": "Microsoft Netlogon Cryptographic Flaw (Zerologon)",
        "service": "Active Directory / SMB",
        "default_port": 445,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "description": "Insecure AES-CFB8 implementation in Netlogon authentication allows unauthenticated attackers to obtain domain controller privileges.",
        "remediation": "Apply Microsoft security update KB4565349 and enforce Secure RPC channel enforcement across domain controllers."
    },
    {
        "cve_id": "CVE-2022-22965",
        "title": "Spring Framework DataBinder Remote Code Execution (Spring4Shell)",
        "service": "Spring MVC",
        "default_port": 80,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "description": "Class loader binding vulnerability in Spring Framework allows RCE when running on Tomcat via WAR deployment.",
        "remediation": "Upgrade Spring Framework to version 5.3.18 or 5.2.20. Upgrade Apache Tomcat to >= 9.0.62 / 10.0.20."
    },
    {
        "cve_id": "CVE-2023-4863",
        "title": "libwebp Heap Buffer Overflow via Lossless WebP",
        "service": "Media Processor",
        "default_port": 8080,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "description": "Out-of-bounds write in BuildHuffmanTable in libwebp permits remote execution via malicious WebP graphic payload.",
        "remediation": "Update libwebp to >= 1.3.2 and redeploy base container images."
    }
]

def scan_target_asset(asset: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Simulates a compliant, authorized vulnerability audit on an asset
    by inspecting configured ports and services against the vulnerability signature base.
    """
    findings = []
    target_ports = [int(p.strip()) for p in asset.get("open_ports", "80,443").split(",") if p.strip().isdigit()]

    for vuln in VULNERABILITY_KB:
        if vuln["default_port"] in target_ports:
            parsed_metrics = parse_vector_string(vuln["vector"])
            cvss_info = calculate_cvss_v31(parsed_metrics)

            findings.append({
                "id": "find-" + str(uuid.uuid4())[:8],
                "asset_id": asset["id"],
                "asset_ip": asset["ip_address"],
                "cve_id": vuln["cve_id"],
                "title": vuln["title"],
                "service": vuln["service"],
                "port": vuln["default_port"],
                "cvss_vector": cvss_info["vector"],
                "base_score": cvss_info["base_score"],
                "severity": cvss_info["severity"],
                "impact_score": cvss_info["impact_score"],
                "exploitability_score": cvss_info["exploitability_score"],
                "description": vuln["description"],
                "remediation": vuln["remediation"],
                "status": "UNREMEDIATED"
            })

    return findings
