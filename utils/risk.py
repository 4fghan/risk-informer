RISKY_PORTS = {
    "21": ("HIGH", "FTP transmits credentials in plaintext"),
    "23": ("HIGH", "Telnet is unencrypted and insecure"),
    "3389": ("MEDIUM", "RDP exposed can be brute-forced"),
    "22": ("LOW", "SSH is secure but should use key auth"),
}

SERVICE_WARNINGS = {
    "http": "Website is not using HTTPS",
    "domain": "DNS service exposed (verify necessity)",
    "tcpwrapped": "Service is filtered or obfuscated",
}


def assess_risk(port, service):
    port = str(port)

    if port == "443":
        return ("INFO", "HTTPS service detected (encryption enabled)")

    if port == "80":
        return ("INFO", "HTTP service detected (secure if redirected to HTTPS)")

    RISKY_PORTS = {
        "21": ("HIGH", "FTP transmits credentials in plaintext"),
        "23": ("HIGH", "Telnet is unencrypted and insecure"),
        "3389": ("MEDIUM", "RDP exposed can be brute-forced"),
        "22": ("LOW", "SSH is secure but should use key auth"),
    }

    if port in RISKY_PORTS:
        return RISKY_PORTS[port]

    SERVICE_WARNINGS = {
        "domain": "DNS service exposed (verify necessity)",
        "tcpwrapped": "Service is filtered or obfuscated",
    }

    return ("INFO", SERVICE_WARNINGS.get(service.lower(), "No immediate risk identified"))

PORT_DETAILS = {
    "21": [
        "Credentials may be transmitted in plaintext if FTP is used without encryption",
        "Susceptible to sniffing attacks if not secured"
    ],
    "22": [
        "Brute-force attacks possible if password authentication is enabled",
        "Risk significantly reduced when using key-based authentication"
    ],
    "23": [
        "Unencrypted remote access makes interception trivial",
        "Should be replaced with SSH in modern environments"
    ],
    "80": [
        "Data transmitted in plaintext unless redirected to HTTPS",
        "Risk depends on whether sensitive data is handled"
    ],
    "3389": [
        "RDP brute-force attacks common if exposed to the internet",
        "Risk reduced with VPN, firewall rules, or account lockouts"
    ]
}

RECOMMENDATIONS = {
    "21": [
        "Disable FTP or use SFTP instead",
        "Avoid transmitting credentials in plaintext"
    ],
    "22": [
        "Disable password authentication",
        "Use SSH keys for authentication",
        "Restrict access via firewall"
    ],
    "23": [
        "Disable Telnet service",
        "Replace with SSH"
    ],
    "80": [
        "Redirect HTTP to HTTPS",
        "Avoid transmitting sensitive data over HTTP"
    ],
    "3389": [
        "Restrict RDP access with firewall rules",
        "Use VPN for remote access",
        "Enable account lockout policies"
    ]
}