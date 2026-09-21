"""Original deterministic indicator rules. Indicators describe evidence, not exploitability."""

import re

from .safety import digest

CAPABILITIES = {
    "READ_LOCAL_FILE": r"\b(?:readFile(?:Sync)?|read_text|read_bytes|read[_ ](?:local[_ ])?files?)\b",
    "WRITE_LOCAL_FILE": r"\b(?:writeFile(?:Sync)?|write_text|write_bytes|write[_ ](?:local[_ ])?files?)\b",
    "DELETE_LOCAL_FILE": r"\b(?:unlink(?:Sync)?|rmtree|delete[_ ]files?)\b",
    "LIST_DIRECTORY": r"\b(?:readdir(?:Sync)?|listdir|list[_ ]director(?:y|ies))\b",
    "READ_ENV": r"\b(?:process\.env|os\.environ|getenv|read[_ ]env)\b",
    "READ_CREDENTIAL": r"(?:\.ssh[/\\]|id_rsa|id_ed25519|\.aws[/\\]credentials|read[_ ]credentials?)",
    "EXECUTE_COMMAND": r"\b(?:subprocess\.(?:run|call|Popen)|os\.system|child_process|execSync|execute[_ ]command|run[_ ]shell)\b",
    "SPAWN_PROCESS": r"\b(?:spawnSync|spawn|Popen)\s*\(",
    "NETWORK_OUTBOUND": r"\b(?:fetch|requests\.(?:get|post)|httpx\.(?:get|post)|urlopen)\s*\(",
    "NETWORK_ARBITRARY": r"\b(?:arbitrary[_ ](?:url|network|host)|any[_ ](?:url|host)|unrestricted[_ ]network)\b",
    "HTTP_REQUEST": r"\b(?:http[_ ]request|fetch|requests\.(?:get|post))\s*(?:\(|\b)",
    "DATABASE_READ": r"\b(?:SELECT\s+.+?\s+FROM|database[_ ]read)\b",
    "DATABASE_WRITE": r"\b(?:INSERT\s+INTO|DELETE\s+FROM|database[_ ]write)\b",
    "EMAIL_SEND": r"\b(?:sendmail|send_email|sendMail|email[_ ]send)\b",
    "MESSAGE_SEND": r"\b(?:chat\.postMessage|send_message|message[_ ]send)\b",
    "BROWSER_CONTROL": r"\b(?:playwright|puppeteer|selenium|browser[_ ]control)\b",
    "GITHUB_WRITE": r"\b(?:repos\.createOrUpdateFileContents|github[_ ]write|create_pull_request)\b",
    "DEPLOYMENT_CONTROL": r"\b(?:kubectl\s+apply|deployment[_ ]control|deploy_production)\b",
    "PAYMENT_INITIATE": r"\b(?:paymentIntents\.create|payment[_ ]initiate|create_payment)\b",
    "PAYMENT_MODIFY": r"\b(?:refunds\.create|payment[_ ]modify|refund_payment)\b",
    "FINANCIAL_TRANSFER": r"\b(?:transfers\.create|financial[_ ]transfer|transfer_funds)\b",
    "IDENTITY_ADMIN": r"\b(?:identity[_ ]admin|create_admin|grant_admin)\b",
    "SECRET_MANAGER_ACCESS": r"\b(?:get_secret_value|secretsmanager|secret[_ ]manager[_ ]access)\b",
    "CLOUD_ADMIN": r"\b(?:AdministratorAccess|cloud[_ ]admin|iam:PassRole)\b",
    "UNKNOWN_HIGH_IMPACT_ACTION": r"\b(?:unrestricted[_ ]access|all[_ ]permissions)\b",
}
HIGH_IMPACT = {
    "READ_CREDENTIAL",
    "EXECUTE_COMMAND",
    "READ_ENV",
    "WRITE_LOCAL_FILE",
    "DELETE_LOCAL_FILE",
    "PAYMENT_INITIATE",
    "PAYMENT_MODIFY",
    "FINANCIAL_TRANSFER",
    "IDENTITY_ADMIN",
    "SECRET_MANAGER_ACCESS",
    "CLOUD_ADMIN",
    "UNKNOWN_HIGH_IMPACT_ACTION",
}
INDICATORS = {
    "HIDDEN_INSTRUCTION": (
        r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069]|<!--\s*(?:ignore|override|system|secret|do not tell)[\s\S]{0,500}?-->|ignore\s+(?:all\s+)?previous\s+instructions",
        "high",
        "Hidden or overriding instructions can influence an agent outside the visible tool contract.",
        "CWE-1427",
    ),
    "ENCODED_PAYLOAD_INDICATOR": (
        r"(?:eval|exec)\s*\([^\n]{0,120}(?:base64|atob)|(?:base64\s+-d|atob\s*\()",
        "high",
        "Encoded content may conceal instructions; this is an indicator requiring review.",
        "CWE-506",
    ),
    "REMOTE_EXECUTION_PIPE": (
        r"\b(?:curl|wget)\b[^\n]{0,200}\|\s*(?:sh|bash)\b",
        "critical",
        "Downloaded content is piped into a command interpreter.",
        "CWE-78",
    ),
    "FLOATING_NPX": (
        r"\bnpx\s+(?:--yes|-y)\s+(?:@[\w.-]+/)?[\w.-]+(?![\w.@/-])",
        "medium",
        "An unpinned runner can fetch changed code on the next invocation.",
        "CWE-829",
    ),
    "SECRET_LOGGING": (
        r"(?:console\.log|print|logging\.\w+)\s*\([^\n]{0,100}(?:process\.env|os\.environ|api_key|private_key)",
        "high",
        "A logging call references environment or credential material.",
        "CWE-532",
    ),
}


def finding(kind, old, new, path, why, severity="medium", evidence=None, confidence="high", references=None):
    return {
        "id": digest([kind, path, old, new])[:24],
        "type": kind,
        "old_value": old,
        "new_value": new,
        "affected_path": path,
        "severity": severity,
        "why_it_matters": why,
        "confidence": confidence,
        "evidence": evidence or {"source": path, "method": "deterministic comparison"},
        "recommendation": "Review the evidence and pin or reject the changed component before approving a new baseline.",
        "references": references or [],
    }


def inspect_text(text, path):
    capabilities, findings = [], []
    for name, pattern in CAPABILITIES.items():
        match = re.search(pattern, text, re.I)
        if match:
            capabilities.append(name)
    for name, (pattern, severity, why, cwe) in INDICATORS.items():
        match = re.search(pattern, text, re.I)
        if match:
            # Keep location and rule, never copy arbitrary source snippets or secret values.
            findings.append(
                finding(
                    name,
                    None,
                    True,
                    path,
                    why,
                    severity,
                    {"source": path, "line": text[: match.start()].count("\n") + 1, "rule": name},
                    "medium",
                    [cwe],
                )
            )
    return sorted(capabilities), findings
