rule Phishing_Uses_Punycode
{
    meta:
        author = "PhishGuard"
        description = "Detects potential IDN homograph usage via punycode"
        severity = "medium"
    strings:
        $puny = "xn--" nocase
    condition:
        $puny
}

rule Phishing_Keyword_Login_Verify
{
    meta:
        author = "PhishGuard"
        description = "Detects login/verification lure terms in URL"
        severity = "high"
    strings:
        $k1 = "login" nocase
        $k2 = "verify" nocase
        $k3 = "account-update" nocase
        $k4 = "security-check" nocase
        $k5 = "password-reset" nocase
    condition:
        any of them
}

rule Phishing_Suspicious_Host_Terms
{
    meta:
        author = "PhishGuard"
        description = "Suspicious host terms often used in phishing domains"
        severity = "high"
    strings:
        $h1 = "secure-" nocase
        $h2 = "-secure" nocase
        $h3 = "billing" nocase
        $h4 = "webscr" nocase
        $h5 = "signin" nocase
    condition:
        any of them
}

rule Phishing_Excessive_At_Or_Query
{
    meta:
        author = "PhishGuard"
        description = "Detects URL obfuscation patterns with @ and multiple query keys"
        severity = "medium"
    strings:
        $at = "@"
        $eq = "="
        $amp = "&"
    condition:
        $at or ( #eq >= 3 and #amp >= 2 )
}
