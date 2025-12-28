rule Phishing_Domain_Keywords
{
    meta:
        description = "Detect common phishing domain keywords"
        author = "Muthu Eswaran"
        date = "2025-09-17"
        reference = "Custom phishing detection"
    
    strings:
        $phish1 = "paypal"
        $phish2 = "bank"
        $phish3 = "login"
        $phish4 = "verify"
        $phish5 = "secure"
    
    condition:
        any of them
}
