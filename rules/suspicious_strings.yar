rule Suspicious_Strings
{
    meta:
        description = "Detect suspicious encoded or obfuscated strings"
        author = "Muthu Eswaran"
        date = "2025-09-17"

    strings:
        $base64_exec = "ZXhlYw=="          // base64("exec")
        $powershell  = "powershell"
        $cmd         = "cmd.exe"
        $wget        = "wget"
        $curl        = "curl"
    
    condition:
        any of them
}
