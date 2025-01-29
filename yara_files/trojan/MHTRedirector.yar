rule Trojan_MHTRedirector_A_con {
    meta:
        description = "Detects HTML code attempting to hijack browsers"
        author = "Kybero Labs"

    strings:
        $malicious_registry1 = /HKCU\\Software\\Microsoft\\Internet Explorer\\Main,SearchURL/ nocase
        $malicious_registry2 = /HKCU\\Software\\Microsoft\\Internet Explorer\\Main,Start Page/ nocase
        $malicious_registry3 = /HKLM\\Software\\Microsoft\\Internet Explorer\\Main,SearchURL/ nocase
        $malicious_registry4 = /HKLM\\Software\\Microsoft\\Internet Explorer\\Main,Start Page/ nocase
        $malicious_winsock = /c:\\windows\\system32\\inetadpt\.dll/ nocase
        $suspicious_exe1 = /C:\\WINDOWS\\sp\.exe/ nocase
        $suspicious_exe2 = /C:\\WINDOWS\\system32\\rundll32\.vbe/ nocase
        $suspicious_exe3 = /C:\\WINDOWS\\image\.dll/ nocase
        $activex_dialer = /ms-its:mhtml:file:\/\/C:\\MAIN\.MHT!http:\/\/d\.dialer2004\.com/ nocase

    condition:
        (
            (2 of ($malicious_registry*)) or
            ($malicious_winsock) or
            (2 of ($suspicious_exe*)) or
            ($activex_dialer)
        )
}
