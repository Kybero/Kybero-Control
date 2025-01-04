rule Adware_OutBrowse_A_con {
    meta:
        description = "Detects OutBrowse"
        author = "Kybero Labs"

    strings:
        $s1 = "\\Microsoft\\Internet Explorer\\Quick Launch"
        $s2 = "OUTBROWSE1" nocase
        $s3 = "OUTBROWSE0" nocase

    condition:
        all of them
}

rule Adware_OutBrowse_B_con {
    meta:
        description = "Detects OutBrowse"
        author = "Kybero Labs"

    strings:
        $s1 = "\\Microsoft\\Internet Explorer\\Quick Launch"
        $s2 = "otopiA SoFt1" nocase
        $s3 = "otopiA SoFt0" nocase

    condition:
        all of them
}

rule Adware_OutBrowse_C_con {
    meta:
        description = "Detects OutBrowse"
        author = "Kybero Labs"

    strings:
        $s1 = "\\Microsoft\\Internet Explorer\\Quick Launch"
        $s2 = "SAFe sofTwaRe SlL1" nocase
        $s3 = "SAFe sofTwaRe SlL0" nocase

    condition:
        all of them
}
