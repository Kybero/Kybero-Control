rule Adware_OutBrowse_A_con {
    meta:
        description = "Detects OutBrowse"
        author = "Kybero Labs"

    strings:
        $s1 = "\\Microsoft\\Internet Explorer\\Quick Launch"
        $s2 = "OUTBROWSE1"
        $s3 = "OUTBROWSE0"

    condition:
        all of them
}

rule Adware_OutBrowse_B_con {
    meta:
        description = "Detects OutBrowse"
        author = "Kybero Labs"

    strings:
        $s1 = "\\Microsoft\\Internet Explorer\\Quick Launch"
        $s2 = "otopiA SoFt1"

    condition:
        all of them
}
