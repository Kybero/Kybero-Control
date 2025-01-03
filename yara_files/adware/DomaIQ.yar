rule Adware_DomaIQ_A_con {
    meta:
        description = "Detects DomaIQ"
        author = "Kybero Labs"

    strings:
        $s1 = "Confuser v1"
        $s2 = "Payments Interactive SL1" nocase
        $s3 = "Payments Interactive SL0" nocase

    condition:
        all of them
}

rule Adware_DomaIQ_B_con {
    meta:
        description = "Detects DomaIQ"
        author = "Kybero Labs"

    strings:
        $s1 = "Confuser v1"
        $s2 = "tuguu sl1" nocase
        $s3 = "tuguu sl0" nocase

    condition:
        all of them
}
