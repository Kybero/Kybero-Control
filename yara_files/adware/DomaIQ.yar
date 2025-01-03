rule Adware_DomaIQ_gen {
    meta:
        description = "Detects DomaIQ"
        author = "Kybero Labs"

    strings:
        $s1 = "Payments Interactive SL1"
        $s2 = "Payments Interactive SL0"
        $s3 = "Confuser v1"

    condition:
        all of them
}

rule Adware_DomaIQ_A_con {
    meta:
        description = "Detects DomaIQ"
        author = "Kybero Labs"

    strings:
        $s1 = "c:\\work\\otronombre2.pdb"
        $s2 = "Payments Interactive SL1"
        $s3 = "Payments Interactive SL0"

    condition:
        all of them
}

rule Adware_DomaIQ_B_con {
    meta:
        description = "Detects DomaIQ"
        author = "Kybero Labs"

    strings:
        $s1 = "Confuser v1"
        $s2 = "tuguu sl1"
        $s3 = "tuguu sl0"

    condition:
        all of them
}

rule Adware_DomaIQ_C_con {
    meta:
        description = "Detects DomaIQ"
        author = "Kybero Labs"

    strings:
        $s1 = "c:\\stout.pdb"
        $s2 = "Payments Interactive SL1"
        $s3 = "Payments Interactive SL0"

    condition:
        all of them
}
