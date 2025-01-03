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
