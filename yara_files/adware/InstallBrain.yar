rule Adware_InstallBrain_A_con {
    meta:
        threat_name = "Adware/InstallBrain.A!con"
        description = "Detects InstallBrain based on certificate"
        author = "Kybero Labs"

    strings:
        $s1 = "Performersoft LLC1"
        $s2 = "Performersoft LLC0"

        $c1 = "Time Stamping" // to ensure the entry is a certificate
        $c2 = "Certification"

    condition:
        all of ($s*) and ($c1 or $c2)
}

rule Adware_InstallBrain_B_con {
    meta:
        threat_name = "Adware/InstallBrain.B!con"
        description = "Detects InstallBrain based on certificate"
        author = "Kybero Labs"

    strings:
        $s1 = "Yellowsoft Inc1"
        $s2 = "Yellowsoft Inc0"

        $c1 = "Time Stamping" // to ensure the entry is a certificate
        $c2 = "Certification"

    condition:
        all of ($s*) and ($c1 or $c2)
}
