rule Adware_InstallBrain_A_con {
    meta:
        description = "Detects InstallBrain based on certificate"
        author = "Kybero Labs"

    strings:
        $s1 = "Performersoft LLC1"
        $s2 = "Performersoft LLC0"

        $c1 = "Time Stamping" // to ensure the entry is a certificate
        $c2 = "Certification"

    condition:
        all of $s* and ( $c1 or $c2 )
}
