rule Ransom_Annabelle_A_con {
    meta:
        threat_name = "Ransom/Annabelle.A!con"
        description = "Detects Annabelle"
        author = "Kybero Labs"

    strings:
        $s1 = "Annabelle.exe"
        $s2 = "Annabelle.My"
        $s3 = "Annabelle.Resources.resources"
        $s4 = "ConfuserEx v1.0.0"

    condition:
        all of them
}
