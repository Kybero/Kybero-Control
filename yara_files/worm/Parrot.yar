rule Worm_Parrot_A_con {
    meta:
        threat_name = "Worm/Parrot.A!con"
        description = "Detects Parrot"
        author = "Kybero Labs"

    strings:
        $s1 = "[Win32.Parrot] by Gigabyte/Metaphase"

    condition:
        all of them
}
