rule Adware_Gamevance_A_con {
    meta:
        description = "Detects Firseria based on certificate (prone to false positives)"
        author = "Kybero Labs"

    strings:
        $s1 = "GlobalSign CodeSigning CA"
        $s2 = "Apps Installer SL1"
        $s3 = "Apps Installer SL0"
        $s4 = "http://secure.globalsign.com/cacert/gstimestampingg2.crt"

    condition:
        all of them
}
