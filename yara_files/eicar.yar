rule EICARTestFile_A_con {
    meta:
        threat_name = "EICARTestFile.A!con"
        description = "EICAR test file string (full)"
        author = "Kybero Labs"

    strings:
        $s = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

        $x = "This program cannot be run in DOS mode"

    condition:
        $s and not $x
}

rule EICARTestFile_B_con {
    meta:
        threat_name = "EICARTestFile.B!con"
        description = "EICAR test file string (shortened)"
        author = "Kybero Labs"

    strings:
        $s = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"

        $f1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        $f2 = "This program cannot be run in DOS mode"

    condition:
        $s and not $f1 and not $f2
}
