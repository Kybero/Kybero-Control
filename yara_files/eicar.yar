rule EICARTestFile_A_con {
    meta:
        description = "EICAR test file string (full)"
        author = "Kybero Labs"

    strings:
        $s = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $s
}

rule EICARTestFile_B_con {
    meta:
        description = "EICAR test file string (shortened)"
        author = "Kybero Labs"

    strings:
        $s = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"

        $f = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $s and not $f
}
