rule EICARTestFile.A!con {
    meta:
        description = "EICAR test file string (full)"

    strings:
        $s = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $s
}

rule EICARTestFile.B!con {
    meta:
        description = "EICAR test file string (shortened)"

    strings:
        $s = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"

        $f = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $s and not $f
}
