rule Trojan_Generic_A {
    meta:
        description = "Detects trojan executables posing as the EICAR test file"
        author = "Kybero Labs"

    strings:
        $s1 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
        $s2 = "This program cannot be run in DOS mode"

    condition:
        uint16(0) == 0x5a4d and all of them
}
