rule Worm_ZippedFiles_A_con {
    meta:
        threat_name = "Worm/ZippedFiles.A!con"
        description = "Detects ZippedFiles email"
        author = "Kybero Labs"

    strings:
        $s1 = "I received your email and I shall send you a reply ASAP."
        $s2 = "Till then, take a look at the attached zipped docs. Very important news for you."

    condition:
        uint16(0) == 0x5a4d and all of them
}
