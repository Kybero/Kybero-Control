rule Trojan_Occamy_A_con {
    meta:
        threat_name = "Trojan/Occamy.A!con"
        description = "Detects Occamy"
        author = "Kybero Labs"

    strings:
        $s1 = "http://www.dego-gh.com/"

    condition:
        uint16(0) == 0x5a4d and all of them
}
