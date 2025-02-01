rule Trojan_SpySheriff_A_con {
    meta:
        threat_name = "Trojan/SpySheriff.A!con"
        description = "Detects SpySheriff executable"
        author = "Kybero Labs"

    strings:
        $s = "<description>SpySheriff Spyware scanner and remover.</description>"

    condition:
        uint16(0) == 0x5a4d and $s
}
