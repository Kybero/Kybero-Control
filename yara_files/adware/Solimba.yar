rule Adware_Solimba_A_con {
    meta:
        description = "Detects Solimba certificate"
        author = "Kybero Labs"

    strings:
        $s = "Solimba Aplicaciones S.L.0"

    condition:
        uint16(0) == 0x5a4d and $s
}
