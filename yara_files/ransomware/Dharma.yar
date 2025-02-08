rule Ransom_Dharma_A_con {
    meta:
        threat_name = "Ransom/Dharma.A!con"
        author = "ditekSHen"
        description = "Detects Dharma ransomware"
    strings:
        $s1 = "C:\\crysis\\Release\\PDB\\payload.pdb" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}
