rule Ransom/BlinkerObject_A_con {
    meta:
        threat_name = "Ransom/BlinkerObject.A!con"
        description = "Detects BlinkerObject"
        author = "Kybero Labs"

    strings:
        $s1 = "BlinkerObject.exe"
        $s2 = "BlinkerObject.Properties"

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule Ransom/BlinkerObject_B_con {
    meta:
        threat_name = "Ransom/BlinkerObject.B!con"
        description = "Detects BlinkerObject certificate"
        author = "Kybero Labs"

    strings:
        $s1 = "win.rar GmbH0"

    condition:
        uint16(0) == 0x5a4d and all of them
}
