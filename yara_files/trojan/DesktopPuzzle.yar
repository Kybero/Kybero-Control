rule Trojan_DesktopPuzzle_A_con {
    meta:
        threat_name = "Trojan/DesktopPuzzle.A!con"
        description = "Detects DesktopPuzzle message"
        author = "Kybero Labs"

    strings:
        $s1 = "Oops, looks like somebody doesn't like you very much ! You have to finish this sliding tile puzzle before you can continue whatever it is you're doing ! Use the cursor keys to move the pieces (black piece is the empty one)."

    condition:
        uint16(0) == 0x5a4d and all of them
}
