rule Worm_MyDoom_A_con {
    meta:
        threat_name = "Worm/MyDoom.A!con"
        description = "Detects MyDoom"
        author = "Kybero Labs"

    strings:
        $s1 = "\\Miš¦išcrosofiš¦it\\Win¦iš¦dows\\š¦išCurren¦"
        $s2 = "¤itVrsš¦išion\\Ru"

    condition:
        all of them
}
