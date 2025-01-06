rule Adware_Morstar_A_con {
    meta:
        description = "Detects Firseria"
        author = "Kybero Labs"

    strings:
        $s1 = "GlobalSign CodeSigning CA - G20"
        $s2 = "Eilio Developments sl1" nocase
        $s3 = "Eilio Developments sl0" nocase
        $s4 = "http://secure.globalsign.com/cacert/gscodesigng2.crt"
        $s5 = "unzip 1.01 Copyright 1998-2004 Gilles Vollant - http://www.winimage.com/zLibDll"

    condition:
        all of them
}
