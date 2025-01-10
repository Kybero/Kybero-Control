rule RAT_AsyncRAT_A_con {
   meta:
      description = "AsyncRAT v0.5.7B - Remote Administration Tool, became popular across hackforums members"
      author = "IrishIRL"
      reference = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
      date = "2022-12-03"
      hash1 = "42b647e06beb09787a9ef602cac06caeacc44ca14b4cceb69520f9dcbb946854"

   strings:
      $magic = "MZ"

      $required01 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide
      $required02 = "START \"\" \"" fullword wide
      $required03 = "DEL \"" fullword wide
      // $required04 = "Stub.exe" fullword wide // official builder requires Stub.exe. However, other builders could easily change to another name.

      $imports01 = "System.Drawing.Imaging" fullword ascii
      $imports02 = "System.Net.Sockets" fullword ascii
      $imports03 = "System.Security.Cryptography" fullword ascii

      $suspicious01 = "HWID" fullword wide
      $suspicious02 = "Pastebin" fullword wide
      $suspicious03 = "Antivirus" fullword wide
      $suspicious04 = "R\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
      $suspicious05 = "Select * from Win32_ComputerSystem" fullword wide
      $suspicious06 = "timeout 3 > NUL" fullword wide

      $antivm01 = "vmware" fullword wide
      $antivm02 = "VirtualBox" fullword wide
      $antivm03 = "SbieDll.dll" fullword wide
      $antivm04 = "VIRTUAL" fullword wide

   condition:
      $magic at 0 and
      all of ($required*) and all of ($imports*) and
      (all of ($suspicious*) or all of ($antivm*) or
      (3 of ($suspicious*) and 2 of ($antivm*)))
}

rule RAT_AsyncRAT_B_con {
    meta:
        description = "detect AsyncRat in memory"
        author = "JPCERT/CC Incident Response Group"
        rule_usage = "memory scan"
        reference = "internal research"
        hash1 = "1167207bfa1fed44e120dc2c298bd25b7137563fdc9853e8403027b645e52c19"
        hash2 = "588c77a3907163c3c6de0e59f4805df41001098a428c226f102ed3b74b14b3cc"

    strings:
        $salt = {BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43 00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41}
        $b1 = {00 00 00 0D 53 00 48 00 41 00 32 00 35 00 36 00 00}
        $b2 = {09 50 00 6F 00 6E 00 67 00 00}
        $s1 = "pastebin" ascii wide nocase
        $s2 = "pong" wide
        $s3 = "Stub.exe" ascii wide
    condition:  ($salt and (2 of ($s*) or 1 of ($b*))) or (all of ($b*) and 2 of ($s*))
}
