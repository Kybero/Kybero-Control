rule Trojan_Winnti_A_con {
   meta:
      threat_name = "Trojan/Winnti.A!con"
      description = "Winnti signature mentioned by Cylance"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      hash1 = "7c32885c258a6d5be37ebe83643f00165da3ebf963471503909781540204752e"
   strings:
      $s1 = "WOODTALE TECHNOLOGY INC" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them )
}

rule Trojan_Winnti_B_con {
   meta:
      description = "Winnti sample - file fonfig.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/VbvJtL"
      date = "2017-01-25"
      hash1 = "2c9882854a60c624ecf6b62b6c7cc7ed04cf4a29814aa5ed1f1a336854697641"
      id = "ca3c186c-0286-5b9b-9585-7680336c8c3d"
   strings:
      $s1 = "mciqtz.exe" fullword wide
      $s2 = "knat9y7m" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule Trojan_Winnti_C_con {
   meta:
      description = "Winnti sample - file NlaifSvc.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/VbvJtL"
      date = "2017-01-25"
      hash1 = "964f9bfd52b5a93179b90d21705cd0c31461f54d51c56d558806fe0efff264e5"
      id = "d2bfcad4-9762-5f2a-88cc-e8cdc648e710"
   strings:
      $x1 = "cracked by ximo" ascii

      $s1 = "Yqrfpk" fullword ascii
      $s2 = "IVVTOC" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and ( 1 of ($x*) or 2 of them ) ) or ( 3 of them )
}
