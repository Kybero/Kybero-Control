import "pe"

rule RAT_Generic_A {
   meta:
        threat_name = "RAT/Generic.A"
        author = "Lucas Acha (http://www.lukeacha.com)"
        description = "Generic Detection for multiple RAT families, PUPs, Packers and suspicious executables"
  strings:
      $htt1 = "WScript.Shell" wide
      $htt2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
      $htt3 = "\\nuR\\noisreVtnerruC\\swodniW" wide
      $htt4 = "SecurityCenter2" wide
      $htt5 = ":ptth" wide
      $htt6 = ":sptth" wide
      $htt7 = "System.Reflection" ascii
      $htt8 = "ConfuserEx" ascii
      $htt9 = ".NET Framework 4 Client Profile" ascii
      $htt10 = "CreateEncryptor" ascii
      $mzh = "This program cannot be run in DOS mode"
  condition:
      (pe.imphash() == "b8bb385806b89680e13fc0cf24f4431e" or pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744") and 3 of ($htt*) and $mzh
}
