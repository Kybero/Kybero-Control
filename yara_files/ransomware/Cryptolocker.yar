rule Ransom_Cryptolocker_A_con {
    meta:
        author = "ditekSHen"
        description = "Detects Cryptolocker ransomware variants (Betarasite)"
    strings:
        $x1 = "CryptoLocker" fullword wide
        $x2 = ".betarasite" fullword wide
        $x3 = "CMSTPBypass" fullword ascii
        $s1 = "CommandToExecute" fullword ascii
        $s2 = "SetInfFile" fullword ascii
        $s3 = "SchoolPrject1" ascii
        $s4 = "$730d5f64-bd57-47c1-9af4-d20aec714d02" fullword ascii
        $s5 = "Encrypt" fullword ascii
        $s6 = "Invalide Key! Please Try Again." fullword wide
        $s7 = "RegAsm" fullword wide
        $s8 = "Your key will be destroyed" wide
        $s9 = "encrypted using RC4 and RSA-2048" wide
        $c1 = "https://coinbase.com" fullword wide
        $c2 = "https://localbictoins.com" fullword wide
        $c3 = "https://bitpanda.com" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or all of ($s*) or (2 of ($x*) and 5 of ($s*)) or (all of ($c*) and 1 of ($x*) and 2 of ($s*)))
}

rule Ransom_Cryptolocker_B_con {
	meta:
		description = "Detection of Cryptolocker Samples"
		author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
		date = "2014-04-13"
		rule_version = "v1"
	    malware_type = "ransomware"
	    malware_family = "Ransom:W32/Cryptolocker"
	    actor_type = "Cybercrime"
	    actor_group = "Unknown"
		
		
	strings:
		$string0 = "static"
		$string1 = " kscdS"
		$string2 = "Romantic"
		$string3 = "CompanyName" wide
		$string4 = "ProductVersion" wide
		$string5 = "9%9R9f9q9"
		$string6 = "IDR_VERSION1" wide
		$string7 = "  </trustInfo>"
		$string8 = "LookFor" wide
		$string9 = ":n;t;y;"
		$string10 = "        <requestedExecutionLevel level"
		$string11 = "VS_VERSION_INFO" wide
		$string12 = "2.0.1.0" wide
		$string13 = "<assembly xmlns"
		$string14 = "  <trustInfo xmlns"
		$string15 = "srtWd@@"
		$string16 = "515]5z5"
		$string17 = "C:\\lZbvnoVe.exe" wide

	condition:
		12 of ($string*)
}

rule Ransom_Cryptolocker_C_con {
	meta:
		description = "Detection of CryptoLocker Variants"
		author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
		date = "2014-04-14"
		rule_version = "v1"
	    malware_type = "ransomware"
	    malware_family = "Ransom:W32/Cryptolocker"
	    actor_type = "Cybercrime"
	    actor_group = "Unknown"

	strings:
		$string0 = "2.0.1.7" wide
		$string1 = "    <security>"
		$string2 = "Romantic"
		$string3 = "ProductVersion" wide
		$string4 = "9%9R9f9q9"
		$string5 = "IDR_VERSION1" wide
		$string6 = "button"
		$string7 = "    </security>"
		$string8 = "VFileInfo" wide
		$string9 = "LookFor" wide
		$string10 = "      </requestedPrivileges>"
		$string11 = " uiAccess"
		$string12 = "  <trustInfo xmlns"
		$string13 = "last.inf"
		$string14 = " manifestVersion"
		$string15 = "FFFF04E3" wide
		$string16 = "3,31363H3P3m3u3z3"

	condition:
		12 of ($string*)
}
