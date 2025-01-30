rule Ransom_Zeoticus_A_con {
	meta:
		description = "Zeoticus rule based on email addresses provided by SISA"
		author = "Protectish"
		reference = "https://www.sisainfosec.com/blogs/zeoticus-2-0-ransomware-all-you-need-to-know/"
	strings:
		$s1 = "outsource@tutanota.com" fullword wide
		$s2 = "outsource@cock.li" fullword wide
	condition:
		all of them
}
