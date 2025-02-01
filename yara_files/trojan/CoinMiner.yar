import "pe"

rule Trojan_CoinMiner_A_con {
   meta:
      description = "Rule to detect Coinminer malware"
      author = "Trellix ATR"
      date = "2021-07-22"
      version = "v1"
      hash1 = "3bdac08131ba5138bcb5abaf781d6dc7421272ce926bc37fa27ca3eeddcec3c2"
      hash2 = "d60766c4e6e77de0818e59f687810f54a4e08505561a6bcc93c4180adb0f67e7"
   
   strings:
  
      $seq0 = { df 75 ab 7b 80 bf 83 c1 48 b3 18 74 70 01 24 5c }
      $seq1 = { 08 37 4e 6e 0f 50 0b 11 d0 98 0f a8 b8 27 47 4e }
      $seq2 = { bf 17 5a 08 09 ab 80 2f a1 b0 b1 da 47 9f e1 61 }
      $seq3 = { 53 36 34 b2 94 01 cc 05 8c 36 aa 8a 07 ff 06 1f }
      $seq4 = { 25 30 ae c4 44 d1 97 82 a5 06 05 63 07 02 28 3a }
      $seq5 = { 01 69 8e 1c 39 7b 11 56 38 0f 43 c8 5f a8 62 d0 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and pe.imphash() == "e4290fa6afc89d56616f34ebbd0b1f2c" and 3 of ($seq*)
      ) 
}

rule Trojan_CoinMiner_B_con {
   meta:
      threat_name = "Trojan/CoinMiner.B!con"
      description = "Detects mining pool protocol string in Executable"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      reference = "https://minergate.com/faq/what-pool-address"
      date = "2018-01-04"
      modified = "2021-10-26"
      nodeepdive = 1
      id = "ac045f83-5f32-57a9-8011-99a2658a0e05"
   strings:
      $sa1 = "stratum+tcp://" ascii
      $sa2 = "stratum+udp://" ascii
      $sb1 = "\"normalHashing\": true,"
   condition:
      filesize < 3000KB and 1 of them
}

rule Trojan_CoinMiner_C_con {
    meta:
        threat_name = "Trojan/CoinMiner.C!con"
        author = "ditekSHen"
        description = "Detects executables referencing many cryptocurrency mining wallets or apps. Observed in information stealers"
    strings:
        $app1 = "Ethereum" nocase ascii wide
        $app2 = "Bitcoin" nocase ascii wide
        $app3 = "Litecoin" nocase ascii wide
        $app4 = "NavCoin4" nocase ascii wide
        $app5 = "ByteCoin" nocase ascii wide
        $app6 = "PotCoin" nocase ascii wide
        $app7 = "Gridcoin" nocase ascii wide
        $app8 = "VERGE" nocase ascii wide
        $app9 = "DogeCoin" nocase ascii wide
        $app10 = "FlashCoin" nocase ascii wide
        $app11 = "Sia" nocase ascii wide
        $app12 = "Reddcoin" nocase ascii wide
        $app13 = "Electrum" nocase ascii wide
        $app14 = "Emercoin" nocase ascii wide
        $app15 = "Exodus" nocase ascii wide
        $app16 = "BBQCoin" nocase ascii wide
        $app17 = "Franko" nocase ascii wide
        $app18 = "IOCoin" nocase ascii wide
        $app19 = "Ixcoin" nocase ascii wide
        $app20 = "Mincoin" nocase ascii wide
        $app21 = "YACoin" nocase ascii wide
        $app22 = "Zcash" nocase ascii wide
        $app23 = "devcoin" nocase ascii wide
        $app24 = "Dash" nocase ascii wide
        $app25 = "Monero" nocase ascii wide
        $app26 = "Riot Games\\" nocase ascii wide
        $app27 = "qBittorrent\\" nocase ascii wide
        $app28 = "Battle.net\\" nocase ascii wide
        $app29 = "Steam\\" nocase ascii wide
        $app30 = "Valve\\Steam\\" nocase ascii wide
        $app31 = "Anoncoin" nocase ascii wide
        $app32 = "DashCore" nocase ascii wide
        $app33 = "DevCoin" nocase ascii wide
        $app34 = "DigitalCoin" nocase ascii wide
        $app35 = "Electron" nocase ascii wide
        $app36 = "ElectrumLTC" nocase ascii wide
        $app37 = "FlorinCoin" nocase ascii wide
        $app38 = "FrancoCoin" nocase ascii wide
        $app39 = "JAXX" nocase ascii wide
        $app40 = "MultiDoge" ascii wide
        $app41 = "TerraCoin" ascii wide
        $app42 = "Electrum-LTC" ascii wide
        $app43 = "ElectrumG" ascii wide
        $app44 = "Electrum-btcp" ascii wide
        $app45 = "MultiBitHD" ascii wide
        $app46 = "monero-project" ascii wide
        $app47 = "Bitcoin-Qt" ascii wide
        $app48 = "BitcoinGold-Qt" ascii wide
        $app49 = "Litecoin-Qt" ascii wide
        $app50 = "BitcoinABC-Qt" ascii wide
        $app51 = "Exodus Eden" ascii wide
        $app52 = "myether" ascii wide
        $app53 = "factores-Binance" ascii wide
        $app54 = "metamask" ascii wide
        $app55 = "kucoin" ascii wide
        $app56 = "cryptopia" ascii wide
        $app57 = "binance" ascii wide
        $app58 = "hitbtc" ascii wide
        $app59 = "litebit" ascii wide
        $app60 = "coinEx" ascii wide
        $app61 = "blockchain" ascii wide
        $app62 = "\\Armory" ascii wide
        $app63 = "\\Atomic" ascii wide
        $app64 = "\\Bytecoin" ascii wide
        $app65 = "simpleos" ascii wide
        $app66 = "WalletWasabi" ascii wide
        $app67 = "atomic\\" ascii wide
        $app68 = "Guarda\\" ascii wide
        $app69 = "Neon\\" ascii wide
        $app70 = "Blockstream\\" ascii wide
        $app71 = "GreenAddress Wallet\\" ascii wide
        $app72 = "bitpay\\" ascii wide

        $ne1 = "C:\\src\\pgriffais_incubator-w7\\Steam\\main\\src\\external\\libjingle-0.4.0\\talk/base/scoped_ptr.h" fullword wide
        $ne2 = "\"%s\\bin\\%slauncher.exe\" -hproc %x -hthread %x -baseoverlayname %s\\%s" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (not any of ($ne*) and 6 of them)
}
