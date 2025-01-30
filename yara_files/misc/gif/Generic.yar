rule GIF_GenericAnomaly_A {
   meta:
      threat_name = "GIF/GenericAnomaly.A"
      description = "Detects files with GIF headers and format anomalies - which means that this image could be an obfuscated file of a different type"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      reference = "https://en.wikipedia.org/wiki/GIF"
      date = "2020-07-02"
      id = "2e77c2ff-a8f6-5444-a93d-843312640a28"
   condition:
      uint16(0) == 0x4947 and uint8(2) == 0x46 /* GIF */
      and uint8(11) != 0x00 /* Background Color Index != 0 */
      and uint8(12) != 0x00 /* Pixel Aspect Ratio != 0 */
      and uint8(filesize-1) != 0x3b /* Trailer (trailes are often 0x00 byte padded and cannot server as sole indicator) */
}
