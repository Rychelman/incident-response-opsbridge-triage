rule OpsBridge_Agent_C2 {
    meta:
        description = "Detects OpsBridge C2 persistent agent configurations and binary strings"
        author = "Rychelman Rodriguez"
        date = "2026-08-26"
    strings:
        $s1 = "opsbridge.digital" ascii wide nocase
        $s2 = "enrollment_key" ascii wide
        $s3 = "auto_persist" ascii wide
        $bin = "OpsBridgeAgent.exe" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or $bin)
}
