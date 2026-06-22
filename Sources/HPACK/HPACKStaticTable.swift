//
//  HPACKStaticTable.swift
//  HPACK
//
//  RFC 7541 Appendix A — the 61-entry static table, generated from the RFC text (not hand-typed).
//  With the dynamic table it forms one index address space (§2.3.3): indices 1...61 are static,
//  62 and up are dynamic.
//

/// The RFC 7541 Appendix A static table.
public enum HPACKStaticTable {

    /// The number of entries in the static table (RFC 7541 Appendix A).
    public static let count = 61

    /// The static table entries, addressed 1...61 in HPACK (here 0-based: `entries[index - 1]`).
    public static let entries: [HPACKField] = [
        HPACKField(name: ":authority"),
        HPACKField(name: ":method", value: "GET"),
        HPACKField(name: ":method", value: "POST"),
        HPACKField(name: ":path", value: "/"),
        HPACKField(name: ":path", value: "/index.html"),
        HPACKField(name: ":scheme", value: "http"),
        HPACKField(name: ":scheme", value: "https"),
        HPACKField(name: ":status", value: "200"),
        HPACKField(name: ":status", value: "204"),
        HPACKField(name: ":status", value: "206"),
        HPACKField(name: ":status", value: "304"),
        HPACKField(name: ":status", value: "400"),
        HPACKField(name: ":status", value: "404"),
        HPACKField(name: ":status", value: "500"),
        HPACKField(name: "accept-charset"),
        HPACKField(name: "accept-encoding", value: "gzip, deflate"),
        HPACKField(name: "accept-language"),
        HPACKField(name: "accept-ranges"),
        HPACKField(name: "accept"),
        HPACKField(name: "access-control-allow-origin"),
        HPACKField(name: "age"),
        HPACKField(name: "allow"),
        HPACKField(name: "authorization"),
        HPACKField(name: "cache-control"),
        HPACKField(name: "content-disposition"),
        HPACKField(name: "content-encoding"),
        HPACKField(name: "content-language"),
        HPACKField(name: "content-length"),
        HPACKField(name: "content-location"),
        HPACKField(name: "content-range"),
        HPACKField(name: "content-type"),
        HPACKField(name: "cookie"),
        HPACKField(name: "date"),
        HPACKField(name: "etag"),
        HPACKField(name: "expect"),
        HPACKField(name: "expires"),
        HPACKField(name: "from"),
        HPACKField(name: "host"),
        HPACKField(name: "if-match"),
        HPACKField(name: "if-modified-since"),
        HPACKField(name: "if-none-match"),
        HPACKField(name: "if-range"),
        HPACKField(name: "if-unmodified-since"),
        HPACKField(name: "last-modified"),
        HPACKField(name: "link"),
        HPACKField(name: "location"),
        HPACKField(name: "max-forwards"),
        HPACKField(name: "proxy-authenticate"),
        HPACKField(name: "proxy-authorization"),
        HPACKField(name: "range"),
        HPACKField(name: "referer"),
        HPACKField(name: "refresh"),
        HPACKField(name: "retry-after"),
        HPACKField(name: "server"),
        HPACKField(name: "set-cookie"),
        HPACKField(name: "strict-transport-security"),
        HPACKField(name: "transfer-encoding"),
        HPACKField(name: "user-agent"),
        HPACKField(name: "vary"),
        HPACKField(name: "via"),
        HPACKField(name: "www-authenticate"),
    ]

    /// Returns the static entry at HPACK index `index` (1...61), or `nil` if out of range.
    public static func field(at index: Int) -> HPACKField? {
        guard index >= 1, index <= count else { return nil }
        return entries[index - 1]
    }
}
