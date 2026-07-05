//
//  HTTPDate.swift
//  HTTPCore
//
//  RFC 9110 §5.6.7 — the preferred HTTP date format, IMF-fixdate (e.g. `Sun, 06 Nov 1994 08:49:37
//  GMT`). Formatted from a Unix timestamp with civil-from-days arithmetic (Howard Hinnant's
//  algorithm), so it needs no `Foundation` and no allocation beyond the result string. Iterative.
//

import ADFCore

/// Formats and parses HTTP dates (RFC 9110 §5.6.7) — IMF-fixdate is the form generated.
public enum HTTPDate {
    private static let weekdays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    private static let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    ]

    /// The IMF-fixdate string for `secondsSinceEpoch` (RFC 9110 §5.6.7), always in GMT.
    public static func imfFixdate(_ secondsSinceEpoch: Int) -> String {
        let days = Int((Double(secondsSinceEpoch) / 86_400).rounded(.down))
        let secondOfDay = secondsSinceEpoch - days * 86_400
        let (year, month, day) = civil(fromDays: days)
        let weekday = ((days % 7) + 4 + 7) % 7  // 1970-01-01 was a Thursday (index 4)
        let hour = secondOfDay / 3_600
        let minute = (secondOfDay % 3_600) / 60
        let second = secondOfDay % 60
        // IMF-fixdate is exactly 29 ASCII octets ("Sun, 06 Nov 1994 08:49:37 GMT"); fill the buffer in a
        // single allocation rather than the ~8 that interpolation + `pad` made per response (audit F10 —
        // a Date header is on every response). Offsets: Www[0-2] ","[3] " "[4] DD[5-6] " "[7] Mon[8-10]
        // " "[11] YYYY[12-15] " "[16] HH[17-18] ":"[19] MM[20-21] ":"[22] SS[23-24] " "[25] GMT[26-28].
        let zero = UInt8(ascii: "0")
        return String(unsafeUninitializedCapacity: 29) { buffer in
            func put(_ text: String, at offset: Int) {
                var index = offset
                for byte in text.utf8 {
                    buffer[index] = byte
                    index += 1
                }
            }
            func put2(_ value: Int, at offset: Int) {
                buffer[offset] = zero + UInt8(value / 10)
                buffer[offset + 1] = zero + UInt8(value % 10)
            }
            put(weekdays[weekday], at: 0)
            buffer[3] = UInt8(ascii: ",")
            buffer[4] = UInt8(ascii: " ")
            put2(day, at: 5)
            buffer[7] = UInt8(ascii: " ")
            put(months[month - 1], at: 8)
            buffer[11] = UInt8(ascii: " ")
            // 4 digits, defensive for any input range
            let yyyy = ((year % 10_000) + 10_000) % 10_000
            buffer[12] = zero + UInt8(yyyy / 1_000)
            buffer[13] = zero + UInt8((yyyy / 100) % 10)
            buffer[14] = zero + UInt8((yyyy / 10) % 10)
            buffer[15] = zero + UInt8(yyyy % 10)
            buffer[16] = UInt8(ascii: " ")
            put2(hour, at: 17)
            buffer[19] = UInt8(ascii: ":")
            put2(minute, at: 20)
            buffer[22] = UInt8(ascii: ":")
            put2(second, at: 23)
            buffer[25] = UInt8(ascii: " ")
            put("GMT", at: 26)
            return 29
        }
    }

    /// Year/month/day from days since 1970-01-01 (Hinnant's civil-from-days; no recursion, no leap
    /// tables).
    private static func civil(fromDays days: Int) -> (year: Int, month: Int, day: Int) {
        let shifted = days + 719_468  // shift the epoch to 0000-03-01
        let era = (shifted >= 0 ? shifted : shifted - 146_096) / 146_097
        let dayOfEra = shifted - era * 146_097  // [0, 146096]
        // [0, 399]
        let yearOfEra =
            (dayOfEra - dayOfEra / 1_460 + dayOfEra / 36_524 - dayOfEra / 146_096) / 365
        let year = yearOfEra + era * 400
        let dayOfYear = dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100)  // [0, 365]
        let monthPrime = (5 * dayOfYear + 2) / 153  // [0, 11]
        let day = dayOfYear - (153 * monthPrime + 2) / 5 + 1  // [1, 31]
        let month = monthPrime < 10 ? monthPrime + 3 : monthPrime - 9  // [1, 12]
        return (month <= 2 ? year + 1 : year, month, day)
    }

    /// Parses an HTTP-date into seconds since the Unix epoch (UTC), or nil if malformed (RFC 9110
    /// §5.6.7). Delegates to the shared, Foundation-free ``ADFCore/HTTPDateParser`` — the one place the
    /// AD* family's HTTP-date parsing lives (also used by `ADServeCore`) — accepting the preferred
    /// IMF-fixdate plus the obsolete rfc850 / asctime forms a recipient must still accept.
    public static func parse(_ value: String) -> Int? {
        HTTPDateParser.parse(value)
    }
}
