//
//  HTTPDate.swift
//  HTTPCore
//
//  RFC 9110 §5.6.7 — the preferred HTTP date format, IMF-fixdate (e.g. `Sun, 06 Nov 1994 08:49:37
//  GMT`). Formatted from a Unix timestamp with civil-from-days arithmetic (Howard Hinnant's
//  algorithm), so it needs no `Foundation` and no allocation beyond the result string. Iterative.
//

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
    /// §5.6.7).
    ///
    /// Accepts the preferred IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`) and the two obsolete forms a
    /// recipient must still accept — rfc850 (`Sunday, 06-Nov-94 08:49:37 GMT`) and asctime
    /// (`Sun Nov  6 08:49:37 1994`). Lenient tokenizing; never traps on hostile input.
    public static func parse(_ value: String) -> Int? {
        let tokens = value.split { $0 == " " || $0 == "\t" || $0 == "," }
        switch tokens.count {
            case 6:
                return parseIMFFixdate(tokens)
            case 5:
                return parseAsctime(tokens)
            case 4:
                return parseRFC850(tokens)
            default:
                return nil
        }
    }

    /// IMF-fixdate: `Sun, 06 Nov 1994 08:49:37 GMT` → [Sun, 06, Nov, 1994, 08:49:37, GMT].
    private static func parseIMFFixdate(_ tokens: [Substring]) -> Int? {
        guard tokens[5] == "GMT", let day = Int(tokens[1]), let month = monthIndex(tokens[2]),
            let year = Int(tokens[3])
        else {
            return nil
        }
        return epoch(year: year, month: month, day: day, time: tokens[4])
    }

    /// asctime: `Sun Nov  6 08:49:37 1994` → [Sun, Nov, 6, 08:49:37, 1994].
    private static func parseAsctime(_ tokens: [Substring]) -> Int? {
        guard let month = monthIndex(tokens[1]), let day = Int(tokens[2]), let year = Int(tokens[4])
        else {
            return nil
        }
        return epoch(year: year, month: month, day: day, time: tokens[3])
    }

    /// rfc850: `Sunday, 06-Nov-94 08:49:37 GMT` → [Sunday, 06-Nov-94, 08:49:37, GMT].
    private static func parseRFC850(_ tokens: [Substring]) -> Int? {
        guard tokens[3] == "GMT" else {
            return nil
        }
        let parts = tokens[1].split(separator: "-")
        guard parts.count == 3, let day = Int(parts[0]), let month = monthIndex(parts[1]),
            let shortYear = Int(parts[2])
        else {
            return nil
        }
        // A 2-digit year pivoted at 70 (a far-future value is read as the recent past, RFC 6265 §5.1.1).
        let year = shortYear < 70 ? 2_000 + shortYear : 1_900 + shortYear
        return epoch(year: year, month: month, day: day, time: tokens[2])
    }

    /// Seconds since the epoch for a calendar date and an `HH:MM:SS` token, or nil if out of range.
    private static func epoch(year: Int, month: Int, day: Int, time: Substring) -> Int? {
        let parts = time.split(separator: ":")
        guard parts.count == 3, let hour = Int(parts[0]), let minute = Int(parts[1]),
            let second = Int(parts[2]),
            (1 ... 12).contains(month), (1 ... 31).contains(day),
            (0 ... 23).contains(hour), (0 ... 59).contains(minute), (0 ... 60).contains(second)
        else {
            return nil
        }
        return daysFromCivil(year: year, month: month, day: day) * 86_400
            + hour * 3_600 + minute * 60 + second
    }

    /// Days since 1970-01-01 for a calendar date — Hinnant's days-from-civil, the inverse of
    /// ``civil(fromDays:)``.
    private static func daysFromCivil(year: Int, month: Int, day: Int) -> Int {
        let shiftedYear = month <= 2 ? year - 1 : year
        let era = (shiftedYear >= 0 ? shiftedYear : shiftedYear - 399) / 400
        let yearOfEra = shiftedYear - era * 400
        let dayOfYear = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1
        let dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear
        return era * 146_097 + dayOfEra - 719_468
    }

    /// The 1-based month number for a three-letter English month name, or nil if unrecognized.
    private static func monthIndex(_ name: some StringProtocol) -> Int? {
        months.firstIndex(of: String(name)).map { $0 + 1 }
    }
}
