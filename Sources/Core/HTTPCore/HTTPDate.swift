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
        return
            "\(weekdays[weekday]), \(pad(day)) \(months[month - 1]) \(year) "
            + "\(pad(hour)):\(pad(minute)):\(pad(second)) GMT"
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

    /// A two-digit, zero-padded decimal (the date fields are all `0...99`).
    private static func pad(_ value: Int) -> String {
        value < 10 ? "0\(value)" : "\(value)"
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
