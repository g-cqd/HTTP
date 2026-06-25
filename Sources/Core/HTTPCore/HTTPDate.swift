//
//  HTTPDate.swift
//  HTTPCore
//
//  RFC 9110 §5.6.7 — the preferred HTTP date format, IMF-fixdate (e.g. `Sun, 06 Nov 1994 08:49:37
//  GMT`). Formatted from a Unix timestamp with civil-from-days arithmetic (Howard Hinnant's
//  algorithm), so it needs no `Foundation` and no allocation beyond the result string. Iterative.
//

/// Formats HTTP dates in the IMF-fixdate form (RFC 9110 §5.6.7).
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
}
