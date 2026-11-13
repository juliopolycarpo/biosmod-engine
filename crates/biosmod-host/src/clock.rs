//! Wall-clock time as a fakeable surface.

use std::time::{SystemTime, UNIX_EPOCH};

/// A point in time, whole seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    pub unix_seconds: u64,
}

/// Source of the current time.
pub trait Clock {
    fn now(&self) -> Timestamp;
}

/// The system clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        Timestamp { unix_seconds }
    }
}

impl Timestamp {
    /// UTC `(year, month, day, hour, minute, second)`.
    fn civil(self) -> (i64, u32, u32, u32, u32, u32) {
        let seconds = self.unix_seconds as i64;
        let days = seconds.div_euclid(86_400);
        let of_day = seconds.rem_euclid(86_400) as u32;
        // Days since 1970-01-01 to a proleptic Gregorian date (Hinnant's civil_from_days).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let day_of_era = z.rem_euclid(146_097);
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let shifted_month = (5 * day_of_year + 2) / 153;
        let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
        let month = if shifted_month < 10 {
            shifted_month + 3
        } else {
            shifted_month - 9
        } as u32;
        let year = year_of_era + era * 400 + i64::from(month <= 2);
        (
            year,
            month,
            day,
            of_day / 3600,
            of_day / 60 % 60,
            of_day % 60,
        )
    }

    /// `YYYY-MM-DD` in UTC, the date format of evidence records.
    ///
    /// Example: `Timestamp { unix_seconds: 1_794_441_600 }.date()` is `"2026-11-12"`.
    pub fn date(self) -> String {
        let (year, month, day, ..) = self.civil();
        format!("{year:04}-{month:02}-{day:02}")
    }

    /// `YYYY-MM-DDThh:mm:ssZ`.
    ///
    /// Example: `Timestamp { unix_seconds: 0 }.rfc3339()` is `"1970-01-01T00:00:00Z"`.
    pub fn rfc3339(self) -> String {
        let (year, month, day, hour, minute, second) = self.civil();
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_match_known_instants() {
        for (seconds, expected) in [
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_794_441_600 + 3_661, "2026-11-12T01:01:01Z"),
            (4_102_444_799, "2099-12-31T23:59:59Z"),
        ] {
            let stamp = Timestamp {
                unix_seconds: seconds,
            };
            assert_eq!(stamp.rfc3339(), expected, "unix seconds {seconds}");
            assert_eq!(stamp.date(), expected[..10]);
        }
    }

    #[test]
    fn system_clock_reports_a_plausible_present() {
        assert!(SystemClock.now().unix_seconds > 1_700_000_000);
    }
}
