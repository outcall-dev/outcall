use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

pub(crate) fn now_iso8601() -> Result<String> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    format_unix_timestamp(i64::try_from(seconds).context("system clock exceeds i64 seconds")?)
}

pub(crate) fn format_unix_timestamp(seconds: i64) -> Result<String> {
    let seconds = u64::try_from(seconds).context("timestamp is before the Unix epoch")?;
    let days_since_epoch = seconds / 86_400;
    let time_of_day = seconds % 86_400;
    let hours = time_of_day / 3_600;
    let minutes = (time_of_day % 3_600) / 60;
    let seconds = time_of_day % 60;
    let (year, month, day) = days_to_ymd(days_since_epoch);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z"
    ))
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_position = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_position + 2) / 5 + 1;
    let month = if month_position < 10 {
        month_position + 3
    } else {
        month_position - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_formatted_and_pre_epoch_values_are_rejected() {
        assert_eq!(format_unix_timestamp(0).unwrap(), "1970-01-01T00:00:00Z");
        assert_eq!(
            format_unix_timestamp(1_776_988_800).unwrap(),
            "2026-04-24T00:00:00Z"
        );
        assert!(format_unix_timestamp(-1).is_err());
    }
}
