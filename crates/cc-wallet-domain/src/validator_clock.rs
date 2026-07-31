#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoundColor {
    Blue,
    Green,
}

impl RoundColor {
    pub fn name(self) -> &'static str {
        match self {
            RoundColor::Blue => "BLUE",
            RoundColor::Green => "GREEN",
        }
    }

    pub fn is_green(self) -> bool {
        matches!(self, RoundColor::Green)
    }

    fn of_round(round_id: u64) -> Self {
        if round_id.is_multiple_of(2) {
            RoundColor::Blue
        } else {
            RoundColor::Green
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorCycle {
    pub validators_elected_for: u32,
    pub elections_start_before: u32,
    pub elections_end_before: u32,
    pub current_utime_since: u32,
    pub current_utime_until: u32,
    pub next_utime_until: Option<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClockDisplay {
    pub round_id: u64,
    pub round_color: RoundColor,
    pub needle_deg: f32,
    pub elect_frac_start: f32,
    pub elect_frac_end: f32,
    pub elections_open: bool,
    pub next_round_color: RoundColor,
    pub round_ends_in: String,
    pub elections_value: String,
    pub elections_countdown: String,
}

impl ValidatorCycle {
    pub fn display(&self, now: u32) -> ClockDisplay {
        let elect_for = self.validators_elected_for.max(1);
        let round_id = u64::from(self.current_utime_since / elect_for);
        let round_color = RoundColor::of_round(round_id);
        let next_round_color = RoundColor::of_round(round_id.wrapping_add(1));
        let round_duration = self
            .current_utime_until
            .saturating_sub(self.current_utime_since)
            .max(1);

        let anchor = self.next_utime_until.unwrap_or(self.current_utime_until);
        let raw_start = anchor.saturating_sub(self.elections_start_before);
        let raw_end = anchor.saturating_sub(self.elections_end_before);
        let shift = if now > raw_end { round_duration } else { 0 };
        let elections_start = raw_start.saturating_add(shift);
        let elections_end = raw_end.saturating_add(shift);
        let elections_open = now >= elections_start && now < elections_end;

        let elapsed = now.saturating_sub(self.current_utime_since);
        let frac = (elapsed as f32 / round_duration as f32).clamp(0.0, 1.0);
        let half_offset = if round_color == RoundColor::Green {
            0.0
        } else {
            180.0
        };
        let needle_deg = -90.0 + frac * 180.0 + half_offset;

        let dur = round_duration as f32;
        let elect_frac_start = (round_duration.saturating_sub(self.elections_start_before) as f32
            / dur)
            .clamp(0.0, 1.0);
        let elect_frac_end =
            (round_duration.saturating_sub(self.elections_end_before) as f32 / dur).clamp(0.0, 1.0);

        let (elections_countdown, elections_value) = if elections_open {
            (
                fmt_duration(elections_end.saturating_sub(now)),
                "OPEN".to_owned(),
            )
        } else {
            (
                fmt_duration(elections_start.saturating_sub(now)),
                "CLOSED".to_owned(),
            )
        };

        ClockDisplay {
            round_id,
            round_color,
            needle_deg,
            elect_frac_start,
            elect_frac_end,
            elections_open,
            next_round_color,
            round_ends_in: fmt_duration(self.current_utime_until.saturating_sub(now)),
            elections_value,
            elections_countdown,
        }
    }
}

pub fn fmt_duration(secs: u32) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cycle() -> ValidatorCycle {
        ValidatorCycle {
            validators_elected_for: 100_000,
            elections_start_before: 30_000,
            elections_end_before: 10_000,
            current_utime_since: 500_000,
            current_utime_until: 600_000,
            next_utime_until: None,
        }
    }

    #[test]
    fn round_id_and_colour_come_from_utime_since() {
        let d = cycle().display(500_000);
        assert_eq!(d.round_id, 5);
        assert_eq!(d.round_color, RoundColor::Green);
        assert_eq!(d.next_round_color, RoundColor::Blue);
    }

    #[test]
    fn the_hand_sweeps_180_degrees_across_a_green_round() {
        let c = cycle();
        assert!((c.display(500_000).needle_deg - (-90.0)).abs() < 0.01);
        assert!((c.display(550_000).needle_deg - 0.0).abs() < 0.01);
        assert!((c.display(600_000).needle_deg - 90.0).abs() < 0.01);
    }

    #[test]
    fn a_blue_round_is_offset_to_the_other_half() {
        let mut c = cycle();
        c.current_utime_since = 400_000;
        c.current_utime_until = 500_000;
        assert!((c.display(400_000).needle_deg - 90.0).abs() < 0.01);
    }

    #[test]
    fn elections_open_and_close_on_schedule() {
        let c = cycle();
        assert!(!c.display(569_999).elections_open, "before the window");
        assert!(c.display(570_000).elections_open, "at the open");
        assert!(c.display(589_999).elections_open, "inside the window");
        assert!(!c.display(590_000).elections_open, "at the close");
    }

    #[test]
    fn labels_and_countdowns_track_the_window() {
        let c = cycle();
        let before = c.display(560_000);
        assert_eq!(before.elections_value, "CLOSED");
        assert_eq!(before.elections_countdown, "2h 46m 40s");

        let during = c.display(575_000);
        assert_eq!(during.elections_value, "OPEN");
        assert_eq!(during.elections_countdown, "4h 10m 0s");

        assert_eq!(before.round_ends_in, "11h 6m 40s");
    }

    #[test]
    fn fmt_duration_drops_leading_zero_units() {
        assert_eq!(fmt_duration(45), "45s");
        assert_eq!(fmt_duration(125), "2m 5s");
        assert_eq!(fmt_duration(3_661), "1h 1m 1s");
    }
}
