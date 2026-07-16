//! Send-rate control: a token-bucket pacer plus an adaptive
//! delivery-rate-matching controller (BBR-flavored, loss-aware).
//!
//! The controller's job is finding the path's bottleneck rate, and it must
//! do so without treating loss itself as a stop sign: the whole point of
//! the fountain is that stochastic loss (netem, wifi, long-haul drops) is
//! repaired by coding overhead, not by slowing down. So the only back-off
//! signal is *excess* loss — interval loss above the link's recent
//! intrinsic floor — which is what congestion looks like (queue overflow
//! at the bottleneck, receiver socket-buffer overrun) and what pure random
//! loss never produces, no matter the rate.
//!
//! Signals, one per receiver `Progress` report (~100 ms cadence, arrival
//! timestamped by the feedback reader):
//!
//!   - interval loss = 1 − Δpkts/Δspan (sealed seq span ⇒ exact wire loss;
//!     plaintext falls back to sent-datagram deltas)
//!   - delivered rate = Δpkts × seg / Δt (authenticated wire bytes/s)
//!
//! Decisions are made on *smoothed* loss — raw 100 ms intervals are noisy,
//! and real links lose in bursts. The floor is a running min of the
//! smoothed signal: it snaps down to any cleaner sample. Upward it relaxes
//! only when the current rate is at (or below) the rate the floor was
//! measured at — loss worsening at the *same* rate means the link itself
//! got lossier; loss worsening at a *higher* rate is presumed congestion
//! and must not contaminate the floor (a floor that chases congestive
//! loss turns into a ratchet: rate creeps up, floor follows, "excess"
//! resets, repeat until the link is drowned). A much slower unconditional
//! relaxation is the failsafe against a floor stuck too low.
//!
//!   - startup: double the rate while delivered keeps growing; exit on a
//!     delivery plateau (deep-buffer links never show loss in time)
//!   - excess loss ≥ 5%: cut to max-recent-delivered. Deliberately *not*
//!     credited back up by the loss floor: delivered ≈ bottleneck × (1−p),
//!     so the cut undershoots the pipe slightly — that dip is where loss
//!     returns to intrinsic and the floor gets re-measured (the cheap
//!     analog of BBR's PROBE_RTT; a controller that never dips below the
//!     bottleneck can never re-calibrate its floor and drifts upward)
//!   - excess loss ≤ 2%: drift up ×1.05 per report
//!   - in between: probe up ×1.01 — never a hold state, because at a
//!     constant rate intrinsic and congestive loss are indistinguishable;
//!     the slow climb forces a decisive signal either way
//!
//! Intervals where the sender was app-limited (ack-settle gaps, encoder
//! stalls) still feed the loss floor but make no rate decision.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Adaptive-mode starting rate (bytes/s): 100 Mbit/s. Low enough to be
/// polite on a slow link, ~7 doublings from 10 Gbit.
pub const START_RATE_BPS: f64 = 100e6 / 8.0;

/// Never pace below this (bytes/s): 5 Mbit/s. The controller must not
/// starve; repair overhead handles whatever loss remains.
const MIN_RATE_BPS: f64 = 5e6 / 8.0;

/// Merge feedback intervals shorter than this (seconds).
const MIN_SAMPLE_DT: f64 = 0.05;

/// An interval is app-limited if the sender put less than this fraction
/// of the pacing rate on the wire; such samples make no rate decision.
const APP_LIMITED_FRAC: f64 = 0.7;

/// Growing needs stronger evidence: only intervals that actually saturated
/// the pacing rate may raise it. Repair-round bursts (say 60–90% duty
/// cycle) fit inside the bottleneck queue without loss and would otherwise
/// read as "clean at this rate" and ratchet the rate between rounds.
const GROW_EVIDENCE_FRAC: f64 = 0.9;

/// Smoothing for the decision loss signal (per ~100 ms sample).
const LOSS_EWMA_ALPHA: f64 = 0.3;

/// Downward tracking of the loss floor per sample (fraction of the gap to
/// a cleaner smoothed sample). Fast but not instant: a 1–2 sample dip of
/// the smoothed signal on a bursty link must not pin the floor low, while
/// a genuine clean stretch (e.g. right after a cut, which lands below the
/// bottleneck) converges it within a few reports.
const FLOOR_FALL: f64 = 0.3;

/// Upward relaxation of the loss floor per sample (fraction of the gap to
/// current smoothed loss, ~5 s time constant at 10 Hz), applied only when
/// the current rate is at or below the floor's measurement rate.
const FLOOR_RELAX: f64 = 0.02;

/// Unconditional (failsafe) upward relaxation per sample: frees a floor
/// stuck too low without letting sustained congestion inflate it within a
/// transfer's typical lifetime.
const FLOOR_RELAX_SLOW: f64 = 0.004;

/// "Same rate" tolerance for the conditional relaxation.
const FLOOR_RATE_TOL: f64 = 1.05;

/// Windowed-max filter for the delivered rate (the BBR-style bandwidth
/// estimate a cut targets), in receiver-clock ms.
const DELIVERED_WINDOW_MS: u64 = 2500;

/// Excess loss at or below this is "clean": keep probing upward.
const CLEAN_EXCESS: f64 = 0.02;

/// Excess loss at or above this is congestion: cut to the delivered rate.
const CUT_EXCESS: f64 = 0.05;

/// Reports to sit out after a cut (measurements still reflect the old rate).
const CUT_COOLDOWN: u32 = 3;

/// A cut always reduces the rate by at least this factor, even when the
/// delivered-based target reads at/above the current rate (a corrupted
/// estimate must never stall the descent out of congestion).
const CUT_MIN_FACTOR: f64 = 0.9;

const GROWTH_STARTUP: f64 = 2.0;
const GROWTH_STEADY: f64 = 1.05;
/// Middle-band probe (excess between CLEAN and CUT).
const GROWTH_SLOW: f64 = 1.01;

/// Startup expects delivered to grow at least this much per sample...
const STARTUP_GROWTH_MIN: f64 = 1.10;
/// ...and exits after this many stagnant samples (delivery plateau).
const STARTUP_STAGNANT_EXIT: u32 = 3;

/// Startup abort: a single *raw* interval this far above the floor cuts
/// immediately. Startup doubles every report, so waiting the 2–3 samples
/// the smoothed signal needs means one more doubling sprayed into an
/// already-overflowing queue.
const STARTUP_ABORT_EXCESS: f64 = 0.15;

/// Burst credit after idle: at most this much send time may be "caught up"
/// in one burst instead of slept off.
const MAX_BURST: Duration = Duration::from_millis(10);

// ─── Pacer ───────────────────────────────────────────────────────────────────

/// Token-bucket-ish pacer: sleeps so cumulative bytes track the current
/// rate, with a small burst allowance after idle so rate changes and
/// feedback gaps don't produce unbounded catch-up bursts.
pub struct Pacer {
    bytes_per_sec: f64,
    /// When the next send is allowed; `None` until the first send.
    next: Option<Instant>,
}

impl Pacer {
    /// Fixed rate in Mbit/s; 0 = unpaced.
    pub fn new_mbps(rate_mbps: f64) -> Self {
        Self::new_bps(rate_mbps * 1e6 / 8.0)
    }

    pub fn new_bps(bytes_per_sec: f64) -> Self {
        Pacer {
            bytes_per_sec,
            next: None,
        }
    }

    pub fn set_rate_bps(&mut self, bytes_per_sec: f64) {
        self.bytes_per_sec = bytes_per_sec;
    }

    pub fn rate_mbps(&self) -> f64 {
        self.bytes_per_sec * 8.0 / 1e6
    }

    pub async fn pace(&mut self, len: usize) {
        if self.bytes_per_sec <= 0.0 {
            return;
        }
        let now = Instant::now();
        let dur = Duration::from_secs_f64(len as f64 / self.bytes_per_sec);
        let floor = now.checked_sub(MAX_BURST).unwrap_or(now);
        let next = self.next.map_or(now, |n| n.max(floor)) + dur;
        self.next = Some(next);
        if next > now {
            tokio::time::sleep(next - now).await;
        }
    }
}

// ─── Controller ──────────────────────────────────────────────────────────────

struct Snap {
    pkts: u64,
    span: u64,
    bytes: u64,
    /// Receiver clock, ms since transfer start.
    t_ms: u64,
}

pub struct RateController {
    /// Current pacing target, bytes/s.
    rate: f64,
    max: f64,
    seg: usize,
    startup: bool,
    best_delivered: f64,
    stagnant: u32,
    cooldown: u32,
    loss_ewma: Option<f64>,
    /// (floor, pacing rate at which it was measured).
    loss_floor: Option<(f64, f64)>,
    /// (receiver t_ms, delivered bytes/s) samples for the max filter.
    delivered: VecDeque<(u64, f64)>,
    last: Option<Snap>,
}

impl RateController {
    /// `seg` is the wire size of one datagram (all spray datagrams are
    /// equal-size); `max_rate_mbps` caps probing.
    pub fn new(seg: usize, max_rate_mbps: f64) -> Self {
        let max = (max_rate_mbps * 1e6 / 8.0).max(MIN_RATE_BPS);
        RateController {
            rate: START_RATE_BPS.min(max),
            max,
            seg,
            startup: true,
            best_delivered: 0.0,
            stagnant: 0,
            cooldown: 0,
            loss_ewma: None,
            loss_floor: None,
            delivered: VecDeque::new(),
            last: None,
        }
    }

    pub fn rate_bps(&self) -> f64 {
        self.rate
    }

    /// Feed one receiver Progress report (cumulative counters, sender's
    /// cumulative wire bytes, and the *receiver's* clock in ms — interval
    /// durations must come from the clock that counted the packets;
    /// sender-side arrival times jitter with the return path and inflate
    /// the delivered estimate). Returns the new pacing rate in bytes/s
    /// when it changed.
    pub fn on_report(
        &mut self,
        pkts: u64,
        span: Option<u64>,
        bytes_sent: u64,
        t_ms: u64,
    ) -> Option<f64> {
        // Plaintext mode has no seq span; sent-datagram deltas are a fair
        // stand-in (boundary in-flight skew cancels across intervals).
        let span = span.unwrap_or(bytes_sent / self.seg as u64);
        let Some(last) = &self.last else {
            self.last = Some(Snap {
                pkts,
                span,
                bytes: bytes_sent,
                t_ms,
            });
            return None;
        };
        let dt = t_ms.saturating_sub(last.t_ms) as f64 / 1e3;
        if dt < MIN_SAMPLE_DT {
            return None; // merge into the next interval
        }
        let dpkts = pkts.saturating_sub(last.pkts);
        let dspan = span.saturating_sub(last.span);
        let dbytes = bytes_sent.saturating_sub(last.bytes);
        self.last = Some(Snap {
            pkts,
            span,
            bytes: bytes_sent,
            t_ms,
        });
        if dspan == 0 || dpkts == 0 {
            // Idle interval, or nothing authenticated yet: no signal (a
            // zero-pkts interval must not be read as 100% loss — the spray
            // may simply not have reached the receiver yet).
            return None;
        }

        let raw_loss = (1.0 - dpkts as f64 / dspan as f64).clamp(0.0, 1.0);
        let delivered = dpkts as f64 * self.seg as f64 / dt;
        let sent_rate = dbytes as f64 / dt;

        // Smooth the decision signal: a single 100 ms interval on a bursty
        // link swings between 0% and 2× the true loss rate.
        let loss = match self.loss_ewma {
            Some(prev) => (1.0 - LOSS_EWMA_ALPHA) * prev + LOSS_EWMA_ALPHA * raw_loss,
            None => raw_loss,
        };
        self.loss_ewma = Some(loss);

        let floor = match self.loss_floor {
            // Post-cut cooldown samples still show the queue draining —
            // stale, elevated loss that must not leak into the floor.
            Some((f, _)) if loss >= f && self.cooldown > 0 => f,
            Some((f, fr)) if loss >= f => {
                let relax = if self.rate <= fr * FLOOR_RATE_TOL {
                    FLOOR_RELAX
                } else {
                    FLOOR_RELAX_SLOW
                };
                // Relaxation is for gently-worsened intrinsic loss; a
                // sample that itself reads as congestion (≥ CUT_EXCESS
                // over the floor) must not be chased wholesale.
                let nf = f + relax * (loss.min(f + CUT_EXCESS) - f);
                self.loss_floor = Some((nf, fr));
                nf
            }
            // A cleaner sample: track down (exponentially) and re-anchor
            // the measurement rate.
            Some((f, _)) => {
                let nf = f + FLOOR_FALL * (loss - f);
                self.loss_floor = Some((nf, self.rate));
                nf
            }
            // First sample.
            None => {
                self.loss_floor = Some((loss, self.rate));
                loss
            }
        };

        if sent_rate < APP_LIMITED_FRAC * self.rate {
            return None; // app-limited: loss floor updated, no decision
        }

        self.delivered.push_back((t_ms, delivered));
        while self
            .delivered
            .front()
            .is_some_and(|(t, _)| t + DELIVERED_WINDOW_MS < t_ms)
        {
            self.delivered.pop_front();
        }
        let max_delivered = self
            .delivered
            .iter()
            .map(|(_, d)| *d)
            .fold(0.0f64, f64::max);

        if self.cooldown > 0 {
            self.cooldown -= 1;
            return None;
        }

        let excess = loss - floor;
        let saturated = sent_rate >= GROW_EVIDENCE_FRAC * self.rate;
        let old = self.rate;
        let startup_abort = self.startup && raw_loss - floor >= STARTUP_ABORT_EXCESS;
        if excess >= CUT_EXCESS || startup_abort {
            // Congestion: cut to what the pipe actually delivered. This
            // lands ≈ bottleneck × (1 − intrinsic), i.e. slightly *below*
            // the pipe — intentional: the dip is what re-measures the loss
            // floor (see module docs). Always come down by ≥ CUT_MIN_FACTOR
            // even if the delivered estimate reads high.
            self.startup = false;
            let ceiling = (self.rate * CUT_MIN_FACTOR).max(MIN_RATE_BPS);
            self.rate = max_delivered.clamp(MIN_RATE_BPS, ceiling);
            self.cooldown = CUT_COOLDOWN;
        } else if excess <= CLEAN_EXCESS && saturated {
            // Above the pipe's proven capacity (credit back intrinsic
            // loss), clean readings are just measurement lag: probe slowly.
            let anchor = max_delivered / (1.0 - floor.min(0.5));
            if !self.startup && self.rate >= anchor {
                self.rate = (self.rate * GROWTH_SLOW).min(self.max);
            } else if self.startup {
                if delivered > self.best_delivered * STARTUP_GROWTH_MIN {
                    self.best_delivered = delivered;
                    self.stagnant = 0;
                    self.rate = (self.rate * GROWTH_STARTUP).min(self.max);
                } else {
                    self.stagnant += 1;
                    if self.stagnant >= STARTUP_STAGNANT_EXIT {
                        // Delivery plateau without loss (deep buffer or
                        // receiver ceiling): settle on what the pipe proved
                        // (never raise on exit).
                        self.startup = false;
                        self.rate = max_delivered.clamp(MIN_RATE_BPS, self.rate.max(MIN_RATE_BPS));
                    }
                }
            } else {
                self.rate = (self.rate * GROWTH_STEADY).min(self.max);
            }
        } else if !self.startup && excess < CUT_EXCESS && saturated {
            // Middle band: probe slowly instead of holding — at a constant
            // rate the loss signal cannot resolve intrinsic vs congestive,
            // so keep nudging until it crosses a threshold either way.
            self.rate = (self.rate * GROWTH_SLOW).min(self.max);
        }

        (self.rate != old).then_some(self.rate)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SEG: usize = 1224;
    const TICK_MS: u64 = 100;

    /// Drive the controller against a queueless bottleneck model:
    /// `min(rate, bottleneck)` gets through, then loses fraction `p` at
    /// random (modeled deterministically). Returns the final rate (Mbit/s).
    fn simulate(bottleneck_mbps: f64, p: f64, cap_mbps: f64, ticks: u64) -> f64 {
        let mut c = RateController::new(SEG, cap_mbps);
        let bneck = bottleneck_mbps * 1e6 / 8.0; // bytes/s
        let (mut pkts, mut span, mut bytes) = (0u64, 0u64, 0u64);
        for i in 0..ticks {
            let dt = TICK_MS as f64 / 1e3;
            let sent = c.rate_bps() * dt;
            let sprayed = (sent / SEG as f64) as u64;
            span += sprayed;
            bytes += sprayed * SEG as u64;
            let through = sent.min(bneck * dt);
            let delivered = ((through * (1.0 - p) / SEG as f64) as u64).min(sprayed);
            pkts += delivered;
            c.on_report(pkts, Some(span), bytes, TICK_MS * (i + 1));
        }
        c.rate_bps() * 8.0 / 1e6
    }

    #[test]
    fn converges_to_clean_bottleneck() {
        let r = simulate(500.0, 0.0, 10_000.0, 200);
        assert!(
            (375.0..650.0).contains(&r),
            "converged to {r} Mbit/s, want ≈500"
        );
    }

    #[test]
    fn random_loss_does_not_starve_the_rate() {
        // The demo property: 10% stochastic loss is repair's problem, not
        // the pacer's. The controller must still find the bottleneck.
        let r = simulate(500.0, 0.10, 10_000.0, 200);
        assert!(r > 375.0, "starved to {r} Mbit/s under 10% random loss");
        assert!(r < 650.0, "overshot to {r} Mbit/s");
    }

    #[test]
    fn heavy_loss_uncongested_probes_to_the_cap() {
        // No bottleneck within the cap, 20% loss: rate must reach the cap.
        let r = simulate(1e9, 0.20, 1000.0, 200);
        assert!(r > 800.0, "stopped at {r} Mbit/s, want ≈cap 1000");
    }

    #[test]
    fn no_ratchet_above_a_lossy_bottleneck() {
        // Regression: a floor that relaxes toward congestive loss ratchets
        // — rate creeps up, floor follows, "excess" resets — and parked a
        // real netem run at 1.5× the bottleneck with 32% loss. Over a long
        // horizon the rate must stay pinned near the bottleneck.
        let r = simulate(500.0, 0.05, 10_000.0, 600);
        assert!(
            r < 625.0,
            "ratcheted to {r} Mbit/s above a 500 Mbit bottleneck"
        );
        assert!(r > 375.0, "starved to {r} Mbit/s");
    }

    #[test]
    fn bursty_loss_does_not_collapse_the_rate() {
        // Regression: qdisc-style burst loss (whole 52-datagram GSO
        // super-packets dropped at once, ~5% average) produced 0%-loss
        // intervals that pinned a min-floor to zero, so every burst read
        // as "excess" → cut → the rate collapsed to ~¼ of the bottleneck.
        let mut c = RateController::new(SEG, 10_000.0);
        let bneck = 500.0 * 1e6 / 8.0; // bytes/s
        let (mut pkts, mut span, mut bytes) = (0u64, 0u64, 0u64);
        let mut rng: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut unit = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            (rng >> 11) as f64 / (1u64 << 53) as f64
        };
        for i in 0..300u64 {
            let dt = TICK_MS as f64 / 1e3;
            let sent = c.rate_bps() * dt;
            let sprayed = (sent / SEG as f64) as u64;
            span += sprayed;
            bytes += sprayed * SEG as u64;
            let through = (sent.min(bneck * dt) / SEG as f64) as u64;
            // Drop whole 52-packet bursts with 5% probability each.
            let mut delivered = 0u64;
            let mut left = through;
            while left > 0 {
                let burst = left.min(52);
                if unit() >= 0.05 {
                    delivered += burst;
                }
                left -= burst;
            }
            pkts += delivered.min(sprayed);
            c.on_report(pkts, Some(span), bytes, TICK_MS * (i + 1));
        }
        let r = c.rate_bps() * 8.0 / 1e6;
        assert!(
            r > 350.0,
            "collapsed to {r} Mbit/s under bursty 5% loss, want ≈500"
        );
        assert!(r < 700.0, "overshot to {r} Mbit/s");
    }

    #[test]
    fn plaintext_fallback_without_span() {
        // span=None uses sent-datagram deltas; same convergence.
        let mut c = RateController::new(SEG, 10_000.0);
        let bneck = 500.0 * 1e6 / 8.0;
        let (mut pkts, mut bytes) = (0u64, 0u64);
        for i in 0..200u64 {
            let dt = TICK_MS as f64 / 1e3;
            let sent = c.rate_bps() * dt;
            let sprayed = (sent / SEG as f64) as u64;
            bytes += sprayed * SEG as u64;
            let through = sent.min(bneck * dt);
            pkts += ((through / SEG as f64) as u64).min(sprayed);
            c.on_report(pkts, None, bytes, TICK_MS * (i + 1));
        }
        let r = c.rate_bps() * 8.0 / 1e6;
        assert!(
            (375.0..650.0).contains(&r),
            "converged to {r} Mbit/s, want ≈500"
        );
    }

    #[test]
    fn app_limited_intervals_make_no_decision() {
        let mut c = RateController::new(SEG, 10_000.0);
        c.on_report(0, Some(0), 0, 0);
        let before = c.rate_bps();
        // Trickle: 10 pkts per 100 ms is far below the pacing rate.
        let mut pkts = 0u64;
        for i in 1..=20u64 {
            pkts += 10;
            let r = c.on_report(pkts, Some(pkts), pkts * SEG as u64, TICK_MS * i);
            assert!(r.is_none(), "app-limited interval changed the rate");
        }
        assert_eq!(c.rate_bps(), before);
    }
}
