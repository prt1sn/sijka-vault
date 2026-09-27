// Copyright (c) 2026 prt1sn. All rights reserved.
//! Collateral withdrawal of tag 51 op 1 and op 6 (SPEC §5.6.4, reviews REC-4,
//! REC-6, REC-7, REC-10): withdraw-queue header (step 4), amount selection
//! (step 7) and the walk over queued requests (step 8).
//!
//! Pure functions over the queue bytes and integers; errors are returned as
//! [`SijkaError`] (the handler logs them with `fail`). The only destination
//! of the withdrawal is `vault_phusd`, and the caller can only lower the
//! amount (`max_amount`), never raise it.

use pinocchio::pubkey::{Pubkey, pubkey_eq};

use crate::constants::{
    BPS, DISC_WITHDRAW_QUEUE, RECOVERY_ENQUEUE_MIN_SLOTS, WITHDRAW_QUEUE_HEADER_LEN, WITHDRAW_QUEUE_LEN,
    WITHDRAW_QUEUE_MAX_NODES, WITHDRAW_QUEUE_NODE_LEN,
};
use crate::error::SijkaError;
use crate::external::layout::withdraw_queue as wq;
use crate::util::bytes::{array_ref, read_u8, read_u32, read_u64};

/// Parsed withdraw-queue header (step 4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueueHeader {
    /// Owner Phoenix, discriminator, `data_len ≥ 120`.
    pub hdr_ok: bool,
    /// `hdr_ok` and the whole queue is parseable (length, `size`, `bump_index`):
    /// only then may op 1 / op 6 enqueue.
    pub q_ok: bool,
    /// `max_budget` (or `max_harvest_per_call` when the header is not parsed).
    pub q_perm: u64,
    /// `min(q_perm, remaining + replenish·Δslot)` (or `max_harvest_per_call`).
    pub q_tmp: u64,
    /// `total_queued > 0`.
    pub busy: bool,
    /// `max(withdrawal_fee, enqueueing_fee)`, 0 when not parsed.
    pub fee_hint: u64,
    /// `total_queued`, 0 when not parsed.
    pub total_queued: u64,
}

/// Parse the header (SPEC §5.6.4 step 4). `fallback` is
/// `max_harvest_per_call`: a cap instead of `u64::MAX`, so that an unparsed
/// header does not make every call ask for more than `max_budget` (REC-7).
pub fn read_queue_header(owned_by_phoenix: bool, d: &[u8], slot: u64, fallback: u64) -> QueueHeader {
    let unparsed = QueueHeader { q_perm: fallback, q_tmp: fallback, ..QueueHeader::default() };
    if !owned_by_phoenix
        || d.len() < WITHDRAW_QUEUE_HEADER_LEN
        || array_ref::<8>(d, wq::DISCRIMINATOR) != Some(&DISC_WITHDRAW_QUEUE)
    {
        return unparsed;
    }
    let (Some(max_budget), Some(remaining), Some(replenish), Some(last), Some(total), Some(wfee), Some(efee)) = (
        read_u64(d, wq::MAX_BUDGET),
        read_u64(d, wq::REMAINING),
        read_u64(d, wq::REPLENISH_PER_SLOT),
        read_u64(d, wq::LAST_UPDATE_SLOT),
        read_u64(d, wq::TOTAL_QUEUED),
        read_u64(d, wq::WITHDRAWAL_FEE),
        read_u64(d, wq::ENQUEUEING_FEE),
    ) else {
        return unparsed;
    };
    // u64·u64 fits u128; saturate anyway, then clamp to max_budget.
    let refill = u128::from(replenish).saturating_mul(u128::from(slot.saturating_sub(last)));
    let tmp = u128::from(remaining).saturating_add(refill);
    let q_tmp = u64::try_from(tmp).unwrap_or(u64::MAX).min(max_budget);
    let q_ok = d.len() == WITHDRAW_QUEUE_LEN
        && read_u64(d, wq::SIZE).is_some_and(|s| s <= WITHDRAW_QUEUE_MAX_NODES)
        && read_u32(d, wq::BUMP_INDEX).is_some_and(|b| u64::from(b) <= WITHDRAW_QUEUE_MAX_NODES.saturating_add(1));
    QueueHeader {
        hdr_ok: true,
        q_ok,
        q_perm: max_budget,
        q_tmp,
        busy: total > 0,
        fee_hint: wfee.max(efee),
        total_queued: total,
    }
}

/// Result of the walk over the queued requests (step 8 (b)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueScan {
    /// No active request of our trader.
    Clear,
    /// Our trader has an active request (state 0..=3): `RecoveryAlreadyQueued`.
    OurActive,
    /// A node pointer out of bounds or 0 before `size` nodes: `WithdrawQueueBusy`.
    Broken,
}

/// Walk exactly `size` nodes from `head` along `next` (node `i`, 1-based, at
/// `144 + 104·(i − 1)`). The loop is bounded by `size ≤ 2048`.
pub fn walk_queue(d: &[u8], trader: &Pubkey) -> QueueScan {
    let (Some(head), Some(size)) = (read_u32(d, wq::HEAD), read_u64(d, wq::SIZE)) else {
        return QueueScan::Broken;
    };
    if size > WITHDRAW_QUEUE_MAX_NODES {
        return QueueScan::Broken;
    }
    let mut node = head;
    for _ in 0..size {
        if node == 0 || u64::from(node) > WITHDRAW_QUEUE_MAX_NODES {
            return QueueScan::Broken;
        }
        let Some(n) = usize::try_from(node)
            .ok()
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| i.checked_mul(WITHDRAW_QUEUE_NODE_LEN))
            .and_then(|o| o.checked_add(wq::NODES))
            .and_then(|o| array_ref::<WITHDRAW_QUEUE_NODE_LEN>(d, o))
        else {
            return QueueScan::Broken;
        };
        let (Some(key), Some(state), Some(next)) =
            (array_ref::<32>(n, wq::N_TRADER_KEY), read_u8(n, wq::N_STATE), read_u32(n, wq::N_NEXT))
        else {
            return QueueScan::Broken;
        };
        if pubkey_eq(key, trader) && state <= wq::STATE_ACTIVE_MAX {
            return QueueScan::OurActive;
        }
        node = next;
    }
    QueueScan::Clear
}

/// Step 8 (a): a new request earlier than `RECOVERY_ENQUEUE_MIN_SLOTS` after
/// the previous one.
pub fn enqueue_too_soon(last_enqueue_slot: u64, slot: u64) -> bool {
    last_enqueue_slot != 0 && slot < last_enqueue_slot.saturating_add(RECOVERY_ENQUEUE_MIN_SLOTS)
}

/// `shave(D) = max(shave_abs, ⌊D·shave_bps / 10 000⌋)` (SPEC §5.6.4 step 7;
/// the handler passes the constants `RECOVERY_SHAVE_ABS` / `RECOVERY_SHAVE_BPS`,
/// SPEC v4). Rounded down (in favour of the pool).
pub fn recovery_shave(d: u64, shave_abs: u64, shave_bps: u16) -> u64 {
    let part = u128::from(d).saturating_mul(u128::from(shave_bps)).checked_div(u128::from(BPS)).unwrap_or(0);
    shave_abs.max(u64::try_from(part).unwrap_or(u64::MAX))
}

/// Step 7, first line (op 1): `W = min(max(free, 0), wd)`,
/// `buf_r = (IM == 0) ? 0 : max(margin_buffer_abs, ⌈IM·margin_buffer_im_bps / 10 000⌉)`,
/// `D_room = W − buf_r` (i128). Returns `(D_room, buf_r)`.
pub fn withdraw_room(free: i64, wd: u64, im: u64, buf_abs: u64, buf_bps: u32) -> Result<(i128, u128), SijkaError> {
    let w = i128::from(free.max(0)).min(i128::from(wd));
    let buf = if im == 0 {
        0
    } else {
        // ⌈x / 10 000⌉ = (x + 9 999) / 10 000; x ≤ 2^96, no overflow.
        let x = u128::from(im).checked_mul(u128::from(buf_bps)).ok_or(SijkaError::MathOverflow)?;
        let ceil = x
            .checked_add(u128::from(BPS).saturating_sub(1))
            .and_then(|y| y.checked_div(u128::from(BPS)))
            .ok_or(SijkaError::MathOverflow)?;
        u128::from(buf_abs).max(ceil)
    };
    let buf_i = i128::try_from(buf).map_err(|_| SijkaError::MathOverflow)?;
    Ok((w.checked_sub(buf_i).ok_or(SijkaError::MathOverflow)?, buf))
}

/// Step 7 inputs: `d_min` (`HarvestParams`) and the fixed shave constants.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlanParams {
    pub d_min: u64,
    pub shave_abs: u64,
    pub shave_bps: u16,
}

/// Outcome of step 7.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WithdrawPlan {
    /// Amount requested from Phoenix.
    pub d: u64,
    /// `D_max = min(D_room, Q_perm)`.
    pub d_max: u64,
    /// QUEUE mode (else IMMEDIATE).
    pub queued: bool,
    /// Event bit0: `D` limited by `Q_perm` / `Q_tmp`.
    pub budget_limited: bool,
    /// Event bit3: `D` limited by `max_amount`.
    pub amount_limited: bool,
}

/// Step 7 (SPEC §5.6.4): choose `D` and the mode. `flat` selects the op 6
/// rule (`shave = D_max − min(d_min, D_max)`) for an IMMEDIATE withdrawal;
/// a QUEUE request of either op must leave at most
/// `max(fee_hint, shave(D_max))` behind (full audit FA-2): only one
/// request of ours may be active and at most one per
/// `RECOVERY_ENQUEUE_MIN_SLOTS`, so a small queued request would cap the
/// recovery at that size per day.
///
/// Errors: `RecoveryNothing` (`D_room ≤ 0`), `RecoveryBelowMinimum`
/// (`max_amount` below `D_max − shave`, budget below `floor` with an
/// unparsed queue, or nothing to ask for), `WithdrawQueueBusy`.
pub fn plan_withdraw(
    d_room: i128,
    q: &QueueHeader,
    max_amount: u64,
    p: &PlanParams,
    flat: bool,
) -> Result<WithdrawPlan, SijkaError> {
    if d_room <= 0 {
        return Err(SijkaError::RecoveryNothing);
    }
    // D_room ≤ wd (op 1) or C_hdr (op 6), so it fits u64.
    let room = u64::try_from(d_room).map_err(|_| SijkaError::MathOverflow)?;
    let d_max = room.min(q.q_perm);
    let d_req = if max_amount == 0 { d_max } else { d_max.min(max_amount) };
    // How much the caller may leave behind: room for a fee charged on top of
    // the amount (op 1 with a parsed header), else down to `d_min`.
    let strict = q.fee_hint.max(recovery_shave(d_max, p.shave_abs, p.shave_bps));
    let shave = if q.hdr_ok && !flat { strict } else { d_max.saturating_sub(p.d_min.min(d_max)) };
    if d_req < d_max.saturating_sub(shave) {
        return Err(SijkaError::RecoveryBelowMinimum);
    }
    let floor = p.d_min.min(d_req);
    let (d, queued) = if !q.busy && q.q_tmp >= floor {
        // Partial withdrawal within the exchange-wide budget.
        (d_req.min(q.q_tmp), false)
    } else if q.q_ok {
        // QUEUE (op 1 and op 6): the strict op 1 bound; `q_ok` implies
        // `hdr_ok`, so `fee_hint` is parsed (full audit FA-2).
        if d_req < d_max.saturating_sub(strict) {
            return Err(SijkaError::RecoveryBelowMinimum);
        }
        (d_req, true)
    } else if q.busy {
        return Err(SijkaError::WithdrawQueueBusy);
    } else {
        return Err(SijkaError::RecoveryBelowMinimum);
    };
    if d == 0 {
        // Only with `max_budget == 0`: nothing to ask for until Phoenix raises it.
        return Err(SijkaError::RecoveryBelowMinimum);
    }
    Ok(WithdrawPlan {
        d,
        d_max,
        queued,
        budget_limited: q.q_perm < room || (!queued && q.q_tmp < d_req),
        amount_limited: max_amount != 0 && max_amount < d_max,
    })
}

/// Step 11: what the withdrawal did. `phusd0` / `phusd1` are
/// `vault_phusd.amount` before / after the CPI, `tq0` is `total_queued`
/// before it and `q_after` the header parsed again after it. Returns
/// `(r, queued)`.
///
/// - `r > 0` (any mode): `r ≤ D`, else `WithdrawAmountMismatch`. No lower
///   bound (REC-8): the fee is the venue's and the destination is pinned.
/// - `r == 0`: success only in QUEUE mode with `total_queued` grown by
///   exactly `D`; else `WithdrawNotImmediate`.
/// - `vault_phusd` shrank: `InvariantViolated`.
pub fn withdraw_outcome(
    plan: &WithdrawPlan,
    tq0: u64,
    phusd0: u64,
    phusd1: u64,
    q_after: &QueueHeader,
) -> Result<(u64, bool), SijkaError> {
    let r = phusd1.checked_sub(phusd0).ok_or(SijkaError::InvariantViolated)?;
    if r > 0 {
        if r > plan.d {
            return Err(SijkaError::WithdrawAmountMismatch);
        }
        return Ok((r, false));
    }
    let expect = tq0.checked_add(plan.d).ok_or(SijkaError::MathOverflow)?;
    if plan.queued && q_after.hdr_ok && q_after.total_queued == expect {
        Ok((0, true))
    } else {
        Err(SijkaError::WithdrawNotImmediate)
    }
}

/// Op 4 step 4: all of `P` left `vault_phusd` (`InvariantViolated`
/// otherwise), `vault_usdc` did not shrink (`InvariantViolated`) and
/// `0 < u ≤ P` (`EmberAmountMismatch`). Returns `u`.
pub fn unwrap_outcome(p: u64, phusd_left: u64, usdc0: u64, usdc1: u64) -> Result<u64, SijkaError> {
    if phusd_left != 0 {
        return Err(SijkaError::InvariantViolated);
    }
    let u = usdc1.checked_sub(usdc0).ok_or(SijkaError::InvariantViolated)?;
    if u == 0 || u > p {
        return Err(SijkaError::EmberAmountMismatch);
    }
    Ok(u)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::constants::WITHDRAW_QUEUE_NODES_OFFSET;

    #[test]
    fn outcomes() {
        let imm = WithdrawPlan { d: 1_000, d_max: 1_000, ..WithdrawPlan::default() };
        let queue = WithdrawPlan { queued: true, ..imm };
        let after =
            |total: u64| QueueHeader { hdr_ok: true, q_ok: true, total_queued: total, ..QueueHeader::default() };
        // Immediate: anything in (0, D], fees below D allowed.
        assert_eq!(withdraw_outcome(&imm, 0, 50, 1_050, &after(0)), Ok((1_000, false)));
        assert_eq!(withdraw_outcome(&imm, 0, 50, 60, &after(0)), Ok((10, false)));
        assert_eq!(withdraw_outcome(&imm, 0, 50, 1_051, &after(0)), Err(SijkaError::WithdrawAmountMismatch));
        assert_eq!(withdraw_outcome(&imm, 0, 50, 49, &after(0)), Err(SijkaError::InvariantViolated));
        // Nothing arrived in IMMEDIATE mode, even if the queue grew.
        assert_eq!(withdraw_outcome(&imm, 0, 50, 50, &after(1_000)), Err(SijkaError::WithdrawNotImmediate));
        // QUEUE: total_queued grew by exactly D.
        assert_eq!(withdraw_outcome(&queue, 7, 50, 50, &after(1_007)), Ok((0, true)));
        assert_eq!(withdraw_outcome(&queue, 7, 50, 50, &after(1_006)), Err(SijkaError::WithdrawNotImmediate));
        assert_eq!(withdraw_outcome(&queue, 7, 50, 50, &after(7)), Err(SijkaError::WithdrawNotImmediate));
        let mut unparsed = after(1_007);
        unparsed.hdr_ok = false;
        assert_eq!(withdraw_outcome(&queue, 7, 50, 50, &unparsed), Err(SijkaError::WithdrawNotImmediate));
        // QUEUE mode but Phoenix paid at once: fine.
        assert_eq!(withdraw_outcome(&queue, 7, 50, 1_050, &after(7)), Ok((1_000, false)));
        assert_eq!(withdraw_outcome(&queue, u64::MAX, 0, 0, &after(0)), Err(SijkaError::MathOverflow));

        assert_eq!(unwrap_outcome(100, 0, 5, 105), Ok(100));
        assert_eq!(unwrap_outcome(100, 0, 5, 104), Ok(99));
        assert_eq!(unwrap_outcome(100, 1, 5, 105), Err(SijkaError::InvariantViolated));
        assert_eq!(unwrap_outcome(100, 0, 5, 4), Err(SijkaError::InvariantViolated));
        assert_eq!(unwrap_outcome(100, 0, 5, 5), Err(SijkaError::EmberAmountMismatch));
        assert_eq!(unwrap_outcome(100, 0, 5, 106), Err(SijkaError::EmberAmountMismatch));
    }

    pub struct Q {
        pub max_budget: u64,
        pub remaining: u64,
        pub replenish: u64,
        pub last_update: u64,
        pub total_queued: u64,
        pub wfee: u64,
        pub efee: u64,
    }

    impl Default for Q {
        fn default() -> Self {
            // Live header (slot ≈ 450 499 332).
            Self {
                max_budget: 2_000_000_000_000,
                remaining: 2_000_000_000_000,
                replenish: 450_000_000,
                last_update: 100,
                total_queued: 0,
                wfee: 500_000,
                efee: 500_000,
            }
        }
    }

    pub fn queue_bytes(q: &Q, nodes: &[(Pubkey, u8)]) -> Vec<u8> {
        let mut d = vec![0u8; WITHDRAW_QUEUE_LEN];
        d[0..8].copy_from_slice(&DISC_WITHDRAW_QUEUE);
        d[24..32].copy_from_slice(&q.max_budget.to_le_bytes());
        d[32..40].copy_from_slice(&q.remaining.to_le_bytes());
        d[40..48].copy_from_slice(&q.replenish.to_le_bytes());
        d[48..56].copy_from_slice(&q.last_update.to_le_bytes());
        d[56..64].copy_from_slice(&q.total_queued.to_le_bytes());
        d[64..72].copy_from_slice(&q.wfee.to_le_bytes());
        d[72..80].copy_from_slice(&q.efee.to_le_bytes());
        // Linked list 1 → 2 → … (nodes stored in reverse order to exercise `next`).
        let n = nodes.len();
        let slot_of = |i: usize| (n - i) as u32; // node index of list element i
        d[120..124].copy_from_slice(&(if n > 0 { slot_of(0) } else { 0 }).to_le_bytes());
        d[124..128].copy_from_slice(&(if n > 0 { slot_of(n - 1) } else { 0 }).to_le_bytes());
        d[128..136].copy_from_slice(&(n as u64).to_le_bytes());
        d[136..140].copy_from_slice(&(n as u32 + 1).to_le_bytes());
        for (i, (key, state)) in nodes.iter().enumerate() {
            let o = WITHDRAW_QUEUE_NODES_OFFSET + (slot_of(i) as usize - 1) * WITHDRAW_QUEUE_NODE_LEN;
            let next = if i + 1 < n { slot_of(i + 1) } else { 0 };
            d[o + 4..o + 8].copy_from_slice(&next.to_le_bytes());
            d[o + 8..o + 40].copy_from_slice(key);
            d[o + 72..o + 80].copy_from_slice(&1_000_000u64.to_le_bytes());
            d[o + 98] = *state;
        }
        d
    }

    const US: Pubkey = [0x70; 32];

    #[test]
    fn header_parsing() {
        let d = queue_bytes(&Q::default(), &[]);
        let h = read_queue_header(true, &d, 200, 77);
        assert!(h.hdr_ok && h.q_ok && !h.busy);
        assert_eq!(h.q_perm, 2_000_000_000_000);
        assert_eq!(h.q_tmp, 2_000_000_000_000); // clamped to max_budget
        assert_eq!(h.fee_hint, 500_000);
        let q = Q { remaining: 10, replenish: 3, last_update: 100, efee: 9, wfee: 1, ..Q::default() };
        let h = read_queue_header(true, &queue_bytes(&q, &[]), 110, 77);
        assert_eq!(h.q_tmp, 40);
        assert_eq!(h.fee_hint, 9);
        // Slot before last_update: no refill (saturating).
        assert_eq!(read_queue_header(true, &queue_bytes(&q, &[]), 50, 77).q_tmp, 10);
        // Saturation.
        let q = Q { max_budget: u64::MAX, remaining: u64::MAX, replenish: u64::MAX, last_update: 0, ..Q::default() };
        assert_eq!(read_queue_header(true, &queue_bytes(&q, &[]), u64::MAX, 77).q_tmp, u64::MAX);
        // Busy.
        let q = Q { total_queued: 1, ..Q::default() };
        let h = read_queue_header(true, &queue_bytes(&q, &[]), 200, 77);
        assert!(h.busy);
        assert_eq!(h.total_queued, 1);
        // Unparsed: owner, disc, short → clamp to the fallback.
        let unparsed = QueueHeader { q_perm: 77, q_tmp: 77, ..QueueHeader::default() };
        assert_eq!(read_queue_header(false, &d, 200, 77), unparsed);
        let mut bad = d.clone();
        bad[0] ^= 1;
        assert_eq!(read_queue_header(true, &bad, 200, 77), unparsed);
        assert_eq!(read_queue_header(true, &d[..119], 200, 77), unparsed);
        // Header only: parsed, but the queue itself is not (no enqueue).
        let h = read_queue_header(true, &d[..120], 200, 77);
        assert!(h.hdr_ok && !h.q_ok);
        let mut big = d.clone();
        big[128..136].copy_from_slice(&2049u64.to_le_bytes());
        assert!(!read_queue_header(true, &big, 200, 77).q_ok);
        let mut bi = d.clone();
        bi[136..140].copy_from_slice(&2050u32.to_le_bytes());
        assert!(!read_queue_header(true, &bi, 200, 77).q_ok);
        bi[136..140].copy_from_slice(&2049u32.to_le_bytes());
        assert!(read_queue_header(true, &bi, 200, 77).q_ok);
    }

    #[test]
    fn queue_walk() {
        let other = [0x71; 32];
        let q = Q::default();
        assert_eq!(walk_queue(&queue_bytes(&q, &[]), &US), QueueScan::Clear);
        assert_eq!(walk_queue(&queue_bytes(&q, &[(other, 1), (other, 0)]), &US), QueueScan::Clear);
        for state in 0..=3u8 {
            let d = queue_bytes(&q, &[(other, 1), (US, state), (other, 2)]);
            assert_eq!(walk_queue(&d, &US), QueueScan::OurActive, "state {state}");
        }
        for state in 4..=7u8 {
            let d = queue_bytes(&q, &[(other, 1), (US, state)]);
            assert_eq!(walk_queue(&d, &US), QueueScan::Clear, "final state {state}");
        }
        // Pointer 0 before `size` nodes, out of bounds, `size` too large.
        let mut d = queue_bytes(&q, &[(other, 1), (other, 1)]);
        d[128..136].copy_from_slice(&3u64.to_le_bytes());
        assert_eq!(walk_queue(&d, &US), QueueScan::Broken);
        let mut d = queue_bytes(&q, &[(other, 1)]);
        d[120..124].copy_from_slice(&2049u32.to_le_bytes());
        assert_eq!(walk_queue(&d, &US), QueueScan::Broken);
        let mut d = queue_bytes(&q, &[(other, 1)]);
        d[128..136].copy_from_slice(&2049u64.to_le_bytes());
        assert_eq!(walk_queue(&d, &US), QueueScan::Broken);
        // A cycle is walked exactly `size` times.
        let mut d = queue_bytes(&q, &[(other, 1), (other, 1)]);
        let tail = WITHDRAW_QUEUE_NODES_OFFSET; // node 1 is the list tail
        d[tail + 4..tail + 8].copy_from_slice(&2u32.to_le_bytes());
        d[128..136].copy_from_slice(&2048u64.to_le_bytes());
        assert_eq!(walk_queue(&d, &US), QueueScan::Clear);
        // Truncated account (header only).
        let d = queue_bytes(&q, &[(US, 1)]);
        assert_eq!(walk_queue(&d[..140], &US), QueueScan::Broken);
        // Full 2048-node queue, ours last.
        let mut nodes = vec![(other, 1u8); 2047];
        nodes.push((US, 1));
        assert_eq!(walk_queue(&queue_bytes(&q, &nodes), &US), QueueScan::OurActive);
    }

    #[test]
    fn enqueue_interval() {
        assert!(!enqueue_too_soon(0, 5));
        assert!(enqueue_too_soon(1000, 1000 + RECOVERY_ENQUEUE_MIN_SLOTS - 1));
        assert!(!enqueue_too_soon(1000, 1000 + RECOVERY_ENQUEUE_MIN_SLOTS));
        assert!(enqueue_too_soon(u64::MAX, u64::MAX - 1));
    }

    #[test]
    fn room_and_buffer() {
        // No positions and no orders: everything withdrawable, no buffer.
        assert_eq!(withdraw_room(1_000, 1_000, 0, 50, 100), Ok((1_000, 0)));
        assert_eq!(withdraw_room(1_000, 600, 0, 50, 100), Ok((600, 0)));
        assert_eq!(withdraw_room(-5, 600, 0, 50, 100), Ok((0, 0)));
        // With IM: max(abs, ⌈IM·bps/1e4⌉).
        assert_eq!(withdraw_room(10_000, 10_000, 1_001, 50, 1_000), Ok((10_000 - 101, 101)));
        assert_eq!(withdraw_room(10_000, 10_000, 1_000, 500, 1_000), Ok((9_500, 500)));
        assert_eq!(withdraw_room(100, 100, 1, 500, 0), Ok((-400, 500)));
        assert!(withdraw_room(i64::MAX, u64::MAX, u64::MAX, u64::MAX, u32::MAX).is_ok());
        assert_eq!(recovery_shave(1_000_000, 5, 10), 1_000);
        assert_eq!(recovery_shave(1_000, 5, 10), 5);
        assert_eq!(recovery_shave(u64::MAX, 0, 10_000), u64::MAX);
    }

    const P: PlanParams = PlanParams { d_min: 1_000, shave_abs: 100, shave_bps: 10 };

    fn hdr(q_perm: u64, q_tmp: u64) -> QueueHeader {
        QueueHeader { hdr_ok: true, q_ok: true, q_perm, q_tmp, busy: false, fee_hint: 500, total_queued: 0 }
    }

    #[test]
    fn plan_vectors() {
        // Plenty of budget: everything, immediately.
        let p = plan_withdraw(1_000_000, &hdr(u64::MAX, u64::MAX), 0, &P, false).unwrap();
        assert_eq!(p, WithdrawPlan { d: 1_000_000, d_max: 1_000_000, ..WithdrawPlan::default() });
        assert_eq!(plan_withdraw(0, &hdr(9, 9), 0, &P, false), Err(SijkaError::RecoveryNothing));
        assert_eq!(plan_withdraw(-1, &hdr(9, 9), 0, &P, false), Err(SijkaError::RecoveryNothing));
        // max_amount may shave off max(fee_hint, shave(D_max)) = 1 000, not more.
        let p = plan_withdraw(1_000_000, &hdr(u64::MAX, u64::MAX), 999_000, &P, false).unwrap();
        assert_eq!((p.d, p.amount_limited), (999_000, true));
        assert_eq!(
            plan_withdraw(1_000_000, &hdr(u64::MAX, u64::MAX), 998_999, &P, false),
            Err(SijkaError::RecoveryBelowMinimum)
        );
        // max_amount above D_max changes nothing.
        let p = plan_withdraw(1_000, &hdr(u64::MAX, u64::MAX), 5_000, &P, false).unwrap();
        assert_eq!((p.d, p.amount_limited), (1_000, false));
        // Q_perm below D_room: capped, bit0.
        let p = plan_withdraw(1_000_000, &hdr(300_000, 300_000), 0, &P, false).unwrap();
        assert_eq!((p.d, p.budget_limited, p.queued), (300_000, true, false));
        // Q_tmp below D_req but ≥ floor: partial immediate.
        let p = plan_withdraw(1_000_000, &hdr(u64::MAX, 5_000), 0, &P, false).unwrap();
        assert_eq!((p.d, p.budget_limited, p.queued), (5_000, true, false));
        // Q_tmp below floor: queue (parsed queue).
        let p = plan_withdraw(1_000_000, &hdr(u64::MAX, 999), 0, &P, false).unwrap();
        assert_eq!((p.d, p.queued), (1_000_000, true));
        // Busy queue: queue, never immediate.
        let mut busy = hdr(u64::MAX, u64::MAX);
        busy.busy = true;
        let p = plan_withdraw(1_000_000, &busy, 0, &P, false).unwrap();
        assert!(p.queued);
        busy.q_ok = false;
        assert_eq!(plan_withdraw(1_000_000, &busy, 0, &P, false), Err(SijkaError::WithdrawQueueBusy));
        // Header parsed, queue not, budget below floor.
        let mut h = hdr(u64::MAX, 10);
        h.q_ok = false;
        assert_eq!(plan_withdraw(1_000_000, &h, 0, &P, false), Err(SijkaError::RecoveryBelowMinimum));
        // Permanent max_budget < d_min: every call withdraws Q_perm (REC-7).
        let p = plan_withdraw(1_000_000, &hdr(999, 999), 0, &P, false).unwrap();
        assert_eq!((p.d, p.queued), (999, false));
        // max_budget == 0: nothing to ask for.
        assert_eq!(plan_withdraw(1_000_000, &hdr(0, 0), 0, &P, false), Err(SijkaError::RecoveryBelowMinimum));
    }

    #[test]
    fn plan_unparsed_header_and_flat() {
        // Unparsed header: clamp to max_harvest_per_call, caller may go down to d_min.
        let h = QueueHeader { q_perm: 50_000, q_tmp: 50_000, ..QueueHeader::default() };
        let p = plan_withdraw(1_000_000, &h, 0, &P, false).unwrap();
        assert_eq!((p.d, p.queued, p.budget_limited), (50_000, false, true));
        let p = plan_withdraw(1_000_000, &h, 1_000, &P, false).unwrap();
        assert_eq!(p.d, 1_000);
        assert_eq!(plan_withdraw(1_000_000, &h, 999, &P, false), Err(SijkaError::RecoveryBelowMinimum));
        // Op 6: shave down to d_min even with a parsed header.
        let p = plan_withdraw(1_000_000, &hdr(u64::MAX, u64::MAX), 1_000, &P, true).unwrap();
        assert_eq!(p.d, 1_000);
        assert_eq!(
            plan_withdraw(1_000_000, &hdr(u64::MAX, u64::MAX), 999, &P, true),
            Err(SijkaError::RecoveryBelowMinimum)
        );
        // Room below d_min: all of it.
        let p = plan_withdraw(500, &hdr(u64::MAX, u64::MAX), 0, &P, true).unwrap();
        assert_eq!(p.d, 500);
        let p = plan_withdraw(500, &hdr(u64::MAX, u64::MAX), 1, &P, true);
        assert_eq!(p, Err(SijkaError::RecoveryBelowMinimum));
    }

    /// Full audit FA-2: op 6 (flat) keeps its `d_min` shave only for an
    /// IMMEDIATE withdrawal; a QUEUE request must be near-full like op 1's,
    /// so nobody can park a `d_min` request in Phoenix's queue and hold the
    /// recovery at `d_min` per `RECOVERY_ENQUEUE_MIN_SLOTS`.
    #[test]
    fn plan_queue_request_is_near_full_for_op6() {
        let mut busy = hdr(u64::MAX, u64::MAX);
        busy.busy = true;
        // Flat, busy exchange queue, max_amount = d_min: refused.
        assert_eq!(plan_withdraw(1_000_000, &busy, 1_000, &P, true), Err(SijkaError::RecoveryBelowMinimum));
        // Strict bound: max(fee_hint 500, shave 1 000) = 1 000 below D_max.
        let p = plan_withdraw(1_000_000, &busy, 999_000, &P, true).unwrap();
        assert_eq!((p.d, p.queued), (999_000, true));
        assert_eq!(plan_withdraw(1_000_000, &busy, 998_999, &P, true), Err(SijkaError::RecoveryBelowMinimum));
        let p = plan_withdraw(1_000_000, &busy, 0, &P, true).unwrap();
        assert_eq!((p.d, p.queued), (1_000_000, true));
        // Budget below floor (queue idle): QUEUE mode, same bound.
        let low = hdr(u64::MAX, 999);
        assert_eq!(plan_withdraw(1_000_000, &low, 1_000, &P, true), Err(SijkaError::RecoveryBelowMinimum));
        assert!(plan_withdraw(1_000_000, &low, 0, &P, true).unwrap().queued);
        // A larger enqueueing fee widens the bound the same way for both ops.
        let mut fee = busy;
        fee.fee_hint = 50_000;
        for flat in [false, true] {
            assert_eq!(plan_withdraw(1_000_000, &fee, 950_000, &P, flat).map(|p| p.d), Ok(950_000));
            assert_eq!(plan_withdraw(1_000_000, &fee, 949_999, &P, flat), Err(SijkaError::RecoveryBelowMinimum));
        }
        // IMMEDIATE op 6 still goes down to d_min (it lands on vault_phusd).
        let p = plan_withdraw(1_000_000, &hdr(u64::MAX, u64::MAX), 1_000, &P, true).unwrap();
        assert_eq!((p.d, p.queued), (1_000, false));
    }

    /// Properties on a deterministic grid: D never exceeds D_room, Q_perm or a
    /// non-zero max_amount; IMMEDIATE never exceeds Q_tmp.
    #[test]
    fn plan_bounds_property() {
        let vals = [0u64, 1, 2, 999, 1_000, 1_001, 5_000, 1_000_000, u64::MAX / 2, u64::MAX];
        for &room in &vals[1..] {
            for &perm in &vals {
                for &tmp in &vals {
                    for &max in &vals {
                        for flags in 0..16u8 {
                            let q = QueueHeader {
                                hdr_ok: flags & 1 != 0,
                                q_ok: flags & 2 != 0,
                                busy: flags & 4 != 0,
                                q_perm: perm,
                                q_tmp: tmp.min(perm),
                                fee_hint: 500,
                                total_queued: 0,
                            };
                            let Ok(p) = plan_withdraw(i128::from(room), &q, max, &P, flags & 8 != 0) else {
                                continue;
                            };
                            assert!(p.d >= 1 && p.d <= room && p.d <= perm);
                            if max != 0 {
                                assert!(p.d <= max);
                            }
                            if p.queued {
                                assert!(q.q_ok);
                                // FA-2: a queued request is near-full for op 1 and op 6.
                                let strict = q.fee_hint.max(recovery_shave(p.d_max, P.shave_abs, P.shave_bps));
                                assert!(p.d >= p.d_max.saturating_sub(strict));
                            } else {
                                assert!(!q.busy && p.d <= q.q_tmp);
                            }
                        }
                    }
                }
            }
        }
    }
}
