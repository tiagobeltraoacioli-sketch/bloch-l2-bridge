// SPDX-License-Identifier: MIT OR Apache-2.0
//! Proof-of-reserves — the §5 public, node-checkable invariant as a PURE
//! predicate over three numbers:
//!
//! ```text
//! sum(UTXO values at the published vault set)
//!     >= gasBLCH_totalSupply_L2 / ATOM_SCALE
//!        + sum(initiated-but-unpaid withdrawal atoms)
//! ```
//!
//! **DETECTS, NOT PREVENTS** (§5 honesty block, non-negotiable): the vault
//! is CUSTODY; colluding keyholders — or Postern itself — can steal
//! reserves, and this check only makes the theft VISIBLE after the fact.
//! It moves no value, freezes nothing, and claws nothing back. It is also
//! only as good as its inputs: `vault_utxo_atoms` must come from the
//! checker's OWN node at a named L1 view (a reorg of that view silently
//! changes the sum — the same §5 caveat as everywhere else).
//!
//! The strict-equality form ([`is_exactly_backed`]) is the tighter
//! sanity invariant for a bridge with no fees skimmed in-band: minted L2
//! supply exactly equals confirmed vault backing net of pending
//! withdrawals. The spec's operational predicate is the `>=` form
//! ([`check_reserves`]), which tolerates operator over-collateralization.
//!
//! SCAFFOLD, UNAUDITED: pure math; nothing here reads a chain.

use crate::atoms::ATOM_SCALE;

/// The three sums the §5 PoR equation is over. All fields are OBSERVED
/// inputs — this module does not fetch them (see module docs for the
/// trust caveats on each).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReserveStatement {
    /// Sum of confirmed UTXO values at the published vault address set,
    /// in atoms, under the checker's own node's view.
    pub vault_utxo_atoms: u128,
    /// Total supply of native gas-BLCH on the L2, in wei.
    pub l2_total_supply_wei: u128,
    /// Sum of initiated-but-unpaid withdrawals, in atoms.
    pub pending_withdrawal_atoms: u128,
}

/// Outcome of the PoR predicate. A value, not an action: nothing here
/// halts, freezes, or pays — DETECTS, not PREVENTS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveCheck {
    /// `vault >= liabilities`; `surplus_atoms = vault - liabilities`.
    Covered { surplus_atoms: u128 },
    /// `vault < liabilities` — reserves do NOT cover the minted supply
    /// plus pending withdrawals. On a custodial vault this means theft,
    /// loss, or accounting corruption HAS ALREADY HAPPENED.
    Shortfall { deficit_atoms: u128 },
    /// The L2 total supply is not a whole number of atoms. Since every
    /// mint is `atoms * ATOM_SCALE` and `withdraw()` enforces
    /// `wei % ATOM_SCALE == 0`, this is unreachable for a correct bridge:
    /// seeing it means the supply figure (or the bridge) is corrupt.
    SupplyNotAtomAligned { remainder: u128 },
    /// `supply_atoms + pending_withdrawal_atoms` overflowed u128. No real
    /// accounting reaches this; refusing beats wrapping silently.
    AccountingOverflow,
}

impl ReserveCheck {
    /// True only for [`ReserveCheck::Covered`].
    pub fn is_covered(&self) -> bool {
        matches!(self, ReserveCheck::Covered { .. })
    }
}

/// Liabilities in atoms: `supply_wei / ATOM_SCALE + pending`, refusing
/// non-atom-aligned supply and overflow.
fn liabilities_atoms(s: &ReserveStatement) -> Result<u128, ReserveCheck> {
    let remainder = s.l2_total_supply_wei % ATOM_SCALE;
    if remainder != 0 {
        return Err(ReserveCheck::SupplyNotAtomAligned { remainder });
    }
    (s.l2_total_supply_wei / ATOM_SCALE)
        .checked_add(s.pending_withdrawal_atoms)
        .ok_or(ReserveCheck::AccountingOverflow)
}

/// The §5 operational PoR predicate (`>=` form). Pure and total.
pub fn check_reserves(s: &ReserveStatement) -> ReserveCheck {
    let liabilities = match liabilities_atoms(s) {
        Ok(l) => l,
        Err(refusal) => return refusal,
    };
    if s.vault_utxo_atoms >= liabilities {
        ReserveCheck::Covered {
            surplus_atoms: s.vault_utxo_atoms - liabilities,
        }
    } else {
        ReserveCheck::Shortfall {
            deficit_atoms: liabilities - s.vault_utxo_atoms,
        }
    }
}

/// The strict-equality invariant: minted L2 supply (in atoms) plus
/// pending withdrawals EXACTLY equals the confirmed vault balance.
/// `false` on any mismatch, including a non-aligned supply or overflow.
pub fn is_exactly_backed(s: &ReserveStatement) -> bool {
    matches!(
        check_reserves(s),
        ReserveCheck::Covered { surplus_atoms: 0 }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atoms::atoms_to_wei;
    use crate::status::ATOMS_PER_BLCH;

    fn stmt(vault: u128, supply_wei: u128, pending: u128) -> ReserveStatement {
        ReserveStatement {
            vault_utxo_atoms: vault,
            l2_total_supply_wei: supply_wei,
            pending_withdrawal_atoms: pending,
        }
    }

    #[test]
    fn exact_backing_is_covered_with_zero_surplus() {
        // 100 BLCH in the vault, 90 minted on L2, 10 pending withdrawal.
        let s = stmt(
            100 * ATOMS_PER_BLCH as u128,
            atoms_to_wei(90 * ATOMS_PER_BLCH),
            10 * ATOMS_PER_BLCH as u128,
        );
        assert_eq!(
            check_reserves(&s),
            ReserveCheck::Covered { surplus_atoms: 0 }
        );
        assert!(is_exactly_backed(&s));
        assert!(check_reserves(&s).is_covered());
    }

    #[test]
    fn over_collateralization_is_covered_but_not_exact() {
        let s = stmt(
            101 * ATOMS_PER_BLCH as u128,
            atoms_to_wei(90 * ATOMS_PER_BLCH),
            10 * ATOMS_PER_BLCH as u128,
        );
        assert_eq!(
            check_reserves(&s),
            ReserveCheck::Covered {
                surplus_atoms: ATOMS_PER_BLCH as u128
            }
        );
        assert!(!is_exactly_backed(&s));
    }

    #[test]
    fn one_atom_shortfall_is_detected() {
        // theft/loss of a single atom flips the predicate — DETECTS.
        let s = stmt(
            100 * ATOMS_PER_BLCH as u128 - 1,
            atoms_to_wei(90 * ATOMS_PER_BLCH),
            10 * ATOMS_PER_BLCH as u128,
        );
        assert_eq!(
            check_reserves(&s),
            ReserveCheck::Shortfall { deficit_atoms: 1 }
        );
        assert!(!is_exactly_backed(&s));
    }

    #[test]
    fn pending_withdrawals_count_as_liabilities() {
        // vault == minted supply, but a pending withdrawal makes it short:
        // the coins for an initiated-but-unpaid withdrawal must STILL be
        // in the vault (they are only paid out at release).
        let s = stmt(
            90 * ATOMS_PER_BLCH as u128,
            atoms_to_wei(90 * ATOMS_PER_BLCH),
            5 * ATOMS_PER_BLCH as u128,
        );
        assert_eq!(
            check_reserves(&s),
            ReserveCheck::Shortfall {
                deficit_atoms: 5 * ATOMS_PER_BLCH as u128
            }
        );
    }

    #[test]
    fn empty_bridge_is_exactly_backed() {
        let s = stmt(0, 0, 0);
        assert_eq!(
            check_reserves(&s),
            ReserveCheck::Covered { surplus_atoms: 0 }
        );
        assert!(is_exactly_backed(&s));
    }

    #[test]
    fn non_atom_aligned_supply_is_refused_not_rounded() {
        // A supply with wei-dust below one atom cannot come from a correct
        // bridge (mints are atoms*SCALE, withdraw() enforces alignment):
        // the check refuses rather than rounding either direction.
        let s = stmt(u128::MAX, atoms_to_wei(ATOMS_PER_BLCH) + 1, 0);
        assert_eq!(
            check_reserves(&s),
            ReserveCheck::SupplyNotAtomAligned { remainder: 1 }
        );
        assert!(!is_exactly_backed(&s));
    }

    #[test]
    fn accounting_overflow_is_refused() {
        let s = stmt(u128::MAX, (u128::MAX / ATOM_SCALE) * ATOM_SCALE, u128::MAX);
        assert_eq!(check_reserves(&s), ReserveCheck::AccountingOverflow);
        assert!(!is_exactly_backed(&s));
    }

    #[test]
    fn detects_not_prevents_is_a_value_not_an_action() {
        // Type-level pin: the outcome is Copy data with no behavior that
        // could move value; the honest claim is in the type system too.
        fn assert_pure_value<T: Copy + core::fmt::Debug + PartialEq>(_: T) {}
        assert_pure_value(check_reserves(&stmt(1, 0, 0)));
    }
}
