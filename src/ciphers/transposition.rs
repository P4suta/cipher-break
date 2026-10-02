// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::alphabet::Letter;

#[must_use]
pub fn columnar(key: &[usize], ct: &[Letter]) -> Vec<Letter> {
    let width = key.len();
    if width == 0 {
        return ct.to_vec();
    }
    let rows = ct.len() / width;
    let spare = ct.len() % width;
    let mut columns: Vec<&[Letter]> = Vec::with_capacity(width);
    let mut rest = ct;
    for &position in key {
        let take = if position < spare { rows + 1 } else { rows };
        let (head, tail) = rest.split_at(take.min(rest.len()));
        columns.push(head);
        rest = tail;
    }
    let mut ordered: Vec<&[Letter]> = vec![&[]; width];
    for (slot, &position) in key.iter().enumerate() {
        ordered[position] = columns[slot];
    }
    let mut out = Vec::with_capacity(ct.len());
    for r in 0..=rows {
        for column in &ordered {
            if let Some(&l) = column.get(r) {
                out.push(l);
            }
        }
    }
    out
}

#[must_use]
pub fn permutations(width: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut current: Vec<usize> = (0..width).collect();
    permute(&mut current, 0, &mut out);
    out
}

fn permute(current: &mut Vec<usize>, k: usize, out: &mut Vec<Vec<usize>>) {
    if k == current.len() {
        out.push(current.clone());
        return;
    }
    for i in k..current.len() {
        current.swap(k, i);
        permute(current, k + 1, out);
        current.swap(k, i);
    }
}

#[must_use]
pub fn rail_fence(rails: usize, ct: &[Letter]) -> Vec<Letter> {
    if rails < 2 {
        return ct.to_vec();
    }
    let mut pattern: Vec<usize> = (0..rails).collect();
    pattern.extend((1..rails - 1).rev());
    let assignment: Vec<usize> = (0..ct.len()).map(|i| pattern[i % pattern.len()]).collect();
    let mut order: Vec<usize> = (0..ct.len()).collect();
    order.sort_by_key(|&i| (assignment[i], i));
    let mut out = vec![0u8; ct.len()];
    for (slot, &target) in order.iter().enumerate() {
        out[target] = ct[slot];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alphabet::{from_letters, to_letters};

    fn columnar_encipher(key: &[usize], pt: &[Letter]) -> Vec<Letter> {
        let width = key.len();
        let mut out = Vec::with_capacity(pt.len());
        for &position in key {
            let mut i = position;
            while i < pt.len() {
                out.push(pt[i]);
                i += width;
            }
        }
        out
    }

    fn rail_encipher(rails: usize, pt: &[Letter]) -> Vec<Letter> {
        let mut pattern: Vec<usize> = (0..rails).collect();
        pattern.extend((1..rails - 1).rev());
        let mut order: Vec<usize> = (0..pt.len()).collect();
        order.sort_by_key(|&i| (pattern[i % pattern.len()], i));
        order.into_iter().map(|i| pt[i]).collect()
    }

    #[test]
    fn columnar_undoes_its_own_enciphering() {
        let msg = to_letters("WEAREDISCOVEREDFLEEATONCEXX");
        for key in [vec![2, 0, 3, 1], vec![0, 1, 2], vec![4, 1, 3, 0, 2]] {
            assert_eq!(columnar(&key, &columnar_encipher(&key, &msg)), msg);
        }
    }

    #[test]
    fn columnar_handles_a_ragged_last_row() {
        let msg = to_letters("ABCDEFGHIJ");
        let key = vec![2, 0, 3, 1];
        assert_eq!(
            from_letters(&columnar(&key, &columnar_encipher(&key, &msg))),
            "ABCDEFGHIJ"
        );
    }

    #[test]
    fn an_empty_key_changes_nothing() {
        let msg = to_letters("ABCDEF");
        assert_eq!(columnar(&[], &msg), msg);
    }

    #[test]
    fn there_are_factorially_many_permutations() {
        assert_eq!(permutations(4).len(), 24);
        assert_eq!(permutations(1).len(), 1);
    }

    #[test]
    fn rail_fence_undoes_its_own_enciphering() {
        let msg = to_letters("WEAREDISCOVEREDFLEEATONCE");
        for rails in [2usize, 3, 4, 7] {
            assert_eq!(rail_fence(rails, &rail_encipher(rails, &msg)), msg);
        }
    }

    #[test]
    fn two_rails_is_the_shortest_fence_there_is() {
        let msg = to_letters("ABCDEF");
        assert_ne!(rail_fence(2, &msg), msg, "two rails must move something");
        assert_eq!(rail_fence(0, &msg), msg);
    }

    #[test]
    fn permutations_of_nothing_is_one_empty_order() {
        assert_eq!(permutations(0).len(), 1);
        assert_eq!(permutations(0)[0], Vec::<usize>::new());
    }

    #[test]
    fn one_rail_changes_nothing() {
        let msg = to_letters("ABCDEF");
        assert_eq!(rail_fence(1, &msg), msg);
    }
}
