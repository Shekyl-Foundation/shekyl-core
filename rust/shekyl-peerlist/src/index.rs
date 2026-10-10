// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! An address table with a uniform index draw.
//!
//! A vector is the draw: [`Index::pick`] is one bounded index, whatever
//! the table holds. A map from the address to that index keeps insert,
//! remove and lookup in step with the vector, by swap-remove. The peer
//! list's hot path — a gray draw, a capacity eviction — used to walk
//! every member into a fresh vector; this table is that walk, done once
//! at insert.

use std::collections::BTreeMap;

use shekyl_net_address::NetworkAddress;
use shekyl_relay_privacy::rng::{bounded_uniform, RelayRng};

/// `members[i]` sits at `position[address] == i`. The two agree after
/// every insert and remove.
#[derive(Debug)]
pub(crate) struct Index<T> {
    members: Vec<(NetworkAddress, T)>,
    position: BTreeMap<NetworkAddress, usize>,
}

impl<T> Default for Index<T> {
    fn default() -> Self {
        Self {
            members: Vec::new(),
            position: BTreeMap::new(),
        }
    }
}

impl<T> Index<T> {
    pub(crate) fn len(&self) -> usize {
        self.members.len()
    }

    pub(crate) fn contains(&self, address: &NetworkAddress) -> bool {
        self.position.contains_key(address)
    }

    pub(crate) fn get(&self, address: &NetworkAddress) -> Option<&T> {
        self.position.get(address).map(|at| &self.members[*at].1)
    }

    pub(crate) fn get_mut(&mut self, address: &NetworkAddress) -> Option<&mut T> {
        let at = *self.position.get(address)?;
        Some(&mut self.members[at].1)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &(NetworkAddress, T)> {
        self.members.iter()
    }

    /// Insert. `false` when the address is already seated — the value is
    /// left as it was.
    pub(crate) fn insert(&mut self, address: NetworkAddress, value: T) -> bool {
        if self.position.contains_key(&address) {
            return false;
        }
        self.position.insert(address.clone(), self.members.len());
        self.members.push((address, value));
        true
    }

    /// Remove. `None` when the address is absent. The last member swaps
    /// into the hole and its position is rewritten.
    pub(crate) fn remove(&mut self, address: &NetworkAddress) -> Option<T> {
        let at = self.position.remove(address)?;
        let (_, value) = self.members.swap_remove(at);
        if at < self.members.len() {
            let moved = self.members[at].0.clone();
            self.position.insert(moved, at);
        }
        Some(value)
    }

    /// One uniform member.
    ///
    /// An empty table is `None`. A one-member table returns that member
    /// and does not draw: there is nothing to choose. Every larger table
    /// draws `bounded_uniform(rng, len - 1)`, an inclusive upper bound,
    /// so the index is uniform.
    pub(crate) fn pick<R: RelayRng + ?Sized>(&self, rng: &mut R) -> Option<&(NetworkAddress, T)> {
        match self.len() {
            0 => None,
            1 => Some(&self.members[0]),
            n => {
                let index = usize::try_from(bounded_uniform(rng, (n - 1) as u64))
                    .expect("the draw is bounded by the member count");
                Some(&self.members[index])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use shekyl_relay_privacy::rng::SplitMix64;

    use super::*;

    fn v4(n: u8) -> NetworkAddress {
        NetworkAddress::Ipv4 {
            ip: Ipv4Addr::new(10, 0, 0, n),
            port: 18080,
        }
    }

    #[test]
    fn insert_is_once_and_swap_remove_keeps_the_rest_addressable() {
        let mut index = Index::default();
        assert!(index.insert(v4(1), 10));
        assert!(
            !index.insert(v4(1), 11),
            "a second insert does not move the value"
        );
        assert_eq!(index.get(&v4(1)), Some(&10));
        assert!(index.insert(v4(2), 20));
        assert!(index.insert(v4(3), 30));
        assert_eq!(index.remove(&v4(1)), Some(10));
        assert!(!index.contains(&v4(1)));
        assert_eq!(index.get(&v4(2)), Some(&20));
        assert_eq!(index.get(&v4(3)), Some(&30));
        assert_eq!(index.len(), 2);

        let mut only = Index::default();
        assert!(only.insert(v4(4), 40));
        let mut rng = SplitMix64::new(1);
        assert_eq!(
            only.pick(&mut rng)
                .map(|(address, value)| (address.clone(), *value)),
            Some((v4(4), 40))
        );
    }
}
