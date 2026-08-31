use core::fmt::Debug as DebugT;
use core::ops::{Deref, DerefMut};

use crate::utils::ManagedSlice;

/// A type that knows how to be located within a slice containing itself and can derive its own key.
/// And knows how to sort a slice of itself in a way that the locate method is expecting.
pub(crate) trait InternallyKeyed: Sized {
    /// TODO: I would like to figure out the lifetime hell that would allow this GAT to contain
    /// borrowed values (if there is a performance improvement to be had)
    type Key: Ord + Copy;

    fn key(&self) -> Self::Key;

    /// Locate the index of the given key within the slice if it exists.
    ///
    /// This method requires a slice that is sorted by the key.
    fn locate(slice: &[Option<Self>], key: &Self::Key) -> Option<usize> {
        slice
            .binary_search_by(|a| a.as_ref().map(|av| av.key()).as_ref().cmp(&Some(key)))
            .ok()
    }
    /// Sorts the values in the slice by their key.
    ///
    /// The locate method requires a sorted slice.
    fn _my_sort(slice: &mut [Option<Self>]) {
        // This data structure is deduplicated by key, so unstable sort is stable.
        //
        // Unstable sort is called unstable because it does not guarantee the ordering of equal
        // elements. That is why it is ok here.
        slice.sort_unstable_by(|a, b| {
            a.as_ref()
                .map(|av| av.key())
                .cmp(&(b.as_ref().map(|bv| bv.key())))
        });
    }
}

impl<'storage, K, V> ManagedSlice<'storage, Option<V>>
where
    K: Ord,
    V: InternallyKeyed<Key = K> + DebugT,
{
    pub(crate) fn insert(&mut self, value: V) -> Result<Option<V>, V> {
        // Look for an existing matching element in the slice.
        let old_opt = match V::locate(&self[..], &value.key()) {
            Some(idx) => {
                // If it exists, replace it and return the old value.

                self[idx].replace(value)
            }
            None => {
                // If it does not exist
                match self {
                    ManagedSlice::Borrowed(borrowed) => {
                        // If the slice is borrowed, find the first empty slot in the slice.
                        let idx_opt = borrowed.iter().position(|x| x.is_none());
                        match idx_opt {
                            Some(idx) => {
                                // If there is space in the slice, insert the value.
                                borrowed[idx] = Some(value);
                            }
                            None => {
                                // If the slice is borrowed then it has pre-allocated capacity, so
                                // we cannot insert.

                                // If it is full, there will be no elements that contain `None`,
                                // return the value that would have been put in.
                                return Err(value);
                            }
                        }
                    }
                    #[cfg(any(feature = "std", feature = "alloc"))]
                    ManagedSlice::Owned(owned) => {
                        // If the slice is owned push the item.
                        owned.push(Some(value));
                    }
                }
                None
            }
        };
        // Ensure the slice is sorted after modifying it.
        V::_my_sort(&mut self[..]);
        Ok(old_opt)
    }

    pub(crate) fn remove(&mut self, key: &K) -> Option<V> {
        let out = V::locate(&self[..], key).and_then(|idx| self[idx].take());
        // Ensure the slice is sorted after modifying it.
        V::_my_sort(&mut self[..]);
        out
    }

    pub(crate) fn get_by_key(&self, key: &K) -> Option<&V> {
        let idx = V::locate(&self[..], key)?;
        self.get(idx)?.as_ref()
    }

    pub(crate) fn get_mut_by_key(&mut self, key: &K) -> Option<&mut V> {
        let idx = V::locate(&self[..], key)?;
        self.get_mut(idx)?.as_mut()
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &V>
    where
        V: 'a,
    {
        self.deref().iter().filter_map(|i| i.as_ref())
    }

    pub(crate) fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &mut V>
    where
        V: 'a,
    {
        self.deref_mut().iter_mut().filter_map(|i| i.as_mut())
    }

    pub(crate) fn iter_slots<'a>(&'a self) -> impl Iterator<Item = &Option<V>>
    where
        V: 'a,
    {
        self.deref().iter()
    }

    pub(crate) fn iter_mut_slots<'a>(&'a mut self) -> impl Iterator<Item = &mut Option<V>>
    where
        V: 'a,
    {
        self.deref_mut().iter_mut()
    }

    pub(crate) fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&V) -> bool,
    {
        self.retain_mut(|elem| f(elem));
    }

    pub(crate) fn retain_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut V) -> bool,
    {
        // This can be naive compared to the std library version because there is no dropping in
        // place, Instead it changes the slot to None and flushes after iterating.
        for slot in self.iter_mut_slots() {
            match slot.as_mut() {
                Some(item) => {
                    if !f(item) {
                        *slot = None;
                    }
                }
                None => {}
            }
        }

        self.flush();
    }

    pub(crate) fn flush(&mut self) {
        if let ManagedSlice::Owned(owned) = self {
            owned.retain(|e| e.is_some());
        }
        // Ensure the slice is sorted after modifying it.
        V::_my_sort(&mut self[..]);
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[allow(dead_code)]
    #[derive(Debug)]
    struct TestValue {
        a: u8,
        b: u16,
        _c: u64,
    }

    #[allow(dead_code)]
    #[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Copy, Clone)]
    struct TestKey {
        key_a: u8,
        key_b: u16,
    }

    impl InternallyKeyed for TestValue {
        type Key = TestKey;

        fn key(&self) -> Self::Key {
            Self::Key {
                key_a: self.a,
                key_b: self.b,
            }
        }
    }

    #[cfg(not(any(feature = "std", feature = "alloc")))]
    #[test]
    fn insert_until_full_fails() {
        let _ = env_logger::try_init();
        let storage: &mut [Option<TestValue>] = &mut [const { None }; 3];
        let mut managed_slice: ManagedSlice<'_, Option<TestValue>> = storage.into();

        for i in (0..=2).rev() {
            managed_slice
                .insert(TestValue {
                    a: i as u8,
                    b: i as u16,
                    _c: i as u64,
                })
                .unwrap_or_else(|_| panic!("Insert {} should have succeeded", i));
        }

        managed_slice
            .insert(TestValue { a: 3, b: 3, _c: 3 })
            .expect_err("Insert 3 should have failed.");
    }

    #[cfg(any(feature = "std", feature = "alloc"))]
    #[test]
    fn insert_until_full_allocates() {
        use alloc::vec::Vec;
        let _ = env_logger::try_init();
        // In std or alloc this becomes an owned vec anc can be resized.
        let mut managed_slice: ManagedSlice<'_, Option<TestValue>> = Vec::new().into();

        for i in (0..=3).rev() {
            managed_slice
                .insert(TestValue {
                    a: i as u8,
                    b: i as u16,
                    _c: i as u64,
                })
                .unwrap_or_else(|_| panic!("Insert {} should have succeeded", i));
        }
    }

    #[cfg(any(feature = "std", feature = "alloc"))]
    #[test]
    fn insert_many_then_get_succeeds() {
        use alloc::vec::Vec;
        let _ = env_logger::try_init();
        // In std or alloc this becomes an owned vec anc can be resized.
        let mut managed_slice: ManagedSlice<'_, Option<TestValue>> = Vec::new().into();

        // First insert a known value that is in the middle of the range of possible numbers.
        let test_value = TestValue {
            a: u8::MAX / 2,
            b: u16::MAX / 2,
            _c: u64::MAX / 2,
        };
        let ret_key = test_value.key();
        let _ = managed_slice.insert(test_value);

        // Insert 100 random values into the slice.
        for _ in 0..100 {
            managed_slice
                .insert(TestValue {
                    a: rand::random(),
                    b: rand::random(),
                    _c: rand::random(),
                })
                .unwrap_or_else(|_| panic!("Insert should have succeeded for owned slice."));
        }

        managed_slice
            .get_by_key(&ret_key)
            .expect("Should have returned expected element.");
        managed_slice
            .get_mut_by_key(&ret_key)
            .expect("Should have returned expected mutable element.");
    }

    #[cfg(any(feature = "std", feature = "alloc"))]
    #[test]
    fn managed_slice_remove_works() {
        use alloc::vec::Vec;
        let _ = env_logger::try_init();
        // In std or alloc this becomes an owned vec anc can be resized.
        let mut managed_slice: ManagedSlice<'_, Option<TestValue>> = Vec::new().into();

        // Insert some elements
        for i in (0..=3).rev() {
            managed_slice
                .insert(TestValue {
                    a: i as u8,
                    b: i as u16,
                    _c: i as u64,
                })
                .unwrap_or_else(|_| panic!("Insert {} should have succeeded", i));
        }

        // Remove one of the elements
        let test_key = TestKey { key_a: 2, key_b: 2 };
        managed_slice
            .remove(&test_key)
            .expect("Element should exist.");
        assert!(
            managed_slice.get_by_key(&test_key).is_none(),
            "Element should not be in the slice anymore."
        )
    }
}
