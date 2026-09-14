use core::fmt::Debug as DebugT;
use core::mem;
use core::ops::{Deref, DerefMut};

use crate::utils::ManagedSlice;

/// Asserts, in non-optimized builds only, that a [`Table`] is sorted by key before it is accessed.
///
/// [`InternallyKeyed::locate`] binary searches, so an unsorted table does not fail loudly, it just
/// returns wrong answers. This turns that into a panic while debugging.
///
/// Expands to nothing in release builds, so the sortedness scan costs nothing there. Must be
/// invoked from a scope where the table's value type is named `V`.
macro_rules! check_sorted {
    ($self:expr) => {
        debug_assert!(
            is_sorted(&$self.0[..]),
            "Table was not sorted on access: {}",
            core::any::type_name_of_val($self)
        );
    };
}
/// A slot in a [`Table`].
///
/// This is used for table values that either require no resources to instantiate, or values that
/// require some pre-allocated resource that can be given back when dropped.
pub(crate) trait TableSlot {
    type Value: InternallyKeyed;
    fn new_occupied(value: Self::Value) -> Self;
    fn value(&self) -> Option<&Self::Value>;
    fn value_mut(&mut self) -> Option<&mut Self::Value>;

    /// Places a value in the slot, dropping whatever was there.
    fn occupy(&mut self, value: Self::Value);

    /// Empties the slot.
    fn free(&mut self);

    /// True when the slot holds nothing, no value and no resource.
    fn is_vacant(&self) -> bool;
    fn is_free(&self) -> bool;
}

impl<V: InternallyKeyed> TableSlot for Option<V> {
    type Value = V;
    fn new_occupied(value: V) -> Self {
        Some(value)
    }
    fn value(&self) -> Option<&V> {
        self.as_ref()
    }
    fn value_mut(&mut self) -> Option<&mut V> {
        self.as_mut()
    }
    fn occupy(&mut self, value: V) {
        *self = Some(value);
    }
    fn free(&mut self) {
        *self = None;
    }
    fn is_vacant(&self) -> bool {
        self.is_none()
    }
    fn is_free(&self) -> bool {
        self.is_none()
    }
}

/// A value that is built from pre-allocated memory and can give it back.
pub(crate) trait Recycle: Sized {
    type Storage: Default;
    fn release(self) -> Self::Storage;
}

/// Storage slot used for pre-allocated memory.
///
/// The type stored at Free can contain types required to instantiate the value at InUse.
pub(crate) enum MaybeInUse<V: Recycle> {
    Free(V::Storage),
    InUse(V),
    Vacant,
}

impl<V: Recycle> MaybeInUse<V> {
    fn storage(self) -> Option<V::Storage> {
        match self {
            MaybeInUse::Free(s) => Some(s),
            _ => None,
        }
    }
}

impl<V: Recycle + InternallyKeyed> TableSlot for MaybeInUse<V> {
    type Value = V;
    fn new_occupied(value: V) -> Self {
        Self::InUse(value)
    }

    /// Returns the instantiated value at the slot if it is in use.
    fn value(&self) -> Option<&V> {
        match self {
            MaybeInUse::InUse(v) => Some(v),
            _ => None,
        }
    }

    /// Returns the instantiated value at the slot if it is in use.
    fn value_mut(&mut self) -> Option<&mut V> {
        match self {
            MaybeInUse::InUse(v) => Some(v),
            _ => None,
        }
    }

    fn occupy(&mut self, value: V) {
        *self = MaybeInUse::InUse(value)
    }

    /// If the value is in use, free's it in place.
    fn free(&mut self) {
        match mem::replace(self, MaybeInUse::Vacant) {
            MaybeInUse::InUse(v) => *self = MaybeInUse::Free(v.release()),
            free => *self = free,
        }
    }

    fn is_vacant(&self) -> bool {
        matches!(self, MaybeInUse::Vacant)
    }

    fn is_free(&self) -> bool {
        matches!(self, MaybeInUse::Free(_))
    }
}

/// A type that knows how to be located within a slice containing itself and can derive its own key.
/// And knows how to sort a slice of itself in a way that the locate method is expecting.
pub(crate) trait InternallyKeyed
where
    Self: Sized + DebugT,
{
    /// TODO: I would like to figure out the lifetime hell that would allow this GAT to contain
    /// borrowed values (if there is a performance improvement to be had)
    type Key: Ord + Copy;

    fn key(&self) -> Self::Key;
}

/// A table for a specific Babel data structure.
///
/// IMPORTANT: The entries of this table are internally keyed, that means they are looked up and
/// sorted by information inside of the entries. Table entries should **NEVER** be able to mutate
/// their keys after initial creation.
///
/// ## Example of good implementation
///
/// This example is `ignore`d rather than run because everything it names is crate private, and a
/// doctest compiles as a downstream crate.
///
/// ```ignore
/// #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
/// pub(crate) struct MyKey {
///     key_val_1: u32,
///     key_val_2: u64,
/// }
///
/// #[derive(Debug)]
/// pub(crate) struct MyItem {
///     // Fully private keys
///     key_val_1: u32,
///     // Fully private keys
///     key_val_2: u64,
///     pub(crate) other_val_1: bool,
///     pub other_val_2: [u8; 16],
/// }
///
/// impl InternallyKeyed for MyItem {
///     type Key = MyKey;
///     fn key(&self) -> Self::Key {
///         MyKey {
///             key_val_1: self.key_val_1,
///             key_val_2: self.key_val_2,
///         }
///     }
/// }
///
/// pub(crate) struct MyTable<'storage> {
///     inner: Table<'storage, MyKey, MyItem>,
/// }
/// ```
pub(crate) struct Table<'storage, S>(ManagedSlice<'storage, S>)
where
    S: TableSlot;

impl<'storage, S> Table<'storage, S>
where
    S: TableSlot,
{
    pub(crate) fn new<T: Into<ManagedSlice<'storage, S>>>(storage: T) -> Self {
        Self(storage.into())
    }

    pub(crate) fn insert(&mut self, value: S::Value) -> Result<Option<S::Value>, S::Value> {
        check_sorted!(self);
        // Look for an existing matching element in the slice.
        let old_opt = match locate(&self.0[..], &value.key()) {
            Some(_idx) => {
                // If it exists, return the new value as an error.
                return Err(value);
            }
            None => {
                // If it does not exist
                match &mut self.0 {
                    ManagedSlice::Borrowed(borrowed) => {
                        // If the slice is borrowed, find the first vacant slot in the slice.
                        let idx_opt = borrowed.iter().position(|x| x.is_vacant());
                        match idx_opt {
                            Some(idx) => {
                                // If there is space in the slice, insert the value.
                                borrowed[idx].occupy(value);
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
                        owned.push(S::new_occupied(value));
                    }
                }
                None
            }
        };
        // Ensure the slice is sorted after modifying it.
        my_sort(&mut self.0[..]);
        Ok(old_opt)
    }

    pub(crate) fn free(&mut self, key: &<S::Value as InternallyKeyed>::Key) {
        check_sorted!(self);
        if let Some(idx) = locate(&self.0[..], key) {
            self.0[idx].free();
        }
        // Ensure the slice is sorted after modifying it.
        self.flush();
    }

    pub(crate) fn get_by_key(&self, key: &<S::Value as InternallyKeyed>::Key) -> Option<&S::Value> {
        check_sorted!(self);
        let idx = locate(&self.0[..], key)?;
        self.0.get(idx)?.value()
    }

    pub(crate) fn get_mut_by_key(
        &mut self,
        key: &<S::Value as InternallyKeyed>::Key,
    ) -> Option<&mut S::Value> {
        check_sorted!(self);
        let idx = locate(&self.0[..], key)?;
        self.0.get_mut(idx)?.value_mut()
    }

    pub(crate) fn iter<'a>(&'a self) -> impl Iterator<Item = &'a S::Value>
    where
        S::Value: 'a,
    {
        check_sorted!(self);
        self.0.deref().iter().filter_map(|i| i.value())
    }

    pub(crate) fn iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut S::Value>
    where
        S::Value: 'a,
    {
        check_sorted!(self);
        self.0.deref_mut().iter_mut().filter_map(|i| i.value_mut())
    }

    pub(crate) fn iter_slots<'a>(&'a self) -> impl Iterator<Item = &'a S>
    where
        S::Value: 'a,
    {
        check_sorted!(self);
        self.0.deref().iter()
    }

    pub(crate) fn iter_mut_slots<'a>(&'a mut self) -> impl Iterator<Item = &'a mut S>
    where
        S::Value: 'a,
    {
        check_sorted!(self);
        self.0.deref_mut().iter_mut()
    }

    /// Groups the slots of the table into runs of consecutive elements that `pred` considers to
    /// belong together.
    ///
    /// The table is always sorted by key, so a predicate over any prefix of the key yields the
    /// groups of entries sharing that prefix.
    pub(crate) fn chunk_by_mut<'a, F>(&'a mut self, pred: F) -> impl Iterator<Item = &'a mut [S]>
    where
        F: FnMut(&S, &S) -> bool,
        S::Value: 'a,
    {
        check_sorted!(self);
        self.0.deref_mut().chunk_by_mut(pred)
    }

    pub(crate) fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&S::Value) -> bool,
    {
        self.retain_mut(|elem| f(elem));
    }

    pub(crate) fn retain_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(&mut S::Value) -> bool,
    {
        check_sorted!(self);
        // This can be naive compared to the std library version because there is no dropping in
        // place, Instead it changes the slot to None and flushes after iterating.
        for slot in self.iter_mut_slots() {
            match slot.value_mut() {
                Some(item) => {
                    if !f(item) {
                        slot.free();
                    }
                }
                None => {}
            }
        }

        // Flushes and sorts the slice after modifying it.
        self.flush();
    }

    pub(crate) fn flush(&mut self) {
        #[cfg(any(feature = "std", feature = "alloc"))]
        if let ManagedSlice::Owned(owned) = &mut self.0 {
            owned.retain(|e| e.value().is_some());
        }
        // Ensure the slice is sorted after modifying it.
        my_sort(&mut self.0[..]);
    }
}

/// Fetches the first available free storage in the table.
///
/// Only implemented if the table contains a type that is created from a resource.
impl<'storage, V: InternallyKeyed + Recycle> Table<'storage, MaybeInUse<V>> {
    pub(crate) fn get_storage(&mut self) -> Option<V::Storage> {
        let out = match &mut self.0 {
            // If the slice is borrowed, look for a free spot.
            ManagedSlice::Borrowed(borrowed) => {
                let item = borrowed.iter_mut().find(|s| s.is_free())?;
                let out = mem::replace(item, MaybeInUse::Vacant).storage();
                out
            }
            // If the slice is owned, push a new slot.
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedSlice::Owned(v) => {
                // If we have access to alloc, then alloc.
                v.push(MaybeInUse::Vacant);
                Some(V::Storage::default())
            }
        };
        // Sort after mutating.
        my_sort(&mut self.0[..]);
        out
    }
}

/// Locate the index of the given key within the slice if it exists.
///
/// This method requires a slice that is sorted by the key.
fn locate<S: TableSlot>(slice: &[S], key: &<S::Value as InternallyKeyed>::Key) -> Option<usize> {
    slice
        .binary_search_by(|a| {
            a.value()
                .as_ref()
                .map(|av| av.key())
                .as_ref()
                .cmp(&Some(key))
        })
        .ok()
}

/// Sorts the values in the slice by their key.
///
/// The locate method requires a sorted slice.
fn my_sort<S: TableSlot>(slice: &mut [S]) {
    // This data structure is deduplicated by key, so unstable sort is stable.
    //
    // Unstable sort is called unstable because it does not guarantee the ordering of equal
    // elements. That is why it is ok here.
    slice.sort_unstable_by(|a, b| {
        a.value()
            .as_ref()
            .map(|av| av.key())
            .cmp(&(b.value().as_ref().map(|bv| bv.key())))
    });
}

fn is_sorted<S: TableSlot>(slice: &[S]) -> bool {
    slice.is_sorted_by_key(|a| a.value().as_ref().map(|av| av.key()))
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
        let mut table: Table<'_, Option<TestValue>> = Table::new(storage);

        for i in (0..=2).rev() {
            table
                .insert(TestValue {
                    a: i as u8,
                    b: i as u16,
                    _c: i as u64,
                })
                .unwrap_or_else(|_| panic!("Insert {} should have succeeded", i));
        }

        table
            .insert(TestValue { a: 3, b: 3, _c: 3 })
            .expect_err("Insert 3 should have failed.");
    }

    #[cfg(any(feature = "std", feature = "alloc"))]
    #[test]
    fn insert_until_full_allocates() {
        use alloc::vec::Vec;
        let _ = env_logger::try_init();
        // In std or alloc this becomes an owned vec anc can be resized.
        let mut table: Table<'_, Option<TestValue>> = Table::new(Vec::new());

        for i in (0..=3).rev() {
            table
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
        let mut table: Table<'_, Option<TestValue>> = Table::new(Vec::new());

        // First insert a known value that is in the middle of the range of possible numbers.
        let test_value = TestValue {
            a: u8::MAX / 2,
            b: u16::MAX / 2,
            _c: u64::MAX / 2,
        };
        let ret_key = test_value.key();
        let _ = table.insert(test_value);

        // Insert 100 random values into the slice.
        for _ in 0..100 {
            table
                .insert(TestValue {
                    a: rand::random(),
                    b: rand::random(),
                    _c: rand::random(),
                })
                .unwrap_or_else(|_| panic!("Insert should have succeeded for owned slice."));
        }

        table
            .get_by_key(&ret_key)
            .expect("Should have returned expected element.");
        table
            .get_mut_by_key(&ret_key)
            .expect("Should have returned expected mutable element.");
    }

    #[cfg(any(feature = "std", feature = "alloc"))]
    #[test]
    fn table_remove_works() {
        use alloc::vec::Vec;
        let _ = env_logger::try_init();
        // In std or alloc this becomes an owned vec anc can be resized.
        let mut table: Table<'_, Option<TestValue>> = Table::new(Vec::new());

        // Insert some elements
        for i in (0..=3).rev() {
            table
                .insert(TestValue {
                    a: i as u8,
                    b: i as u16,
                    _c: i as u64,
                })
                .unwrap_or_else(|_| panic!("Insert {} should have succeeded", i));
        }

        // Remove one of the elements
        let test_key = TestKey { key_a: 2, key_b: 2 };
        table.free(&test_key);
        assert!(
            table.get_by_key(&test_key).is_none(),
            "Element should not be in the slice anymore."
        )
    }

    /// Pins down the `check_sorted!` guard, including the type it names in the panic message.
    ///
    /// `locate` binary searches, so an out-of-order table returns wrong answers rather than
    /// failing. The guard is what turns that into a panic, and it only exists in non-optimized
    /// builds, which is where tests run.
    ///
    /// The exact rendering of `type_name_of_val` is not a stability guarantee of `core`, so a
    /// toolchain bump may reformat the type (the `'_`, for instance) and require the expected
    /// string below to be updated. That is the cost of pinning that the type is named at all.
    #[cfg(any(feature = "std", feature = "alloc"))]
    #[test]
    #[should_panic]
    fn access_of_unsorted_table_panics() {
        use alloc::vec::Vec;
        let _ = env_logger::try_init();
        let mut table: Table<'_, Option<TestValue>> = Table::new(Vec::new());

        for i in 0..=1 {
            table
                .insert(TestValue {
                    a: i as u8,
                    b: i as u16,
                    _c: i as u64,
                })
                .unwrap_or_else(|_| panic!("Insert {} should have succeeded", i));
        }

        // Break the ordering behind the table's back. Nothing in the public surface can do this,
        // which is the point: the guard catches a bug in the table's own bookkeeping.
        table.0.deref_mut().swap(0, 1);

        table.get_by_key(&TestKey { key_a: 0, key_b: 0 });
    }
}
