use core::{cmp::Ordering, ops};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SeqNo(u16);

impl SeqNo {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ops::Add for SeqNo {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl ops::AddAssign for SeqNo {
    fn add_assign(&mut self, rhs: Self) {
        *self = Self(self.0.wrapping_add(rhs.0));
    }
}

impl ops::Add<u16> for SeqNo {
    type Output = Self;
    fn add(self, rhs: u16) -> Self::Output {
        Self(self.0.wrapping_add(rhs))
    }
}

impl ops::AddAssign<u16> for SeqNo {
    fn add_assign(&mut self, rhs: u16) {
        *self = Self(self.0.wrapping_add(rhs));
    }
}

/// 3.2.1-7: Given two sequence numbers s and s', the relation s is less than s' (s < s') is defined
/// by the following:

/// s < s' (modulo 2^16) when 0 < ((s' - s) MOD 2^16) < 32768

/// or, equivalently,

/// s < s' (modulo 2^16) when s /= s' and ((s' - s) AND 32768) = 0.
impl PartialOrd for SeqNo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self == other {
            return Some(Ordering::Equal);
        }

        let d_fwd = self.0.wrapping_sub(other.0);

        if d_fwd == 32768 {
            return None;
        }
        if d_fwd < 32768 {
            Some(Ordering::Less)
        } else {
            Some(Ordering::Greater)
        }
    }
}
