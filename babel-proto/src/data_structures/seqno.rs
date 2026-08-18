use core::{cmp::Ordering, ops};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SeqNo(pub u16);

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

impl ops::Sub<SeqNo> for SeqNo {
    type Output = Self;
    fn sub(self, rhs: SeqNo) -> Self::Output {
        Self(self.0.wrapping_sub(rhs.0))
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

        let d_fwd = other.0.wrapping_sub(self.0);

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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn partial_order_undefined_case() {
        let s = SeqNo(0);
        let s_prime = SeqNo(32768);
        assert!(s.partial_cmp(&s_prime).is_none());
        assert!(s_prime.partial_cmp(&s).is_none())
    }

    #[test]
    fn partial_order_returns_returns_false_for_boolean_opposites() {
        // Since SeqNo only implements PartialOrd, this means that two opposite boolean statements
        // for the case in which <SeqNo as PartialOrd>.partial_cmp() returns None will both return
        // false.
        assert!(!(SeqNo(0) <= SeqNo(32768)));
        assert!(!(SeqNo(0) >= SeqNo(32768)));
    }

    #[test]
    fn simple_case_matches_normal_order() {
        assert!(SeqNo(5) < SeqNo(10));
        assert!(SeqNo(10) > SeqNo(5));
    }

    #[test]
    fn wraparound_less_than() {
        // 65534 < 2, since 2 comes shortly "after" 65534 going forward.
        assert!(SeqNo(65534) < SeqNo(2));
        assert!(!(SeqNo(2) < SeqNo(65534)));
    }
    #[test]
    fn addition_wraps() {
        assert_eq!(SeqNo(65535) + 1, SeqNo(0));
        assert_eq!(SeqNo(65530) + 10, SeqNo(4));
    }
}
