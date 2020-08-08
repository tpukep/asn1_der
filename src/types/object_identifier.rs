use std::fmt;

extern crate num_bigint;
use self::num_bigint::BigUint;

extern crate num_traits;
use self::num_traits::{FromPrimitive, One, ToPrimitive, Zero};

use {
    der::{DerObject, DerTag, DerValue},
    types::{FromDerObject, IntoDerObject},
    Asn1DerError,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectIdentifier(Vec<BigUint>);

impl ObjectIdentifier {
    /// Generate an ASN.1. The vector should be in the obvious format,
    /// with each component going left-to-right.
    pub fn new(x: Vec<BigUint>) -> ObjectIdentifier {
        ObjectIdentifier(x)
    }

    fn as_raw(&self) -> Result<Vec<u8>, Asn1DerError> {
        match (self.0.get(0), self.0.get(1)) {
            (Some(v1), Some(v2)) => {
                let two = BigUint::from_u8(2).unwrap();

                // first, validate that the first two items meet spec
                if v1 > &two {
                    return Err(Asn1DerError::LengthMismatch);
                }

                let u175 = BigUint::from_u8(175).unwrap();
                let u39 = BigUint::from_u8(39).unwrap();
                let bound = if v1 == &two { u175 } else { u39 };

                if v2 > &bound {
                    return Err(Asn1DerError::LengthMismatch);
                }

                // the following unwraps must be safe, based on the
                // validation above.
                let value1 = v1.to_u8().unwrap();
                let value2 = v2.to_u8().unwrap();
                let byte1 = (value1 * 40) + value2;

                // now we can build all the rest of the body
                let mut body = vec![byte1];

                for num in self.0.iter().skip(2) {
                    let mut local = encode_base127(&num);
                    body.append(&mut local);
                }

                Ok(body)
            }

            _ => Err(Asn1DerError::LengthMismatch),
        }
    }

    pub fn from(body: &[u8]) -> Result<ObjectIdentifier, Asn1DerError> {
        if body.len() == 0 {
            return Err(Asn1DerError::LengthMismatch);
        }

        let mut value1 = BigUint::zero();
        let mut value2 = BigUint::from_u8(body[0]).unwrap();
        let mut oidres = Vec::new();
        let mut bindex = 1;

        if body[0] >= 40 {
            if body[0] < 80 {
                value1 = BigUint::one();
                value2 = value2 - BigUint::from_u8(40).unwrap();
            } else {
                value1 = BigUint::from_u8(2).unwrap();
                value2 = value2 - BigUint::from_u8(80).unwrap();
            }
        }

        oidres.push(value1);
        oidres.push(value2);

        while bindex < body.len() {
            oidres.push(decode_base127(body, &mut bindex)?);
        }

        let id = ObjectIdentifier(oidres);

        return Ok(id);
    }
}

impl<'a> PartialEq<ObjectIdentifier> for &'a ObjectIdentifier {
    fn eq(&self, v2: &ObjectIdentifier) -> bool {
        let &&ObjectIdentifier(ref vec1) = self;
        let &ObjectIdentifier(ref vec2) = v2;

        if vec1.len() != vec2.len() {
            return false;
        }

        for i in 0..vec1.len() {
            if vec1[i] != vec2[i] {
                return false;
            }
        }

        true
    }
}

impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Extract the value using tuple indexing,
        // and create a reference to `vec`.
        let vec = &self.0;

        write!(f, "[")?;

        // Iterate over `v` in `vec` while enumerating the iteration
        // count in `count`.
        for (count, v) in vec.iter().enumerate() {
            // For every element except the first, add a comma.
            // Use the ? operator, or try!, to return on errors.
            if count != 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", v)?;
        }

        // Close the opened bracket and return a fmt::Result value.
        write!(f, "]")
    }
}

impl FromDerObject for ObjectIdentifier {
    fn from_der_object(object: DerObject) -> Result<Self, Asn1DerError> {
        // Validate the tag and check that we have at least one byte
        if object.tag != DerTag::ObjectIdentifier {
            return Err(Asn1DerError::InvalidTag);
        }
        if object.value.data.is_empty() {
            return Err(Asn1DerError::InvalidEncoding);
        }

        ObjectIdentifier::from(&object.value.data)
    }
}

impl IntoDerObject for ObjectIdentifier {
    fn into_der_object(self) -> DerObject {
        let data = self.as_raw().unwrap();
        let value = DerValue::from(data);

        DerObject::new(DerTag::ObjectIdentifier, value)
    }

    fn serialized_len(&self) -> usize {
        return self.as_raw().unwrap().len() + 2;
    }
}

/// A handy macro for generating OIDs from a sequence of `u64`s.
///
/// Usage: oid!(1,2,840,113549,1,1,1) creates an OID that matches
/// 1.2.840.113549.1.1.1. (Coincidentally, this is RSA.)
#[macro_export]
macro_rules! oid {
    ( $( $e: expr ),* ) => {{
        let mut res = Vec::new();

        $(
            res.push(BigUint::from($e as u64));
        )*
        ObjectIdentifier::new(res)
    }};
}

fn decode_base127(i: &[u8], index: &mut usize) -> Result<BigUint, Asn1DerError> {
    let mut res = BigUint::zero();

    loop {
        if *index >= i.len() {
            return Err(Asn1DerError::LengthMismatch);
        }

        let nextbyte = i[*index];

        *index += 1;
        res = (res << 7) + BigUint::from(nextbyte & 0x7f);
        if (nextbyte & 0x80) == 0 {
            return Ok(res);
        }
    }
}

fn encode_base127(value: &BigUint) -> Vec<u8> {
    let mut res = Vec::new();
    let zero = BigUint::zero();

    if value == &zero {
        res.push(0);
        return res;
    }

    let mut acc = value.clone();
    let u128 = BigUint::from_u8(128).unwrap();

    while acc > zero {
        // we build this vector backwards
        let digit = &acc % &u128;
        acc = acc >> 7;

        match digit.to_u8() {
            Some(x) if res.is_empty() => res.push(x),
            Some(x) => res.push(x | 0x80),
            None => panic!("7 bits don't fit into 8, cause ..."),
        }
    }

    res.reverse();

    return res;
}
