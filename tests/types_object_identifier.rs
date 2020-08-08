#[macro_use]
extern crate asn1_der;
use asn1_der::{FromDerObject, IntoDerObject, ObjectIdentifier};

extern crate num_bigint;
use num_bigint::BigUint;

#[test]
fn test_ok() {
    fn test((bytes, boolean): &(&[u8], &ObjectIdentifier)) {
        // Test deserialization
        let deserialized = ObjectIdentifier::deserialize(bytes.iter()).unwrap();
        assert_eq!(*boolean, deserialized);

        // Test length prediction
        assert_eq!(deserialized.serialized_len(), bytes.len());

        // Test serialization
        let mut target = [0u8; 19];
        deserialized.serialize(target.iter_mut()).unwrap();
        assert_eq!(*bytes, &target[..bytes.len()]);
    }

    [(
        [0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d].as_ref(),
        &oid!(1, 2, 840, 113549),
    )]
    .iter()
    .for_each(test);
}

// #[test]
// fn test_err() {
//     fn test((bytes, error): &(&[u8], Asn1DerError)) {
//         assert_eq!(
//             ObjectIdentifier::deserialize(bytes.iter()).unwrap_err(),
//             *error
//         );
//     }

//     [].iter().for_each(test);
// }
