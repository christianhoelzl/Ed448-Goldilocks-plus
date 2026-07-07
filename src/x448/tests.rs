use super::{
    EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret, X448_BASEPOINT_BYTES,
    x448,
};

fn decode<const N: usize>(hex: &str) -> [u8; N] {
    let bytes = hex::decode(hex).expect("valid hex");
    bytes.try_into().expect("valid byte length")
}

#[test]
fn rfc7748_x448_vectors() {
    let scalar = decode(
        "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121\
         700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
    );
    let u = decode(
        "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9\
         814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
    );
    let expected = decode(
        "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f\
         e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f",
    );
    assert_eq!(x448(scalar, u), expected);

    let scalar = decode(
        "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5\
         38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
    );
    let u = decode(
        "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b\
         165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
    );
    let expected = decode(
        "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7\
         ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d",
    );
    assert_eq!(x448(scalar, u), expected);
}

#[test]
fn rfc7748_x448_iterated_vector() {
    let mut k = X448_BASEPOINT_BYTES;
    let mut u = X448_BASEPOINT_BYTES;

    for _ in 0..1000 {
        let old_k = k;
        k = x448(k, u);
        u = old_k;
    }

    let expected = decode(
        "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4\
         af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38",
    );
    assert_eq!(k, expected);
}

#[test]
fn rfc7748_curve448_diffie_hellman_vector() {
    let alice_secret = StaticSecret::from(decode(
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
         d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
    ));
    let bob_secret = StaticSecret::from(decode(
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d\
         6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
    ));

    let alice_public = PublicKey::from(&alice_secret);
    let bob_public = PublicKey::from(&bob_secret);

    assert_eq!(
        alice_public.to_bytes(),
        decode(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c\
             22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
        )
    );
    assert_eq!(
        bob_public.to_bytes(),
        decode(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430\
             27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
        )
    );

    let alice_shared = alice_secret.diffie_hellman(&bob_public);
    let bob_shared = bob_secret.diffie_hellman(&alice_public);
    let expected = decode(
        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b\
         b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
    );

    assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    assert_eq!(alice_shared.to_bytes(), expected);
    assert!(alice_shared.was_contributory());
}

#[test]
fn typed_api_matches_x25519_dalek_shape() {
    let alice = EphemeralSecret::from([7u8; 56]);
    let alice_public = PublicKey::from(&alice);
    let bob = ReusableSecret::from([9u8; 56]);
    let bob_public = PublicKey::from(&bob);
    let bob_static = StaticSecret::from([11u8; 56]);
    let bob_static_public = PublicKey::from(&bob_static);

    let alice_shared = alice.diffie_hellman(&bob_public);
    let bob_shared = bob.diffie_hellman(&alice_public);
    let static_shared = bob_static.diffie_hellman(&alice_public);

    assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    assert!(SharedSecret::as_ref(&static_shared).len() == 56);
    assert!(PublicKey::as_ref(&bob_static_public).len() == 56);
    assert!(bob_static.as_ref().len() == 56);
}

#[test]
fn shared_secret_reports_non_contributory_all_zero_secret() {
    let secret = StaticSecret::from([0u8; 56]);
    let public = PublicKey::from([0u8; 56]);
    let shared = secret.diffie_hellman(&public);

    assert!(!shared.was_contributory());
    assert_eq!(shared.to_bytes(), [0u8; 56]);
}
