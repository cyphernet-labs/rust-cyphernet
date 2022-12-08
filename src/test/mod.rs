mod arbitrary;

mod test {
    use crate::addr::{PeerAddr, SocketAddr, UniversalAddr};
    use crate::crypto::ed25519::PublicKey;
    use std::net;

    #[test]
    fn universal_addr() {
        // test ability to define universal type with Curve25519 type
        let _: UniversalAddr<PeerAddr<PublicKey, SocketAddr<10>>>;
        let _: UniversalAddr<PeerAddr<PublicKey, net::SocketAddr>>;
    }
}
