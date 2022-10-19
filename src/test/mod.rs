mod arbitrary;

mod test {
    use crate::addr::{PeerAddr, SocketAddr, UniversalAddr};
    use crate::crypto::ed25519::Curve25519;
    use std::net;

    #[test]
    fn universal_addr() {
        // test ability to define universal type with Curve25519 type
        let _: UniversalAddr<PeerAddr<Curve25519, SocketAddr<10>>>;
        let _: UniversalAddr<PeerAddr<Curve25519, net::SocketAddr>>;
    }
}
