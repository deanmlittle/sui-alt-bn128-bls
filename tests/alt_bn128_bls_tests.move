#[test_only]
module alt_bn128_bls::alt_bn128_bls_tests {

    use alt_bn128_bls::alt_bn128_bls;

    #[test]
    fun test_alt_bn128_bls_verify() {
        let signature = x"2ca45a48148082719e9570119963a39979f0e847568b14810110d06e71586e82";
        let pubkey = x"24ffdf72294e9dd829abe637db77d1b0fb372b7c9c24f03b8543d8eb4aed881e76f512bdd4279bf6ccad300671ebbaa8e4cba669b484f27819a44f243ec61a8b";
        let hash = x"fd86647bc69f8c20ce0b2d1eec9544e8608a75fe94c21c898908508cf028e011";
        assert!(alt_bn128_bls::verify(signature, pubkey, hash))
    }

    #[test]
    fun test_alt_bn128_bls_verify_vk() {
        let signature = x"2ca45a48148082719e9570119963a39979f0e847568b14810110d06e71586e82";
        let pubkey = x"24ffdf72294e9dd829abe637db77d1b0fb372b7c9c24f03b8543d8eb4aed881e76f512bdd4279bf6ccad300671ebbaa8e4cba669b484f27819a44f243ec61a8b";
        let hash = x"fd86647bc69f8c20ce0b2d1eec9544e8608a75fe94c21c898908508cf028e011";
        assert!(alt_bn128_bls::verify_vk(signature, pubkey, hash))
    }
}