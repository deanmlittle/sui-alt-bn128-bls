module alt_bn128_bls::alt_bn128_bls {
    use sui::groth16;

    // Bytes used to null out additonal pairings
    const STATIC_VK_BYTES: vector<u8> = x"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400100000000000000000000000000000000000000000000000000000000000000000000000000004006aa5d67636c8b6cd301220a3fefd62e06f6dccaab9fa2c4928e53923ad09f2d2d0084af5bb4685e9b84a6be59f739c8db3c1be2d12c49df2921d69ff507d01885ec7a2bc2cc2e824a98997b32fddbd0081a13bee3da3d2bfa3a594a57999f1391adb05befa3694a7a4946850d2ad3fad47289474e964a202c88e9fa35a988155c0399f2eedc6e239863d9745e68cf46a81a75083545b70d803c8cbc4d2be005612dc573e436661ae91fbe5101a74fda3e1ce3c61711855aba3862bc367cd128be3c487f1e0439e67cf62f610be274931af19a25646ae7e1280d9c16e9d4a11973e0ff4fd1dd13052b89af2a59ef0ef91740fd818efd34ea6918c64e06b0f22c32bfd72f84397801c2398eac9a3820188a6653144437facdb02030dc7647b4137f868fdf84aa3de530a0b3cd069bfdb5a5d67e538089d6b00dc9718010f5f917549ff5a506ff489815c68f2a2c0b8cfc221326d9338c6da4b6be8de8ab81612e4376c57d2cc14ad548fff751ee6918a242d18e94a2ac53c2d1e237956177321f000000000000000001000000000000000001";

    const EINCORRECT_SIG_LENGTH: u64 = 1;
    const EINCORRECT_PUBKEY_LENGTH: u64 = 2;
    const EINCORRECT_HASH_LENGTH: u64 = 3;

    /// # Verify
    /// This function verifies BN254 (AltBN128) BLS signature. It takes 3 parameters:
    /// 
    /// signature: A 32-byte vector representing a compressed BN254 G1 point
    /// pubkey: A 64-byte vector representing a compressed BN254 G1 point
    /// hash_pointt: A 32-byte vector representing a compressed BN254 G1 point
    /// 
    /// This function works by nulling out some values in the groth16 verifier
    /// to simplify the equation into a simple pairing check t overify BLS
    /// signatures. 
    /// 
    /// It assumes that you have externally checked that `hash_point` 
    /// is on-curve. Providing an off-curve `hash_point` will result in an `abort`.
    public fun verify(signature: vector<u8>, pubkey: vector<u8>, hash_point: vector<u8>): bool {  
        // Check lengths
        assert!(std::vector::length(&signature) == 32, EINCORRECT_SIG_LENGTH);
        assert!(std::vector::length(&pubkey) == 64, EINCORRECT_PUBKEY_LENGTH);
        assert!(std::vector::length(&hash_point) == 32, EINCORRECT_HASH_LENGTH);      

        // Flip byte order of hash
        let mut vk_bytes = copy hash_point;

        // Concatenate the reversed hash point and pubkey with the static part of the vk
        std::vector::append(&mut vk_bytes, pubkey);
        std::vector::append(&mut vk_bytes, STATIC_VK_BYTES);
        
        // Prepare the verifying key
        let pvk = groth16::prepare_verifying_key(&groth16::bn254(), &vk_bytes);
        
        // Create the proof points using the provided signature
        let mut proof_bytes = copy signature;
        std::vector::append(&mut proof_bytes, x"edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e190000000000000000000000000000000000000000000000000000000000000040");

        let proof_points = groth16::proof_points_from_bytes(proof_bytes);
        
        // Public inputs remain empty as per the original implementation
        let public_inputs = groth16::public_proof_inputs_from_bytes(x"");
        
        // Verify the proof
        groth16::verify_groth16_proof(&groth16::bn254(), &pvk, &public_inputs, &proof_points)
    }

    /// # Verify VK
    /// This function verifies BN254 (AltBN128) BLS signature. It takes 3 parameters:
    /// 
    /// signature: A 32-byte vector representing a compressed BN254 G1 point
    /// pubkey: A 64-byte vector representing a compressed BN254 G1 point
    /// hash_pointt: A 32-byte vector representing a compressed BN254 G1 point
    /// 
    /// This function works by abusing the prepare_verifying_key function with
    /// null inputs to simplify the equation into a single pairing, performs
    /// two pairs, then compares results to verify.
    /// 
    /// It assumes that you have externally checked that `hash_point` is on-curve. 
    /// Providing an off-curve `hash_point` will result in an `abort`.
    public fun verify_vk(signature: vector<u8>, pubkey: vector<u8>, hash_point: vector<u8>): bool {    
        // Check lengths
        assert!(std::vector::length(&signature) == 32, EINCORRECT_SIG_LENGTH);
        assert!(std::vector::length(&pubkey) == 64, EINCORRECT_PUBKEY_LENGTH);
        assert!(std::vector::length(&hash_point) == 32, EINCORRECT_HASH_LENGTH);  

        // Prepare verifying key bytes for first pairing
        let mut vk_bytes = copy hash_point;
        std::vector::append(&mut vk_bytes, pubkey);
        std::vector::append(&mut vk_bytes, STATIC_VK_BYTES);

        // Prepare verifying key 1
        let pvk = groth16::prepare_verifying_key(&groth16::bn254(), &vk_bytes);

        // Prepare verifying key bytes for second pairing
        let mut vk2_bytes = copy signature;
        std::vector::append(&mut vk2_bytes, x"edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19");
        std::vector::append(&mut vk2_bytes, STATIC_VK_BYTES);

        // Prepare verifying key 2
        let pvk2 = groth16::prepare_verifying_key(&groth16::bn254(), &vk2_bytes);

        // Verify
        pvk == pvk2
    }
}