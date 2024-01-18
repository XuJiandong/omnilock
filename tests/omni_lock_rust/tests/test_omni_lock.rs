#![allow(unused_imports)]
#![allow(dead_code)]

mod misc;

use std::fs::File;
use std::io::Read;

use blake2b_rs::{Blake2b, Blake2bBuilder};
use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_crypto::secp::Generator;
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier, TxVerifyEnv};
use ckb_types::core::hardfork::HardForks;
use ckb_types::{
    bytes::Bytes,
    bytes::BytesMut,
    core::{cell::ResolvedTransaction, EpochNumberWithFraction, HeaderView},
    packed::WitnessArgs,
    prelude::*,
    H256,
};
use lazy_static::lazy_static;
use misc::*;
use std::sync::Arc;

//
// owner lock section
//
#[test]
fn test_simple_owner_lock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, false);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    // For ckb 0.40.0
    // let mut verifier =
    //     TransactionScriptsVerifier::new(&resolved_tx, data_loader);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_owner_lock_without_witness() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, false);
    config.scheme2 = TestScheme2::NoWitness;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_simple_owner_lock_mismatched() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, false);
    config.scheme = TestScheme::OwnerLockMismatched;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_LOCK_SCRIPT_HASH_NOT_FOUND)
}

#[test]
fn test_owner_lock_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_owner_lock_on_wl_without_witness() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::OnWhiteList;
    config.scheme2 = TestScheme2::NoWitness;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
}

#[test]
fn test_owner_lock_not_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::NotOnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_NOT_ON_WHITE_LIST)
}

#[test]
fn test_owner_lock_no_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    // only black list is used, but not on it.
    // but omni_lock requires at least one white list
    config.scheme = TestScheme::NotOnBlackList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_NO_WHITE_LIST)
}

#[test]
fn test_owner_lock_on_bl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::BothOn;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_ON_BLACK_LIST)
}

#[test]
fn test_owner_lock_emergency_halt_mode() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_OWNER_LOCK, true);
    config.scheme = TestScheme::EmergencyHaltMode;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_RCE_EMERGENCY_HALT)
}

//
// pubkey hash section
//

#[test]
fn test_pubkey_hash_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_pubkey_hash_without_omni_identity() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.set_omni_identity(false);
    config.scheme = TestScheme::OnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_pubkey_hash_on_wl_without_witness() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::OnWhiteList;
    config.scheme2 = TestScheme2::NoWitness;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);

    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
}

#[test]
fn test_pubkey_hash_not_on_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::NotOnWhiteList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_NOT_ON_WHITE_LIST)
}

#[test]
fn test_pubkey_hash_no_wl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    // only black list is used, but not on it.
    // but omni_lock requires at least one white list
    config.scheme = TestScheme::NotOnBlackList;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_NO_WHITE_LIST)
}

#[test]
fn test_pubkey_hash_on_bl() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::BothOn;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_ON_BLACK_LIST)
}

#[test]
fn test_pubkey_hash_emergency_halt_mode() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_PUBKEY_HASH, true);
    config.scheme = TestScheme::EmergencyHaltMode;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_RCE_EMERGENCY_HALT)
}

#[test]
fn test_rsa_via_dl_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_rsa();

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_rsa_via_dl_wrong_sig() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_rsa();
    config.scheme = TestScheme::RsaWrongSignature;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_RSA_VERIFY_FAILED);
}

#[test]
fn test_rsa_via_dl_unlock_with_time_lock() {
    let mut data_loader = DummyDataLoader::new();

    let args_since = 0x2000_0000_0000_0000u64 + 200;
    let input_since = 0x2000_0000_0000_0000u64 + 200;
    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_rsa();
    config.set_since(args_since, input_since);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_rsa_via_dl_unlock_with_time_lock_failed() {
    let mut data_loader = DummyDataLoader::new();

    let args_since = 0x2000_0000_0000_0000u64 + 200;
    let input_since = 0x2000_0000_0000_0000u64 + 100;
    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_rsa();
    config.set_since(args_since, input_since);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);

    assert_script_error(verify_result.unwrap_err(), ERROR_INCORRECT_SINCE_VALUE);
}

// currently, the signature can only be signed via hardware.
// Here we can only provide a failed case.
#[test]
fn test_iso9796_2_batch_via_dl_unlock_failed() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DL, false);
    config.set_iso9796_2();

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
}

#[test]
fn test_eth_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_ETHEREUM, false);
    config.set_chain_config(Box::new(EthereumConfig::default()));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

fn test_btc_success(vtype: u8) {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: vtype,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

fn test_cobuild_btc_success(vtype: u8) {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: vtype,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

fn test_btc_err_pubkey(vtype: u8) {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: vtype,
        pubkey_err: true,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
    assert_script_error(verify_result.unwrap_err(), ERROR_PUBKEY_BLAKE160_HASH);
}

fn test_btc(vtype: u8) {
    test_btc_success(vtype);
    test_btc_err_pubkey(vtype);
}

#[test]
fn test_btc_unlock() {
    test_btc(BITCOIN_V_TYPE_P2PKHUNCOMPRESSED);
    test_btc(BITCOIN_V_TYPE_P2PKHCOMPRESSED);
    test_btc(BITCOIN_V_TYPE_SEGWITP2SH);
    test_btc(BITCOIN_V_TYPE_SEGWITBECH32);
}

#[test]
fn test_cobuild_btc_native_segwit() {
    test_cobuild_btc_success(BITCOIN_V_TYPE_P2PKHCOMPRESSED);
}

#[test]
fn test_dogecoin_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DOGECOIN, false);
    config.set_chain_config(Box::new(DogecoinConfig::default()));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_dogecoin_err_pubkey() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_DOGECOIN, false);
    let mut dogecoin = DogecoinConfig::default();
    dogecoin.0.pubkey_err = true;
    config.set_chain_config(Box::new(dogecoin));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err())
}

fn test_eos_success(vtype: u8) {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_EOS, false);
    let mut eos = EOSConfig::default();
    eos.0.sign_vtype = vtype;
    config.set_chain_config(Box::new(EOSConfig::default()));

    let tx: ckb_types::core::TransactionView = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

fn test_eos_err_pubkey(vtype: u8) {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_EOS, false);
    let mut eos = EOSConfig::default();
    eos.0.sign_vtype = vtype;
    eos.0.pubkey_err = true;
    config.set_chain_config(Box::new(eos));

    let tx: ckb_types::core::TransactionView = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
    assert_script_error(verify_result.unwrap_err(), ERROR_PUBKEY_BLAKE160_HASH);
}

fn test_eos(vtype: u8) {
    test_eos_success(vtype);
    test_eos_err_pubkey(vtype)
}

#[test]
fn test_eos_unlock() {
    test_eos(BITCOIN_V_TYPE_P2PKHCOMPRESSED);
    test_eos(BITCOIN_V_TYPE_P2PKHUNCOMPRESSED);
}

#[test]
fn test_tron_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_TRON, false);
    config.set_chain_config(Box::new(TronConfig::default()));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_tron_err_pubkey() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_TRON, false);
    let mut tron = TronConfig::default();
    tron.pubkey_err = true;
    config.set_chain_config(Box::new(tron));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
    assert_script_error(verify_result.unwrap_err(), ERROR_PUBKEY_BLAKE160_HASH);
}

#[test]
fn test_eth_displaying_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_ETHEREUM_DISPLAYING, false);
    config.set_chain_config(Box::new(EthereumDisplayConfig::default()));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

// this test can fail during development
#[test]
fn test_binary_unchanged() {
    let mut buf = [0u8; 8 * 1024];
    // build hash
    let mut blake2b = Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();

    let mut fd = File::open("../../build/omni_lock").expect("open file");
    loop {
        let read_bytes = fd.read(&mut buf).expect("read file");
        if read_bytes > 0 {
            blake2b.update(&buf[..read_bytes]);
        } else {
            break;
        }
    }

    let mut hash = [0u8; 32];
    blake2b.finalize(&mut hash);

    let actual_hash = faster_hex::hex_string(&hash);
    assert_eq!(
        "eb9483b29855bdafcad85595f02644f548e9094c24d544eeb51cd26ee2ecf14a",
        &actual_hash
    );
}

#[test]
fn test_try_union_unpack_id_by_default() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    config.custom_extension_witnesses = Some(vec![Bytes::from([00, 00].to_vec())]);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_try_union_unpack_id_by_cobuild() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    config.custom_extension_witnesses = Some(vec![Bytes::from([00, 00].to_vec())]);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_non_empty_witness() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let lock_args = config.gen_args();
    let tx = gen_tx_with_grouped_args(&mut data_loader, vec![(lock_args, 2)], &mut config);

    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    // let tx_json = ckb_jsonrpc_types::Transaction::from(resolved_tx.transaction.data());
    // println!("{}", serde_json::to_string(&tx_json).unwrap());

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_script_error(verify_result.unwrap_err(), ERROR_MOL2_ERR_OVERFLOW);
}

#[test]
fn test_input_cell_data_size_0() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_input_cell_data_size_1() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let inputs_len = tx.inputs().len();
    for i in 0..inputs_len {
        let input_cell = tx.inputs().get(i).unwrap();
        let input_cell_out_point = input_cell.previous_output();
        let (input_cell_output, _) = data_loader.cells.get(&input_cell_out_point).unwrap();
        data_loader.cells.insert(
            input_cell_out_point,
            (input_cell_output.clone(), Bytes::from(vec![0x42; 1])),
        );
    }
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}


#[test]
fn test_input_cell_data_size_2048() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let inputs_len = tx.inputs().len();
    for i in 0..inputs_len {
        let input_cell = tx.inputs().get(i).unwrap();
        let input_cell_out_point = input_cell.previous_output();
        let (input_cell_output, _) = data_loader.cells.get(&input_cell_out_point).unwrap();
        data_loader.cells.insert(
            input_cell_out_point,
            (input_cell_output.clone(), Bytes::from(vec![0x42; 2048])),
        );
    }
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_input_cell_data_size_2049() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let inputs_len = tx.inputs().len();
    for i in 0..inputs_len {
        let input_cell = tx.inputs().get(i).unwrap();
        let input_cell_out_point = input_cell.previous_output();
        let (input_cell_output, _) = data_loader.cells.get(&input_cell_out_point).unwrap();
        data_loader.cells.insert(
            input_cell_out_point,
            (input_cell_output.clone(), Bytes::from(vec![0x42; 2049])),
        );
    }
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_input_cell_data_size_500k() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BITCOIN, false);
    config.cobuild_enabled = true;
    config.set_chain_config(Box::new(BitcoinConfig {
        sign_vtype: BITCOIN_V_TYPE_P2PKHCOMPRESSED,
        pubkey_err: false,
    }));

    let tx = gen_tx(&mut data_loader, &mut config);
    let inputs_len = tx.inputs().len();
    for i in 0..inputs_len {
        let input_cell = tx.inputs().get(i).unwrap();
        let input_cell_out_point = input_cell.previous_output();
        let (input_cell_output, _) = data_loader.cells.get(&input_cell_out_point).unwrap();
        data_loader.cells.insert(
            input_cell_out_point,
            (input_cell_output.clone(), Bytes::from(vec![0x42; 500 * 1024])),
        );
    }
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = verify_tx(resolved_tx, data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}
