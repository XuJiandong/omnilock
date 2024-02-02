use ckb_types::prelude::{Builder, Entity, Pack};
use omni_lock_test::schemas;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct Resource {
    pub cell: HashMap<ckb_types::packed::OutPoint, ckb_types::core::cell::CellMeta>,
}

impl ckb_traits::CellDataProvider for Resource {
    fn get_cell_data(&self, out_point: &ckb_types::packed::OutPoint) -> Option<ckb_types::bytes::Bytes> {
        self.cell.get(out_point).and_then(|cell_meta| cell_meta.mem_cell_data.clone())
    }

    fn get_cell_data_hash(&self, out_point: &ckb_types::packed::OutPoint) -> Option<ckb_types::packed::Byte32> {
        self.cell.get(out_point).and_then(|cell_meta| cell_meta.mem_cell_data_hash.clone())
    }
}

impl ckb_traits::HeaderProvider for Resource {
    fn get_header(&self, _: &ckb_types::packed::Byte32) -> Option<ckb_types::core::HeaderView> {
        unimplemented!()
    }
}

impl ckb_traits::ExtensionProvider for Resource {
    fn get_block_extension(&self, _: &ckb_types::packed::Byte32) -> Option<ckb_types::packed::Bytes> {
        unimplemented!()
    }
}

impl ckb_types::core::cell::CellProvider for Resource {
    fn cell(&self, out_point: &ckb_types::packed::OutPoint, eager_load: bool) -> ckb_types::core::cell::CellStatus {
        let _ = eager_load;
        if let Some(data) = self.cell.get(out_point).cloned() {
            ckb_types::core::cell::CellStatus::Live(data)
        } else {
            ckb_types::core::cell::CellStatus::Unknown
        }
    }
}

impl ckb_types::core::cell::HeaderChecker for Resource {
    fn check_valid(&self, _: &ckb_types::packed::Byte32) -> Result<(), ckb_types::core::error::OutPointError> {
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct Verifier {}

impl Verifier {
    pub fn verify_prior(&self, tx_resolved: &ckb_types::core::cell::ResolvedTransaction, _: &Resource) {
        let a = tx_resolved.transaction.outputs().item_count();
        let b = tx_resolved.transaction.outputs_data().item_count();
        assert_eq!(a, b);
    }

    pub fn verify(
        &self,
        tx_resolved: &ckb_types::core::cell::ResolvedTransaction,
        dl: &Resource,
    ) -> Result<ckb_types::core::Cycle, ckb_error::Error> {
        self.verify_prior(&tx_resolved, &dl);
        let hardfork = ckb_types::core::hardfork::HardForks {
            ckb2021: ckb_types::core::hardfork::CKB2021::new_mirana().as_builder().rfc_0032(10).build().unwrap(),
            ckb2023: ckb_types::core::hardfork::CKB2023::new_mirana().as_builder().rfc_0049(20).build().unwrap(),
        };
        let consensus = ckb_chain_spec::consensus::ConsensusBuilder::default().hardfork_switch(hardfork).build();
        let mut verifier = ckb_script::TransactionScriptsVerifier::new(
            Arc::new(tx_resolved.clone()),
            dl.clone(),
            Arc::new(consensus),
            Arc::new(ckb_script::TxVerifyEnv::new_commit(
                &ckb_types::core::HeaderView::new_advanced_builder()
                    .epoch(ckb_types::core::EpochNumberWithFraction::new(10, 0, 1).pack())
                    .build(),
            )),
        );
        verifier.set_debug_printer(|script: &ckb_types::packed::Byte32, msg: &str| {
            let str = format!("Script({})", hex::encode(&script.as_slice()[..4]));
            println!("{}: {}", str, msg);
        });
        verifier.verify(u64::MAX)
    }
}

#[derive(Clone, Default)]
pub struct Pickaxer {
    outpoint_hash: ckb_types::packed::Byte32,
    outpoint_i: u32,
}

impl Pickaxer {
    pub fn insert_cell_data(&mut self, dl: &mut Resource, data: &[u8]) -> ckb_types::core::cell::CellMeta {
        let cell_out_point = ckb_types::packed::OutPoint::new(self.outpoint_hash.clone(), self.outpoint_i);
        let cell_output = ckb_types::packed::CellOutput::new_builder()
            .capacity(ckb_types::core::Capacity::bytes(61 + data.len()).unwrap().pack())
            .build();
        let cell_data = ckb_types::bytes::Bytes::copy_from_slice(data);
        let cell_meta = ckb_types::core::cell::CellMetaBuilder::from_cell_output(cell_output, cell_data)
            .out_point(cell_out_point.clone())
            .build();
        dl.cell.insert(cell_out_point.clone(), cell_meta.clone());
        self.outpoint_i += 1;
        cell_meta
    }

    pub fn insert_cell_fund(
        &mut self,
        dl: &mut Resource,
        lock: ckb_types::packed::Script,
        kype: Option<ckb_types::packed::Script>,
        data: &[u8],
    ) -> ckb_types::core::cell::CellMeta {
        let cell_out_point = ckb_types::packed::OutPoint::new(self.outpoint_hash.clone(), self.outpoint_i);
        let cell_output = ckb_types::packed::CellOutput::new_builder()
            .capacity(ckb_types::core::Capacity::bytes(61 + data.len()).unwrap().pack())
            .lock(lock)
            .type_(ckb_types::packed::ScriptOpt::new_builder().set(kype).build())
            .build();
        let cell_data = ckb_types::bytes::Bytes::copy_from_slice(data);
        let cell_meta = ckb_types::core::cell::CellMetaBuilder::from_cell_output(cell_output, cell_data)
            .out_point(cell_out_point.clone())
            .build();
        dl.cell.insert(cell_out_point.clone(), cell_meta.clone());
        self.outpoint_i += 1;
        cell_meta
    }

    pub fn create_cell_dep(&self, cell_meta: &ckb_types::core::cell::CellMeta) -> ckb_types::packed::CellDep {
        ckb_types::packed::CellDep::new_builder()
            .out_point(cell_meta.out_point.clone())
            .dep_type(ckb_types::core::DepType::Code.into())
            .build()
    }

    pub fn create_cell_input(&self, cell_meta: &ckb_types::core::cell::CellMeta) -> ckb_types::packed::CellInput {
        ckb_types::packed::CellInput::new(cell_meta.out_point.clone(), 0)
    }

    pub fn create_cell_output(
        &self,
        lock: ckb_types::packed::Script,
        kype: Option<ckb_types::packed::Script>,
        data: &[u8],
    ) -> ckb_types::packed::CellOutput {
        ckb_types::packed::CellOutput::new_builder()
            .capacity(ckb_types::core::Capacity::bytes(61 + data.len()).unwrap().pack())
            .lock(lock)
            .type_(ckb_types::packed::ScriptOpt::new_builder().set(kype).build())
            .build()
    }

    pub fn create_script(&self, cell_meta: &ckb_types::core::cell::CellMeta, args: &[u8]) -> ckb_types::packed::Script {
        ckb_types::packed::Script::new_builder()
            .args(args.pack())
            .code_hash(cell_meta.mem_cell_data_hash.clone().unwrap())
            .hash_type(ckb_types::core::ScriptHashType::Data1.into())
            .build()
    }
}

pub fn println_hex(name: &str, data: &[u8]) {
    println!("Tester(........): {}(len={}): {}", name, data.len(), hex::encode(data));
}

static BINARY_ALWAYS_SUCCESS: &[u8] = include_bytes!("../../../build/always_success");
static BINARY_SECP256K1_DATA: &[u8] = include_bytes!("../../../build/secp256k1_data_20210801");
static BINARY_OMNI_LOCK: &[u8] = include_bytes!("../../../build/omni_lock");

pub const IDENTITY_FLAGS_ETHEREUM: u8 = 1;
pub const IDENTITY_FLAGS_BITCOIN: u8 = 4;

pub fn hash_keccak160(message: &[u8]) -> Vec<u8> {
    hash_keccak256(message)[12..].to_vec()
}

pub fn hash_keccak256(message: &[u8]) -> Vec<u8> {
    use sha3::Digest;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(message);
    let r = hasher.finalize();
    r.to_vec()
}

pub fn hash_ripemd160_sha256(message: &[u8]) -> Vec<u8> {
    return hash_ripemd160(&hash_sha256(message));
}

pub fn hash_ripemd160(message: &[u8]) -> Vec<u8> {
    use ripemd::Digest;
    let mut hasher = ripemd::Ripemd160::new();
    hasher.update(message);
    hasher.finalize().to_vec()
}

pub fn hash_sha256(message: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(message);
    hasher.finalize().to_vec()
}

pub fn sign_bitcoin_p2pkh_compressed(prikey: ckb_crypto::secp::Privkey, message: &[u8]) -> Vec<u8> {
    assert_eq!(message.len(), 32);
    let sign = [
        vec![24],
        b"Bitcoin Signed Message:\n".to_vec(),
        vec![99],
        b"CKB (Bitcoin Layer) transaction: 0x".to_vec(),
        hex::encode(&message).as_bytes().to_vec(),
    ];
    let sign = sign.concat();
    let sign = hash_sha256(&hash_sha256(&sign));
    let sign = prikey.sign_recoverable(&ckb_types::H256::from_slice(&sign).unwrap()).unwrap().serialize();
    let sign = [vec![sign[64] + 31], sign[..64].to_vec()].concat();
    sign
}

pub fn sign_ethereum(prikey: ckb_crypto::secp::Privkey, message: &[u8]) -> Vec<u8> {
    let sign = [b"\x19Ethereum Signed Message:\n32".to_vec(), message.to_vec()].concat();
    let sign = hash_keccak256(&sign);
    let sign = ckb_types::H256::from_slice(&sign).unwrap();
    let sign = prikey.sign_recoverable(&sign).unwrap().serialize();
    sign
}

pub fn cobuild_create_signing_message_hash_sighash_all(
    tx: ckb_types::core::TransactionView,
    dl: &Resource,
    message: &schemas::basic::Message,
) -> Vec<u8> {
    let mut hasher = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-tcob-sighash").build();
    hasher.update(message.as_slice());
    hasher.update(tx.hash().as_slice());
    let inputs_len = tx.inputs().len();
    for i in 0..inputs_len {
        let input_cell = tx.inputs().get(i).unwrap();
        let input_cell_out_point = input_cell.previous_output();
        let input_cell_meta = dl.cell.get(&input_cell_out_point).unwrap();
        hasher.update(input_cell_meta.cell_output.as_slice());
        hasher.update(&(input_cell_meta.data_bytes as u32).to_le_bytes());
        hasher.update(&input_cell_meta.mem_cell_data.clone().unwrap());
    }
    for witness in tx.witnesses().into_iter().skip(inputs_len) {
        hasher.update(&(witness.len() as u32).to_le_bytes());
        hasher.update(&witness.raw_data());
    }
    let mut result = vec![0u8; 32];
    hasher.finalize(&mut result);
    result
}

pub fn cobuild_create_signing_message_hash_sighash_all_only(
    tx: ckb_types::core::TransactionView,
    dl: &Resource,
) -> Vec<u8> {
    let mut hasher = blake2b_ref::Blake2bBuilder::new(32).personal(b"ckb-tcob-sgohash").build();
    hasher.update(tx.hash().as_slice());
    let inputs_len = tx.inputs().len();
    for i in 0..inputs_len {
        let input_cell = tx.inputs().get(i).unwrap();
        let input_cell_out_point = input_cell.previous_output();
        let input_cell_meta = dl.cell.get(&input_cell_out_point).unwrap();
        hasher.update(input_cell_meta.cell_output.as_slice());
        hasher.update(&(input_cell_meta.data_bytes as u32).to_le_bytes());
        hasher.update(&input_cell_meta.mem_cell_data.clone().unwrap());
    }
    for witness in tx.witnesses().into_iter().skip(inputs_len) {
        hasher.update(&(witness.len() as u32).to_le_bytes());
        hasher.update(&witness.raw_data());
    }
    let mut result = vec![0u8; 32];
    hasher.finalize(&mut result);
    result
}

pub fn omnilock_create_witness_lock(sign: &[u8]) -> Vec<u8> {
    omni_lock_test::omni_lock::OmniLockWitnessLock::new_builder()
        .signature(Some(ckb_types::bytes::Bytes::copy_from_slice(sign)).pack())
        .build()
        .as_bytes()
        .to_vec()
}

#[test]
fn test_cobuild_sighash_all_bitcoin_p2pkh_compressed() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx_builder = ckb_types::core::TransactionBuilder::default();

    // Create prior knowledge
    let prikey = "0000000000000000000000000000000000000000000000000000000000000001";
    let prikey = ckb_crypto::secp::Privkey::from_str(prikey).unwrap();
    let pubkey = prikey.pubkey().unwrap();
    let pubkey_hash = hash_ripemd160_sha256(&pubkey.serialize());
    let args = [vec![IDENTITY_FLAGS_BITCOIN], pubkey_hash.to_vec(), vec![0x00]].concat();

    // Create cell meta
    let cell_meta_always_success = px.insert_cell_data(&mut dl, BINARY_ALWAYS_SUCCESS);
    let cell_meta_secp256k1_data = px.insert_cell_data(&mut dl, BINARY_SECP256K1_DATA);
    let cell_meta_omni_lock = px.insert_cell_data(&mut dl, BINARY_OMNI_LOCK);
    let cell_meta_i = px.insert_cell_fund(&mut dl, px.create_script(&cell_meta_omni_lock, &args), None, &[]);

    // Create cell dep
    let tx_builder = tx_builder.cell_dep(px.create_cell_dep(&cell_meta_always_success));
    let tx_builder = tx_builder.cell_dep(px.create_cell_dep(&cell_meta_secp256k1_data));
    let tx_builder = tx_builder.cell_dep(px.create_cell_dep(&cell_meta_omni_lock));

    // Create input
    let tx_builder = tx_builder.input(px.create_cell_input(&cell_meta_i));

    // Create output
    let tx_builder = tx_builder.output(px.create_cell_output(
        px.create_script(&cell_meta_always_success, &[]),
        Some(px.create_script(&cell_meta_always_success, &[])),
        &[],
    ));

    // Create output data
    let tx_builder = tx_builder.output_data(Vec::new().pack());

    // Create witness
    let msgs = {
        let action = schemas::basic::Action::new_builder()
            .script_info_hash(ckb_types::packed::Byte32::from_slice(&[0x00; 32]).unwrap())
            .script_hash(px.create_script(&cell_meta_always_success, &[]).calc_script_hash())
            .data(ckb_types::bytes::Bytes::from(vec![0x42; 128]).pack())
            .build();
        let action_vec = schemas::basic::ActionVec::new_builder().push(action).build();
        let msgs = schemas::basic::Message::new_builder().actions(action_vec).build();
        msgs
    };
    let sign = cobuild_create_signing_message_hash_sighash_all(tx_builder.clone().build(), &dl, &msgs);
    let sign = sign_bitcoin_p2pkh_compressed(prikey, &sign);
    let sign = omnilock_create_witness_lock(&sign);
    let seal = [vec![0x00], sign].concat();
    println_hex("seal", seal.pack().as_slice());
    let sa = schemas::basic::SighashAll::new_builder().seal(seal.pack()).message(msgs).build();
    let wl = schemas::top_level::WitnessLayout::new_builder().set(sa).build();
    let tx_builder = tx_builder.witness(wl.as_bytes().pack());

    // Verify transaction
    let tx = tx_builder.build();
    let tx_resolved = ckb_types::core::cell::resolve_transaction(tx, &mut HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    verifier.verify(&tx_resolved, &dl).unwrap();
}

#[test]
fn test_cobuild_sighash_all_only_ethereum() {
    let mut dl = Resource::default();
    let mut px = Pickaxer::default();
    let tx_builder = ckb_types::core::TransactionBuilder::default();

    // Create prior knowledge
    let prikey = "0000000000000000000000000000000000000000000000000000000000000001";
    let prikey = ckb_crypto::secp::Privkey::from_str(prikey).unwrap();
    let pubkey = prikey.pubkey().unwrap();
    let pubkey_hash = hash_keccak160(&pubkey.as_ref()[..]);
    let args = [vec![IDENTITY_FLAGS_ETHEREUM], pubkey_hash, vec![0x00]].concat();

    // Create cell meta
    let cell_meta_always_success = px.insert_cell_data(&mut dl, BINARY_ALWAYS_SUCCESS);
    let cell_meta_secp256k1_data = px.insert_cell_data(&mut dl, BINARY_SECP256K1_DATA);
    let cell_meta_omni_lock = px.insert_cell_data(&mut dl, BINARY_OMNI_LOCK);
    let cell_meta_i = px.insert_cell_fund(&mut dl, px.create_script(&cell_meta_omni_lock, &args), None, &[]);

    // Create cell dep
    let tx_builder = tx_builder.cell_dep(px.create_cell_dep(&cell_meta_always_success));
    let tx_builder = tx_builder.cell_dep(px.create_cell_dep(&cell_meta_secp256k1_data));
    let tx_builder = tx_builder.cell_dep(px.create_cell_dep(&cell_meta_omni_lock));

    // Create input
    let tx_builder = tx_builder.input(px.create_cell_input(&cell_meta_i));

    // Create output
    let tx_builder =
        tx_builder.output(px.create_cell_output(px.create_script(&cell_meta_always_success, &[]), None, &[]));

    // Create output data
    let tx_builder = tx_builder.output_data(Vec::new().pack());

    // Create witness
    let sign = cobuild_create_signing_message_hash_sighash_all_only(tx_builder.clone().build(), &dl);
    let sign = sign_ethereum(prikey, &sign);
    let sign = omnilock_create_witness_lock(&sign);
    let seal = [vec![0x00], sign].concat();
    println_hex("seal", seal.pack().as_slice());
    let so = schemas::basic::SighashAllOnly::new_builder().seal(seal.pack()).build();
    let wl = schemas::top_level::WitnessLayout::new_builder().set(so).build();
    let tx_builder = tx_builder.witness(wl.as_bytes().pack());

    // Verify transaction
    let tx = tx_builder.build();
    let tx_resolved = ckb_types::core::cell::resolve_transaction(tx, &mut HashSet::new(), &dl, &dl).unwrap();
    let verifier = Verifier::default();
    verifier.verify(&tx_resolved, &dl).unwrap();
}
