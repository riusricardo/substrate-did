// Copyright 2019 Ricardo Rius. 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#![cfg(test)]

use crate::{did, AccountId};
use support::{impl_outer_origin, parameter_types};
use runtime_io::TestExternalities;
use sr_primitives::{
    traits::{BlakeTwo256, IdentityLookup},
    weights::Weight,
    Perbill,
    testing::{Header}
};

use primitives::{H256, Blake2Hasher, sr25519, Pair};

impl_outer_origin! {
    pub enum Origin for Test {}
}

#[derive(Clone, Eq, PartialEq)]
pub struct Test;
parameter_types! {
    pub const BlockHashCount: u64 = 250;
    pub const MaximumBlockWeight: Weight = 1024;
    pub const MaximumBlockLength: u32 = 2 * 1024;
    pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
    pub const ExistentialDeposit: u64 = 0;
    pub const TransferFee: u64 = 0;
    pub const CreationFee: u64 = 0;
    pub const TransactionBaseFee: u64 = 0;
    pub const TransactionByteFee: u64 = 0;
    pub const MinimumPeriod: u64 = 5;
}

impl system::Trait for Test {
    type Origin = Origin;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type WeightMultiplierUpdate = ();
    type Event = ();
    type BlockHashCount = BlockHashCount;
    type MaximumBlockWeight = MaximumBlockWeight;
    type MaximumBlockLength = MaximumBlockLength;
    type AvailableBlockRatio = AvailableBlockRatio;
}

impl balances::Trait for Test {
    type Balance = u64;
    type OnFreeBalanceZero = ();
    type OnNewAccount = ();
    type Event = ();
    type TransactionPayment = ();
    type TransferPayment = ();
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type TransferFee = TransferFee;
    type CreationFee = CreationFee;
    type TransactionBaseFee = TransactionBaseFee;
    type TransactionByteFee = TransactionByteFee;
    type WeightToFee = ();
}

impl timestamp::Trait for Test {
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = MinimumPeriod;
}

impl did::Trait for Test {
    type Event = ();
    type Signature = sr25519::Signature;
}

pub fn new_test_ext() -> TestExternalities<Blake2Hasher> {
    let mut t = system::GenesisConfig::default().build_storage::<Test>().unwrap();
    balances::GenesisConfig::<Test>{
			balances: vec![
                        (account_key("Alice"), 100000),
                        (account_key("Bob"), 100000),
                        (account_key("Tom"), 100000),
                        (account_key("Madera"), 10000000),
                        (account_key("Mantequilla"), 10000000),
                        (account_key("Roberto"), 10000000),
                        (account_key("Derecha"), 1000),
                        (account_key("Satoshi"), 999999999999999),
                        (account_key("Nakamoto"), 999999999999999)
                        ],
			vesting: vec![],
		}.assimilate_storage(&mut t.0, &mut t.1).unwrap();
	runtime_io::TestExternalities::new_with_children(t)
}

pub fn account_key(s: &str) -> AccountId {
    sr25519::Pair::from_string(&format!("//{}", s), None)
    .expect("static values are valid; qed")
    .public()
}

pub fn account_pair(s: &str) -> sr25519::Pair {
    sr25519::Pair::from_string(&format!("//{}", s), None)
    .expect("static values are valid; qed")
}

pub type DID = did::Module<Test>;
pub type System = system::Module<Test>;
pub type Moment = timestamp::Module<Test>;
pub type AttributeTransaction<Signature,AccountId> = did::AttributeTransaction<Signature,AccountId>;