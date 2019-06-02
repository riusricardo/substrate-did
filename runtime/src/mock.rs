// Copyright 2019 Ricardo Rius. 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#![cfg(test)]

use crate::{did, AccountId};
use support::impl_outer_origin;
use runtime_io::TestExternalities;
use runtime_primitives::{
    BuildStorage,
    traits::{BlakeTwo256, IdentityLookup},
    testing::{Digest, DigestItem, Header}
};
use primitives::{H256, Blake2Hasher, sr25519, Pair};

impl_outer_origin! {
    pub enum Origin for Test {}
}

#[derive(Clone, Eq, PartialEq)]
pub struct Test;
impl system::Trait for Test {
    type Origin = Origin;
    type Index = u64;
    type BlockNumber = u64;
    type Hash = H256;
    type Hashing = BlakeTwo256;
    type Digest = Digest;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type Header = Header;
    type Event = ();
    type Log = DigestItem;
}

impl balances::Trait for Test {
    type Balance = u64;
    type OnFreeBalanceZero = ();
    type OnNewAccount = ();
    type Event = ();
    type TransactionPayment = ();
    type TransferPayment = ();
    type DustRemoval = ();
}

impl timestamp::Trait for Test {
    type Moment = u64;
    type OnTimestampSet = ();
}

impl did::Trait for Test {
    type Event = ();
    type Signature = sr25519::Signature;
}

pub fn new_test_ext() -> TestExternalities<Blake2Hasher> {
    let mut t = system::GenesisConfig::<Test>::default().build_storage().unwrap().0;
    t.extend(balances::GenesisConfig::<Test>::default().build_storage().unwrap().0);
    TestExternalities::new(t)
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