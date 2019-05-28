// Copyright 2019 Ricardo Rius. 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// This module was based on ERC-1056
// DID compliant. https://w3c-ccg.github.io/did-spec/

//! # DID Module
//!
//! The DID module allows resolving and management for DIDs (Decentralized Identifiers).
//!
//! ## Overview
//!
//! The DID module provides functionality for DIDs management. 
//!
//! * Change Identity Owner
//! * Add Delegate
//! * Revoke Delegate
//! * Add Attribute
//! * Revoke Attribute
//! * Delete Attribute
//!
//! To use it in your runtime, you need to implement the DID [`Trait`](./trait.Trait.html).
//!
//! The supported dispatchable functions are documented in the [`Call`](./enum.Call.html) enum.
//!
//! ### Terminology
//!
//! * **Valid Delegate:** The action of obtaining the period of validity of the delegate.
//! * **Change Identity Owner:** The action of transferring ownership.
//! * **Add Delegate:** The process of adding delegate privileges to an identity. An identity can assign multiple delegates to manage signing on their behalf for specific purposes.
//! * **Revoke Delegate:** The process of revoking delegate privileges from an identity.
//! * **Add Attribute:** The process of assigning a specific identity attribute or feature.
//! * **Revoke Attribute:** The process of revoking a specific identity attribute or feature.
//! * **Delete Attribute:** The process of deleting a specific identity attribute or feature.
//! * **DID:** A Decentralized Identifiers compliant with the DID standard.
//!
//! *


use support::{decl_event, decl_module, decl_storage, ensure, StorageMap, dispatch::{Result, Vec}};
use runtime_primitives::{AnySignature, traits::{Hash, Verify}};//,Convert,Identity}};
use parity_codec::{Encode, Decode};
use system::{self, ensure_signed, ensure_none};
use rstd::{prelude::*};


// /// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = AnySignature;
pub type AccountKey = <Signature as Verify>::Signer;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Default)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Attribute<BlockNumber, Moment> {
    name: Vec<u8>,
    value: Vec<u8>,
    validity: BlockNumber,
    creation: Moment,
    nonce: u64,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Transaction<AnySignature,AccountKey> {
    signature: AnySignature, 
    msg: Vec<u8>, 
    signer: AccountKey
}

pub trait Trait: system::Trait + timestamp::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_storage! {
    trait Store for Module<T: Trait> as DID {
        pub DelegateOf get(delegate_of): map (T::AccountId, Vec<u8>, T::AccountId) => Option<T::BlockNumber>;
        pub AccountKeyOf get(account_key_of): map T::AccountId => AccountKey;
        pub AttributeOf get(attribute_of): map (T::AccountId, T::Hash) => Attribute<T::BlockNumber, T::Moment>;
        pub AttributeNonce get(nonce_of): map (T::AccountId, Vec<u8>) => u64;
        pub OwnerOf get(owner_of): map T::AccountId => Option<T::AccountId>;
        pub UpdatedOn get(updated_on): map T::AccountId => (T::BlockNumber, T::Moment);
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {

        fn deposit_event<T>() = default;

        pub fn valid_delegate(_origin, identity: T::AccountId, delegate_type: Vec<u8>, delegate: T::AccountId) -> Result {
                ensure!(delegate_type.len() <= 32, "delegate type cannot exceed 32 bytes");
                ensure!(
                    Self::_is_valid_delegate(&identity, &delegate_type, &delegate).is_ok() ||
                    Self::_is_owner(&identity, &delegate).is_ok(),
                "invalid delegate");
                
                Ok(())
        }

        pub fn valid_attribute(_origin, identity: T::AccountId, name: Vec<u8>, value: Vec<u8>) -> Result { 
                ensure!(name.len() <= 64, "invalid attribute name");
                let result = Self::_attribute_and_id(identity, name);

                let (attr, _id) = match result {
                    Some((attr, id)) => (attr, id),
                    None => return Err("invalid attribute"),
                };

                if (attr.validity > (<system::Module<T>>::block_number())) && (attr.value == value) {
                    Ok(())
                } else {
                    Err("invalid attribute")
                }
        }

        pub fn change_owner(origin, identity: T::AccountId, new_owner: T::AccountId) -> Result {
                let who = ensure_signed(origin)?;
                Self::_is_owner(&identity, &who)?;
                
                let now_timestamp = <timestamp::Module<T>>::now();
                let now_block_number = <system::Module<T>>::block_number();
                
                <OwnerOf<T>>::insert(&identity, &new_owner);
                <UpdatedOn<T>>::insert(&identity, (now_block_number.clone(), now_timestamp));
                
                Self::deposit_event(RawEvent::OwnerChanged(identity, who, new_owner, now_block_number));
        
                Ok(())
        }

        pub fn add_delegate(origin, identity: T::AccountId, delegate: T::AccountId, delegate_type: Vec<u8>, valid_for: T::BlockNumber) -> Result {
                let who = ensure_signed(origin)?;
                Self::_is_owner(&identity, &who)?;
                ensure!(&who != &delegate,"owner cannot be explicity set as delegate");
                ensure!(!Self::_is_valid_delegate(&identity, &delegate_type, &delegate).is_ok(), "delegate exists");
                ensure!(delegate_type.len() <= 32, "delegate type cannot exceed 32 bytes");
                
                let now_timestamp = <timestamp::Module<T>>::now();
                let now_block_number = <system::Module<T>>::block_number();
                let validity = now_block_number.clone() + valid_for.clone();

                <DelegateOf<T>>::insert((identity.clone(), delegate_type.clone(), delegate.clone()), validity.clone());
                <UpdatedOn<T>>::insert(&identity, (now_block_number, now_timestamp));

                Self::deposit_event(RawEvent::DelegateAdded(identity, delegate_type, delegate, validity, valid_for));
        
                Ok(())
        }

        pub fn revoke_delegate(origin, identity: T::AccountId, delegate_type: Vec<u8>, delegate: T::AccountId) -> Result {
                let who = ensure_signed(origin)?;
                Self::_is_owner(&identity, &who)?;
                Self::_is_valid_delegate(&identity, &delegate_type, &delegate)?;
                ensure!(delegate_type.len() <= 32, "delegate type cannot exceed 32 bytes");
                
                let now_timestamp = <timestamp::Module<T>>::now();
                let now_block_number = <system::Module<T>>::block_number();
                
                <DelegateOf<T>>::mutate((identity.clone(), delegate_type.clone(), delegate.clone()), |b| *b = Some(now_block_number.clone()));
                <UpdatedOn<T>>::insert(&identity, (now_block_number, now_timestamp));
                
                Self::deposit_event(RawEvent::DelegateRevoked(identity, delegate_type, delegate));

                Ok(())
        }

        pub fn add_attribute(origin, identity: T::AccountId, name: Vec<u8>, value: Vec<u8>, valid_for: T::BlockNumber) -> Result {
                let who = ensure_signed(origin)?;
                Self::_is_owner(&identity, &who)?;
                ensure!(name.len() <= 64, "invalid attribute name");

                let nonce = Self::nonce_of((identity.clone(), name.clone()));
                
                let now_timestamp = <timestamp::Module<T>>::now();
                let now_block_number = <system::Module<T>>::block_number();
                let validity = now_block_number + valid_for;

                let new_attribute = Attribute {
                    name: name.clone(),
                    value,
                    validity,
                    creation: now_timestamp.clone(),
                    nonce,
                };

                let id = (&identity, &name, nonce).using_encoded(<T as system::Trait>::Hashing::hash);

                <AttributeOf<T>>::insert((identity.clone(), id), new_attribute);;

                <AttributeNonce<T>>::mutate((identity.clone(), name.clone()), |n| *n += 1);

                <UpdatedOn<T>>::insert(&identity, (<system::Module<T>>::block_number(), now_timestamp));

                Self::deposit_event(RawEvent::AttributeAdded(identity, name, validity));

                Ok(())
        }

        pub fn revoke_attribute(origin, identity: T::AccountId, name: Vec<u8>) -> Result { 
                let who = ensure_signed(origin)?;
                Self::_is_owner(&identity, &who)?;
                ensure!(name.len() <= 64, "invalid attribute name");

                let now_block_number = <system::Module<T>>::block_number();

                let result = Self::_attribute_and_id(identity.clone(), name.clone());
                match result {
                    Some((mut attribute, id)) =>  {
                        attribute.validity = now_block_number.clone();
                        <AttributeOf<T>>::mutate((identity.clone(), id), |a| *a = attribute);  
                    },
                    None => return Err("invalid attribute"),
                }
                
                <UpdatedOn<T>>::insert(&identity, (now_block_number.clone(), <timestamp::Module<T>>::now()));
                
                Self::deposit_event(RawEvent::AttributeRevoked(identity, name, now_block_number));
                
                Ok(())
        }

        pub fn delete_attribute(origin, identity: T::AccountId, name: Vec<u8>) -> Result {
                let who = ensure_signed(origin)?;
                Self::_is_owner(&identity, &who)?;
                ensure!(name.len() <= 64, "invalid attribute name");

                let now_block_number = <system::Module<T>>::block_number();
                let result = Self::_attribute_and_id(identity.clone(), name.clone());

                match result {
                    Some((_, id)) => <AttributeOf<T>>::remove((identity.clone(), id)),
                    None => return Err("invalid attribute"),
                }

                <UpdatedOn<T>>::insert(&identity, (now_block_number.clone(), <timestamp::Module<T>>::now()));
                
                Self::deposit_event(RawEvent::AttributeDeleted(identity, name, now_block_number));

                Ok(())
        }


        pub fn execute(origin, transaction: Transaction<AnySignature,AccountKey>, signer: AccountKey) -> Result {
            ensure_none(origin)?;

            ensure!(Self::_check_signature(&transaction.signature, &transaction.msg, &signer),"invalid signature");
            
            Self::update_storage(&transaction)?;

            Self::deposit_event(RawEvent::TransactionExecuted(transaction));

            Ok(())
        }
    }
}

decl_event!(
  pub enum Event<T>
  where
  <T as system::Trait>::AccountId,
  <T as system::Trait>::BlockNumber,
  {
    OwnerChanged(AccountId, AccountId, AccountId, BlockNumber),
    DelegateAdded(AccountId, Vec<u8>, AccountId, BlockNumber, BlockNumber),
    DelegateRevoked(AccountId, Vec<u8>, AccountId),
    AttributeAdded(AccountId,Vec<u8>,BlockNumber),
    AttributeRevoked(AccountId,Vec<u8>,BlockNumber),
    AttributeDeleted(AccountId,Vec<u8>,BlockNumber),
    TransactionExecuted(Transaction<AnySignature,AccountKey>),
  }
);

impl<T: Trait> Module<T> {

    pub fn identity_owner(identity: &T::AccountId) -> T::AccountId {
        let owner = match Self::owner_of(identity) {
            Some(id) => id,
            None => identity.clone(),
        };
        owner
    }

    fn _is_owner(identity: &T::AccountId, actual_owner: &T::AccountId) -> Result {
        let owner = Self::identity_owner(identity);
        match owner == *actual_owner {
            true => Ok(()),
            false => Err("invalid owner"),
        }
    }

    fn _is_valid_delegate(identity: &T::AccountId, delegate_type: &Vec<u8>, delegate: &T::AccountId) -> Result {
        ensure!(<DelegateOf<T>>::exists((identity.clone(), delegate_type.clone(), delegate.clone())), "delegate does not exist");

        let validity = Self::delegate_of((identity.clone(), delegate_type.clone(), delegate.clone()));
        match validity > Some(<system::Module<T>>::block_number()) {
            true => Ok(()),
            false => Err("invalid delegate"),
        }
    }

    fn _attribute_and_id(identity: T::AccountId, name: Vec<u8>) -> Option<(Attribute<T::BlockNumber, T::Moment>, T::Hash)> {

        let nonce = Self::nonce_of((identity.clone(), name.clone()));

        // Used for first time attribute creation
        let lookup_nonce = match nonce.clone() {
            0u64 => 0, // prevents intialization panic
            _ => nonce - 1u64,
        };
        let id = (&identity, name, lookup_nonce ).using_encoded(<T as system::Trait>::Hashing::hash);
        
        if <AttributeOf<T>>::exists((identity.clone(), id.clone())){
            Some((Self::attribute_of((identity, id)), id))
        } else{
            None
        }
    }

    fn _check_signature(signature: &AnySignature, msg: &Vec<u8>, signer: &AccountKey) -> bool {

        let encoded = msg.encode();
        signature.verify(&encoded[..], signer.into())
    }

    fn update_storage(_transaction: &Transaction<AnySignature,AccountKey>) -> Result {

        Ok(())
    }
}

/// tests for this module
#[cfg(test)]
mod tests {
    use super::*;
	use support::{impl_outer_origin, assert_ok, assert_noop};
	use runtime_io::{with_externalities, TestExternalities};
	use primitives::{H256, Blake2Hasher};
	use runtime_primitives::{
		BuildStorage,
        traits::{BlakeTwo256, IdentityLookup},
		testing::{Digest, DigestItem, Header}
	};

	impl_outer_origin! {
		pub enum Origin for DIDTest {}
	}

	#[derive(Clone, Eq, PartialEq)]
	pub struct DIDTest;
	impl system::Trait for DIDTest {
		type Origin = Origin;
		type Index = u64;
		type BlockNumber = u64;
		type Hash = H256;
		type Hashing = BlakeTwo256;
		type Digest = Digest;
		type AccountId = u64;
		type Lookup = IdentityLookup<Self::AccountId>;
		type Header = Header;
		type Event = ();
		type Log = DigestItem;
	}
	
	impl balances::Trait for DIDTest {
		type Balance = u64;
		type OnFreeBalanceZero = ();
		type OnNewAccount = ();
		type Event = ();
		type TransactionPayment = ();
		type TransferPayment = ();
		type DustRemoval = ();
	}

	impl timestamp::Trait for DIDTest {
        type Moment = u64;
        type OnTimestampSet = ();
	}

	impl super::Trait for DIDTest {
		type Event = ();
	}

	fn new_test_ext() -> TestExternalities<Blake2Hasher> {
        let t = system::GenesisConfig::<DIDTest>::default().build_storage().unwrap().0;
        TestExternalities::new(t)
	}

	type DID = super::Module<DIDTest>;
    type System = system::Module<DIDTest>;
    type Moment = timestamp::Module<DIDTest>;

	#[test]
	fn transfer_ownership_should_work() {
		with_externalities(&mut new_test_ext(), || {
            
            // Get the owner of an identity
            assert_eq!(DID::identity_owner(&1),1);

            // Verify identity owner
            assert_ok!(DID::_is_owner(&1,&1));

            // Transfer identity ownership
            assert_ok!(DID::change_owner(Origin::signed(1), 1, 2));

            // Previous owner is invalid
            assert_noop!(DID::_is_owner(&1,&1),"invalid owner");

            // Verify new owner
            assert_ok!(DID::_is_owner(&1,&2));

            // Get the new owner of an identity
            assert_eq!(DID::identity_owner(&1),2);
		})
	}

    #[test]
	fn owner_as_delegate_should_work() {
		with_externalities(&mut new_test_ext(), || {

            System::set_block_number(1);

            // Owner is a valid degate for any type and time
            assert_ok!(DID::valid_delegate(Origin::signed(99),1,vec![7,7,7],1));

            System::set_block_number(1000);

            // Owner is a valid degate for any type and time
            assert_ok!(DID::valid_delegate(Origin::signed(99),1,vec![9,9,9],1));

            System::set_block_number(2000);

            // Transfer identity ownership to AccountId-2
            assert_ok!(DID::change_owner(Origin::signed(1), 1, 2));

            // Previous identity owner should be an invalid delegate
            assert_noop!(DID::valid_delegate(Origin::signed(99),1,vec![7,7,7],1),"invalid delegate");

            // New owner is a valid delegate for any type and time
            assert_ok!(DID::valid_delegate(Origin::signed(99),1,vec![8,8,8],2));

		})
	}

    #[test]
	fn add_delegate_should_work() {
		with_externalities(&mut new_test_ext(), || {

            // Should fail to explicity set owner(AccountId-1) in the delegates list
            assert_noop!(DID::add_delegate(Origin::signed(1),1,1,vec![7,7,7],20),"owner cannot be explicity set as delegate");

            // AccountId-5 is an invalid delegate previous to adding it
            assert_noop!(DID::valid_delegate(Origin::signed(99),1,vec![7,7,7],5),"invalid delegate");

            // Add AccountId-5 as delegate of AccountId-1 for a period of 20 blocks
            assert_ok!(DID::add_delegate(Origin::signed(1),1,5,vec![7,7,7],20));

            // AccountId-5 is a valid for a specified type
            assert_ok!(DID::valid_delegate(Origin::signed(99),1,vec![7,7,7],5));

            // AccountId-5 is an invalid delegate for a different type
            assert_noop!(DID::valid_delegate(Origin::signed(99),1,vec![8,8,8],5),"invalid delegate");

		})
	}

    #[test]
	fn delegate_expiration_should_work() {
		with_externalities(&mut new_test_ext(), || {

            System::set_block_number(1);

            // Add AccountId-5 as delegate of AccountId-1 for a period of 3 blocks
            assert_ok!(DID::add_delegate(Origin::signed(1),1,5,vec![7,7,7],3));

            System::set_block_number(3);
            
            // AccountId-5 is a valid specific type delegate
            assert_ok!(DID::valid_delegate(Origin::signed(99),1,vec![7,7,7],5));

            System::set_block_number(4);

            // AccountId-5 is an invalid delegate after expiration
            assert_noop!(DID::valid_delegate(Origin::signed(99),1,vec![7,7,7],5),"invalid delegate");

		})
	}

    #[test]
	fn revoke_delegate_should_work() {
		with_externalities(&mut new_test_ext(), || {

            System::set_block_number(1);

            // Add AccountId-5 as delegate of AccountId-1 for a period of 1000 blocks
            assert_ok!(DID::add_delegate(Origin::signed(1),1,5,vec![7,7,7],1000));

            System::set_block_number(50);
            
            // AccountId-5 is a valid specific type delegate
            assert_ok!(DID::valid_delegate(Origin::signed(99),1,vec![7,7,7],5));

            // AccountId-5 is a revoked delegate from AccountId-1
            assert_ok!(DID::revoke_delegate(Origin::signed(1),1,vec![7,7,7],5));

            // Delegate max valid block is current block
            assert_eq!(DID::delegate_of((1,vec![7,7,7],5)),Some(50));

            System::set_block_number(51);

            // AccountId-5 is an invalid delegate after revocation
            assert_noop!(DID::valid_delegate(Origin::signed(99),1,vec![7,7,7],5),"invalid delegate");

		})
	}

    #[test]
	fn add_attribute_should_work() {
		with_externalities(&mut new_test_ext(), || {

            System::set_block_number(1);
            
            assert_ok!(DID::add_attribute(Origin::signed(1),1,vec![1,2,3],vec![7,7,7],1000));
            
            assert_ok!(DID::valid_attribute(Origin::signed(99),1,vec![1,2,3],vec![7,7,7]));

            let (attr, id) = DID::_attribute_and_id(1, vec![1,2,3]).unwrap();
            
            // Validate attribute fields
            assert_eq!(attr.name, vec![1,2,3]);
            assert_eq!(attr.value, vec![7,7,7]);
            assert_eq!(attr.validity, 1000 + System::block_number());
            assert_eq!(attr.creation, Moment::now());
            assert_eq!(attr.nonce, 0);

            let hash_id = (&1, vec![1,2,3], 0u64).using_encoded(<DIDTest as system::Trait>::Hashing::hash);
            assert_eq!(hash_id, id);
		})
	}

    #[test]
	fn revoke_attribute_should_work() {
		with_externalities(&mut new_test_ext(), || {

            System::set_block_number(1);

            assert_ok!(DID::add_attribute(Origin::signed(1),1,vec![1,2,3],vec![7,7,7],100));
            
            System::set_block_number(5);

            assert_ok!(DID::revoke_attribute(Origin::signed(1),1,vec![1,2,3]));

            System::set_block_number(50);

            assert_noop!(DID::valid_attribute(Origin::signed(99),1,vec![1,2,3],vec![7,7,7]),"invalid attribute");
		})
	}

    #[test]
	fn delete_attribute_should_work() {
		with_externalities(&mut new_test_ext(), || {

            System::set_block_number(1);

            assert_ok!(DID::add_attribute(Origin::signed(1),1,vec![1,2,3],vec![7,7,7],100));
            
            System::set_block_number(5);

            assert_ok!(DID::delete_attribute(Origin::signed(1),1,vec![1,2,3]));

            System::set_block_number(50);

            assert_noop!(DID::valid_attribute(Origin::signed(99),1,vec![1,2,3],vec![7,7,7]),"invalid attribute");
		})
	}

}
