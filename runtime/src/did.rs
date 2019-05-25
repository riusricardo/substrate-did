// Copyright 2019 Ricardo Rius. 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

// This module was inspired by ERC-1056 "Ethereum DID Registry"
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
//! * **Change Identity Owner:** The action of transferring ownership.
//! * **Add Delegate:** The process of adding delegate privileges to an identity. An identity can assign multiple delegates to manage signing on their behalf for specific purposes.
//! * **Revoke Delegate:** The process of revoking delegate privileges from an identity.
//! * **Add Attribute:** The process of assigning a specific identity attribute or feature.
//! * **Revoke Attribute:** The process of revoking a specific identity attribute or feature.
//! * **Delete Attribute:** The process of deleting a specific identity attribute or feature.
//! * **DID:** A Decentralized Identifiers compliant with the DID standard.
//!
//! *


use support::{decl_event, decl_module, decl_storage, ensure, dispatch::Result, StorageMap};
use runtime_primitives::{traits::{Hash}};
use parity_codec::{Encode, Decode};
use system::{self, ensure_signed};
use rstd::{prelude::*};

// Definition: ext_secp256k1_ecdsa_recover(msg_data: *const u8, sig_data: *const u8, pubkey_data: *mut u8) -> u32
// use runtime_io::ext_secp256k1_ecdsa_recover;

#[derive(Encode, Decode, Default, Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Attribute<BlockNumber> {
    name: Vec<u8>,
    value: Vec<u8>,
    validity: BlockNumber,
    nonce: u64,
}
pub trait Trait: system::Trait + timestamp::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_storage! {
    trait Store for Module<T: Trait> as DID {
        pub DelegateOf get(delegate_of): map (T::AccountId, Vec<u8>, T::AccountId) => Option<T::BlockNumber>;
        pub AttributeOf get(attribute_of): map (T::AccountId, T::Hash) => Attribute<T::BlockNumber>;
        pub AttributeNonce get(nonce_of): map (T::AccountId, Vec<u8>) => u64;
        pub OwnerOf get(owner_of): map T::AccountId => Option<T::AccountId>;
        pub UpdatedOn get(updated_on): map T::AccountId => (T::BlockNumber, T::Moment);
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {

        fn deposit_event<T>() = default;

        pub fn change_owner(origin, identity: T::AccountId, actual_owner: T::AccountId, new_owner: T::AccountId) -> Result {
                let who = ensure_signed(origin)?;
                ensure!(who == actual_owner, "invalid owner");
                ensure!(Self::_is_owner(&identity, &who), "you do not own this identity");
                
                let now_timestamp = <timestamp::Module<T>>::now();
                let now_block_number = <system::Module<T>>::block_number();
                
                <OwnerOf<T>>::insert(&identity, &new_owner);
                <UpdatedOn<T>>::insert(&identity, (now_block_number.clone(), now_timestamp.clone()));
                
                Self::deposit_event(RawEvent::DIDChangedOwner(identity, actual_owner, now_block_number));
        
                Ok(())
        }

        pub fn add_delegate(origin, identity: T::AccountId, delegate: T::AccountId, delegate_type: Vec<u8>, valid_for: T::BlockNumber) -> Result {
                let who = ensure_signed(origin)?;
                ensure!(delegate_type.len() <= 64, "delegate type cannot exceed 64 bytes");
                ensure!(Self::_is_owner(&identity, &who), "you do not own this identity");
                
                let now_timestamp = <timestamp::Module<T>>::now();
                let now_block_number = <system::Module<T>>::block_number();
                let validity = now_block_number.clone() + valid_for.clone();

                <DelegateOf<T>>::insert((identity.clone(), delegate_type.clone(), delegate.clone()), validity.clone());
                <UpdatedOn<T>>::insert(&identity, (now_block_number, now_timestamp));

                Self::deposit_event(RawEvent::DIDAddedDelegate(identity, delegate_type, delegate, validity, valid_for));
        
                Ok(())
        }

        pub fn revoke_delegate(origin, identity: T::AccountId, delegate_type: Vec<u8>, delegate: T::AccountId) -> Result {
                let who = ensure_signed(origin)?;
                ensure!(delegate_type.len() <= 64, "delegate type cannot exceed 64 bytes");
                ensure!(Self::_is_owner(&identity, &who), "you do not own this identity");
                ensure!(Self::_is_valid_delegate(&identity, &delegate_type, &delegate), "invalid delegate");
                
                let now_timestamp = <timestamp::Module<T>>::now();
                let now_block_number = <system::Module<T>>::block_number();
                
                <DelegateOf<T>>::mutate((identity.clone(), delegate_type.clone(), delegate.clone()), |b| *b = Some(now_block_number.clone()));
                <UpdatedOn<T>>::insert(&identity, (now_block_number, now_timestamp));
                
                Self::deposit_event(RawEvent::DIDRevokedDelegate(identity, delegate_type, delegate));

                Ok(())
        }

        pub fn valid_delegate(origin, identity: T::AccountId, delegate_type: Vec<u8>, delegate: T::AccountId) -> Result {
                let _ = ensure_signed(origin)?;
                
                ensure!(delegate_type.len() <= 64, "delegate type cannot exceed 64 bytes");
                ensure!(Self::_is_valid_delegate(&identity, &delegate_type, &delegate), "invalid delegate");
                
                Self::deposit_event(RawEvent::DIDValidatedDelegate(identity, delegate_type, delegate));
                
                Ok(())
        }

        pub fn add_attribute(origin, identity: T::AccountId, attribute_name: Vec<u8>, attribute_value: Vec<u8>, valid_for: T::BlockNumber) -> Result {
                let who = ensure_signed(origin)?;
                ensure!(Self::_is_owner(&identity, &who), "you do not own this identity");
                ensure!(attribute_name.len() <= 32, "invalid attribute name");

                let attribute_nonce = Self::nonce_of((identity.clone(), attribute_name.clone()));
                
                
                let lookup_nonce = match attribute_nonce.clone() {
                    0u64 => 0, // prevent intialization panic
                    _ => attribute_nonce.clone() - 1u64,
                };
                
                let attribute_hash = (&identity, &attribute_name, lookup_nonce ).using_encoded(<T as system::Trait>::Hashing::hash);
                
                ensure!(!<AttributeOf<T>>::exists((identity.clone(), attribute_hash)), "attribute already in use");

                let now_timestamp = <timestamp::Module<T>>::now();
                let now_block_number = <system::Module<T>>::block_number();
                let validity = now_block_number.clone() + valid_for.clone();

                let new_attribute = Attribute {
                    name: attribute_name.clone(),
                    value: attribute_value.clone(),
                    validity: validity.clone(),
                    nonce: attribute_nonce,
                };

                let attribute_id = (&identity, &attribute_name, attribute_nonce).using_encoded(<T as system::Trait>::Hashing::hash);

                <AttributeOf<T>>::insert((identity.clone(), attribute_id), new_attribute);;
                <AttributeNonce<T>>::mutate((identity.clone(), attribute_name.clone()), |n| *n += 1);
                <UpdatedOn<T>>::insert(&identity, (now_block_number.clone(), now_timestamp));

                Self::deposit_event(RawEvent::DIDAddedAttribute(identity, attribute_name, validity));

                Ok(())
        }

        pub fn revoke_attribute(origin, identity: T::AccountId, attribute_name: Vec<u8>) -> Result { 
                let who = ensure_signed(origin)?;
                ensure!(Self::_is_owner(&identity, &who), "you do not own this identity");
                ensure!(attribute_name.len() <= 32, "invalid attribute name");

                let attribute_nonce = Self::nonce_of((identity.clone(), attribute_name.clone()));

                let lookup_nonce = match attribute_nonce.clone() {
                    0u64 => 0, // prevent intialization panic
                    _ => attribute_nonce.clone() - 1u64,
                };
                let attribute_hash = (&identity, &attribute_name, lookup_nonce ).using_encoded(<T as system::Trait>::Hashing::hash);
                
                ensure!(<AttributeOf<T>>::exists((identity.clone(), attribute_hash)), "attribute does not exist");

                let now_timestamp = <timestamp::Module<T>>::now();
                let now_block_number = <system::Module<T>>::block_number();
                let mut attribute = Self::attribute_of((identity.clone(), attribute_hash.clone()));

                attribute.validity = now_block_number.clone();

                <AttributeOf<T>>::mutate((identity.clone(), attribute_hash), |a| *a = attribute.clone());
                <UpdatedOn<T>>::insert(&identity, (now_block_number.clone(), now_timestamp.clone()));
                
                Self::deposit_event(RawEvent::DIDRevokedAttribute(identity, attribute_name, now_block_number));
                
                Ok(())
        }

        pub fn delete_attribute(origin, identity: T::AccountId, attribute_name: Vec<u8>) -> Result {
                let who = ensure_signed(origin)?;
                ensure!(Self::_is_owner(&identity, &who), "you do not own this identity");
                ensure!(attribute_name.len() <= 32, "invalid attribute name");

                let now_timestamp = <timestamp::Module<T>>::now();
                let now_block_number = <system::Module<T>>::block_number();
                let attribute_nonce = Self::nonce_of((identity.clone(), attribute_name.clone()));
                let lookup_nonce = match attribute_nonce.clone() {
                    0u64 => 0, // prevent intialization panic
                    _ => attribute_nonce.clone() - 1u64,
                };
                let attribute_hash = (&identity, &attribute_name, lookup_nonce ).using_encoded(<T as system::Trait>::Hashing::hash);
                
                ensure!(<AttributeOf<T>>::exists((identity.clone(), attribute_hash.clone())), "attribute does not exist");

                <AttributeOf<T>>::remove((identity.clone(), attribute_hash));
                <UpdatedOn<T>>::insert(&identity, (now_block_number.clone(), now_timestamp));
                
                Self::deposit_event(RawEvent::DIDDeletedAttribute(identity, attribute_name, now_block_number));

                Ok(())
        }
    }
}

decl_event!(
  pub enum Event<T>
  where
  <T as system::Trait>::AccountId,
  <T as system::Trait>::BlockNumber,
  //<T as timestamp::Trait>::Moment
  {
    DIDChangedOwner(AccountId, AccountId, BlockNumber),
    DIDAddedDelegate(AccountId, Vec<u8>, AccountId, BlockNumber, BlockNumber),
    DIDValidatedDelegate(AccountId, Vec<u8>, AccountId),
    DIDRevokedDelegate(AccountId, Vec<u8>, AccountId),
    DIDAddedAttribute(AccountId,Vec<u8>,BlockNumber),
    DIDRevokedAttribute(AccountId,Vec<u8>,BlockNumber),
    DIDDeletedAttribute(AccountId,Vec<u8>,BlockNumber),
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

    fn _is_owner(identity: &T::AccountId, actual_owner: &T::AccountId) -> bool {
        let owner = Self::identity_owner(identity);
        let approved_as_owner = if owner == *actual_owner {
            true
        } else {
            false
        };
        approved_as_owner
    }

    fn _is_valid_delegate(identity: &T::AccountId, delegate_type: &Vec<u8>, delegate: &T::AccountId) -> bool {
        let validity = Self::delegate_of((identity.clone(), delegate_type.clone(), delegate.clone()));
        let valid = match validity {
            Some(val) => val > (<system::Module<T>>::block_number()),
            None => false,
        };
        valid
    }
}

/// tests for this module
#[cfg(test)]
mod tests {
	use super::*;
	use runtime_io::with_externalities;
	use srml_support::{impl_outer_origin, impl_outer_dispatch, assert_noop, assert_ok};
	use substrate_primitives::{H256, Blake2Hasher};
	use primitives::BuildStorage;
	use primitives::traits::{BlakeTwo256, IdentityLookup};
	use primitives::testing::{Digest, DigestItem, Header};

	impl_outer_origin! {
		pub enum Origin for DIDTest {}
	}

	#[derive(Clone, Eq, PartialEq, Debug)]
	pub struct Test;
	impl system::Trait for Test {
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
	impl Trait for Test {
		type Event = ();
	}
	type DID = Module<Test>;
    type System = system::Module<Test>;

	// This function basically just builds a genesis storage key/value store according to
	// our desired mockup.
	fn new_test_ext() -> runtime_io::TestExternalities<Blake2Hasher> {
		system::GenesisConfig::<Test>::default().build_storage().unwrap().0.into()
	}

	#[test]
	fn it_works_for_default_value() {
		with_externalities(&mut new_test_ext(), || {

		});
	}
}
