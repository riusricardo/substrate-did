// Copyright 2019 Ricardo Rius. 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// This module is based on ERC-1056

//! # DID Module
//!
//! The DID module allows resolving and management for DIDs (Decentralized Identifiers).
//! DID compliant with: https://w3c-ccg.github.io/did-spec/
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
//! ### Terminology
//!
//! * **DID:** A Decentralized Identifiers/Identity compliant with the DID standard.
//! The DID is an AccountId with associated attributes/properties.
//! * **Delegate:** A Delegate recives delegated permissions from a DID for a specific purpose.
//! * **Attribute:** It is a feature that gives extra information of an identity.
//! * **Valid Delegate:** The action of obtaining the validity period of the delegate.
//! * **Valid Attribute:** The action of obtaining the validity period of an attribute.
//! * **Change Identity Owner:** The process of transferring ownership.
//! * **Add Delegate:** The process of adding delegate privileges to an identity. 
//! An identity can assign multiple delegates for specific purposes on its behalf.
//! * **Revoke Delegate:** The process of revoking delegate privileges from an identity.
//! * **Add Attribute:** The process of assigning a specific identity attribute or feature.
//! * **Revoke Attribute:** The process of revoking a specific identity attribute or feature.
//! * **Delete Attribute:** The process of deleting a specific identity attribute or feature.
//!
//! ### Goals
//!
//! The DID system in Substrate is designed to make the following possible:
//!
//! * 
//!
//! ### Dispatchable Functions
//!
//! * `valid_delegate` - Validates if a delegate belongs to an identity and it has not expired.
//! * `valid_attribute` - Validates if an attribute belongs to an identity and it has not expired.
//! * `change_owner` - Transfers an `identity` represented as an `AccountId` from the owner account (`origin`) to a `target` account.
//! * `add_delegate` - Creates a new delegate with an expiration period and for a specific purpose.
//! * `revoke_delegate` - Revokes an identity's delegate by setting its expiration to the current block number.
//! * `add_attribute` - Creates a new attribute/property as part of an identity. Sets its expiration period.
//! * `revoke_attribute` - Revokes an attribute/property from an identity. Sets its expiration period to the actual block number.
//! * `delete_attribute` - Removes an attribute/property from an identity. This attribute/property becomes unavailable.
//!
//! ### Public Functions
//!
//! * `is_owner` - Returns a boolean value. `True` if the `account` owns the `identity`.
//! * `identity_owner` - Get the account owner of an `identity`.
//! * `valid_listed_delegate` - Returns a boolean value. `True` if the `delegate` belongs the `identity` delegates list.
//! * `attribute_and_id` - Get the `attribute` and its `hash` identifier.
//!
//! *

use support::{decl_event, decl_module, decl_storage, ensure, StorageMap, Parameter, 
            dispatch::{Result, Vec},
            traits::{Currency, ExistenceRequirement, WithdrawReason}
};
use runtime_primitives::{traits::{Hash, Verify}};
use parity_codec::{Encode, Decode};
use system::{self, ensure_signed};
use rstd::{prelude::*};


/// Attributes or properties that make up an identity.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Default)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Attribute<BlockNumber, Moment> {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub validity: BlockNumber,
    pub creation: Moment,
    pub nonce: u64,
}

/// Off-chain signed transaction.
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct AttributeTransaction<Signature,AccountId> {
    pub signature: Signature,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub validity: u32,
    pub signer: AccountId,
    pub identity: AccountId
}

pub trait Trait: system::Trait + timestamp::Trait + balances::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type Signature: Parameter + Default + Verify<Signer=Self::AccountId>;
}

decl_storage! {
    trait Store for Module<T: Trait> as DID {
        /// Identity delegates stored by type.
        /// Delegates are only valid for a specific period defined as blocks number.
        pub DelegateOf get(delegate_of): map (T::AccountId, Vec<u8>, T::AccountId) => Option<T::BlockNumber>;
        /// The attributes that belong to an identity. 
        /// Attributes are only valid for a specific period defined as blocks number.
        pub AttributeOf get(attribute_of): map (T::AccountId, T::Hash) => Attribute<T::BlockNumber, T::Moment>;
        /// Attribute nonce used to generate a unique hash even if the attribute is deleted and recreated.
        pub AttributeNonce get(nonce_of): map (T::AccountId, Vec<u8>) => u64;
        /// Identity owner.
        pub OwnerOf get(owner_of): map T::AccountId => Option<T::AccountId>;
        /// Tracking the latest identity update.
        pub UpdatedBy get(updated_by): map T::AccountId => (T::AccountId, T::BlockNumber, T::Moment);
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {

        fn deposit_event<T>() = default;

        /// Transfers ownership of an identity.
        pub fn change_owner(origin, identity: T::AccountId, new_owner: T::AccountId) -> Result {
                let who = ensure_signed(origin)?;
                Self::is_owner(&identity, &who)?;
                
                let now_timestamp = <timestamp::Module<T>>::now();
                let now_block_number = <system::Module<T>>::block_number();
                
                <OwnerOf<T>>::insert(&identity, &new_owner);
                <UpdatedBy<T>>::insert(&identity, (who.clone(), now_block_number.clone(), now_timestamp));
                
                Self::deposit_event(RawEvent::OwnerChanged(identity, who, new_owner, now_block_number));
        
                Ok(())
        }

        /// Creates a new delegate with an expiration period and for a specific purpose.
        pub fn add_delegate(origin, identity: T::AccountId, delegate: T::AccountId, delegate_type: Vec<u8>, valid_for: T::BlockNumber) -> Result {
                let who = ensure_signed(origin)?;
                Self::is_owner(&identity, &who)?;
                ensure!(&who != &delegate,"owner cannot be explicity set as delegate");
                ensure!(!Self::valid_listed_delegate(&identity, &delegate_type, &delegate).is_ok(), "delegate exists");
                ensure!(delegate_type.len() <= 32, "delegate type cannot exceed 32 bytes");

                let now_timestamp = <timestamp::Module<T>>::now();
                let now_block_number = <system::Module<T>>::block_number();
                let validity = now_block_number.clone() + valid_for.clone();

                <DelegateOf<T>>::insert((identity.clone(), delegate_type.clone(), delegate.clone()), validity.clone());
                <UpdatedBy<T>>::insert(&identity, (who, now_block_number, now_timestamp));

                Self::deposit_event(RawEvent::DelegateAdded(identity, delegate_type, delegate, validity, valid_for));
        
                Ok(())
        }

        /// Revokes an identity's delegate by setting its expiration to the current block number.
        pub fn revoke_delegate(origin, identity: T::AccountId, delegate_type: Vec<u8>, delegate: T::AccountId) -> Result {
                let who = ensure_signed(origin)?;
                Self::is_owner(&identity, &who)?;
                Self::valid_listed_delegate(&identity, &delegate_type, &delegate)?;
                ensure!(delegate_type.len() <= 32, "delegate type cannot exceed 32 bytes");

                let now_timestamp = <timestamp::Module<T>>::now();
                let now_block_number = <system::Module<T>>::block_number();
                
                // Update only the validity period to revoke the delegate.
                <DelegateOf<T>>::mutate((identity.clone(), delegate_type.clone(), delegate.clone()), |b| *b = Some(now_block_number.clone()));
                <UpdatedBy<T>>::insert(&identity, (who, now_block_number, now_timestamp));
                
                Self::deposit_event(RawEvent::DelegateRevoked(identity, delegate_type, delegate));

                Ok(())
        }

        /// Creates a new attribute as part of an identity. Sets its expiration period.
        pub fn add_attribute(origin, identity: T::AccountId, name: Vec<u8>, value: Vec<u8>, valid_for: T::BlockNumber) -> Result {
                let who = ensure_signed(origin)?;
                Self::is_owner(&identity, &who)?;
                ensure!(name.len() <= 64, "invalid attribute name");

                Self::create_attribute(who, &identity, &name, &value, &valid_for)?;

                Self::deposit_event(RawEvent::AttributeAdded(identity, name, valid_for));

                Ok(())
        }

        /// Revokes an attribute/property from an identity. Sets its expiration period to the actual block number.
        pub fn revoke_attribute(origin, identity: T::AccountId, name: Vec<u8>) -> Result { 
                let who = ensure_signed(origin)?;
                Self::is_owner(&identity, &who)?;
                ensure!(name.len() <= 64, "invalid attribute name");

                Self::reset_attribute(who, &identity, &name)?;
                
                Self::deposit_event(RawEvent::AttributeRevoked(identity, name, <system::Module<T>>::block_number()));
                
                Ok(())
        }

        /// Removes an attribute from an identity. This attribute/property becomes unavailable.
        pub fn delete_attribute(origin, identity: T::AccountId, name: Vec<u8>) -> Result {
                let who = ensure_signed(origin)?;
                Self::is_owner(&identity, &who)?;
                ensure!(name.len() <= 64, "invalid attribute name");

                let now_block_number = <system::Module<T>>::block_number();
                let result = Self::attribute_and_id(&identity, &name);

                match result {
                    Some((_, id)) => <AttributeOf<T>>::remove((identity.clone(), id)),
                    None => return Err("invalid attribute"),
                }

                <UpdatedBy<T>>::insert(&identity, (who, now_block_number.clone(), <timestamp::Module<T>>::now()));
                
                Self::deposit_event(RawEvent::AttributeDeleted(identity, name, now_block_number));

                Ok(())
        }

        /// Executes off-chain signed transaction.
        pub fn execute(origin, transaction: AttributeTransaction<T::Signature,T::AccountId>) -> Result {
            let who = ensure_signed(origin)?;

            let mut encoded = transaction.name.encode();
            encoded.extend(transaction.value.encode());
            encoded.extend(transaction.validity.encode());
            encoded.extend(transaction.identity.encode());

            Self::signed_attribute(who, &encoded, &transaction)?;
            Self::deposit_event(RawEvent::AttributeTransactionExecuted(transaction));

            Ok(())
        }
    }
}

decl_event!(
  pub enum Event<T>
  where
  <T as system::Trait>::AccountId,
  <T as system::Trait>::BlockNumber,
  <T as Trait>::Signature
  {
    OwnerChanged(AccountId, AccountId, AccountId, BlockNumber),
    DelegateAdded(AccountId, Vec<u8>, AccountId, BlockNumber, BlockNumber),
    DelegateRevoked(AccountId, Vec<u8>, AccountId),
    AttributeAdded(AccountId,Vec<u8>,BlockNumber),
    AttributeRevoked(AccountId,Vec<u8>,BlockNumber),
    AttributeDeleted(AccountId,Vec<u8>,BlockNumber),
    AttributeTransactionExecuted(AttributeTransaction<Signature,AccountId>),
  }
);

impl<T: Trait> Module<T> {

    /// Validates if the AccountId 'actual_owner' owns the identity.
    pub fn is_owner(identity: &T::AccountId, actual_owner: &T::AccountId) -> Result {
        let owner = Self::identity_owner(identity);
        match owner == *actual_owner {
            true => Ok(()),
            false => Err("invalid owner"),
        }
    }

    /// Get the identity owner if set.
    /// If never changed, returns the identity as its owner.
    pub fn identity_owner(identity: &T::AccountId) -> T::AccountId {
        let owner = match Self::owner_of(identity) {
            Some(id) => id,
            None => identity.clone(),
        };
        owner
    }

    /// Validates if a delegate belongs to an identity and it has not expired.
    pub fn valid_delegate(identity: &T::AccountId, delegate_type: &Vec<u8>, delegate: &T::AccountId) -> Result {
            ensure!(delegate_type.len() <= 32, "delegate type cannot exceed 32 bytes");
            ensure!(
                Self::valid_listed_delegate(identity, delegate_type, delegate).is_ok() ||
                Self::is_owner(identity, delegate).is_ok(),
            "invalid delegate");

            Ok(())
    }

    /// Validates that a delegate exists for specific purpose and remains valid at this block high.
    pub fn valid_listed_delegate(identity: &T::AccountId, delegate_type: &Vec<u8>, delegate: &T::AccountId) -> Result {
        ensure!(<DelegateOf<T>>::exists((identity.clone(), delegate_type.clone(), delegate.clone())), "delegate does not exist");

        let validity = Self::delegate_of((identity.clone(), delegate_type.clone(), delegate.clone()));
        match validity > Some(<system::Module<T>>::block_number()) {
            true => Ok(()),
            false => Err("invalid delegate"),
        }
    }

    /// Validates if an attribute belongs to an identity and it has not expired.
    pub fn valid_attribute(identity: &T::AccountId, name: &Vec<u8>, value: &Vec<u8>) -> Result { 
            ensure!(name.len() <= 64, "invalid attribute name");
            let result = Self::attribute_and_id(identity, name);

            let (attr, _) = match result {
                Some((attr, id)) => (attr, id),
                None => return Err("invalid attribute"),
            };

            if (attr.validity > (<system::Module<T>>::block_number())) && (attr.value == *value) {
                Ok(())
            } else {
                Err("invalid attribute")
            }
    }

    /// Returns the attribute and its hash identifier.
    /// Uses a nonce to keep track of identifiers making them unique after attributes deletion.
    pub fn attribute_and_id(identity: &T::AccountId, name: &Vec<u8>) -> Option<(Attribute<T::BlockNumber, T::Moment>, T::Hash)> {
        
        let nonce = Self::nonce_of((identity.clone(), name.clone()));

        // Used for first time attribute creation
        let lookup_nonce = match nonce.clone() {
            0u64 => 0, // prevents intialization panic
            _ => nonce - 1u64,
        };
        let id = (identity.clone(), name.clone(), lookup_nonce ).using_encoded(<T as system::Trait>::Hashing::hash);
        
        if <AttributeOf<T>>::exists((identity.clone(), id.clone())){
            Some((Self::attribute_of((identity.clone(), id.clone())), id.clone()))
        } else{
            None
        }
    }

    /// Checks if a signature is valid. Used to validate off-chain transactions.
    pub fn check_signature(signature: &T::Signature, msg: &[u8], signer: &T::AccountId) -> Result {
        
        if signature.verify(msg, signer.into()) {
            Ok(())
        } else{
            Err("invalid signer")
        }
    }

    /// Checks if a signature is valid. Used to validate off-chain transactions.
    pub fn valid_signer(identity: &T::AccountId, signature: &T::Signature, msg: &[u8], signer: &T::AccountId) -> Result {
        
        // Predefined delegate type: "sr25519-signer"
        let delegate_type: Vec<u8> = [115, 114, 50, 53, 53, 49, 57, 45, 115, 105, 103, 110, 101, 114].to_vec();
        
        Self::valid_delegate(&identity, &delegate_type, &signer)?; // owner or a delegate signer.

        Self::check_signature(&signature, &msg, &signer)

    }

    /// Creates a new attribute from a off-chain transaction.
    fn signed_attribute(who: T::AccountId, encoded: &[u8], transaction: &AttributeTransaction<T::Signature,T::AccountId>) -> Result {
        Self::valid_signer(&transaction.identity, &transaction.signature, &encoded, &transaction.signer)?;
        Self::is_owner(&transaction.identity, &transaction.signer)?;
        
        let now_block_number = <system::Module<T>>::block_number();
        let validity = now_block_number + transaction.validity.into();

        if validity > now_block_number {
            Self::create_attribute(who, &transaction.identity, &transaction.name, &transaction.value, &transaction.validity.into())?;
        
        } else {
            Self::reset_attribute(who, &transaction.identity, &transaction.name)?;
        }

        Ok(())
    }

    fn create_attribute(who: T::AccountId, identity: &T::AccountId, name: &Vec<u8>, value: &Vec<u8>, valid_for: &T::BlockNumber) -> Result {

        let now_timestamp = <timestamp::Module<T>>::now();
        let now_block_number = <system::Module<T>>::block_number();
        let nonce = Self::nonce_of((identity.clone(), name.clone()));
        let validity = now_block_number + *valid_for;

        // Used for first time attribute creation
        let lookup_nonce = match nonce.clone() {
            0u64 => 0, // prevents intialization panic
            _ => nonce.clone() - 1u64,
        };

        let id = (identity, name, lookup_nonce).using_encoded(<T as system::Trait>::Hashing::hash);
        
        if <AttributeOf<T>>::exists((identity.clone(), id.clone())){
            Err("attribute exists")
        } else{
            let new_attribute = Attribute {
                    name: name.clone(),
                    value: value.clone(),
                    validity,
                    creation: now_timestamp,
                    nonce,
                };

            let size: u32 = value.len() as u32;
            let fee = size.into();
            Self::pay_fee(&who, fee)?;

            <AttributeOf<T>>::insert((identity.clone(), id), new_attribute);
            <AttributeNonce<T>>::mutate((identity.clone(), name.clone()), |n| *n += 1);
            <UpdatedBy<T>>::insert(identity, (who, <system::Module<T>>::block_number(), <timestamp::Module<T>>::now()));
            
            Ok(())
        }
    }

    fn reset_attribute(who: T::AccountId, identity: &T::AccountId, name: &Vec<u8>) -> Result {

        let result = Self::attribute_and_id(identity, name);
        match result {
            Some((mut attribute, id)) =>  {
                attribute.validity = <system::Module<T>>::block_number();
                <AttributeOf<T>>::mutate((identity.clone(), id), |a| *a = attribute);  
            },
            None => return Err("invalid attribute"),
        }
        
        <UpdatedBy<T>>::insert(identity, (who, <system::Module<T>>::block_number(), <timestamp::Module<T>>::now()));
        
        Ok(())
    }

    fn pay_fee(who: &T::AccountId, amount: T::Balance) -> Result {
        let _ = <balances::Module<T> as Currency<_>>::withdraw(
            who,
            amount,
            WithdrawReason::Fee,
            ExistenceRequirement::KeepAlive
        )?;

        Ok(())
    }
}