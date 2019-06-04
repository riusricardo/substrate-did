// Copyright 2019 Ricardo Rius. 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#![cfg(test)]

use crate::mock::{DID, System, Moment, Origin, AttributeTransaction, 
                  new_test_ext, account_pair, account_key};
use parity_codec::Encode;
use support::{assert_ok, assert_noop};
use runtime_io::with_externalities;
use primitives::Pair;
use std::string::String;


#[test]
fn validate_claim() {
    with_externalities(&mut new_test_ext(), || {
        
        let value: Vec<u8> = String::from("I am Satoshi Nakamoto").into();

        // Create a new account pair and get the public key.
        let satoshi_pair = account_pair("Satoshi");
        let satoshi_public = satoshi_pair.public();

        // Encode and sign the claim message.
        let claim = value.encode();
        let satoshi_sig = satoshi_pair.sign(&claim);
        
        // Validate that "Satoshi" signed the message.
        assert_ok!(DID::valid_signer(&satoshi_public, &satoshi_sig, &claim, &satoshi_public));

        // Create a different public key to test the signature.
        let bob_public = account_key("Bob");
        
        // Fail to validate that Bob did signed the message.
        assert_noop!(DID::check_signature(&satoshi_sig, &claim, &bob_public),"invalid signer");
    })
}

#[test]
fn validate_delegated_claim() {
    with_externalities(&mut new_test_ext(), || {

        System::set_block_number(1);

        // Predefined delegate type: "Sr25519VerificationKey2018"
        let delegate_type: Vec<u8> = String::from("Sr25519VerificationKey2018").into();

        let data: Vec<u8> = String::from("I am Satoshi Nakamoto").into();

        let satoshi_public = account_key("Satoshi");            // Get Satoshi's public key.
        let nakamoto_pair = account_pair("Nakamoto");           // Create a new delegate account pair.
        let nakamoto_public = nakamoto_pair.public();           // Get delegate's public key.

        // Add signer delegate
        assert_ok!(DID::add_delegate(
                    Origin::signed(satoshi_public.clone()),
                    satoshi_public.clone(),     // owner
                    nakamoto_public.clone(),    // new signer delgate
                    delegate_type.clone(),      // "sr25519-signer"
                    5)                          // valid for 5 blocks
                );


        let claim = data.encode();
        let satoshi_sig = nakamoto_pair.sign(&claim);   // Sign the data with delegates private key.

        System::set_block_number(3);

        // Validate that satoshi's delegate signed the message.
        assert_ok!(DID::valid_signer(&satoshi_public, &satoshi_sig, &claim, &nakamoto_public));

        System::set_block_number(6);

        // Delegate became invalid at block 6
        assert_noop!(DID::valid_signer(&satoshi_public, &satoshi_sig, &claim, &nakamoto_public),"invalid delegate");
    })
}

#[test]
fn add_on_chain_and_revoke_off_chain_attribute() {
    with_externalities(&mut new_test_ext(), || {

        let name: Vec<u8> = String::from("MyAttribute").into();
        let mut value = [1,2,3].to_vec();
        let mut validity: u32 = 1000;

        // Create a new account pair and get the public key.
        let alice_pair = account_pair("Alice");
        let alice_public = alice_pair.public();
        
        // Add a new attribute to an identity. Valid until block 1 + 1000.
        assert_ok!(DID::add_attribute(Origin::signed(alice_public.clone()),alice_public.clone(),name.clone(),value.clone(),validity.clone().into()));

        // Validate that the attribute exists and has not expired.
        assert_ok!(DID::valid_attribute(&alice_public, &name, &value));        
        
        // Revoke attribute off-chain
        // Set validity to 0 in order to revoke the attribute.
        validity = 0;                       
        value = [0].to_vec();
        let mut encoded = name.encode();
        encoded.extend(value.encode());
        encoded.extend(validity.encode());
        encoded.extend(alice_public.encode());

        let revoke_sig = alice_pair.sign(&encoded);

        let revoke_transaction = AttributeTransaction {
            signature: revoke_sig,
            name: name.clone(),
            value: value.clone(),
            validity,
            signer: alice_public.clone(),
            identity: alice_public.clone(),
        };

        // Revoke with off-chain signed transaction.
        assert_ok!(DID::execute(Origin::signed(alice_public.clone()), revoke_transaction));

        // Validate that the attribute was revoked.
        assert_noop!(DID::valid_attribute(&alice_public, &name, &[1,2,3].to_vec()),"invalid attribute");

    })
}

#[test]
fn add_off_chain_and_revoke_on_chain_attribute() {
    with_externalities(&mut new_test_ext(), || {

        let name: Vec<u8> = String::from("MyAttribute").into();
        let value = [1,2,3].to_vec();
        let validity: u32 = 50;

        // Create a new account pair and get the public key.
        let alice_pair = account_pair("Alice");
        let alice_public = alice_pair.public(); 

        let mut encoded = name.encode();
        encoded.extend(value.encode());
        encoded.extend(validity.encode());
        encoded.extend(alice_public.encode());

        let create_sig = alice_pair.sign(&encoded); // Sign the data with private key.

        let new_transaction = AttributeTransaction {
            signature: create_sig,
            name: name.clone(),
            value: value.clone(),
            validity,
            signer: alice_public.clone(),
            identity: alice_public.clone(),
        };

        // Create with signed transaction.
        assert_ok!(DID::execute(Origin::signed(alice_public.clone()), new_transaction));
        
        // Validate that the attribute exists and has not expired.
        assert_ok!(DID::valid_attribute(&alice_public, &name, &value));        

        // Revoke attribute from an identity by setting its expiration to actual block number.
        assert_ok!(DID::revoke_attribute(Origin::signed(alice_public.clone()),alice_public.clone(),name.clone()));
        
        // Validate that the attribute was revoked.
        assert_noop!(DID::valid_attribute(&alice_public, &name, &value),"invalid attribute");

    })
}

#[test]
fn add_and_revoke_off_chain_attribute() {
    with_externalities(&mut new_test_ext(), || {

        let name: Vec<u8> = String::from("MyAttribute").into();
        let value = [1,2,3].to_vec();
        let mut validity: u32 = 50;

        // Create a new account pair and get the public key.
        let alice_pair = account_pair("Alice");
        let alice_public = alice_pair.public();

        let mut encoded = name.encode();
        encoded.extend(value.encode());
        encoded.extend(validity.encode());
        encoded.extend(alice_public.encode());

        let create_sig = alice_pair.sign(&encoded); // Sign the data with private key.

        let new_transaction = AttributeTransaction {
            signature: create_sig,
            name: name.clone(),
            value: value.clone(),
            validity,
            signer: alice_public.clone(),
            identity: alice_public.clone(),
        };

        // Create with signed transaction.
        assert_ok!(DID::execute(Origin::signed(alice_public.clone()), new_transaction));
        
        // Validate that the attribute exists and has not expired.
        assert_ok!(DID::valid_attribute(&alice_public, &name, &value));        
        
        // Set validity to 0 in order to revoke the attribute.
        validity = 0;                       
        encoded = name.encode();
        encoded.extend(value.encode());
        encoded.extend(validity.encode());
        encoded.extend(alice_public.encode());

        let revoke_sig = alice_pair.sign(&encoded);

        let revoke_transaction = AttributeTransaction {
            signature: revoke_sig,
            name: name.clone(),
            value: value.clone(),
            validity,
            signer: alice_public.clone(),
            identity: alice_public.clone(),
        };

        // Revoke with signed transaction.
        assert_ok!(DID::execute(Origin::signed(alice_public.clone()), revoke_transaction));

        // Validate that the attribute was revoked.
        assert_noop!(DID::valid_attribute(&alice_public, &name, &value),"invalid attribute");

    })
}

#[test]
fn transfer_identity_ownership() {
    with_externalities(&mut new_test_ext(), || {
        
        // Get the owner of an identity
        assert_eq!(DID::identity_owner(&account_key("Alice")),account_key("Alice"));

        // Verify identity owner
        assert_ok!(DID::is_owner(&account_key("Alice"),&account_key("Alice")));

        // Transfer identity ownership
        assert_ok!(DID::change_owner(Origin::signed(account_key("Alice")), account_key("Alice"), account_key("Bob")));

        // Previous owner is invalid
        assert_noop!(DID::is_owner(&account_key("Alice"),&account_key("Alice")),"invalid owner");

        // Verify new owner
        assert_ok!(DID::is_owner(&account_key("Alice"),&account_key("Bob")));

        // Get the new owner of an identity
        assert_eq!(DID::identity_owner(&account_key("Alice")),account_key("Bob"));
    })
}

#[test]
fn attacker_to_transfer_identity_should_fail() {
    with_externalities(&mut new_test_ext(), || {

        // Attacker is not the owner
        assert_eq!(DID::identity_owner(&account_key("Alice")),account_key("Alice"));

        // Transfer identity ownership to attacker
        assert_noop!(DID::change_owner(Origin::signed(account_key("BadBoy")), account_key("Alice"), account_key("BadBoy")),"invalid owner");

        // Attacker is not the owner
        assert_noop!(DID::is_owner(&account_key("Alice"),&account_key("BadBoy")),"invalid owner");

        // Verify that the owner never changed
        assert_eq!(DID::identity_owner(&account_key("Alice")),account_key("Alice"));

    })
}

#[test]
fn owner_is_a_valid_delegate() {
    with_externalities(&mut new_test_ext(), || {

        System::set_block_number(1);

        // Owner is a valid degate for any type and time
        assert_ok!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Alice")));

        System::set_block_number(1000);

        // Owner is a valid degate for any type and time
        assert_ok!(DID::valid_delegate(&account_key("Alice"),&vec![9,9,9],&account_key("Alice")));

        System::set_block_number(2000);

        // Transfer identity ownership to AccountId-2
        assert_ok!(DID::change_owner(Origin::signed(account_key("Alice")), account_key("Alice"), account_key("Bob")));

        // Previous identity owner should be an invalid delegate
        assert_noop!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Alice")),"invalid delegate");

        // New owner is a valid delegate for any type and time
        assert_ok!(DID::valid_delegate(&account_key("Alice"),&vec![8,8,8],&account_key("Bob")));

    })
}

#[test]
fn add_new_delegate() {
    with_externalities(&mut new_test_ext(), || {

        // Should fail to explicity set owner(AccountId-1) in the delegates list
        assert_noop!(DID::add_delegate(Origin::signed(account_key("Alice")),account_key("Alice"),account_key("Alice"),vec![7,7,7],20),"owner cannot be explicity set as delegate");

        // AccountId-5 is an invalid delegate previous to adding it
        assert_noop!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")),"invalid delegate");

        // Add AccountId-5 as delegate of AccountId-1 for a period of 20 blocks
        assert_ok!(DID::add_delegate(Origin::signed(account_key("Alice")),account_key("Alice"),account_key("Tom"),vec![7,7,7],20));

        // AccountId-5 is a valid for a specified type
        assert_ok!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")));

        // AccountId-5 is an invalid delegate for a different type
        assert_noop!(DID::valid_delegate(&account_key("Alice"),&vec![8,8,8],&account_key("Tom")),"invalid delegate");

    })
}

#[test]
fn renew_delegate() {
    with_externalities(&mut new_test_ext(), || {

        System::set_block_number(1);

        // Add AccountId-5 as delegate of AccountId-1 for a period of 3 blocks
        assert_ok!(DID::add_delegate(Origin::signed(account_key("Alice")),account_key("Alice"),account_key("Tom"),vec![7,7,7],3));

        System::set_block_number(3);
        
        // AccountId-5 is a valid specific type delegate
        assert_ok!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")));

        System::set_block_number(4);

        // AccountId-5 is an invalid delegate after expiration
        assert_noop!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")),"invalid delegate");

        // Add AccountId-5 as delegate of AccountId-1 for a period of 3 blocks
        assert_ok!(DID::add_delegate(Origin::signed(account_key("Alice")),account_key("Alice"),account_key("Tom"),vec![7,7,7],3));

        System::set_block_number(6);
        
        // AccountId-5 is a valid specific type delegate
        assert_ok!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")));

    })
}

#[test]
fn identity_delegate_should_expire() {
    with_externalities(&mut new_test_ext(), || {

        System::set_block_number(1);

        // Add AccountId-5 as delegate of AccountId-1 for a period of 3 blocks
        assert_ok!(DID::add_delegate(Origin::signed(account_key("Alice")),account_key("Alice"),account_key("Tom"),vec![7,7,7],3));

        System::set_block_number(3);
        
        // AccountId-5 is a valid specific type delegate
        assert_ok!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")));

        System::set_block_number(4);

        // AccountId-5 is an invalid delegate after expiration
        assert_noop!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")),"invalid delegate");

    })
}

#[test]
fn revoke_identity_delegate() {
    with_externalities(&mut new_test_ext(), || {

        System::set_block_number(1);

        // Add AccountId-5 as delegate of AccountId-1 for a period of 1000 blocks
        assert_ok!(DID::add_delegate(Origin::signed(account_key("Alice")),account_key("Alice"),account_key("Tom"),vec![7,7,7],1000));

        System::set_block_number(50);
        
        // AccountId-5 is a valid specific type delegate
        assert_ok!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")));

        // AccountId-5 is a revoked delegate from AccountId-1
        assert_ok!(DID::revoke_delegate(Origin::signed(account_key("Alice")),account_key("Alice"),vec![7,7,7],account_key("Tom")));

        // Delegate max valid block is current block
        assert_eq!(DID::delegate_of((account_key("Alice"),vec![7,7,7],account_key("Tom"))),Some(50));

        System::set_block_number(51);

        // AccountId-5 is an invalid delegate after revocation
        assert_noop!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")),"invalid delegate");

    })
}

#[test]
fn add_on_chain_attribute() {
    with_externalities(&mut new_test_ext(), || {

        System::set_block_number(1);
        
        // Add a new attribute to an identity. Valid until block 1 + 1000.
        assert_ok!(DID::add_attribute(Origin::signed(account_key("Alice")),account_key("Alice"),vec![1,2,3],vec![7,7,7],1000));

        let (attr, _) = DID::attribute_and_id(&account_key("Alice"), &vec![1,2,3]).unwrap();
        
        // Validate attribute fields.
        assert_eq!(attr.name, vec![1,2,3]);
        assert_eq!(attr.value, vec![7,7,7]);
        assert_eq!(attr.validity, 1000 + System::block_number());
        assert_eq!(attr.creation, Moment::now());
        assert_eq!(attr.nonce, 0);
        
        System::set_block_number(1000);

        // Validate that the attribute exists and has not expired.
        assert_ok!(DID::valid_attribute(&account_key("Alice"),&vec![1,2,3],&vec![7,7,7]));
        
        System::set_block_number(1001);

        // Validate attribute expiration.
        assert_noop!(DID::valid_attribute(&account_key("Alice"),&vec![1,2,3],&vec![7,7,7]),"invalid attribute");

    })
}

#[test]
fn revoke_on_chain_attribute() {
    with_externalities(&mut new_test_ext(), || {

        System::set_block_number(50);
        
        // Add a new attribute to an identity on block 50 for a validity of 50 + 100 blocks
        // Valid until block 150.
        assert_ok!(DID::add_attribute(Origin::signed(account_key("Alice")),account_key("Alice"),vec![1,2,3],vec![7,7,7],100));
        
        System::set_block_number(110);

        // Revoke attribute from an identity by setting its expiration to actual block number.
        assert_ok!(DID::revoke_attribute(Origin::signed(account_key("Alice")),account_key("Alice"),vec![1,2,3]));

        System::set_block_number(111);

        // Attribute should be invalid after revocation. 
        assert_noop!(DID::valid_attribute(&account_key("Alice"),&vec![1,2,3],&vec![7,7,7]),"invalid attribute");
    })
}

#[test]
fn delete_attribute() {
    with_externalities(&mut new_test_ext(), || {

        System::set_block_number(50);

        // Add a new attribute to an identity on block 50 for a validity of 50 + 100 blocks
        // Valid until block 150.
        assert_ok!(DID::add_attribute(Origin::signed(account_key("Alice")),account_key("Alice"),vec![1,2,3],vec![7,7,7],100));
        
        System::set_block_number(110);

        // Delete attribute from identity on block 110.
        assert_ok!(DID::delete_attribute(Origin::signed(account_key("Alice")),account_key("Alice"),vec![1,2,3]));

        System::set_block_number(120);

        // Attribute becomes unavailable.
        assert_noop!(DID::valid_attribute(&account_key("Alice"),&vec![1,2,3],&vec![7,7,7]),"invalid attribute");
    })
}