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
        let bobtc_public = account_key("Bob");
        
        // Fail to validate that Bob signed the message.
        assert_noop!(DID::check_signature(&satoshi_sig, &claim, &bobtc_public),"invalid signer");
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
                    delegate_type.clone(),      // "Sr25519VerificationKey2018"
                    5)                          // valid for 5 blocks
                );


        let claim = data.encode();
        let satoshi_sig = nakamoto_pair.sign(&claim);   // Sign the data with delegate private key.

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

        // Transfer again identity ownership by updating
        assert_ok!(DID::change_owner(Origin::signed(account_key("Bob")), account_key("Alice"), account_key("Tom")));

        // Get the new owner of an identity.
        assert_eq!(DID::identity_owner(&account_key("Alice")),account_key("Tom"));
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

        // Transfer identity ownership to Bob
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

        // Should fail to explicity set owner(Alice) in the delegates list
        assert_noop!(DID::add_delegate(Origin::signed(account_key("Alice")),account_key("Alice"),account_key("Alice"),vec![7,7,7],20),"owner cannot be explicity set as delegate");

        // Tom is an invalid delegate previous to adding it
        assert_noop!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")),"invalid delegate");

        // Add Tom as delegate of Alice for a period of 20 blocks
        assert_ok!(DID::add_delegate(Origin::signed(account_key("Alice")),account_key("Alice"),account_key("Tom"),vec![7,7,7],20));

        // Tom is a valid for a specified type
        assert_ok!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")));

        // Tom is an invalid delegate for a different type
        assert_noop!(DID::valid_delegate(&account_key("Alice"),&vec![8,8,8],&account_key("Tom")),"invalid delegate");

    })
}

#[test]
fn attacker_add_new_delegate_should_fail() {
    with_externalities(&mut new_test_ext(), || {

        // BadBoy is an invalid delegate previous to attack.
        assert_noop!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("BadBoy")),"invalid delegate");

        // Attacker should fail to add delegate.
        assert_noop!(DID::add_delegate(Origin::signed(account_key("BadBoy")),account_key("Alice"),account_key("BadBoy"),vec![7,7,7],20),"invalid owner");

        // BadBoy is an invalid delegate.
        assert_noop!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("BadBoy")),"invalid delegate");

    })
}

#[test]
fn renew_delegate() {
    with_externalities(&mut new_test_ext(), || {

        System::set_block_number(1);

        // Add Tom as delegate of Alice for a period of 3 blocks
        assert_ok!(DID::add_delegate(Origin::signed(account_key("Alice")),account_key("Alice"),account_key("Tom"),vec![7,7,7],3));

        System::set_block_number(3);
        
        // Tom is a valid specific type delegate
        assert_ok!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")));

        System::set_block_number(4);

        // Tom is an invalid delegate after expiration
        assert_noop!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")),"invalid delegate");

        // Add Tom as delegate of Alice for a period of 3 blocks
        assert_ok!(DID::add_delegate(Origin::signed(account_key("Alice")),account_key("Alice"),account_key("Tom"),vec![7,7,7],3));

        System::set_block_number(6);
        
        // Tom is a valid specific type delegate
        assert_ok!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")));

    })
}

#[test]
fn identity_delegate_should_expire() {
    with_externalities(&mut new_test_ext(), || {

        System::set_block_number(1);

        // Add Tom as delegate of Alice for a period of 3 blocks
        assert_ok!(DID::add_delegate(Origin::signed(account_key("Alice")),account_key("Alice"),account_key("Tom"),vec![7,7,7],3));

        System::set_block_number(3);
        
        // Tom is a valid specific type delegate
        assert_ok!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")));

        System::set_block_number(4);

        // Tom is an invalid delegate after expiration
        assert_noop!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")),"invalid delegate");

    })
}

#[test]
fn revoke_identity_delegate() {
    with_externalities(&mut new_test_ext(), || {

        System::set_block_number(1);

        // Add Tom as delegate of Alice for a period of 1000 blocks
        assert_ok!(DID::add_delegate(Origin::signed(account_key("Alice")),account_key("Alice"),account_key("Tom"),vec![7,7,7],1000));

        System::set_block_number(50);
        
        // Tom is a valid specific type delegate
        assert_ok!(DID::valid_delegate(&account_key("Alice"),&vec![7,7,7],&account_key("Tom")));

        // Tom is a revoked delegate from Alice
        assert_ok!(DID::revoke_delegate(Origin::signed(account_key("Alice")),account_key("Alice"),vec![7,7,7],account_key("Tom")));

        // Delegate max valid block is current block
        assert_eq!(DID::delegate_of((account_key("Alice"),vec![7,7,7],account_key("Tom"))),Some(50));

        System::set_block_number(51);

        // Tom is an invalid delegate after revocation
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
fn attacker_add_attribute_should_fail() {
    with_externalities(&mut new_test_ext(), || {

        System::set_block_number(1);
        
        // Attacker tries to add a new attribute to an identity.
        assert_noop!(DID::add_attribute(Origin::signed(account_key("BadBoy")),account_key("Alice"),vec![1,2,3],vec![7,7,7],1000),"invalid owner");
        
        System::set_block_number(2);

        // Validate that the attribute exists and has not expired.
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
fn attacker_revoke_attribute_should_fail() {
    with_externalities(&mut new_test_ext(), || {

        System::set_block_number(50);
        
        // Add a new attribute to an identity on block 50 for a validity of 50 + 100 blocks
        // Valid until block 150.
        assert_ok!(DID::add_attribute(Origin::signed(account_key("Alice")),account_key("Alice"),vec![1,2,3],vec![7,7,7],100));
        
        System::set_block_number(110);

        // Attacker should fail to revoke external attribute.
        assert_noop!(DID::revoke_attribute(Origin::signed(account_key("BadBoy")),account_key("Alice"),vec![1,2,3]),"invalid owner");

        System::set_block_number(111);

        // Attribute should be valid and continue existing. 
        assert_ok!(DID::valid_attribute(&account_key("Alice"),&vec![1,2,3],&vec![7,7,7]));
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

#[test]
fn attacker_delete_attribute_should_fail() {
    with_externalities(&mut new_test_ext(), || {

        System::set_block_number(50);

        // Add a new attribute to an identity on block 50 for a validity of 50 + 100 blocks
        // Valid until block 150.
        assert_ok!(DID::add_attribute(Origin::signed(account_key("Alice")),account_key("Alice"),vec![1,2,3],vec![7,7,7],100));
        
        System::set_block_number(110);

        // Attacker should fail to delete attribute.
        assert_noop!(DID::delete_attribute(Origin::signed(account_key("BadBoy")),account_key("Alice"),vec![1,2,3]),"invalid owner");

        System::set_block_number(120);

        // Attribute still exists.
        assert_ok!(DID::valid_attribute(&account_key("Alice"),&vec![1,2,3],&vec![7,7,7]));
    })
}

#[test]
fn the_never_ending_story() {
    with_externalities(&mut new_test_ext(), || {

        /************************************************************
        IMPORTANT: Any resemblance to reality is purely coincidental.
        ************************************************************/

        /*** HAPPY NEW YEAR!!! The Financial System is Broken! :( ***/
        System::set_block_number(2009);
        
        // A new type of digital money is born.
        let btc_title: Vec<u8> = String::from("Bitcoin: A Peer-to-Peer Electronic Cash System").into();
        let btc_wp: Vec<u8> = String::from("http://www.bitcoin.org/bitcoin.pdf").into();

        let s_nakamoto_pair = account_pair("Nakamoto");
        let s_nakamoto_public = s_nakamoto_pair.public();

        // Sign the Bitcoin White paper.
        let mut btc_claim = btc_title.encode();
        btc_claim.extend(btc_wp.encode());
        let btc_wp_sig = s_nakamoto_pair.sign(&btc_claim);

        // The proof is that S.Nakamoto is ................... S.Nakamoto.
        assert_ok!(DID::valid_signer(&s_nakamoto_public, &btc_wp_sig, &btc_claim, &s_nakamoto_public));




        /*** HAPPY NEW YEAR!!! ***/
        System::set_block_number(2013);

        // Mr. V.Mantequilla publishes a new blockchain idea.
        let eth_wp_title: Vec<u8> = String::from("Next generation smart contract & Decentralized Applications (Dapps) platform").into();
        let eth_wp: Vec<u8> = String::from("https://web.archive.org/web/20131228111141/http:/vbuterin.com/ethereum.html").into();

        let eth_public = account_key("ETH");
        let mut delegate_type: Vec<u8> = String::from("Sr25519VerificationKey2018").into();

        // Create Mr.Mantequilla's key-pair
        let v_mantequilla_pair = account_pair("Mantequilla");
        let v_mantequilla_public = v_mantequilla_pair.public();

        // Mr. Mantequilla becomes an ETH contributor.
        assert_ok!(DID::add_delegate(Origin::signed(v_mantequilla_public.clone()),v_mantequilla_public.clone(),eth_public.clone(),delegate_type.clone(),1000));

        // Encode and sign the Ethereum white paper.
        let mut eth_wp_claim = eth_wp_title.encode();
        eth_wp_claim.extend(eth_wp.encode());
        let eth_wp_sig = v_mantequilla_pair.sign(&eth_wp_claim);



        /*** HAPPY NEW YEAR!!! ***/
        System::set_block_number(2014);

        // Dr. G.Madera joins Mr. V.Mantequilla and writes al the technical specifications.
        let eth_yp_title: Vec<u8> = String::from("Ethereum: A Secure Decentralised Generalised Transaction Ledger").into();
        let eth_yp: Vec<u8> = String::from("https://web.archive.org/web/20140410013339/http:/gavwood.com/paper.pdf").into();

        // Create Dr. G.Madera's key-pair
        let g_madera_pair = account_pair("Madera");
        let g_madera_public = g_madera_pair.public();

        // Dr. G.Madera becomes an ETH contributor.
        assert_ok!(DID::add_delegate(Origin::signed(g_madera_public.clone()),g_madera_public.clone(),eth_public.clone(),delegate_type.clone(),1000));

        // Encode and sign the Ethereum yellow paper.
        let mut eth_yp_claim = eth_yp_title.encode();
        eth_yp_claim.extend(eth_yp.encode());
        let eth_yp_sig = g_madera_pair.sign(&eth_yp_claim);

        // Ethereum launches !!!
        let eth_address: Vec<u8> = String::from("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3").into();
        let eth_claim = eth_address.encode();
        // Ethereum delegates
        assert_ok!(DID::add_delegate(Origin::signed(eth_public.clone()),eth_public.clone(),g_madera_public.clone(),delegate_type.clone(),1000));
        assert_ok!(DID::add_delegate(Origin::signed(eth_public.clone()),eth_public.clone(),v_mantequilla_public.clone(),delegate_type.clone(),1000));
        // Sign as Ethereum delegate
        let v_eth_sig = v_mantequilla_pair.sign(&eth_claim);
        let g_eth_sig = g_madera_pair.sign(&eth_claim);

        // Mr. V.Mantequilla wrote the White paper.
        assert_ok!(DID::valid_signer(&v_mantequilla_public, &eth_wp_sig, &eth_wp_claim, &v_mantequilla_public));

        // Dr. G.Madera wrote the Yellow paper.
        assert_ok!(DID::valid_signer(&g_madera_public, &eth_yp_sig, &eth_yp_claim, &g_madera_public));

        // Dr. G.Madera proof as Ethereum Co-founder
        assert_ok!(DID::valid_signer(&eth_public, &g_eth_sig, &eth_claim, &g_madera_public));

        // Mr. V.Mantequilla proof as Ethereum Co-founder
        assert_ok!(DID::valid_signer(&eth_public, &v_eth_sig, &eth_claim, &v_mantequilla_public));

        // Dr. C.Derecha tries to cheat, but cannot prove being part of Ethereum launch.
        assert_ok!(DID::add_delegate(Origin::signed(account_key("Derecha")),account_key("Derecha").clone(),eth_public.clone(),delegate_type.clone(),1000));
        assert_noop!(DID::valid_signer(&eth_public, &v_eth_sig, &eth_claim, &account_key("Derecha")),"invalid delegate");


        // HAPPY NEW YEAR!!!
        System::set_block_number(2015);

        // Dr. C.Derecha says he is S.Nakamoto.
        let c_msg: Vec<u8> = String::from("I am S.Nakamoto").into();
        let c_derecha_pair = account_pair("Derecha");
        let c_derecha_public = c_derecha_pair.public();
        let c_sig = g_madera_pair.sign(&c_msg.encode());

        // Fail to prove that C.Derecha is S.Nakamoto.
        assert_noop!(DID::valid_signer(&s_nakamoto_public, &c_sig, &c_msg, &c_derecha_public),"invalid delegate");



        /*** HAPPY NEW YEAR!!! ***/
        System::set_block_number(2016);

        // Fail to prove that C.Derecha is S.Nakamoto.
        assert_noop!(DID::valid_signer(&s_nakamoto_public, &c_sig, &c_msg, &c_derecha_public),"invalid delegate");



        /*** HAPPY NEW YEAR!!! ***/
        System::set_block_number(2017);

        // Fail to prove that C.Derecha is S.Nakamoto.
        assert_noop!(DID::valid_signer(&s_nakamoto_public, &c_sig, &c_msg, &c_derecha_public),"invalid delegate");

        // Dr. G.Madera finds an interconnectivity issues on the existing blockchains.
        let p_dots: Vec<u8> = String::from("I want to start building an inter-galactic blockchain with many dots").into();
        let p_claim = p_dots.encode();

        // Create Roberto's key-pair
        let r_pair = account_pair("Roberto");
        let r_public = r_pair.public();
        let r_sig = r_pair.sign(&p_claim);
        delegate_type = String::from("Inter-Galactic").into();

        // Dr. G.Madera will delegate some Inter-Galactic tasks to Roberto.
        assert_ok!(DID::add_delegate(Origin::signed(g_madera_public.clone()),g_madera_public.clone(),r_public.clone(),delegate_type.clone(),1000));



        /*** HAPPY NEW YEAR!!! ***/
        System::set_block_number(2018);

        // Fail to prove that C.Derecha is S.Nakamoto.
        assert_noop!(DID::valid_signer(&s_nakamoto_public, &c_sig, &c_msg, &c_derecha_public),"invalid delegate");



        /*** HAPPY NEW YEAR!!! ***/
        System::set_block_number(2019);

        // Fail to prove that C.Derecha is S.Nakamoto.
        assert_noop!(DID::valid_signer(&s_nakamoto_public, &c_sig, &c_msg, &c_derecha_public),"invalid delegate");



        /*** The inter-galactic chain with many dots launches succesfully !!! ***/

        // Roberto is a valid Inter-Galactic delegate for Dr. G.Madera.
        assert_ok!(DID::valid_delegate(&g_madera_public,&delegate_type,&r_public));

        // Dr. G.Madera and Roberto are P Dots Co-founders
        assert_ok!(DID::check_signature(&r_sig, &p_claim, &r_public));




        /**************************************
        Uncomment the next lines for next year.
        **************************************/

        // /*** HAPPY NEW YEAR!!! ***/
        // System::set_block_number(2020);

        // // Fail to prove that C.Derecha is S.Nakamoto.
        // assert_noop!(DID::valid_signer(&s_nakamoto_public, &c_sig, &c_msg, &c_derecha_public),"invalid delegate");


        /****************
         TO BE CONTINUED
        ****************/

    })
}