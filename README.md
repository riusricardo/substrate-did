# The Missing Piece

Your data and identity are your most important assets. Blockchain is the missing component that enables trust in relationships without the need for an intermediary identity provider. This is a new era of trust where establishing, proving, verifying and controlling identity are decentralized.

**“ Everyone shall have the right to recognition everywhere as a person before the law. ”**
-- Article 6 of the Universal Declaration of Human Rights

**“ More than 1.1 billion people in the world are unable to prove their identity and therefore lack access to vital services, including healthcare, social protection, education, and finance. ”** -- World Bank, 2017

For those who have a digital presence, it remains rooted in usernames and passwords. The infromation is often isolated and siloed by enterprises to profit from it. The more siloed and numerous our digital identifiers become, the less control we have over them. You may have a digital identity, but you probably don’t have control over it.

Personal information is regularly shared without awareness and becomes a centralized source of sensitive data for hackers.
A Google report found that 3.3 billion credentials were stolen during third-party breaches, and 12 million were stolen via phishing attacks. In other words, the system is broken.
Compliance and regulations, such as the GDPR in Europe, are also driving change for new solutions.


## Self-sovereign Identity

A decentralized identity or self-sovereign identity is a new approach where no one but you owns or controls the state of your digital identity. 

Some of the inherited benefits from this identities are:

* Identity Verification
* Non-Custodial Login Solutions
* Stronger Protections for Critical Infrastructure
* Securing the Internet of Things

A digital identity should always be portable, persistent, privacy-protecting, and personal.

# DID

_Decentralized Identifiers (DIDs) are a new type of identifier for verifiable, "self-sovereign" digital identity. DIDs are fully under the control of the DID subject, independent from any centralized registry, identity provider, or certificate authority. DIDs are URLs that relate a DID subject to means for trustable interactions with that subject. DIDs resolve to DID Documents — simple documents that describe how to use that specific DID. Each DID Document may contain at least three things: proof purposes, verification methods, and service endpoints. Proof purposes are combined with verification methods to provide mechanisms for proving things. For example, a DID Document can specify that a particular verification method, such as a cryptographic public key or pseudonymous biometric protocol, can be used to verify a proof that was created for the purpose of authentication. Service endpoints enable trusted interactions with the DID controller._  -  [DID - W3C Community Contributor](https://w3c-ccg.github.io/did-spec/)

## DID Runtime Module

## DID Document Examples:
### Substrate
``` JSON
{  
   "@context":"https://w3id.org/did/v1",
   "id":"did:substrate:5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX",
   "publicKeys":[  
      {  
         "id":"did:substrate:5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX#owner",
         "owner":"did:substrate:5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX",
         "type":"Secp256k1VerificationKey2018",
         "publicKeyHex":"e43a60dbfc251a3a835b45b172bcb49243ed56f820ca89a1c746143c1ab9565d",
         "address":"5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX"
      },
      {  
         "id":"did:substrate:5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX#signingKey#delegate-1",
         "type":"Sr25519VerificationKey2018",
         "publicKeyHex":"dea36bf1a0c198afd259633c2e70b502b19577cc5133760ac569ea6fb4d3b977",
         "address":"5H6d2vR8iqQRANBe7bNegFbEiEJgeCKid4VhS3Pg52VUEqeM"
      },
      {
         "id": "did:substrate:5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX#delegate-2",
         "type": "RSAVerificationKey2018",
         "owner": "did:substrate:5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX",
         "publicKeyPem": "-----BEGIN PUBLIC KEY...END PUBLIC KEY-----\r\n",
      }
   ],
   "service": [
      { 
         "id": "did:substrate:5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX#openid",
         "serviceEndpoint":"https://openid.example.com/",
         "type":"OpenIdConnectVersion1.0Service"
      }
   ],
   "authentication":[
      {  
         "type":"Secp256k1SignatureAuthentication2018",
         "publicKey":"did:substrate:5HDx7jPsiED6n47eNfERrBBRHZb59jVW6UMZZMTSBpikzvhX#owner",
      }
   ],
   "updated":"2019-06-03T06:41:39.723Z"
}
```


### uPort
``` JSON
{  
   "@context":"https://w3id.org/did/v1",
   "id":"did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
   "publicKey":[  
      {  
         "id":"did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#owner",
         "type":"Secp256k1VerificationKey2018",
         "owner":"did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
         "ethereumAddress":"0xb9c5714089478a327f09197987f16f9e5d936e8a"
      }
   ],
   "authentication":[  
      {  
         "type":"Secp256k1SignatureAuthentication2018",
         "publicKey":"did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#owner"
      }
   ]
}
```

### 3Box
``` JSON
{  
   "@context":"https://w3id.org/did/v1",
   "id":"did:3:zdpuAt4qH8ur3vHpVrP1xb7rtJuyVUVbRiGatkkVcJZRgAXDf",
   "publicKeys":[  
      {  
         "id":"did:3:zdpuAt4qH8ur3vHpVrP1xb7rtJuyVUVbRiGatkkVcJZRgAXDf#signingKey",
         "type":"Secp256k1VerificationKey2018",
         "publicKeyHex":"03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479"
      },
      {  
         "id":"did:3:zdpuAt4qH8ur3vHpVrP1xb7rtJuyVUVbRiGatkkVcJZRgAXDf#encryptionKey",
         "type":"Curve25519EncryptionPublicKey",
         "publicKeyBase64":"AtF8hCxh9h1zlExuOZutuw+tRzmk3zVdfA=="
      },
      {  
         "id":"did:3:zdpuAt4qH8ur3vHpVrP1xb7rtJuyVUVbRiGatkkVcJZRgAXDf#managementKey",
         "type":"Secp256k1VerificationKey2018",
         "ethereumAddress":"0xb9c5714089478a327f09197987f16f9e5d936e8a"
      }
   ],
   "authentication":[  
      {  
         "type":"Secp256k1SignatureAuthentication2018",
         "publicKey":"did:3:zdpuAt4qH8ur3vHpVrP1xb7rtJuyVUVbRiGatkkVcJZRgAXDf#signingKey"
      }
   ]
}
```

# Build

Install Rust:

```bash
curl https://sh.rustup.rs -sSf | sh
```

Install required tools:

```bash
./scripts/init.sh
```

Build the WebAssembly binary:

```bash
./scripts/build.sh
```

Build all native code:

```bash
cargo build --release
```
# Test

Execute module tests:

```bash
cargo test -p identitychain-runtime
```
# Run

You can start a development chain with:

```bash
cargo run -- --dev
```

Detailed logs may be shown by running the node with the following environment variables set: `RUST_LOG=debug RUST_BACKTRACE=1 cargo run -- --dev`.

Additional CLI usage options are available and may be shown by running `cargo run -- --help`.
