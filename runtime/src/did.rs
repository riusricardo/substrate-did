use parity_codec::{Decode, Encode};
use rstd::prelude::*;
use runtime_primitives::traits::{As, Hash, Zero};
use runtime_primitives::transaction_validity::TransactionValidity;
use runtime_primitives::{create_runtime_str, generic, ApplyResult};
use support::{
    decl_event, decl_module, decl_storage, dispatch::Result, ensure, Parameter, StorageMap,
};
use system::{self, ensure_signed};
use timestamp::Call as TimestampCall;

pub trait Trait: system::Trait + timestamp::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_storage! {
    trait Store for Module<T: Trait> as DID {
        pub Delegates get(delegate_of): map (T::AccountId, Vec<u8>, T::AccountId) => Option<T::Moment>;
        pub Owners get(owner_of): map T::AccountId => Option<T::AccountId>;
        pub Changed get(changed_on): map T::AccountId => T::BlockNumber;
        pub Nonce get(nonce_of): map T::AccountId => u64;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        // initialize the default event for this module
        fn deposit_event<T>() = default;

        pub fn change_owner(origin, identity: T::AccountId, actor: T::AccountId, new_owner: T::AccountId) {
                let who = ensure_signed(origin)?;
                ensure!(who == actor, "invalid actor");
                ensure!(Self::_is_owner(identity.clone(), actor.clone()), "you do not own this DID");
                let now_block = <system::Module<T>>::block_number();
                <Owners<T>>::insert(&identity, &new_owner);
                <Changed<T>>::insert(&identity, &now_block);
                Self::deposit_event(RawEvent::DIDOwnerChanged(identity, actor, now_block));
        }

        pub fn add_delegate(origin, identity: T::AccountId, delegate: T::AccountId, delegate_type: Vec<u8>, valid_for: T::Moment)  {
                let who = ensure_signed(origin)?;
                ensure!(delegate_type.len() <= 64, "delegate type cannot exceed 64 bytes");
                ensure!(Self::_is_owner(identity.clone(), who.clone()), "you do not own this DID");
                let now_time = <timestamp::Module<T>>::now();
                let validity = now_time + valid_for.clone();
                <Delegates<T>>::insert((identity.clone(), delegate_type.clone(), delegate.clone()), validity.clone());
                Self::deposit_event(RawEvent::DIDDelegateChanged(identity, delegate_type, delegate, validity, valid_for));
        }

        pub fn revoke_delegate(origin, identity: T::AccountId, delegate_type: Vec<u8>, delegate: T::AccountId) {
                let who = ensure_signed(origin)?;
                ensure!(delegate_type.len() <= 64, "delegate type cannot exceed 64 bytes");
                ensure!(Self::_is_owner(identity.clone(), who.clone()), "you do not own this DID");
                ensure!(Self::_is_valid_delegate(identity.clone(), delegate_type.clone(), delegate.clone()), "invalid delegate");
                let now_time = <timestamp::Module<T>>::now();
                let now_block = <system::Module<T>>::block_number();
                <Delegates<T>>::insert((identity.clone(), delegate_type.clone(), delegate.clone()), now_time.clone());
                <Changed<T>>::insert(&identity, now_block);
                Self::deposit_event(RawEvent::RevokedDelegate(identity, delegate_type, delegate));
        }

        pub fn valid_delegate(identity: T::AccountId, delegate_type: Vec<u8>, delegate: T::AccountId) -> Result {
                ensure!(delegate_type.len() <= 64, "delegate type cannot exceed 64 bytes");
                ensure!(Self::_is_valid_delegate(identity.clone(), delegate_type.clone(), delegate.clone()),"Invalid delegate");
                Ok(())
        }
    }
}

decl_event!(
  pub enum Event<T>
  where
  <T as system::Trait>::AccountId,
  <T as system::Trait>::BlockNumber,
  <T as timestamp::Trait>::Moment
  //<T as system::Trait>::Hash
  {
    RevokedDelegate(AccountId, Vec<u8>, AccountId),
    DIDOwnerChanged(AccountId, AccountId, BlockNumber),
    DIDDelegateChanged(AccountId, Vec<u8>, AccountId, Moment, Moment),
    DIDValidDelegate(AccountId, Vec<u8>, AccountId, Moment, Moment),
  }
);

impl<T: Trait> Module<T> {

    fn _identity_owner(identity: &T::AccountId) -> T::AccountId {
        let owner = match Self::owner_of(identity) {
            Some(id) => id,
            None => identity.clone(),
        };
        owner
    }

    fn _is_owner(identity: T::AccountId, actor: T::AccountId) -> bool {
        let owner = Self::_identity_owner(&identity);
        let approved_as_owner = match owner {
            actor => true,
            _ => false
        };
        approved_as_owner
    }

    fn _is_valid_delegate(identity: T::AccountId, delegate_type: Vec<u8>, delegate: T::AccountId) -> bool {
        let now_time = <timestamp::Module<T>>::now();
        let validity = Self::delegate_of((identity.clone(), delegate_type.clone(), delegate.clone()));
        let valid = match validity {
            Some(val) => val > now_time,
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
	use primitives::{H256, Blake2Hasher};
	use support::{impl_outer_origin, assert_ok};
	use runtime_primitives::{
		BuildStorage,
		traits::{BlakeTwo256, IdentityLookup},
		testing::{Digest, DigestItem, Header}
	};

	impl_outer_origin! {
		pub enum Origin for DIDTest {}
	}

	// For testing the module, we construct most of a mock runtime. This means
	// first constructing a configuration type (`DIDTest`) which `impl`s each of the
	// configuration traits of modules we want to use.
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
	impl Trait for DIDTest {
		type Event = ();
	}
	type DID = Module<Test>;

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
