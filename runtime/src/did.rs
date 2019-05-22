use parity_codec::{Decode, Encode};
use rstd::prelude::*;
use runtime_primitives::traits::{As, Hash, Zero};
use support::{
    decl_event, decl_module, decl_storage, dispatch::Result, ensure, Parameter, StorageMap,
};
use system::{self, ensure_signed};

pub trait Trait: system::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_storage! {
    trait Store for Module<T: Trait> as DID {
        pub Delegates get(delegate_of): map (T::AccountId, Vec<u8>, T::AccountId) => T::BlockNumber;
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
                let now = <system::Module<T>>::block_number();
                <Owners<T>>::insert(&identity, &new_owner);
                <Changed<T>>::insert(&identity, &now);
                Self::deposit_event(RawEvent::DIDOwnerChanged(identity, actor, now));
        }

        pub fn add_delegate(origin, identity: T::AccountId, delegate: T::AccountId, delegate_type: Vec<u8>, valid_for: T::BlockNumber)  {
                let who = ensure_signed(origin)?;
                ensure!(Self::_is_owner(identity.clone(), who.clone()), "you do not own this DID");
                ensure!(delegate_type.len() <= 64, "delegate type cannot exceed 64 bytes");
                let now = <system::Module<T>>::block_number();
                let validity = now + valid_for.clone();
                <Delegates<T>>::insert((identity.clone(), delegate_type.clone(), delegate.clone()), validity);
                Self::deposit_event(RawEvent::DIDDelegateChanged(identity, delegate_type, delegate, validity, valid_for));
        }

        pub fn revoke_delegate(origin, identity: T::AccountId, delegate_type: Vec<u8>, delegate: T::AccountId) {
                let who = ensure_signed(origin)?;
                ensure!(Self::_is_owner(identity.clone(), who.clone()), "you do not own this DID");
                ensure!(delegate_type.len() <= 64, "delegate type cannot exceed 64 bytes");
                let now = <system::Module<T>>::block_number();
                <Delegates<T>>::insert((identity.clone(), delegate_type.clone(), delegate.clone()), now.clone());
                <Changed<T>>::insert(&identity, now);
                Self::deposit_event(RawEvent::RevokedDelegate(identity, delegate_type, delegate));
        }

        pub fn valid_delegate(identity: T::AccountId, delegate_type: Vec<u8>, delegate: T::AccountId) -> Result {
                ensure!(delegate_type.len() <= 64, "delegate type cannot exceed 64 bytes");
                let now = <system::Module<T>>::block_number();
                let validity = Self::delegate_of((identity.clone(), delegate_type.clone(), delegate.clone()));
                if validity > now {
                    Ok(())
                } else{
                    Err("invalid delegate")
                }
        }
    }
}

decl_event!(
  pub enum Event<T>
  where
  <T as system::Trait>::AccountId,
  <T as system::Trait>::BlockNumber,
  //<T as system::Trait>::Hash
  {
    RevokedDelegate(AccountId, Vec<u8>, AccountId),
    DIDOwnerChanged(AccountId,AccountId,BlockNumber),
    DIDDelegateChanged(AccountId,Vec<u8>,AccountId,BlockNumber,BlockNumber),
  }
);

impl<T: Trait> Module<T> {
    
    fn _is_owner(identity: T::AccountId, actor: T::AccountId) -> bool {
        let mut approved_as_owner = false;
        let owner = match Self::owner_of(&identity) {
            Some(id) => id,
            None => identity.clone(),
        };
        if owner == actor {
            approved_as_owner = true;
        } else {
            approved_as_owner = false;
        }
        approved_as_owner
    }

    // pub fn identity_owner(identity: T::AccountId) => T::AccountId {
    // 	let owner = Self::owner_of(identity);
    // 	if (<Owners<T>>::exists(&identity)) {
    // 		return owner
    // 	}
    // 	return identity
    // }
}
