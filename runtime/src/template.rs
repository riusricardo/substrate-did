use rstd::prelude::*;
use parity_codec::{Encode, Decode};
use support::{dispatch::Result, Parameter, StorageMap, decl_storage, decl_module, decl_event, ensure};
use runtime_primitives::traits::{As, Hash, Zero};
use system::{self, ensure_signed};

pub trait Trait: system::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

decl_storage! {
	trait Store for Module<T: Trait> as TemplateModule {
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

		// /* Cannot return AccountId */
		// pub fn identity_owner(identity: T::AccountId) => T::AccountId {
		// 	let owner = Self::owner_of(identity);
		// 	if (<Owners<T>>::exists(&identity)) {
		// 		return owner
		// 	} 
		// 	return identity
		// } 

		pub fn add_delegate(origin, to: T::AccountId, valid_to: T::BlockNumber, delegate_type: Vec<u8>)  {
			let who = ensure_signed(origin)?;
			ensure!(delegate_type.len() <= 64, "delegate type cannot exceed 64 bytes");
			let now = <system::Module<T>>::block_number();
			let validity = now + valid_to.clone();
			<Delegates<T>>::insert((who.clone(), delegate_type.clone(), to.clone()), validity);
			Self::deposit_event(RawEvent::DIDDelegateChanged(who, delegate_type, to, validity, valid_to));
		}

		pub fn revoke_delegate(origin, to: T::AccountId, delegate_type: Vec<u8>) {
			let who = ensure_signed(origin)?;
			ensure!(Self::_is_owner(who.clone()), "You do not own this DID");
			ensure!(delegate_type.len() <= 64, "delegate type cannot exceed 64 bytes");
			let now = <system::Module<T>>::block_number();
			<Delegates<T>>::insert((who.clone(), delegate_type.clone(), to.clone()), now.clone());
			<Changed<T>>::insert(who.clone(), now);
			Self::deposit_event(RawEvent::RevokedDelegate(who, delegate_type, to));
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

	fn _is_owner(identity: T::AccountId) -> bool {
		let mut approved_as_owner = false;
		let owner = match Self::owner_of(&identity) {
			Some(id) => id,
			None => identity.clone(),
		};
		if owner == identity {
			approved_as_owner = true;
		}
		return approved_as_owner
	}
}