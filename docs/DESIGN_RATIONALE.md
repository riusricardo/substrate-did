The DID Runtime Module is based on ERC-1056. This design is a beneficial way of handling identities.
In general terms, the registry works as a type of non-fungible token. The owner of an identity is always itself until the ownership is transferred to another account.

An identity can have delegates to handle some specific tasks on their behalf. A Delegate is not able to represent  an identity in every aspect; it is constrained to a specific task.

Another aspect is the usage of attributes, which are an extension to an identity. It can contain specific public data that should not impact the identity if it remains always available. An example of this could be a service point or provider where an external service can get in touch for a defined action with the DID.

A difference between the ERC-1056 and the SRML-DID is on the technique used to store attributes. On the ERC-1056 the way the data is stored is by exploiting the advantage of using very cheap storage on the bloom filter logs used on the Ethereum events.
This is an interesting decision however, it brings the problem of data pruning and losing access to the attributes on light clients and non-full nodes.
This is not a requirement on an SRML because we can set a specific storage fee for attributes, which makes a lot of sense, and we can find the adequate balance of paying for cheap storage.

The ability to sign off-chain transactions and adding attributes is a convenient way of interacting with SRMs. 

Some of the things that I would want to explore is the integration of a DID into the democracy module. The Democracy module has a defined type of delegates so as an upgrade I would look to make usage of more standard properties for better inter-module communication. Also, align the off-chain transactions with the existing work on the off-chain workers.