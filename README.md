## MetaMerkles - Smart contract ingestable metadata on groups of practically any size

WIP Tealscript Contracts for putting Merkle roots on chain & allowing other contracts to verify & fetch metadata against those merkle roots.

## How does this work?

Merkle trees give us a `log2(n)` (very efficient) method of verifying whether a hash is part of a group.

We use these inside smart contracts to create arbitrarily large groups that are quickly verifiable.

We then attach metadata key-value pairs to the merkle root prefixed by the creators address so at any given time onchain, in any contract we can call the `MetaMerkles` contract to fetch metadata about a specific group, whether thats Assets, Addresses or Apps.

## Potential use cases
- contract enforced royalties
- whitelists & blacklists of addresses
- anything that needs to verify large lists of assetIDs | addresses | appIDs

## ARC58 smart wallet specific use cases
- Arbitrary groups for plugins with a single box key ( apps & addresses )
- Bartering - eg. i offer you 160 cheap assets for your 25 rarer ones
