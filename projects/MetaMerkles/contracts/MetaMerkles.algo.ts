import { Contract } from '@algorandfoundation/tealscript';

const hashLength = 32;
const rootKeyLength = 64;
const truncatedKeyLength = 32;
const schemaKeyByteLength = 11;
const listTypeKeyByteLength = 9;
const uint64ByteLength = 8;

const rootMinBalance: uint64 = 2_500 + (400 * rootKeyLength);
const schemaMinBalance: uint64 = 2_500 + (400 * ((truncatedKeyLength + schemaKeyByteLength) + uint64ByteLength));
const listTypeMinBalance: uint64 = 2_500 + (400 * ((truncatedKeyLength + listTypeKeyByteLength) + uint64ByteLength));

type bytes16 = StaticArray<byte, 16>;

interface RootKey { address: Address, root: bytes32 };

interface DataKey { address: bytes16, root: bytes16, key: string };

/**
 * 
 * Schema's are onchain convenience indicators about the
 * underlying structure of the data hashes they can
 * help ensure consumers of contracts are given
 * the proper structure to create leaf hashes for a given tree
*/ 

// TODO: replace with enum when tealscript supports it

/** 
 * Unspecified is a special value that, on verified reads, specifies the caller doesnt care what the schema is
 * this value should not be used when adding merkle roots to the contract
*/
export const SchemaTypeUnspecified = 0;

/**
 * Hashes are byte strings
 * 
 * eg. a 32byte address
 */
export const SchemaTypeString = 1;

/**
 * Hashes are uint64's that represent something like asa IDs or app IDs
 * 
 * eg. 00000000
 */
export const SchemaTypeUint64 = 2;

/**
 * Hashes are double uint64's, first 8 bytes represent something like an asa ID, latter 8 represent something like an amount
 * 
 * eg. 0000000000000000
 */
export const SchemaTypeDoubleUint64 = 3;

/**
 * List Types are required metadata for roots
 * that inform other contracts about the intended use
 * of the list when metadata is being consumed.
 * List types are necessary because creators will have
 * many arbitrary & overlapping groups depending on
 * their personal needs, because an asset could be 
 * included in a number of lists for any given reason
 * we need a way to ensure that the root & proof that 
 * are provided to a contract that utilizes `MetaMerkles`
 * can also verify that the list is being used for its 
 * intended purpose.
 * 
 * eg. without list types, if a creator had their collection
 * traits on chain, rather than submitting the proper merkle
 * tree root & proof with the given meta key `royalties`
 * a malicious actor could submit the root & proof for an 
 * adjacent group whose purpose is trait declaration.
 * The calling contract would then be unable to find a `royalties` 
 * value and thus would settle for some default value or zero.
 */

// TODO: replace with enum when tealscript supports it

// Unspecified is a special value that, on verified reads, specifies the caller doesnt care what the list type is
// this value should not be used when adding merkle roots to the contract
export const ListTypeUnspecified = 0;
// Collection list types represent a collection of asset IDs onchain
export const ListTypeCollection = 1;
// Trait list types represent a collection of asset IDs 
export const ListTypeTrait = 2;
// A list created for the sole purpose of setting up a merkle tree based asset swap
export const ListTypeTrade = 3

export class MetaMerkles extends Contract {

  // the max size of all args to a contract is 2048
  // which means accounting for box key & leaf
  // and a byte length of 66 for each proof in the
  // array, max we can verify is 30, plenty.
  roots = BoxMap<RootKey, StaticArray<byte, 0>>();

  // rootData is the box map for managing the data
  // associated with a group
  data = BoxMap<DataKey, string>();

  /** 
   * Creates two boxes and adds a merkle root
   * using a `RootKey` to the root box map and also a list type to the 
   * metadata attached to the root in the data box map
   * 
   * @param pmt the fee to cover box storage allocation
   * @param hashedRoot a sha256'd 32 byte merkle tree root
   * @param type an index of the `RootType` enum of the type of the list
   */
  addRoot(pmt: PayTxn, hashedRoot: bytes32, schema: uint64, listType: uint64): void {
    const key: RootKey = { address: this.txn.sender, root: hashedRoot };
    const schemaKey: DataKey = this.getDataKey(this.txn.sender, hashedRoot, 'list.schema');
    const listTypeKey: DataKey = this.getDataKey(this.txn.sender, hashedRoot, 'list.type');

    assert(!this.roots(key).exists)
    assert(!this.data(schemaKey).exists)
    assert(!this.data(listTypeKey).exists)

    verifyPayTxn(pmt, {
      receiver: this.app.address,
      amount: rootMinBalance + schemaMinBalance + listTypeMinBalance,
    })

    this.roots(key).create(0);
    this.data(schemaKey).value = itob(schema);
    this.data(listTypeKey).value = itob(listType);
  }

  /**
   * Deletes the merkle root from the root box map
   * 
   * @param hashedRoot the sha256'd 32 byte merkle tree root
   */
  deleteRoot(hashedRoot: bytes32): void {
    const key: RootKey = { address: this.txn.sender, root: hashedRoot };
    assert(this.roots(key).exists)
    this.roots(key).delete();

    // return their MBR
    sendPayment({
      receiver: this.txn.sender,
      amount: rootMinBalance,
    })
  }

  /**
   * Registers a key & value in the data box map that
   * corresponds to a merkle root in the root box map
   * 
   * @param pmt the payment to cover the increased mbr of adding to box storage
   * @param hashedRoot the sha256'd 32 byte merkle tree root
   * @param key the metadata key eg. `Royalty`
   * @param value the metadata value eg. `5` encoded as a bytestring for 5%
   */
  addData(pmt: PayTxn, hashedRoot: bytes32, key: string, value: string): void {
    const rootKey: RootKey = { address: this.txn.sender, root: hashedRoot };

    assert(key.length <= 32, 'key length maximum is 32 bytes');
    assert(value.length <= 2048, 'max box size is 1KB')
    assert(this.roots(rootKey).exists, 'there must be a root to associate the data to');

    verifyPayTxn(pmt, {
      receiver: this.app.address,
      amount: this.getBoxCreateMinBalance(32 + key.length, value.length),
    });

    const dataKey: DataKey = this.getDataKey(this.txn.sender, hashedRoot, key);

    this.data(dataKey).value = value;
  }

  /**
   * Deletes a metadata key & value pair from the data box map
   * 
   * @param hashedRoot the sha256'd 32 byte merkle tree root
   * @param key the metadata key you want to remove
   */
  deleteData(hashedRoot: bytes32, key: string): void {
    const dataKey: DataKey = this.getDataKey(this.txn.sender, hashedRoot, key);

    assert(this.data(dataKey).exists);

    let valueLength = this.data(dataKey).value.length;

    this.data(dataKey).delete();

    sendPayment({
      receiver: this.txn.sender,
      amount: this.getBoxCreateMinBalance(32 + key.length, valueLength),
    })
  }

  /**
   * verify an inclusion in a merkle tree
   * 
   * @param address the address of the merkle tree root creator
   * @param hashedRoot the sha256'd 32 byte merkle tree root
   * @param proof the proof the hash is included
   * @param data the data being verified
   * @returns a boolean indicating the check passed or failed
   */
  verify(address: Address, hashedRoot: bytes32, proof: string, data: string): boolean {
    const rootKey: RootKey = { address: address, root: hashedRoot };
    assert(this.roots(rootKey).exists);

    let hash = sha256(data) as string;
    for (let i = 0; i < proof.length; i + hashLength) {
      hash = this.hash(hash, extract3(proof, i, hashLength))
    }

    return hashedRoot === sha256(hash);
  }

  /**
   * Fetch a metadata property
   * 
   * @param address the address of the merkle tree root creator
   * @param hashedRoot the sha256'd 32 byte merkle tree root
   * @param key the metadata key eg. `Royalty`
   * @returns the value set eg. `5` encoded as a bytestring for 5%
   */
  read(address: Address, hashedRoot: bytes32, key: string): string {
    const dataKey: DataKey = this.getDataKey(address, hashedRoot, key);
    assert(this.data(dataKey).exists)
    return this.data(dataKey).value
  }

  /**
   * Read metadata from box storage and verify the data provided is included
   * in the merkle tree given a sha256'd 32 byte merkle tree root & a proof
   * thats pre-computed off chain.
   * 
   * verify an inclusion in a merkle tree 
   * & read an associated key value pair
   * & check against the underlying data's schema
   * & check against the underlying data's list type or purpose
   * 
   * @param address the address of the merkle tree root creator
   * @param hashedRoot the sha256'd 32 byte merkle tree root
   * @param proof the proof the hash is included
   * @param data the data being verified
   * @param key the metadata key eg. `Royalty`
   * @param schema the schema to verify the underlying data shape ( 0 if the caller doesnt care )
   * @param listType the list type that helps contracts ensure 
   * the lists purpose isn't being misused ( 0 if the caller doesnt care )
   * @returns a boolean indicating the check passed or failed
   */
  verifiedRead(
    address: Address,
    hashedRoot: bytes32,
    proof: string,
    data: string,
    key: string,
    schema: uint64,
    listType: uint64,
  ): string {
    assert(this.verify(address, hashedRoot, proof, data), 'failed to verify inclusion')
    if (schema !== 0) assert(this.getListSchema(address, hashedRoot) === schema)
    if (listType !== 0) assert(this.getListType(address, hashedRoot) === listType)

    return this.read(address, hashedRoot, key);
  }
  
  private getListSchema(address: Address, hashedRoot: bytes32): uint64 {
    const schemaKey: DataKey = this.getDataKey(address, hashedRoot, 'list.schema');
    assert(this.data(schemaKey).exists)
    return btoi(this.data(schemaKey).value)
  }

  private getListType(address: Address, hashedRoot: bytes32): uint64 {
    const listTypeKey: DataKey = this.getDataKey(address, hashedRoot, 'list.type');
    assert(this.data(listTypeKey).exists)
    return btoi(this.data(listTypeKey).value)
  }

  private hash(a: string, b: string): string {
    return sha256(btoi(a) < btoi(b) ? a + b : b + a) as string;
  }

  private getBoxCreateMinBalance(a: uint64, b: uint64): uint64 {
    return 2_500 + (400 * (a + b))
  }

  private getDataKey(address: Address, root: bytes32, key: string): DataKey {
    let truncatedAddress = extract3(address, 0, 16) as bytes16;
    let truncatedRoot = extract3(root, 0, 16) as bytes16;

    return { address: truncatedAddress, root: truncatedRoot, key: key };
  }
}
