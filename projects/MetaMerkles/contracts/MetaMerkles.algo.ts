import { Contract } from '@algorandfoundation/tealscript';

const hashLength = 32;
const rootKeyLength = 64;
const truncatedKeyLength = 32;
const typeKeyByteLength = 4;
const typeValueByteLength = 8;

const rootMinBalance: uint64 = 25_00 + (400 * rootKeyLength);
const dataTypeMinBalance: uint64 = 25_00 + (400 * ((truncatedKeyLength + typeKeyByteLength) + typeValueByteLength));

type bytes16 = StaticArray<byte, 16>;

interface RootKey { address: Address, root: bytes32 };

interface DataKey { address: bytes16, root: bytes16, key: string };

// TODO: replace with enum when tealscript supports it
const RootTypeMixed = 0;
const RootTypeAsset = 1;
const RootTypeAddress = 2;
const RootTypeApp = 3;

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
  addRoot(pmt: PayTxn, hashedRoot: bytes32, type: uint64): void {
    const key: RootKey = { address: this.txn.sender, root: hashedRoot };
    const dataKey: DataKey = this.getDataKey(this.txn.sender, hashedRoot, 'type');

    assert(!this.roots(key).exists)
    assert(!this.data(dataKey).exists)

    verifyPayTxn(pmt, {
      receiver: this.app.address,
      amount: rootMinBalance + dataTypeMinBalance,
    })

    this.roots(key).create(0);
    this.data(dataKey).value = itob(type);
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
   * verify an inclusion in a merkle tree & ensure the merkle tree
   * is in reference to a group of asset IDs
   * 
   * @param address the address of the merkle tree root creator
   * @param hashedRoot the sha256'd 32 byte merkle tree root
   * @param proof the proof for the asset
   * @param verifyingAsset the `assetID` we're checking against the merkle root
   * @returns a boolean indicating the check passed or failed
   */
  verifyAsset(
    address: Address,
    hashedRoot: bytes32,
    proof: string,
    verifyingAsset: AssetID,
  ): boolean {
    const rootKey: RootKey = { address: address, root: hashedRoot };
    assert(this.roots(rootKey).exists);

    let type = btoi(this.read(address, hashedRoot, 'type'));
    assert(type === RootTypeAsset, 'mtree is not type AssetID or Mixed');

    let hash: string = sha256(itob(verifyingAsset)) as string;

    return this.verify(hashedRoot, proof, hash);
  }

  /**
   * verify an inclusion in a merkle tree & ensure the merkle tree
   * is in reference to a group of addresses
   * 
   * @param address the address of the merkle tree root creator
   * @param hashedRoot the sha256'd 32 byte merkle tree root
   * @param proof the proof for the address
   * @param verifyingAddress the `Address` we're checking against the merkle root
   * @returns a boolean indicating the check passed or failed
   */
  verifyAddress(
    address: Address,
    hashedRoot: bytes32,
    proof: string,
    verifyingAddress: Address,
  ): boolean {
    const rootKey: RootKey = { address: address, root: hashedRoot };
    assert(this.roots(rootKey).exists)

    let type = btoi(this.read(address, hashedRoot, 'type'));
    assert(type === RootTypeAddress, 'mtree is not type Address or Mixed');

    let hash: string = sha256(verifyingAddress) as string;

    return this.verify(hashedRoot, proof, hash);
  }

  /**
   * verify an inclusion in a merkle tree & ensure the merkle tree
   * is in reference to a group of appIDs
   * 
   * @param address the address of the merkle tree root creator
   * @param hashedRoot the sha256'd 32 byte merkle tree root
   * @param proof the proof for the app
   * @param verifyingApp the `AppID` we're checking against the merkle root
   * @returns a boolean indicating the check passed or failed
   */
  verifyApp(
    address: Address,
    hashedRoot: bytes32,
    proof: string,
    verifyingApp: AppID,
  ): boolean {
    const rootKey: RootKey = { address: address, root: hashedRoot };
    assert(this.roots(rootKey).exists)

    let type = btoi(this.read(address, hashedRoot, 'type'));
    assert((type === RootTypeApp), 'mtree is not type AppID or Mixed');

    let hash: string = sha256(itob(verifyingApp)) as string;

    return this.verify(hashedRoot, proof, hash);
  }

  /**
   * verify an inclusion in a merkle tree
   * 
   * @param hashedRoot the sha256'd 32 byte merkle tree root
   * @param proof the proof the hash is included
   * @param hash the hash of the info being verified
   * @returns a boolean indicating the check passed or failed
   */
  verify(hashedRoot: bytes32, proof: string, hash: string): boolean {
    for (let i = 0; i < proof.length; i + hashLength) {
      hash = this.hash(hash, extract3(proof, i, hashLength))
    }

    return hashedRoot === sha256(hash);
  }

  /**
   * fetch a metadata property
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

  
  private hash(a: string, b: string): string {
    return sha256(btoi(a) < btoi(b) ? a + b : b + a) as string;
  }

  private getBoxCreateMinBalance(a: uint64, b: uint64): uint64 {
    return 25_00 + (400 * (a + b))
  }

  private getDataKey(address: Address, root: bytes32, key: string): DataKey {
    let truncatedAddress = extract3(address, 0, 16) as bytes16;
    let truncatedRoot = extract3(root, 0, 16) as bytes16;

    return { address: truncatedAddress, root: truncatedRoot, key: key };
  }
}
