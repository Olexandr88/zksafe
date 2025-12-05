# Hiding Owners in ZkSafe

The version 1.0.x of zkSafe could only hide who signed a particular transaction out of a given set of owners.
With the version 2.0 of zkSafe, we introduce the ability to hide the owners themselves.

## Merkle Tree of Hidden Owners

The zkSafe contract keeps a Merkle tree root of the set of hidden owners. The users of zkSafe willing to use this functionality must maintain the list of hidden owners somewhere offchain. Additionally, the private configuration of zkSafe holds the threshold for the zkSafe (the threshold is public).

Only the party proving transactions has to have access to this full list, in addition to the full list of signatures.

This could be, for example, in a secret chat between the owners of the Safe, an encrypted storage, or a program running in a Trusted Execution Environment that manages owners.

## Usage

At the moment, only command line in the form of Hardhat tasks is implemented:

     * Task  `createZkSafe` accepts additional arguments `--zksafemoduleprivateowners` and `--zksafemodulethreshold`.
     * Task `prove` accepts `--zksafemoduleprivateowners`.
 

For example:

    ```
    $ npx hardhat createZkSafe --network <mainnet|gnosis|sepolia> --owners 0x0Ccb2b6675A60EC6a5c20Fb0631Be8EAF3Ba2dCD,0x48129F999598675F40A6d36Cec58a623b8c0228d,0x6804a7411adFAEB185d4dE27a04e5B6281160822 --threshold 2 --zksafemoduleprivateowners 0x1510B92f94e3f67Fb3d9a12501AF7Ce5B567063d,0x1E8A0CD8045C7C0C9762408AFF2c64C63F26C5f4,0x2Ef9Dbc8683d44d6e782823F2f637b22576fB7f1,0xbd8faF57134f9C5584da070cC0be7CA8b5A24953 --zksafemodulethreshold 2
    ```



And for proving:

    ```
    npx hardhat --network <mainnet|sepolia|gnosis|etc> prove --safe <safe address> --signatures <signature1>,<signature2>,<sinagure3> --txhash <txhash> --zksafemoduleprivateowners 0x1510B92f94e3f67Fb3d9a12501AF7Ce5B567063d,0x1E8A0CD8045C7C0C9762408AFF2c64C63F26C5f4,0x2Ef9Dbc8683d44d6e782823F2f637b22576fB7f1,0xbd8faF57134f9C5584da070cC0be7CA8b5A24953 --ownersaddressesformat 0
    ```


If the `--zksafemoduleprivateowners` is not given, all operations performed are for public owners.

## Combined Contract

There's only one zkSafe module contract in the system. It handles both public and private owners. There are two UltraHonk verifiers, and the zkSafe module contract chooses among them during verficiation based on the operation requested by the user (via the `usePrivateOwners` argument to `verifyZkSafeTransaction` and `sendZksafeTransaction`).


## UI

Outside of the simplest Hardhat tasks, there's no other UI at the time of this writing.

All Safe UIs that assume that owners of the Safe will not work with private owners, because the UI doesn't have access to them.

One possible good way to use the system:

1. Prepare a transaction using a normal Safe UI (either the main one or alternatives). Two options:

    - A private owner is also a public owner (that is, one of the private owners is revealed).
    - Using Safe delegates (https://help.safe.global/en/articles/40799-what-is-a-delegate-key)
  
2. While the transaction itself is in the open, signature collection is performed off-chain among the private owners. If the first option above is used (one of the private owners revealing themselves signed, their signature could be reused).

3. Proving is done after the signature collection with the proving party supplying the hidden owners list to the prover together with transaction details.

4. Transaction is executed.  Bumped nonce will consume the transaction created in the Safe UI.


Another way would be implementing an alternative Safe UI that keeps owners in the private, and performs proving in a TEE environment.
