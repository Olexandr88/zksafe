import { zeroAddress, parseEther, encodeFunctionData, toHex, Account, toBytes, recoverAddress, recoverPublicKey, Hex, createWalletClient, http, WalletClient, Address} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { formatEther } from 'viem';
import Safe from '@safe-global/protocol-kit';
import { SafeAccountConfig } from '@safe-global/protocol-kit';
import { SafeTransactionData, SafeSignature } from '@safe-global/types-kit';
import assert from 'assert';
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { vars } from "hardhat/config";

import { poseidon } from '@iden3/js-crypto';
import { IMT } from '@zk-kit/imt';
import circuit from '../noir/circuits/target/circuits.json';
import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js';

import ZkSafeModule from "../ignition/modules/zkSafe";

/// Extract x and y coordinates from a serialized ECDSA public key.
export function extractCoordinates(serializedPubKey: string): { x: number[], y: number[] } {
    // Ensure the key starts with '0x04' which is typical for an uncompressed key.
    if (!serializedPubKey.startsWith('0x04')) {
        throw new Error('The public key does not appear to be in uncompressed format.');
    }

    // The next 64 characters after the '0x04' are the x-coordinate.
    let xHex = serializedPubKey.slice(4, 68);

    // The following 64 characters are the y-coordinate.
    let yHex = serializedPubKey.slice(68, 132);

    // Convert the hex string to a byte array.
    let xBytes = Array.from(Buffer.from(xHex, 'hex'));
    let yBytes = Array.from(Buffer.from(yHex, 'hex'));
    return { x: xBytes, y: yBytes };
}

export function extractRSFromSignature(signatureHex: string): number[] {
    if (signatureHex.length !== 132 || !signatureHex.startsWith('0x')) {
        throw new Error('Signature should be a 132-character hex string starting with 0x.');
    }
    return Array.from(Buffer.from(signatureHex.slice(2, 130), 'hex'));
}

export function addressToArray(address: string): number[] {
    if (address.length !== 42 || !address.startsWith('0x')) {
        throw new Error('Address should be a 40-character hex string starting with 0x.');
    }
    return Array.from(toBytes(address));
}

export function padArray(arr: any[], length: number, fill: any = 0) {
    return arr.concat(Array(length - arr.length).fill(fill));
}

function ensureHexPrefix(value: string): `0x${string}` {
    return value.startsWith("0x") ? value as `0x${string}` : `0x${value}`;
}

export function makeOwnersMerkleTree(owners: Address[]) {
    const depth = Math.ceil(Math.log2(owners.length));
    let ownersMerkleTree = new IMT(poseidon.hash, depth, 0, 2);
    // Normalize to lowercase for consistent hashing
    const sortedOwners = [...owners].map(a => a.toLowerCase() as Address).sort((a, b) => a.localeCompare(b));
    console.log("Building merkle tree with sorted owners:");
    sortedOwners.forEach((owner, i) => {
        const hash = poseidon.hash([BigInt(owner)]);
        console.log(`  [${i}]: ${owner} -> hash: ${hash}`);
        ownersMerkleTree.insert(hash);
    });
    return ownersMerkleTree;
}

export async function proveTransactionSignatures(hre: HardhatRuntimeEnvironment,
                                                 safe: Safe,
                                                 signatures: Hex[],
                                                 txHash: Hex,
                                                 privateOwners: Address[],
                                                 threshold: number | bigint) {
    // Use private_owners circuit if we have private owners, otherwise use public owners circuit
    const circuitName = privateOwners.length > 0 ? "private_owners" : "circuits";
    const { noir, backend } = await hre.noir.getCircuit(circuitName);
    console.log("noir backend initialized for", circuitName);
    
    const nil_pubkey = {
        x: Array.from(toBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
        y: Array.from(toBytes("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    };
    // Our Nil signature is a signature with r and s set to the generator point.
    const nil_signature = Array.from(
        toBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));
    const zero_address = new Array(20).fill(0);
    
    // Sort signatures by address - this is how the Safe contract does it.
    const sortedSignatures = await Promise.all(signatures.map(async (sig) => {
        const addr = await recoverAddress({hash: txHash, signature: sig});
        return { sig, addr };
    }));
    sortedSignatures.sort((a, b) => a.addr.localeCompare(b.addr));
    const sortedSigs = sortedSignatures.map(s => s.sig);

    console.log("Sorted signatures by address:");
    sortedSignatures.forEach((s, i) => console.log(`  [${i}]:`, s.addr));

    let input;
    if (privateOwners.length > 0) {
        let ownersMerkleTree = makeOwnersMerkleTree(privateOwners);
        console.log("Merkle tree leaves (sorted owners):", privateOwners.map((addr, i) => `[${i}]: ${addr}`));
        console.log("Merkle tree root:", toHex(ownersMerkleTree.root));
        const ownersIndicesProof: number[] = [];
        const ownersPathsProof: any[][] = [];
        for (var signature of sortedSignatures) {
            // Normalize address to lowercase for consistent lookup
            const normalizedAddr = signature.addr.toLowerCase();
            const index= await ownersMerkleTree.indexOf(poseidon.hash([BigInt(normalizedAddr)]));
            const addressProof= await ownersMerkleTree.createProof(index);
            console.log(`  Address ${normalizedAddr} found at index ${index}, pathIndices:`, addressProof.pathIndices);
            addressProof.siblings = addressProof.siblings.map((s) => s[0]);
            ownersIndicesProof.push(Number("0b" + addressProof.pathIndices.join("")));
            ownersPathsProof.push(addressProof.siblings);
        }
        const signers = padArray(await Promise.all(sortedSigs.map(async (sig) => extractCoordinates(
            await recoverPublicKey({hash: txHash, signature: sig})))),
                          4,
                          nil_pubkey);
        const sigs = padArray(sortedSigs.map(extractRSFromSignature), 4, nil_signature);

        console.log("Circuit inputs for signature verification:");
        for (let i = 0; i < Math.min(2, sortedSigs.length); i++) {
            console.log(`  Sig ${i}: ${sortedSigs[i].slice(0, 20)}...`);
            console.log(`    Pubkey X (first 8 bytes): [${signers[i].x.slice(0, 8).join(', ')}]`);
            console.log(`    Signature R (first 8 bytes): [${sigs[i].slice(0, 8).join(', ')}]`);
        }

        input = {
            threshold: Number(threshold),
            signers: signers,
            signatures: sigs,
            txn_hash: Array.from(toBytes(txHash as `0x${string}`)),
            owners_root: toHex(ownersMerkleTree.root),
            indices: padArray(ownersIndicesProof.map(idx => toHex(idx)), 4, "0x0"),
            siblings: padArray(ownersPathsProof.map(paths => paths.map(p => toHex(p))), 4, ["0x0", "0x0", "0x0"])
        };
    } else {
        input = {
            threshold: await safe.getThreshold(),
            signers: padArray(await Promise.all(sortedSigs.map(async (sig) => {
                const pubKey = await recoverPublicKey({
                    hash: txHash as `0x${string}`,
                    signature: sig
                });
                return extractCoordinates(pubKey);
            })), 10, nil_pubkey),
            signatures: padArray(sortedSigs.map(extractRSFromSignature), 10, nil_signature),
            txn_hash: Array.from(toBytes(txHash as `0x${string}`)),
            owners: padArray((await safe.getOwners()).map(addressToArray), 10, zero_address),
        }
    }
    const { witness } = await noir.execute(input);
    
    // Use backend to generate proof from witness
    const proof = await backend.generateProof(witness, { keccak: true });
    
    // Verify proof
    const verification = await backend.verifyProof(proof, { keccak: true });
    assert(verification, "Verification failed");
    console.log("verification in JS succeeded");
    return proof;
}


export async function prove(hre: HardhatRuntimeEnvironment, safeAddr: string, txHash: string, signatures_: string) {
    // Initialize Safe - we need it to prepare the witness (owners/threeshold) from onchain data.
    const safe = await Safe.init({
        provider: hre.network.config.url,
        safeAddress: safeAddr
    });

    const version = await safe.getContractVersion();
    const threshold = await safe.getThreshold();
    const owners = await safe.getOwners();
    const address = await safe.getAddress();
    console.log("connected to safe ", address);
    console.log("  version: ", version);
    console.log("  owners: ", owners);
    console.log("  threshold: ", threshold);
    console.log("  nonce: ", await safe.getNonce());
    console.log("  chainId: ", await safe.getChainId());
    console.log("  balance: ", formatEther(await safe.getBalance()));

    const signatures = signatures_.split(",").map(sig => sig.trim()).filter(sig => {
        if (!sig.startsWith("0x")) {
            throw new Error("Invalid signature format (must start with 0x)");
        }
        return true;
    });
    const proof = await proveTransactionSignatures(hre, safe, signatures as Hex[], txHash as Hex);
    console.log("Proof: ", toHex(proof.proof));
}

export async function sign(hre: HardhatRuntimeEnvironment, safeAddr: string, to: string, value: string, data: string) {
    // Get wallet client
    const pk = vars.get("SAFE_OWNER_PRIVATE_KEY") as string;
    const publicClient = await hre.viem.getPublicClient();
    const account = privateKeyToAccount(ensureHexPrefix(pk));
    const mywalletAddress = account.address;
    console.log("My wallet address: ", mywalletAddress);

    // Initialize Safe
    const safe = await Safe.init({
        provider: hre.network.config.url,
        signer: pk,
        safeAddress: safeAddr
    });

    const version = await safe.getContractVersion();
    const threshold = await safe.getThreshold();
    const owners = await safe.getOwners();
    const address = await safe.getAddress();
    console.log("connected to safe ", address);
    console.log("  version: ", version);
    console.log("  owners: ", owners);
    console.log("  threshold: ", threshold);
    console.log("  nonce: ", await safe.getNonce());
    console.log("  chainId: ", await safe.getChainId());
    console.log("  balance: ", formatEther(await safe.getBalance()));

    const safeTransactionData: SafeTransactionData = {
        to,
        value,
        data,
        operation: 0,
        // default fields below
        safeTxGas: "0x0",
        baseGas: "0x0",
        gasPrice: "0x0",
        gasToken: zeroAddress,
        refundReceiver: zeroAddress,
        nonce: await safe.getNonce(),
    };

    console.log("transaction", safeTransactionData);
    const transaction = await safe.createTransaction({ transactions: [safeTransactionData] });
    const txHash = await safe.getTransactionHash(transaction);
    console.log("txHash", txHash);

    // Sign the transaction using the Safe instance
    const signedTransaction = await safe.signTransaction(transaction);
    const safeSig = signedTransaction.getSignature(mywalletAddress)!;
    console.log("Signature: ", safeSig.data);
}

export async function createZkSafe(hre: HardhatRuntimeEnvironment, owners: string[], threshold: number, zkSafeModulePrivateOwners: string[], zkSafeModuleThreshold: number) {
    // Get wallet client
    const pk = vars.get("DEPLOYER_PRIVATE_KEY") as string;
    const account = privateKeyToAccount(ensureHexPrefix(pk));
    const walletClient: WalletClient = createWalletClient({
        account,
        transport: http(hre.network.config.url)
    });
    const publicClient = await hre.viem.getPublicClient();
    const mywalletAddress = walletClient.account!.address;
    console.log("My wallet address: ", mywalletAddress);

    const result = await hre.ignition.deploy(ZkSafeModule);
    const zkSafeModule = result.zkSafeModule;

    console.log("zkSafeModule: ", zkSafeModule.address);

    const ownersRoot = zkSafeModulePrivateOwners.length > 0 ?
          hre.viem.toHex(makeOwnersMerkleTree(zkSafeModulePrivateOwners).root) :
          hre.viem.toHex(0n);
  
    // Enable module
    const calldata = encodeFunctionData({
        abi: [{
            name: 'enableModule',
            type: 'function',
            stateMutability: 'nonpayable',
            inputs: [{ name: 'ownersRoot', type: 'bytes32' },
                     { name: 'threshold', type: 'uint256' }],
            outputs: []
        }],
        functionName: 'enableModule',
        args: [ownersRoot, zkSafeModuleThreshold],
    });

    const safe = await Safe.init({
        provider: walletClient.transport,
        predictedSafe: {
            safeAccountConfig: {
                owners,
                threshold: threshold,
                to: zkSafeModule.address,
                data: calldata,
            }
        },
    });

    const safeAddress = await safe.getAddress() as `0x${string}`;
    const deploymentTransaction = await safe.createSafeDeploymentTransaction();

    const transactionHash = await walletClient.sendTransaction({
        account: walletClient.account as Account,
        chain: walletClient.chain,
        to: deploymentTransaction.to,
        value: parseEther(deploymentTransaction.value),
        data: deploymentTransaction.data as `0x${string}`,
    });

    const transactionReceipt = await publicClient.waitForTransactionReceipt({
        hash: transactionHash
    });

    if (transactionReceipt.status != "success") {
        throw new Error("Safe failed to deploy.")
    }

    console.log("Created zkSafe at address: ", safeAddress);
}

export async function sign(hre: HardhatRuntimeEnvironment, safeAddr: string, to: string, value: string, data: string) {
    // Get wallet client
    const pk = vars.get("SAFE_OWNER_PRIVATE_KEY") as string;
    const publicClient = await hre.viem.getPublicClient();
    const account = privateKeyToAccount(ensureHexPrefix(pk));
    const mywalletAddress = account.address;
    console.log("My wallet address: ", mywalletAddress);

    // Initialize Safe
    const safe = await Safe.init({
        provider: hre.network.config.url,
        signer: pk,
        safeAddress: safeAddr
    });

    const version = await safe.getContractVersion();
    const threshold = await safe.getThreshold();
    const owners = await safe.getOwners();
    const address = await safe.getAddress();
    console.log("connected to safe ", address);
    console.log("  version: ", version);
    console.log("  owners: ", owners);
    console.log("  threshold: ", threshold);
    console.log("  nonce: ", await safe.getNonce());
    console.log("  chainId: ", await safe.getChainId());
    console.log("  balance: ", formatEther(await safe.getBalance()));

    const safeTransactionData: SafeTransactionData = {
        to,
        value,
        data,
        operation: 0,
        // default fields below
        safeTxGas: "0x0",
        baseGas: "0x0",
        gasPrice: "0x0",
        gasToken: zeroAddress,
        refundReceiver: zeroAddress,
        nonce: await safe.getNonce(),
    };

    console.log("transaction", safeTransactionData);
    const transaction = await safe.createTransaction({ transactions: [safeTransactionData] });
    const txHash = await safe.getTransactionHash(transaction);
    console.log("txHash", txHash);

    // Sign the transaction using the Safe instance
    const signedTransaction = await safe.signTransaction(transaction);
    const safeSig = signedTransaction.getSignature(mywalletAddress)!;
    console.log("Signature: ", safeSig.data);
}

export async function zksend(hre: any, safeAddr: string, to: string, value: string, data: string, proof: string, privateOwners: bool) {
    // Get wallet client
    const pk = ensureHexPrefix(vars.get("DEPLOYER_PRIVATE_KEY") as string);
    const account = privateKeyToAccount(pk);
    const mywalletAddress = account.address;
    console.log("My wallet address: ", mywalletAddress);
    const publicClient = await hre.viem.getPublicClient();

    // Initialize Safe
    const safe = await Safe.init({
        provider: hre.network.config.url,
        signer: pk,
        safeAddress: safeAddr
    });

    const version = await safe.getContractVersion();
    const threshold = await safe.getThreshold();
    const owners = await safe.getOwners();
    const safeAddress = await safe.getAddress();
    console.log("connected to safe ", safeAddress);
    console.log("  version: ", version);
    console.log("  owners: ", owners);
    console.log("  threshold: ", threshold);
    console.log("  nonce: ", await safe.getNonce());
    console.log("  chainId: ", await safe.getChainId());
    console.log("  balance: ", formatEther(await safe.getBalance()));

    // Find ZkSafeModule
    const modules = await safe.getModules();
    let zkSafeModule = null;
    for (const moduleAddress of modules) {
        console.log("Checking module: ", moduleAddress);
        try {
            const module = await hre.viem.getContractAt("ZkSafePrivateOwnersModule", moduleAddress);
            const version = await module.read.zkSafeModuleVersion();
            console.log("ZkSafe version: ", version);
            zkSafeModule = module;
            break;
        } catch (e) {
            console.log("Not a ZkSafe module", e);
        }
    }
    if (!zkSafeModule) {
        throw new Error(`ZkSafeModule not found on Safe ${safeAddress}`);
    }

    // Send transaction
    const txn = await zkSafeModule.write.sendZkSafeTransaction([
        safeAddress,
        {
            to,
            value: BigInt(value),
            data,
            operation: 0
        },
        privateOwners,
        proof,
    ]);

    console.log("Transaction hash: ", txn);
    const receipt = await publicClient.waitForTransactionReceipt({ hash: txn });
    console.log("Transaction result: ", receipt);
}

