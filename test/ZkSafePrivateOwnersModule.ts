import hre, { deployments } from 'hardhat';
import { expect } from "chai";
import assert = require('assert');
import { WalletClient, PublicClient, zeroAddress, parseEther, encodeFunctionData, isBytes, isHex, toHex, fromHex, concatHex, Account, toBytes, fromBytes, recoverAddress, recoverPublicKey, Hex, getContract } from "viem";
import { privateKeyToAccount } from 'viem/accounts';
import Safe, {
    ContractNetworksConfig,
    PredictedSafeProps,
    SafeAccountConfig,
} from '@safe-global/protocol-kit';
import { MetaTransactionData, SafeSignature, SafeTransaction, OperationType, SafeTransactionData } from "@safe-global/types-kit";
import { IMT } from '@zk-kit/imt';
import { poseidon } from '@iden3/js-crypto';
import ZkSafeModule from "../ignition/modules/zkSafe";

import circuit from '../circuits/target/circuits.json';
import { UltraHonkBackend } from '@aztec/bb.js';
import { extractCoordinates, extractRSFromSignature, addressToArray, padArray, prove, proveTransactionSignatures, makeOwnersMerkleTree } from '../zksafe/zksafeprivateowners';

const DEFAULT_TRANSACTION = {
    to: zeroAddress,
    value: "0x0",
    data: "0x",
    operation: 0,
    // default fields below
    safeTxGas: "0x0",
    baseGas: "0x0",
    gasPrice: "0x0",
    gasToken: zeroAddress,
    refundReceiver: zeroAddress,
}

function makeSafeTransaction(nonce: number, fields: Partial<SafeTransactionData>) {
    return { nonce, ...DEFAULT_TRANSACTION, ...fields }
}

async function getContractNetworks(chainId: number): Promise<ContractNetworksConfig> {
    const deploymentAddresses = Object.fromEntries(
        await Promise.all(
            Object.entries({
                safeSingletonAddress: "SafeL2",
                safeProxyFactoryAddress: "SafeProxyFactory",
                multiSendAddress: "MultiSend",
                multiSendCallOnlyAddress:  "MultiSendCallOnly",
                fallbackHandlerAddress: "CompatibilityFallbackHandler",
                signMessageLibAddress:  "SignMessageLib",
                createCallAddress:  "CreateCall",
            }).map(async ([key, value]) => [key, (await deployments.get(value)).address])
        )
    )
    return {
        [chainId.toString()]: {
            ...deploymentAddresses,
            simulateTxAccessorAddress: zeroAddress,
            safeWebAuthnSignerFactoryAddress: zeroAddress,
            safeWebAuthnSharedSignerAddress: zeroAddress,
        }
    }
}

function accountAddresses(accounts: WalletClient[]) {
    return accounts.map((account) => account.account?.address!);
}

describe("ZkSafeModule", function () {

    let namedAccounts: { [name: string]: string };
    let accounts: WalletClient[];
    let safeAddress: `0x${string}`;
    let zkSafeModuleAddress: `0x${string}`;

    let publicClient: PublicClient;
    let walletClient: WalletClient;
    let usersWalletClient: WalletClient;

    let safe: Safe;
    let zkSafeModule: any;
    let publicVerifierContract: any;
    let privateVerifierContract: any;

    let createSafeFromWalletAddress:  (wallet: WalletClient, safeAddress: string) => Promise<Safe>;
    let signTransactionFromUser: (wallet: WalletClient, safe: Safe, transaction: SafeTransaction) => Promise<SafeSignature>;
    let signTransactionEIP712: (wallet: WalletClient, safe: Safe, transaction: SafeTransaction, chainId: number) => Promise<Hex>;

    let privateOwners: WalletClient[];
    
    let ownersMerkleTree: IMT;

    before(async function () {
        await deployments.fixture();

        const result = await hre.ignition.deploy(ZkSafeModule);
        zkSafeModule = result.zkSafePrivateOwnersModule;
        publicVerifierContract = result.publicVerifier;
        privateVerifierContract = result.privateVerifier;

        // Get deployer account
        accounts = await hre.viem.getWalletClients();
        publicClient = await hre.viem.getPublicClient();

        // Configure for consistent gas estimation
        const originalEstimateGas = publicClient.estimateGas;
        publicClient.estimateGas = async (args: any) => {
            // Use a cached/fixed value for gas estimation
            return BigInt("0x1000000");
        };

        namedAccounts = await hre.getNamedAccounts();
        walletClient = accounts[0];
        usersWalletClient = accounts[1];
        const chainId = walletClient.chain?.id ?? 1;

        createSafeFromWalletAddress = async (wallet: WalletClient, safeAddress: string): Promise<Safe> => {
            return await Safe.init({
                provider: wallet.transport,
                signer: wallet.account?.address,
                safeAddress,
                contractNetworks: await getContractNetworks(chainId),
            });
        }
                                              
        privateOwners = accounts.slice(3, 8);
        const ownersRoot = toHex(makeOwnersMerkleTree(accountAddresses(privateOwners)).root);
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
            args: [ownersRoot, BigInt(1)],
        });

        safe = await Safe.init({
            provider: walletClient.transport,
            predictedSafe: {
                safeAccountConfig: {
                    owners: [(accounts[0].account as Account).address,
                               (accounts[1].account as Account).address,
                               (accounts[2].account as Account).address],
                    threshold: 1,
                    to: zkSafeModule.address,
                    data: calldata,
                }
            },
            contractNetworks: await getContractNetworks(chainId),
        });

        safeAddress = await safe.getAddress() as `0x${string}`;
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

        expect(transactionReceipt.status).to.be.equal("success");
        console.log("Safe created at: ", safeAddress);
        expect(await safe.isSafeDeployed()).to.be.true;

        // Now when the Safe is deployed, reinitialize protocol-kit Safe wrapper as
        // initialized Safe.
        safe = await createSafeFromWalletAddress(usersWalletClient, safeAddress);

        const privateSafeConfig = await zkSafeModule.read.safeToConfig([safeAddress]);

        signTransactionFromUser = async (wallet: WalletClient, safe: Safe, transaction: SafeTransaction): Promise<SafeSignature> => {
            const userSafe = await createSafeFromWalletAddress(wallet, await safe.getAddress());
            const signerAddress = await userSafe.getSafeProvider().getSignerAddress();
            const signedTransaction = await userSafe.signTransaction(transaction);
            return signedTransaction.getSignature(signerAddress!)!;
        };

        // Sign transaction using EIP-712 without Safe ownership check
        signTransactionEIP712 = async (wallet: WalletClient, safe: Safe, transaction: SafeTransaction, chainId: number): Promise<Hex> => {
            const safeAddress = await safe.getAddress();

            // EIP-712 domain for Safe
            const domain = {
                chainId: chainId,
                verifyingContract: safeAddress as `0x${string}`,
            };

            // EIP-712 types for Safe transaction
            const types = {
                SafeTx: [
                    { name: 'to', type: 'address' },
                    { name: 'value', type: 'uint256' },
                    { name: 'data', type: 'bytes' },
                    { name: 'operation', type: 'uint8' },
                    { name: 'safeTxGas', type: 'uint256' },
                    { name: 'baseGas', type: 'uint256' },
                    { name: 'gasPrice', type: 'uint256' },
                    { name: 'gasToken', type: 'address' },
                    { name: 'refundReceiver', type: 'address' },
                    { name: 'nonce', type: 'uint256' },
                ],
            };

            // Message to sign
            const message = {
                to: transaction.data.to,
                value: BigInt(transaction.data.value),
                data: transaction.data.data,
                operation: transaction.data.operation,
                safeTxGas: BigInt(transaction.data.safeTxGas),
                baseGas: BigInt(transaction.data.baseGas),
                gasPrice: BigInt(transaction.data.gasPrice),
                gasToken: transaction.data.gasToken,
                refundReceiver: transaction.data.refundReceiver,
                nonce: BigInt(transaction.data.nonce),
            };

            return await wallet.signTypedData({ domain, types, primaryType: 'SafeTx', message });
        };
    });

    function readjustSigFromEthSign(signature: SafeSignature): Hex {
        const sig = toBytes(signature.data);
        if (sig[64] > 30) {
           sig[64] -= 4;
        }
        return fromBytes(sig, 'hex');
    }

    it("Should succeed verification of a basic transaction", async function () {

        const nonce = await safe.getNonce();
        const privateSafeConfig = await zkSafeModule.read.safeToConfig([safeAddress]);
        const threshold = privateSafeConfig[1];
        const metaTransaction = makeSafeTransaction(nonce, {});
        const transaction = await safe.createTransaction({ transactions: [metaTransaction] });
        const txHash = await safe.getTransactionHash(transaction);

        // Get chainId for EIP-712 signing
        const chainId = await publicClient.getChainId();

        // Sign with private owners using EIP-712 (bypassing Safe ownership check)
        const sig1 = await signTransactionEIP712(privateOwners[0], safe, transaction, chainId);
        const sig2 = await signTransactionEIP712(privateOwners[1], safe, transaction, chainId);
        const sig3 = await signTransactionEIP712(privateOwners[2], safe, transaction, chainId);
        const signatures = [sig2, sig3]; // sig1 is not included, threshold of 2 should be enough.

        // Debug: Verify the signatures recover to the expected addresses
        const addr1 = await recoverAddress({hash: txHash as Hex, signature: sig1});
        const addr2 = await recoverAddress({hash: txHash as Hex, signature: sig2});
        const addr3 = await recoverAddress({hash: txHash as Hex, signature: sig3});
        console.log("Signer addresses recovered from signatures:");
        console.log("  sig1:", addr1, "expected:", privateOwners[0].account?.address);
        console.log("  sig2:", addr2, "expected:", privateOwners[1].account?.address);
        console.log("  sig3:", addr3, "expected:", privateOwners[2].account?.address);

        const proof = await proveTransactionSignatures(hre,
                                                       safe,
                                                       signatures,
                                                       txHash as Hex,
                                                       accountAddresses(privateOwners),
                                                       threshold);
        // Convert Uint8Array proof to hex string for contract call
        const proofHex = `0x${Buffer.from(proof.proof).toString('hex')}`;

        const directVerification = await privateVerifierContract.read.verify([proofHex, proof.publicInputs]);

        const contractVerification = await zkSafeModule.read.verifyZkSafeTransaction([await safe.getAddress(), txHash, true, proofHex]);
        const txn = await zkSafeModule.write.sendZkSafeTransaction([
            safeAddress,
            { to: transaction.data.to,
              value: BigInt(transaction.data.value),
              data: transaction.data.data,
              operation: transaction.data.operation,
            },
            true, // usePrivateOwners
            proofHex, // Use truncated proof for transaction
        ]);

        const receipt = await publicClient.waitForTransactionReceipt({ hash: txn });
        expect(receipt.status).to.equal('success');
        let newNonce = await safe.getNonce();
        expect(newNonce).to.equal(nonce + 1);
    });

    it("Should fail to verify a nonexistent contract", async function () {

        const transaction  = {
            to: "0x0000000000000000000000000000000000000000",
            value: 0,
            data: "0x",
            operation: 0,
        }

        await expect(zkSafeModule.write.sendZkSafeTransaction([
          "0x0000000000000000000000000000000000000000",
          transaction,
          true, // usePrivateOwners
          "0x", // empty proof
        ])).to.be.rejected;
    });

    it("Should fail a basic transaction with a wrong proof", async function () {

        const transaction  = {
            to: "0x0000000000000000000000000000000000000000",
            value: 0,
            data: "0x",
            operation: 0,
        }

        await expect(zkSafeModule.write.sendZkSafeTransaction([
            await safe.getAddress(),
            transaction,
            true, // usePrivateOwners
            "0x" + "0".repeat(2 * 440 * 32), // invalid proof (440 * 32 zeros)
        ])).to.be.rejectedWith(/custom error/);
    });
});
