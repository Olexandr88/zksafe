import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("zkSafe", (m) => {
  const publicVerifier = m.contract("noir/target/Verifier.sol:HonkVerifier", [], {id: "PublicOwnersVerifier" });
  const privateVerifier = m.contract("noir/target/PrivateOwnersVerifier.sol:HonkVerifier", [], {id: "PrivateOwnersVerifier"});
  const zkSafePrivateOwnersModule = m.contract("ZkSafePrivateOwnersModule", [publicVerifier, privateVerifier]);
  return { zkSafePrivateOwnersModule, publicVerifier, privateVerifier };
});
