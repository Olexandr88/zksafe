import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("zkSafe_v1", (m) => {
  const verifier = m.contract("HonkVerifier", []);
  const zkSafeModule = m.contract("ZkSafeModule", [verifier]);
  const zkSafePrivateOwnersModule = m.contract("ZkSafePrivateOwnersModule", [verifier]);
  return { zkSafeModule, zkSafePrivateOwnersModule, verifier };
});
