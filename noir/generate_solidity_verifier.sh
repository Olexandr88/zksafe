# Generate the verification key. You need to pass the `--oracle_hash keccak` flag when generating vkey and proving
# to instruct bb to use keccak as the hash function, which is more optimal in Solidity
mkdir -p ./target/circuits_vk
bb write_vk -b ./target/circuits.json -o ./target/circuits_vk --oracle_hash keccak
mkdir -p ./target/private_owners_vk
bb write_vk -b ./target/private_owners.json -o ./target/private_owners_vk --oracle_hash keccak

# Generate the Solidity verifier from the vkey
bb write_solidity_verifier -k ./target/circuits_vk/vk -o ./target/Verifier.sol
bb write_solidity_verifier -k ./target/private_owners_vk/vk -o ./target/PrivateOwnersVerifier.sol
