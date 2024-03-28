# FRI to KZG Verifier

## Unit Test

```sh

# mock_verifier
cargo test -r --package fri-kzg-verifier --lib -- exec::mock_verifier::tests::test_sc_fir_kzg_verifier_evm --exact --nocapture --ignored

cargo test -r --package fri-kzg-verifier --lib -- exec::mock_verifier::tests::test_evm_verifier_from_local --exact --nocapture --ignored

```

## Integrated Test

```sh

cargo test -r --test test_verifier_solidity -- test_verifier_solidity --exact --nocapture --ignored

cargo test -r --test test_verifier_solidity -- test_v_s_with_kzg_loaded --exact --nocapture --ignored

```
