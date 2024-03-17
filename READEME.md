# FRI to KZG Verifier

## Unit Test

```sh

# mock_verifier
cargo test -r --package fri-kzg-verifier --lib -- exec::mock_verifier::tests::test_sc_fir_kzg_verifier_evm --exact --nocapture --ignored

cargo test -r --package fri-kzg-verifier --lib -- exec::mock_verifier::tests::test_evm_verifier_from_local --exact --nocapture --ignored

```
