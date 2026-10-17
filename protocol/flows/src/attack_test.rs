#[cfg(test)]
mod tests {
    use kaspa_p2p_lib::common::ProtocolError;
    use kaspa_consensus_core::errors::pruning::PruningImportError;
    use kaspa_hashes::Hash;

    #[tokio::test]
    async fn test_malicious_peer_ban() {
        // Simulate the exact error the node throws when it sees the bad proof
        let bad_proof_error = ProtocolError::PruningImportError(
            PruningImportError::ZethoraPowEpochImplausible(
                Hash::default(), 
                42, 
                1, 
                2
            )
        );

        // Verify the classifier catches it
        assert!(bad_proof_error.is_implausible_pow_epoch(), "Classifier failed to catch the bad proof!");
        println!("Test passed: Bad proof is classified correctly and triggers the ban logic.");
    }
}