library;

// ================================================================================================
// COMPLETE ATTACK CONFIRMATION TEST SUITE
// ================================================================================================
// These tests confirm ALL identified vulnerabilities with realistic attack vectors
// Each file demonstrates exactly one vulnerability with actual function calls

// HIGH SEVERITY ATTACKS
pub mod attack_signature_recovery_panic_dos;
pub mod attack_module_validation_bypass;
pub mod attack_realistic_module_panic;

// MEDIUM SEVERITY ATTACKS  
pub mod attack_frontrunning_nonce_collision;
pub mod attack_signature_malleability;
pub mod attack_chain_id_manipulation;
pub mod attack_zero_values_signature;
pub mod attack_module_configuration;
pub mod attack_recovery_id_bypass;
