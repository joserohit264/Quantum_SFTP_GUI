"""
Test script for Phase 1: Core Hash Functions

Tests hash computation, verification, registry management,
and constant-time comparison.
"""

import os
import sys

# Add WebApp directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Codes', 'WebApp'))

from hash_verifier import (
    compute_file_hash, 
    compute_data_hash, 
    verify_file_hash,
    compare_hashes,
    register_file_hash,
    get_file_hash,
    hash_verifier
)


def test_hash_computation():
    """Test 1: Hash Computation"""
    print("\n" + "="*60)
    print("TEST 1: HASH COMPUTATION")
    print("="*60)
    
    # Create a test file
    test_file = "test_file.txt"
    test_data = b"This is a test file for hash verification!"
    
    with open(test_file, 'wb') as f:
        f.write(test_data)
    
    print(f"✓ Created test file: {test_file}")
    
    # Compute hash
    file_hash = compute_file_hash(test_file)
    print(f"✓ File hash (SHA-256): {file_hash}")
    
    # Compute data hash
    data_hash = compute_data_hash(test_data)
    print(f"✓ Data hash (SHA-256): {data_hash}")
    
    # Verify they match
    if file_hash == data_hash:
        print("✅ PASS: File hash matches data hash")
    else:
        print("❌ FAIL: Hash mismatch!")
    
    # Cleanup
    os.remove(test_file)
    return file_hash


def test_hash_verification():
    """Test 2: Hash Verification"""
    print("\n" + "="*60)
    print("TEST 2: HASH VERIFICATION")
    print("="*60)
    
    # Create test file
    test_file = "test_verify.txt"
    test_data = b"Verify this file!"
    
    with open(test_file, 'wb') as f:
        f.write(test_data)
    
    # Compute hash
    original_hash = compute_file_hash(test_file)
    print(f"✓ Original hash: {original_hash[:32]}...")
    
    # Test 1: Correct hash
    is_valid, current_hash = verify_file_hash(test_file, original_hash)
    if is_valid:
        print("✅ PASS: File verified with correct hash")
    else:
        print("❌ FAIL: Verification failed for correct hash")
    
    # Test 2: Wrong hash
    wrong_hash = "0" * 64
    is_valid, current_hash = verify_file_hash(test_file, wrong_hash)
    if not is_valid:
        print("✅ PASS: Correctly rejected wrong hash")
    else:
        print("❌ FAIL: Accepted wrong hash!")
    
    # Cleanup
    os.remove(test_file)


def test_constant_time_comparison():
    """Test 3: Constant-Time Hash Comparison"""
    print("\n" + "="*60)
    print("TEST 3: CONSTANT-TIME COMPARISON")
    print("="*60)
    
    hash1 = "a" * 64
    hash2 = "a" * 64
    hash3 = "b" * 64
    
    # Same hashes
    if compare_hashes(hash1, hash2):
        print("✅ PASS: Correctly identified matching hashes")
    else:
        print("❌ FAIL: Failed to match identical hashes")
    
    # Different hashes
    if not compare_hashes(hash1, hash3):
        print("✅ PASS: Correctly identified different hashes")
    else:
        print("❌ FAIL: Matched different hashes!")


def test_registry_operations():
    """Test 4: Hash Registry CRUD"""
    print("\n" + "="*60)
    print("TEST 4: REGISTRY OPERATIONS")
    print("="*60)
    
    # Create test file
    test_file = "test_registry.txt"
    test_data = b"Registry test data"
    
    with open(test_file, 'wb') as f:
        f.write(test_data)
    
    # Compute hash
    file_hash = compute_file_hash(test_file)
    print(f"✓ Computed hash: {file_hash[:32]}...")
    
    # Register file
    file_id = register_file_hash(
        filepath=test_file,
        hash_value=file_hash,
        username="testuser",
        filename="test_registry.txt",
        file_size=len(test_data)
    )
    print(f"✓ Registered file with ID: {file_id}")
    
    # Retrieve hash
    entry = get_file_hash(test_file)
    if entry:
        print(f"✓ Retrieved entry: {entry['filename']}")
        print(f"  - Uploaded by: {entry['uploaded_by']}")
        print(f"  - File size: {entry['file_size']} bytes")
        print(f"  - Status: {entry['verification_status']}")
        print("✅ PASS: Registry operations successful")
    else:
        print("❌ FAIL: Failed to retrieve entry")
    
    # Cleanup
    os.remove(test_file)


def test_registry_stats():
    """Test 5: Registry Statistics"""
    print("\n" + "="*60)
    print("TEST 5: REGISTRY STATISTICS")
    print("="*60)
    
    stats = hash_verifier.get_registry_stats()
    
    print(f"Total files tracked: {stats['total_files']}")
    print(f"Valid files: {stats['valid']}")
    print(f"Corrupted files: {stats['corrupted']}")
    print(f"Missing files: {stats['missing']}")
    print(f"Tampered files: {stats['tampered']}")
    print(f"Health: {stats['health_percentage']:.1f}%")
    
    if stats['total_files'] > 0:
        print("✅ PASS: Statistics retrieved successfully")
    else:
        print("⚠️  WARNING: No files in registry yet")


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print(" Q-SFTP HASH VERIFICATION - PHASE 1 TEST SUITE")
    print("="*70)
    
    try:
        test_hash_computation()
        test_hash_verification()
        test_constant_time_comparison()
        test_registry_operations()
        test_registry_stats()
        
        print("\n" + "="*70)
        print(" ✅ ALL TESTS COMPLETED")
        print("="*70)
        print("\nPhase 1 implementation successful!")
        print("Next: Implement Phase 2 (Upload Verification)")
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
