
import sys
import base64
try:
    from kyber_py.kyber import Kyber512
    from dilithium_py.dilithium import Dilithium2
except ImportError as e:
    print(f"Import Error: {e}")
    sys.exit(1)

def test_kyber():
    print("Testing Kyber512...")
    pk, sk = Kyber512.keygen()
    
    # Encapsulation
    # Returns (shared_key, ciphertext) based on previous run
    key_client, c = Kyber512.encaps(pk)
    print(f"Ciphertext len: {len(c)}")
    print(f"Shared Key (Client) len: {len(key_client)}")
    
    # Decapsulation
    key_server = Kyber512.decaps(sk, c)
    print(f"Shared Key (Server) len: {len(key_server)}")
    
    assert key_client == key_server
    print("Kyber Key Exchange Successful!")

def test_dilithium():
    print("\nTesting Dilithium2...")
    pk, sk = Dilithium2.keygen()
    
    msg = b"Hello Quantum World"
    sig = Dilithium2.sign(sk, msg)
    print(f"Signature len: {len(sig)}")
    
    valid = Dilithium2.verify(pk, msg, sig)
    print(f"Signature Valid: {valid}")
    assert valid

if __name__ == "__main__":
    test_kyber()
    test_dilithium()
