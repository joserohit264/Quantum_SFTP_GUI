
import sys
import inspect

try:
    import kyber_py
    print("Imported kyber_py")
    print(dir(kyber_py))
except ImportError as e:
    print(f"Failed to import kyber_py: {e}")

try:
    import dilithium_py
    print("Imported dilithium_py")
    print(dir(dilithium_py))
except ImportError as e:
    print(f"Failed to import dilithium_py: {e}")

# Try to find Kyber class
try:
    from kyber_py.kyber import Kyber512
    print("Found Kyber512 in kyber_py.kyber")
except ImportError:
    print("Kyber512 not found in kyber_py.kyber")

try:
    from kyber_py.ml_kem.ml_kem import ML_KEM_512
    print("Found ML_KEM_512 in kyber_py.ml_kem.ml_kem")
except ImportError:
    print("ML_KEM_512 not found in kyber_py.ml_kem.ml_kem")

# Try to find Dilithium class
try:
    from dilithium_py.dilithium import Dilithium2
    print("Found Dilithium2 in dilithium_py.dilithium")
except ImportError:
    print("Dilithium2 not found in dilithium_py.dilithium")

try:
    from dilithium_py.ml_dsa.ml_dsa import ML_DSA_44
    print("Found ML_DSA_44 in dilithium_py.ml_dsa.ml_dsa")
except ImportError:
    print("ML_DSA_44 not found in dilithium_py.ml_dsa.ml_dsa")
