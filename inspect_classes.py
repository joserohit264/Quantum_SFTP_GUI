
import sys
from kyber_py.kyber import Kyber512
from dilithium_py.dilithium import Dilithium2

print("Kyber512 attributes:")
for attr in dir(Kyber512):
    if not attr.startswith("_"):
        print(attr)

print("\nDilithium2 attributes:")
for attr in dir(Dilithium2):
    if not attr.startswith("_"):
        print(attr)
