from sphincs import *


class TestSphincs:
    def __init__(self, args=None):
        self.sphincs = Sphincs()

    def test_key_gen(self):
        SK, PK = self.sphincs.spx_keygen()
        print(SK)
        print(PK)
        return 1


T = TestSphincs()
print(T.test_key_gen())
