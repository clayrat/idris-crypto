module Data.Crypto.MAC

import Data.Bits

%default total

class Signer s (blockLength : Nat) (outputLength : Nat) | s where
  signMessage : e -> List (Bits blockLength) -> Bits outputLength

class Verifier v (blockLength : Nat) (outputLength : Nat) | v where
  verifyMessage : v -> List (Bits blockLength) -> Bits n -> Bool

class (Signer m b o, Verifier m b o) => MAC m (b : Nat) (o : Nat) | m where
  instance Verifier m b o where
    verifyMessage key message digest = digest == signMessage key message
