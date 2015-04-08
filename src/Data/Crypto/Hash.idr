module Data.Crypto.Hash

import Data.Bits
import Data.Vect

%default total

class Hash h (blockLength : Nat) (outputLength : Nat) | h where
  initialize : h -> Vect m (Bits n) -> List (Bits blockLength)
  initialContext : h
  updateContext : h -> Bits blockLength -> h
  finalize : h -> Bits outputLength

hashMessage : Hash h b outputLength => h -> Vect m (Bits n) -> Bits outputLength
hashMessage hash message =
  finalize (foldl updateContext hash (initialize hash message))
