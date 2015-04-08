module Data.Crypto.Encryption.Stream

import Data.Bits
import Data.Crypto.Util
import Data.Crypto.Encryption
import Data.Vect

%default total
%access public

class Cipher k bitsPerChunk => StreamCipher k (bitsPerChunk : Nat) | k where
  generateKeystream : k -> Stream (Bits bitsPerChunk)

-- Stream ciphers are automorphic, so the encryption and decryption algorithms
-- are identical. I don’t know when that would ever be useful, but if it is, you
-- can just use `confound*` to handle whichever way you want.

confoundStream : StreamCipher k b => k -> Stream (Bits b) -> Stream (Bits b)
confoundStream key = Prelude.Stream.zipWith xor (generateKeystream key)

encryptStream : StreamCipher k b => k -> Stream (Bits b) -> Stream (Bits b)
encryptStream = confoundStream

decryptStream : StreamCipher k b => k -> Stream (Bits b) -> Stream (Bits b)
decryptStream = confoundStream

takeV : (n : Nat) -> (xs : Stream a) -> Vect n a
takeV Z     _         = []
takeV (S n) (x :: xs) = x :: (takeV n xs)

confoundMessage : StreamCipher k b => k -> List (Bits b) -> List (Bits b)
confoundMessage key message =
  toList (zipWith xor
                  (takeV (length message) (generateKeystream key))
                  (fromList message))

instance StreamCipher sc b => Encrypter sc b where
  encryptMessage = confoundMessage

instance StreamCipher sc b => Decrypter sc b where
  decryptMessage = confoundMessage

instance (StreamCipher sc b, Encrypter sc b, Decrypter sc b) =>
  SymmetricCipher sc b where

confound : (StreamCipher k b, Serializable i, Serializable o) => k -> i -> o
confound key = decode . confoundMessage key . encode
