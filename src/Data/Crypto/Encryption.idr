module Data.Crypto.Encryption

import Data.Bits
import Data.Crypto.Util

%default total
%access public

class Cipher c (bitsPerChunk : Nat) | c where

class Cipher e bitsPerChunk => Encrypter e (bitsPerChunk : Nat) | e where
  encryptMessage : e -> List (Bits bitsPerChunk) -> List (Bits bitsPerChunk)
  
class Cipher d bitsPerChunk => Decrypter d (bitsPerChunk : Nat) | d where
  decryptMessage : d -> List (Bits bitsPerChunk) -> List (Bits bitsPerChunk)

encrypt : (Encrypter c b, Serializable pt, Serializable ct) => c -> pt -> ct
encrypt cipher = decode . encryptMessage cipher . encode

decrypt : (Decrypter c b, Serializable pt, Serializable ct) => c -> pt -> ct
decrypt cipher = decode . decryptMessage cipher . encode

class (Encrypter c bitsPerChunk, Decrypter c bitsPerChunk) =>
  SymmetricCipher c (bitsPerChunk : Nat) | c where

class (Encrypter p pb, Decrypter v vb) =>
  AsymmetricCipher p v (pb : Nat) (vb : Nat) | p, v where
