module Data.Crypto.Encryption.Block

import Data.Bits
import Data.Crypto.Util
import Data.Crypto.Encryption

%default total
%access private

||| for a block cypher, you only need to provide functions to encrypt/decrypt a
||| single block.
public
class BlockCipher k (bitsPerBlock : Nat) (maximumBlocks : Nat) | k where
  encryptBlock : k -> Bits bitsPerBlock -> Bits bitsPerBlock
  decryptBlock : k -> Bits bitsPerBlock -> Bits bitsPerBlock
  -- blockTranslation : k -> Iso b b
  -- blockTranslation = MkIso (encryptBlock k) (decryptBlock k)

||| The encryption mode specifies how to apply a block cipher to multiple blocks
public
class EncryptionMode (em : Nat -> Type) where
  encryptBlocks : BlockCipher k bitsPerBlock mb
                  => k -> em bitsPerBlock -> List (Bits bitsPerBlock)
                  -> List (Bits bitsPerBlock)
  decryptBlocks : BlockCipher k bitsPerBlock mb
                  => k -> em bitsPerBlock -> List (Bits bitsPerBlock)
                  -> List (Bits bitsPerBlock)

instance (BlockCipher bc bitsPerBlock _, EncryptionMode em) =>
         Cipher (bc, em bitsPerBlock) bitsPerBlock where

instance (BlockCipher bc bitsPerBlock _, EncryptionMode em) =>
         Encrypter (bc, em bitsPerBlock) bitsPerBlock where
  encryptMessage = uncurry encryptBlocks

instance (BlockCipher bc bitsPerBlock _, EncryptionMode em) =>
         Decrypter (bc, em bitsPerBlock) bitsPerBlock where
  decryptMessage = uncurry decryptBlocks

instance (BlockCipher bc bitsPerBlock _, EncryptionMode em) =>
         SymmetricCipher (bc, em bitsPerBlock) bitsPerBlock where
