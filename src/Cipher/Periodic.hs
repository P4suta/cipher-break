-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | The three ciphers that reuse a key letter every @n@ positions.
--
-- They differ only in the arithmetic joining plaintext, key and ciphertext, so
-- one 'Family' parameter lets every attack in this package cover all three at
-- once instead of being written three times.
module Cipher.Periodic
  ( Family (..)
  , families
  , encipher
  , decipher
  , encipherLetter
  , decipherLetter
  , columns
  , every
  ) where

import Cipher.Alphabet (Letter, alphabetSize)

-- | Which member of the Vigenere family a key is read under.
data Family
  = -- | @c = p + k@
    Vigenere
  | -- | @c = k - p@, an involution: enciphering twice returns the plaintext.
    Beaufort
  | -- | @c = p - k@, the Vigenere table used backwards.
    VariantBeaufort
  deriving (Eq, Ord, Show, Enum, Bounded)

families :: [Family]
families = [minBound .. maxBound]

-- | Encipher under a repeating key; an empty key is the identity.
encipher :: Family -> [Letter] -> [Letter] -> [Letter]
encipher fam key = zipWith (encipherLetter fam) (cycle key')
  where
    key' = if null key then [0] else key

-- | One plaintext letter under one key letter.
encipherLetter :: Family -> Letter -> Letter -> Letter
encipherLetter fam k p = case fam of
  Vigenere -> (p + k) `mod` alphabetSize
  Beaufort -> (k - p) `mod` alphabetSize
  VariantBeaufort -> (p - k) `mod` alphabetSize

-- | The inverse of 'encipher' for the same family and key.
decipher :: Family -> [Letter] -> [Letter] -> [Letter]
decipher fam key = zipWith (decipherLetter fam) (cycle key')
  where
    key' = if null key then [0] else key

-- | One ciphertext letter under one key letter.
decipherLetter :: Family -> Letter -> Letter -> Letter
decipherLetter fam k c = case fam of
  Vigenere -> (c - k) `mod` alphabetSize
  Beaufort -> (k - c) `mod` alphabetSize
  VariantBeaufort -> (c + k) `mod` alphabetSize

-- | Every @n@-th element, starting with the first.
every :: Int -> [a] -> [a]
every n xs
  | n <= 1 = xs
  | otherwise = go xs
  where
    go [] = []
    go (y : ys) = y : go (drop (n - 1) ys)

-- | Split a text into the @n@ positions a single key letter enciphered.
--
-- Each column is a monoalphabetic cipher, which is the whole reason a period
-- is worth finding.
columns :: Int -> [a] -> [[a]]
columns n xs
  | n <= 1 = [xs]
  | otherwise = [every n (drop i xs) | i <- [0 .. n - 1]]
