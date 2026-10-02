-- SPDX-License-Identifier: MIT OR Apache-2.0

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

data Family
  =
    Vigenere
  |
    Beaufort
  |
    VariantBeaufort
  deriving (Eq, Ord, Show, Enum, Bounded)

families :: [Family]
families = [minBound .. maxBound]

encipher :: Family -> [Letter] -> [Letter] -> [Letter]
encipher fam key = zipWith (encipherLetter fam) (cycle key')
  where
    key' = if null key then [0] else key

encipherLetter :: Family -> Letter -> Letter -> Letter
encipherLetter fam k p = case fam of
  Vigenere -> (p + k) `mod` alphabetSize
  Beaufort -> (k - p) `mod` alphabetSize
  VariantBeaufort -> (p - k) `mod` alphabetSize

decipher :: Family -> [Letter] -> [Letter] -> [Letter]
decipher fam key = zipWith (decipherLetter fam) (cycle key')
  where
    key' = if null key then [0] else key

decipherLetter :: Family -> Letter -> Letter -> Letter
decipherLetter fam k c = case fam of
  Vigenere -> (c - k) `mod` alphabetSize
  Beaufort -> (k - c) `mod` alphabetSize
  VariantBeaufort -> (c + k) `mod` alphabetSize

every :: Int -> [a] -> [a]
every n xs
  | n <= 1 = xs
  | otherwise = go xs
  where
    go [] = []
    go (y : ys) = y : go (drop (n - 1) ys)

columns :: Int -> [a] -> [[a]]
columns n xs
  | n <= 1 = [xs]
  | otherwise = [every n (drop i xs) | i <- [0 .. n - 1]]
