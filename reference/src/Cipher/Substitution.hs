-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | The plain substitution cipher, and the affine and shift ciphers inside it.
--
-- This is the cipher most puzzles turn out to be, and the one a general tool
-- has least excuse for missing. Its key space is 26 factorial, far past
-- enumeration, but its landscape is the friendliest in classical cryptography:
-- swapping two letters of a wrong key changes two letters of the plaintext and
-- nothing else, so a search always knows which way is uphill.
module Cipher.Substitution
  ( Key
  , identityKey
  , applyKey
  , invertKey
  , shiftKey
  , affineKey
  , affineKeys
  , atbashKey
  ) where

import Cipher.Alphabet (Letter, alphabetSize)
import Data.Array (Array, listArray, (!))

-- | Where each of the 26 letters goes.
type Key = [Letter]

identityKey :: Key
identityKey = [0 .. alphabetSize - 1]

applyKey :: Key -> [Letter] -> [Letter]
applyKey key = map (table !)
  where
    table :: Array Int Letter
    table = listArray (0, alphabetSize - 1) (take alphabetSize (key ++ [0 ..]))

-- | The key that undoes another.
invertKey :: Key -> Key
invertKey key =
  [ case [i | (i, k) <- zip [0 ..] key, k == l] of
      (i : _) -> i
      [] -> 0
  | l <- [0 .. alphabetSize - 1]
  ]

-- | A Caesar shift, as a substitution key.
shiftKey :: Int -> Key
shiftKey n = [(l + n) `mod` alphabetSize | l <- [0 .. alphabetSize - 1]]

-- | @l -> a*l + b@, defined only when @a@ has an inverse modulo 26.
affineKey :: Int -> Int -> Key
affineKey a b = [(a * l + b) `mod` alphabetSize | l <- [0 .. alphabetSize - 1]]

-- | Every affine key there is: twelve multipliers, 26 offsets.
affineKeys :: [(String, Key)]
affineKeys =
  [ ("a=" ++ show a ++ " b=" ++ show b, affineKey a b)
  | a <- [1 .. alphabetSize - 1]
  , gcd a alphabetSize == 1
  , b <- [0 .. alphabetSize - 1]
  ]

-- | The alphabet reversed.
atbashKey :: Key
atbashKey = [alphabetSize - 1 - l | l <- [0 .. alphabetSize - 1]]
