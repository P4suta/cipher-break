-- SPDX-License-Identifier: MIT OR Apache-2.0

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

type Key = [Letter]

identityKey :: Key
identityKey = [0 .. alphabetSize - 1]

applyKey :: Key -> [Letter] -> [Letter]
applyKey key = map (table !)
  where
    table :: Array Int Letter
    table = listArray (0, alphabetSize - 1) (take alphabetSize (key ++ [0 ..]))

invertKey :: Key -> Key
invertKey key =
  [ case [i | (i, k) <- zip [0 ..] key, k == l] of
      (i : _) -> i
      [] -> 0
  | l <- [0 .. alphabetSize - 1]
  ]

shiftKey :: Int -> Key
shiftKey n = [(l + n) `mod` alphabetSize | l <- [0 .. alphabetSize - 1]]

affineKey :: Int -> Int -> Key
affineKey a b = [(a * l + b) `mod` alphabetSize | l <- [0 .. alphabetSize - 1]]

affineKeys :: [(String, Key)]
affineKeys =
  [ ("a=" ++ show a ++ " b=" ++ show b, affineKey a b)
  | a <- [1 .. alphabetSize - 1]
  , gcd a alphabetSize == 1
  , b <- [0 .. alphabetSize - 1]
  ]

atbashKey :: Key
atbashKey = [alphabetSize - 1 - l | l <- [0 .. alphabetSize - 1]]
