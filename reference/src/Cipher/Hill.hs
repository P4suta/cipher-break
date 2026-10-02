-- SPDX-License-Identifier: MIT OR Apache-2.0

module Cipher.Hill
  ( Matrix (..)
  , determinant
  , invertible
  , matrices
  , apply
  ) where

import Cipher.Alphabet (Letter, alphabetSize)

data Matrix = Matrix Int Int Int Int
  deriving (Eq, Ord, Show)

determinant :: Matrix -> Int
determinant (Matrix a b c d) = (a * d - b * c) `mod` alphabetSize

invertible :: Matrix -> Bool
invertible m = gcd (determinant m) alphabetSize == 1

matrices :: [Matrix]
matrices =
  [ m
  | a <- [0 .. alphabetSize - 1]
  , b <- [0 .. alphabetSize - 1]
  , c <- [0 .. alphabetSize - 1]
  , d <- [0 .. alphabetSize - 1]
  , let m = Matrix a b c d
  , invertible m
  ]

apply :: Matrix -> [Letter] -> [Letter]
apply (Matrix a b c d) = go
  where
    go (x : y : rest) =
      (a * x + b * y) `mod` alphabetSize : (c * x + d * y) `mod` alphabetSize : go rest
    go rest = rest
