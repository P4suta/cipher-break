-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | Hill's cipher on pairs of letters.
--
-- Enciphering two letters at a time is what flattens the single-letter
-- statistics that every classical attack in this package relies on, so no
-- amount of frequency work touches it. It is also small: a two-by-two key over
-- 26 letters has 157,248 invertible forms, and a machine can simply try all of
-- them. Searching the deciphering matrices directly avoids inverting anything,
-- since every invertible matrix is the inverse of exactly one other.
module Cipher.Hill
  ( Matrix (..)
  , determinant
  , invertible
  , matrices
  , apply
  ) where

import Cipher.Alphabet (Letter, alphabetSize)

-- | A two-by-two matrix over the integers modulo 26.
data Matrix = Matrix Int Int Int Int
  deriving (Eq, Ord, Show)

determinant :: Matrix -> Int
determinant (Matrix a b c d) = (a * d - b * c) `mod` alphabetSize

-- | A matrix is usable exactly when its determinant has an inverse modulo 26.
invertible :: Matrix -> Bool
invertible m = gcd (determinant m) alphabetSize == 1

-- | Every invertible two-by-two matrix.
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

-- | Transform a text two letters at a time; a trailing odd letter is left be.
apply :: Matrix -> [Letter] -> [Letter]
apply (Matrix a b c d) = go
  where
    go (x : y : rest) =
      (a * x + b * y) `mod` alphabetSize : (c * x + d * y) `mod` alphabetSize : go rest
    go rest = rest
