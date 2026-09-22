-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | Porta's cipher: periodic, but not built from shifts.
--
-- Porta matters here because it is the hole in superposition. Each column is a
-- reciprocal substitution rather than a rotation, so lining the columns up by
-- a shift finds nothing, however faithfully the period is there. What does
-- still hold is that every column is monoalphabetic, which the plain index of
-- coincidence within the columns can see. Its key space is also thirteen wide
-- per column rather than twenty-six, which puts short periods within reach of
-- simply trying them all.
module Cipher.Porta
  ( tableCount
  , substitute
  , apply
  ) where

import Cipher.Alphabet (Letter, alphabetSize)

-- | Key letters pair up, so there are thirteen tables rather than 26.
tableCount :: Int
tableCount = alphabetSize `div` 2

-- | One letter under one table.
--
-- The transformation is its own inverse, which is why enciphering and
-- deciphering are the same operation.
substitute :: Int -> Letter -> Letter
substitute table l
  | l < half = (l + n) `mod` half + half
  | otherwise = (l - half - n) `mod` half
  where
    half = tableCount
    n = table `mod` tableCount

-- | Apply a repeating list of tables across a text.
apply :: [Int] -> [Letter] -> [Letter]
apply [] ls = ls
apply tables ls = zipWith substitute (cycle tables) ls
