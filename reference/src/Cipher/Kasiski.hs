-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | Kasiski examination: repeated ciphertext, and what its spacing implies.
--
-- A substring that repeats usually means the same plaintext met the same part
-- of the key, so the distance between the two occurrences is a multiple of the
-- period. Short texts also repeat by chance, so the output is a tally to weigh
-- rather than an answer.
module Cipher.Kasiski
  ( Repeat (..)
  , repeats
  , factorTally
  ) where

import Cipher.Alphabet (Letter, fromLetters)
import Data.List (sortOn, tails)
import qualified Data.Map.Strict as M

-- | A substring that occurs more than once, with the positions it occurs at.
data Repeat = Repeat
  { repeatText :: String
  , repeatPositions :: [Int]
  , repeatDistances :: [Int]
  }
  deriving (Eq, Show)

-- | Every substring of the given length occurring at least twice, longest
-- distances first.
repeats :: Int -> [Letter] -> [Repeat]
repeats n ls =
  [ Repeat t (reverse ps) (gaps (reverse ps))
  | (t, ps) <- M.toList table
  , length ps > 1
  ]
    `orderedBy` (negate . length . repeatPositions)
  where
    windows = [(fromLetters (take n s), i) | (i, s) <- zip [0 ..] (tails ls), length s >= n]
    table = M.fromListWith (++) [(t, [i]) | (t, i) <- windows]
    gaps ps = zipWith (-) (drop 1 ps) ps
    orderedBy xs f = sortOn f xs

-- | For each candidate period, how many observed distances it divides.
--
-- The tally covers @2..limit@; a period only ever explains a distance it
-- divides exactly.
factorTally :: Int -> [Int] -> [(Int, Int)]
factorTally limit ds =
  [ (p, length [d | d <- ds, d > 0, d `mod` p == 0])
  | p <- [2 .. limit]
  ]
