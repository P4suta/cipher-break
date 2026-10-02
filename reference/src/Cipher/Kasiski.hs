-- SPDX-License-Identifier: MIT OR Apache-2.0

module Cipher.Kasiski
  ( Repeat (..)
  , repeats
  , factorTally
  ) where

import Cipher.Alphabet (Letter, fromLetters)
import Data.List (sortOn, tails)
import qualified Data.Map.Strict as M

data Repeat = Repeat
  { repeatText :: String
  , repeatPositions :: [Int]
  , repeatDistances :: [Int]
  }
  deriving (Eq, Show)

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

factorTally :: Int -> [Int] -> [(Int, Int)]
factorTally limit ds =
  [ (p, length [d | d <- ds, d > 0, d `mod` p == 0])
  | p <- [2 .. limit]
  ]
