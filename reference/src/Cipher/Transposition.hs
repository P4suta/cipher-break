-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | Ciphers that move letters without changing them.
--
-- A transposition leaves every letter count exactly as it found it, so the
-- index of coincidence passes straight through and identifies the class
-- outright: a ciphertext whose index of coincidence is not that of some
-- language was not produced by one of these. That makes them cheap to rule in
-- or out before any key is tried, which is worth more than the small key
-- spaces below.
module Cipher.Transposition
  ( columnar
  , columnarKeys
  , railFence
  , railKeys
  ) where

import Cipher.Alphabet (Letter)
import Data.List (permutations, sortOn)

-- | Undo a columnar transposition: read the columns back in key order.
--
-- The text was written across a grid of the given width and taken off column
-- by column, in the order the key gives. Recovering it means giving each
-- column back its length — the last row is usually short — and interleaving.
columnar :: [Int] -> [Letter] -> [Letter]
columnar key ct
  | width == 0 = ct
  | otherwise = concat (transposeRagged (reorder columns))
  where
    width = length key
    n = length ct
    rows = n `div` width
    spare = n `mod` width
    -- Columns are taken off in key order, and the columns that fall in the first `spare` positions of the grid are the long ones.
    lengths = [if position < spare then rows + 1 else rows | position <- key]
    columns = cut lengths ct
    cut [] _ = []
    cut (l : ls) xs = let (a, b) = splitAt l xs in a : cut ls b
    reorder cols = map snd (sortOn fst (zip key cols))
    transposeRagged cols
      | all null cols = []
      | otherwise = [x | (x : _) <- cols] : transposeRagged [drop 1 c | c <- cols]

-- | Every column order for a given width, which is only tractable while the
-- width is small.
columnarKeys :: Int -> [(String, [Int])]
columnarKeys width = [(show p, p) | p <- permutations [0 .. width - 1]]

-- | Undo a rail fence of the given height.
railFence :: Int -> [Letter] -> [Letter]
railFence rails ct
  | rails < 2 = ct
  | otherwise = map snd (sortOn fst (zip order ct))
  where
    pattern' = cycle ([0 .. rails - 1] ++ [rails - 2, rails - 3 .. 1])
    assignment = take (length ct) pattern'
    order = map snd (sortOn fst (zip assignment [0 :: Int ..]))

railKeys :: Int -> [Int]
railKeys n = [2 .. max 2 (min 12 (n `div` 2))]
