-- SPDX-License-Identifier: MIT OR Apache-2.0

module Cipher.Transposition
  ( columnar
  , columnarKeys
  , railFence
  , railKeys
  ) where

import Cipher.Alphabet (Letter)
import Data.List (permutations, sortOn)

columnar :: [Int] -> [Letter] -> [Letter]
columnar key ct
  | width == 0 = ct
  | otherwise = concat (transposeRagged (reorder columns))
  where
    width = length key
    n = length ct
    rows = n `div` width
    spare = n `mod` width
    lengths = [if position < spare then rows + 1 else rows | position <- key]
    columns = cut lengths ct
    cut [] _ = []
    cut (l : ls) xs = let (a, b) = splitAt l xs in a : cut ls b
    reorder cols = map snd (sortOn fst (zip key cols))
    transposeRagged cols
      | all null cols = []
      | otherwise = [x | (x : _) <- cols] : transposeRagged [drop 1 c | c <- cols]

columnarKeys :: Int -> [(String, [Int])]
columnarKeys width = [(show p, p) | p <- permutations [0 .. width - 1]]

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
