-- SPDX-License-Identifier: MIT OR Apache-2.0

module Cipher.Porta
  ( tableCount
  , substitute
  , apply
  ) where

import Cipher.Alphabet (Letter, alphabetSize)

tableCount :: Int
tableCount = alphabetSize `div` 2

substitute :: Int -> Letter -> Letter
substitute table l
  | l < half = (l + n) `mod` half + half
  | otherwise = (l - half - n) `mod` half
  where
    half = tableCount
    n = table `mod` tableCount

apply :: [Int] -> [Letter] -> [Letter]
apply [] ls = ls
apply tables ls = zipWith substitute (cycle tables) ls
