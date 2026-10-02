-- SPDX-License-Identifier: MIT OR Apache-2.0

module Cipher.Square
  ( Square
  , squareSize
  , squareOmitting
  , omissionsFor
  , swapPositions
  , perturb
  , randomSquare
  ) where

import Cipher.Alphabet (Letter, alphabetSize)
import Cipher.Random (Seed, nextWord, shuffle)

type Square = [Letter]

squareSize :: Int
squareSize = 5

squareOmitting :: Letter -> Square
squareOmitting missing = [l | l <- [0 .. alphabetSize - 1], l /= missing]

omissionsFor :: [Letter] -> [Letter]
omissionsFor ct = [l | l <- [0 .. alphabetSize - 1], l `notElem` ct]

swapPositions :: Int -> Int -> Square -> Square
swapPositions i j sq
  | i == j = sq
  | otherwise = [pick k x | (k, x) <- zip [0 ..] sq]
  where
    pick k x
      | k == i = sq !! j
      | k == j = sq !! i
      | otherwise = x

perturb :: Seed -> Square -> (Square, Seed)
perturb s0 sq = (swapPositions i j sq, s2)
  where
    n = length sq
    (w1, s1) = nextWord s0
    (w2, s2) = nextWord s1
    i = fromIntegral (w1 `mod` fromIntegral (max 1 n))
    j = fromIntegral (w2 `mod` fromIntegral (max 1 n))

randomSquare :: Letter -> Seed -> (Square, Seed)
randomSquare missing = shuffle (squareOmitting missing)
