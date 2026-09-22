-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | Five-by-five squares, and the moves a search makes over them.
--
-- Bifid, Playfair and the two- and four-square ciphers all key themselves with
-- an arrangement of 25 letters, so they all face the same search problem and
-- can share the same moves over it.
--
-- One letter has to be left out, and for a given ciphertext the choice is not
-- free: every ciphertext letter must be somewhere in the square, so the letter
-- omitted has to be one the ciphertext never uses. That usually leaves a
-- handful of candidates instead of 26, and it is the cheapest constraint these
-- ciphers offer.
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

-- | The 25 letters of a square, in reading order.
type Square = [Letter]

squareSize :: Int
squareSize = 5

-- | The plain alphabet with one letter left out.
squareOmitting :: Letter -> Square
squareOmitting missing = [l | l <- [0 .. alphabetSize - 1], l /= missing]

-- | The letters a square could have omitted, given what the ciphertext uses.
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

-- | Exchange two letters, the move a square search is built from.
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
