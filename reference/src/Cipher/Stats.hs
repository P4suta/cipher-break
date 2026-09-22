-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | Frequency statistics: the two numbers every classical attack rests on.
module Cipher.Stats
  ( counts
  , frequencies
  , indexOfCoincidence
  , englishFrequencies
  , chiSquared
  ) where

import Cipher.Alphabet (Letter, alphabetSize)
import Data.Array (Array, accumArray, elems)

-- | How often each of the 26 letters occurs, indexed @0..25@.
counts :: [Letter] -> [Int]
counts ls = elems arr
  where
    arr :: Array Int Int
    arr = accumArray (+) 0 (0, alphabetSize - 1) [(l `mod` alphabetSize, 1) | l <- ls]

-- | 'counts' divided by the length; all zeroes for empty input.
frequencies :: [Letter] -> [Double]
frequencies ls
  | n == 0 = replicate alphabetSize 0
  | otherwise = [fromIntegral c / fromIntegral n | c <- counts ls]
  where
    n = length ls

-- | The probability that two letters drawn without replacement match.
--
-- Random text sits near @0.0385@ (which is @1/26@) and English near @0.0667@.
-- A text enciphered with a long key looks random by this measure, which is
-- what makes the statistic a period detector rather than a language detector.
indexOfCoincidence :: [Letter] -> Double
indexOfCoincidence ls
  | n < 2 = 0
  | otherwise = sum [fromIntegral (c * (c - 1)) | c <- counts ls] / fromIntegral (n * (n - 1))
  where
    n = length ls

-- | Letter frequencies of English prose, as fractions summing to one.
englishFrequencies :: [Double]
englishFrequencies =
  map (/ 100)
    [ 8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966
    , 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987
    , 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074
    ]

-- | Pearson's statistic against 'englishFrequencies'; smaller is more English.
chiSquared :: [Letter] -> Double
chiSquared ls
  | n == 0 = 0
  | otherwise = sum (zipWith term (counts ls) englishFrequencies)
  where
    n = length ls
    term observed p =
      let expected = p * fromIntegral n
       in (fromIntegral observed - expected) ^ (2 :: Int) / expected
