-- SPDX-License-Identifier: MIT OR Apache-2.0

module Cipher.Superpose
  ( mutualIC
  , alignment
  , merge
  , mergedIC
  , nullDistribution
  , Significance (..)
  , significance
  , significanceOf
  , FamilyWise (..)
  , familywise
  ) where

import Cipher.Alphabet (Letter, alphabetSize)
import Cipher.Periodic (columns)
import Cipher.Random (Seed, shuffles)
import Cipher.Stats (counts, indexOfCoincidence)

mutualIC :: [Letter] -> [Letter] -> Int -> Double
mutualIC a b d
  | na == 0 || nb == 0 = 0
  | otherwise =
      sum [fromIntegral (ca !! i * cb !! ((i + d) `mod` alphabetSize)) | i <- [0 .. alphabetSize - 1]]
        / fromIntegral (na * nb)
  where
    ca = counts a
    cb = counts b
    na = length a
    nb = length b

unshift :: Int -> [Letter] -> [Letter]
unshift d = map (\c -> (c - d) `mod` alphabetSize)

merge :: Int -> [Int] -> [Letter] -> [Letter]
merge p shifts ct = concat (zipWith unshift shifts (columns p ct))

alignment :: Int -> [Letter] -> [Int]
alignment p ct
  | p <= 1 = [0]
  | otherwise = settle initial (objective initial)
  where
    cols = columns p ct
    initial = case cols of
      (reference : rest) -> 0 : map (bestAgainst reference) rest
      [] -> []
    bestAgainst reference col =
      snd (maximum [(mutualIC reference col d, d) | d <- [0 .. alphabetSize - 1]])
    objective shifts = indexOfCoincidence (merge p shifts ct)
    settle shifts best =
      let (shifts', best') = sweep shifts best
       in if best' > best then settle shifts' best' else shifts
    sweep shifts best = foldl improveAt (shifts, best) [1 .. p - 1]
    improveAt (shifts, best) i =
      let (v, shifts') =
            maximum [(objective s, s) | d <- [0 .. alphabetSize - 1], let s = substitute i d shifts]
       in if v > best then (shifts', v) else (shifts, best)
    substitute i d xs = take i xs ++ [d] ++ drop (i + 1) xs

mergedIC :: [Letter] -> Int -> Double
mergedIC ct p = indexOfCoincidence (merge p (alignment p ct) ct)

nullDistribution :: Int -> Int -> [Letter] -> Seed -> [Double]
nullDistribution trials p ct s0 =
  [mergedIC sample p | sample <- take trials (shuffles ct s0)]

data Significance = Significance
  { sigObserved :: Double
  , sigNullMean :: Double
  , sigNullSd :: Double
  , sigZ :: Double
  }
  deriving (Eq, Show)

significance :: Int -> Int -> [Letter] -> Seed -> Significance
significance = significanceOf mergedIC

significanceOf :: ([Letter] -> Int -> Double) -> Int -> Int -> [Letter] -> Seed -> Significance
significanceOf statistic trials p ct s0 = Significance observed mean sd z
  where
    observed = statistic ct p
    sample = [statistic shuffled p | shuffled <- take trials (shuffles ct s0)]
    n = fromIntegral (max 1 (length sample))
    mean = sum sample / n
    sd = sqrt (max 1e-12 (sum [(x - mean) ^ (2 :: Int) | x <- sample] / n))
    z = (observed - mean) / sd

data FamilyWise = FamilyWise
  { fwPeriod :: Int
  , fwZ :: Double
  , fwNullMean :: Double
  , fwP :: Double
  }
  deriving (Eq, Show)

familywise :: ([Letter] -> Int -> Double) -> Int -> [Int] -> [Letter] -> Seed -> FamilyWise
familywise statistic trials periods ct s0 = FamilyWise chosenPeriod chosenZ nullMean pValue
  where
    stream = shuffles ct s0
    (calibration, scored) = splitAt trials stream
    reference =
      [ (p, moments [statistic text p | text <- calibration])
      | p <- periods
      ]
    moments xs =
      let n = fromIntegral (max 1 (length xs))
          m = sum xs / n
       in (m, sqrt (max 1e-15 (sum [(x - m) ^ (2 :: Int) | x <- xs] / n)))
    zAt text p = case lookup p reference of
      Just (m, sd) -> (statistic text p - m) / sd
      Nothing -> 0
    peak text = maximum [(zAt text p, p) | p <- periods]
    (chosenZ, chosenPeriod) = peak ct
    nullPeaks = [fst (peak text) | text <- take trials scored]
    nullMean = sum nullPeaks / fromIntegral (max 1 (length nullPeaks))
    pValue =
      fromIntegral (length (filter (>= chosenZ) nullPeaks))
        / fromIntegral (max 1 (length nullPeaks))
