-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | Kerckhoffs' superposition: breaking a periodic cipher without knowing the
-- language it hides.
--
-- Every column of a periodic cipher shows the same plaintext distribution,
-- each moved by its own key letter. The shifts that line the columns back up
-- can therefore be found from the columns alone, with no table of letter
-- frequencies and no guess at the language. What comes out is the plaintext
-- under one unknown shift, and — the point of doing it first — an index of
-- coincidence computed over the whole text rather than over one short column,
-- which is a far steadier answer to the only question that matters early on:
-- is there a period here at all?
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

-- | How much two columns' distributions overlap when the second is moved back
-- by @d@.
--
-- At the right @d@ this reaches the language's index of coincidence; at any
-- other it falls to about @1/26@.
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

-- | Move every letter of a column back by a shift.
unshift :: Int -> [Letter] -> [Letter]
unshift d = map (\c -> (c - d) `mod` alphabetSize)

-- | Put the columns back on a common footing and read them as one text.
merge :: Int -> [Int] -> [Letter] -> [Letter]
merge p shifts ct = concat (zipWith unshift shifts (columns p ct))

-- | The shifts that line the columns up, with the first column held at zero.
--
-- Pairing every column against the first is the textbook move and is also the
-- noisiest one available, because a column of a short message is a thin
-- sample. The pairing is therefore only a starting point: the shifts are then
-- improved one at a time against the whole merged text, which each round knows
-- more about the plaintext distribution than any single column ever does.
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

-- | The index of coincidence of the merged text at a given period.
--
-- Read down the periods, this is the period detector: a natural language sits
-- near @0.065@ or above and anything else stays near @0.038@.
mergedIC :: [Letter] -> Int -> Double
mergedIC ct p = indexOfCoincidence (merge p (alignment p ct) ct)

-- | What 'mergedIC' returns for texts that are known to hide nothing.
--
-- Aligning @p@ columns means choosing @p - 1@ shifts to maximise a statistic,
-- so the statistic rises with the period whether or not a period is there.
-- Reading 'mergedIC' down the periods therefore says nothing on its own: the
-- only honest comparison is against the same procedure run on text with the
-- same letters in an order known to be meaningless.
nullDistribution :: Int -> Int -> [Letter] -> Seed -> [Double]
nullDistribution trials p ct s0 =
  [mergedIC sample p | sample <- take trials (shuffles ct s0)]

-- | An observed value beside the null it has to beat.
data Significance = Significance
  { sigObserved :: Double
  , sigNullMean :: Double
  , sigNullSd :: Double
  , sigZ :: Double
  }
  deriving (Eq, Show)

-- | How far above chance the merged index of coincidence is, in standard
-- deviations of the null.
significance :: Int -> Int -> [Letter] -> Seed -> Significance
significance = significanceOf mergedIC

-- | 'significance' for any statistic that takes a text and a period.
--
-- Superposition is not the only way a period shows itself, and it only sees
-- periods built from shifts. A cipher that gives each column its own mixed
-- alphabet — Porta, or any of the Quagmires — leaves superposition nothing to
-- align, but still leaves every column a monoalphabetic substitution, and so
-- still raises the plain index of coincidence within the columns. Whichever
-- statistic is used, it needs the same null.
significanceOf :: ([Letter] -> Int -> Double) -> Int -> Int -> [Letter] -> Seed -> Significance
significanceOf statistic trials p ct s0 = Significance observed mean sd z
  where
    observed = statistic ct p
    sample = [statistic shuffled p | shuffled <- take trials (shuffles ct s0)]
    n = fromIntegral (max 1 (length sample))
    mean = sum sample / n
    sd = sqrt (max 1e-12 (sum [(x - mean) ^ (2 :: Int) | x <- sample] / n))
    z = (observed - mean) / sd

-- | The largest z across a range of periods, tested as one claim.
--
-- Reporting sixteen z scores and then pointing at the biggest is how a
-- one-in-twenty coincidence gets mistaken for a finding. The statistic that
-- was actually chosen is "the largest of sixteen", so that is the statistic
-- that has to be calibrated: the same maximum is taken over noise, and the
-- observed maximum is read against those.
--
-- The two halves of the shuffle stream are kept apart on purpose. Calibrating
-- the per-period means and deviations on the same draws that are then scored
-- against them would pull every null maximum towards zero and make the
-- observation look better than it is.
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
