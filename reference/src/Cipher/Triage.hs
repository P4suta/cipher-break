-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | What kind of thing is this, before any attempt to read it.
--
-- Every attack in this package assumes something: a period, a family, a
-- language. Before assuming any of them it is worth asking the question that
-- has no assumptions in it — does this text differ from 72 letters drawn at
-- random? Each statistic below is computed on the text and on a large sample
-- of random texts of the same length, and reported with the share of the
-- sample that matched or beat it. A statistic that nothing distinguishes is
-- not evidence, however suggestive it looks on its own.
module Cipher.Triage
  ( Statistic (..)
  , Tail (..)
  , statistics
  , Verdict (..)
  , assess
  , triage
  , windows
  ) where

import Cipher.Alphabet (Letter, letterChar)
import Cipher.Random (Seed, randomKeys)
import Cipher.Stats (indexOfCoincidence)
import Data.List (group)
import qualified Data.Map.Strict as M

-- | A number computed from a text, and the name to report it under.
data Statistic = Statistic
  { statName :: String
  , statTail :: Tail
  , statOf :: [Letter] -> Double
  }

-- | Which end of the null distribution counts as surprising.
data Tail = Upper | Lower
  deriving (Eq, Show)

-- | Adjacent equal letters, which most fractionating ciphers suppress and most
-- substitution ciphers pass through.
doubles :: [Letter] -> Double
doubles ls = fromIntegral (length (filter id (zipWith (==) ls (drop 1 ls))))

-- | Occurrences of an n-gram beyond its first, summed over all n-grams.
--
-- This is what a Kasiski examination looks at, counted rather than listed.
repetition :: Int -> [Letter] -> Double
repetition n ls = fromIntegral (total - M.size table)
  where
    grams = [take n s | s <- suffixes, length s >= n]
    suffixes = takeWhile (not . null) (iterate (drop 1) ls)
    table = M.fromListWith (+) [(g, 1 :: Int) | g <- grams]
    total = length grams

-- | Index of coincidence over non-overlapping pairs.
--
-- A cipher that enciphers two letters at a time leaves its fingerprint here
-- rather than on single letters, because it is pairs it maps consistently.
digraphIC :: [Letter] -> Double
digraphIC ls
  | n < 2 = 0
  | otherwise = sum [fromIntegral (c * (c - 1)) | c <- M.elems table] / fromIntegral (n * (n - 1))
  where
    pairs = chunk ls
    chunk (a : b : rest) = (a, b) : chunk rest
    chunk _ = []
    table = M.fromListWith (+) [(p, 1 :: Int) | p <- pairs]
    n = length pairs

-- | How many of the letters are vowels.
--
-- Worth a line of its own because a person inventing a random-looking string
-- avoids vowels without meaning to: letters that would make the result read
-- like a word get passed over. A cipher has no such preference.
vowels :: [Letter] -> Double
vowels ls = fromIntegral (length [l | l <- ls, l `elem` [0, 4, 8, 14, 20]])

-- | Adjacent letters that neighbour each other on a QWERTY keyboard.
--
-- The other half of the same suspicion: a mashed keyboard leaves its own
-- geometry behind, and this is what that looks like when counted.
qwertyRuns :: [Letter] -> Double
qwertyRuns ls = fromIntegral (length (filter neighbouring (zip ls (drop 1 ls))))
  where
    rows = ["QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"]
    places = [(c, (r, i)) | (r, row) <- zip [0 :: Int ..] rows, (i, c) <- zip [0 :: Int ..] row]
    place l = lookup (letterChar l) places
    neighbouring (a, b) = case (place a, place b) of
      (Just (r1, c1), Just (r2, c2)) ->
        abs (r1 - r2) <= 1 && abs (c1 - c2) <= 1 && (r1, c1) /= (r2, c2)
      _ -> False

-- | The longest stretch of one repeated letter.
longestRun :: [Letter] -> Double
longestRun = fromIntegral . foldr step (0 :: Int) . runs
  where
    runs ls = [length g | g <- group ls]
    step n acc = max n acc

-- | How many of the 26 letters appear at all.
coverage :: [Letter] -> Double
coverage ls = fromIntegral (M.size (M.fromListWith (+) [(l, 1 :: Int) | l <- ls]))

statistics :: [Statistic]
statistics =
  [ Statistic "index of coincidence" Upper indexOfCoincidence
  , Statistic "adjacent doubles" Upper doubles
  , Statistic "repeated bigrams" Upper (repetition 2)
  , Statistic "repeated trigrams" Upper (repetition 3)
  , Statistic "digraph IC" Upper digraphIC
  , Statistic "distinct letters" Lower coverage
  , Statistic "vowels" Lower vowels
  , Statistic "QWERTY neighbours" Upper qwertyRuns
  , Statistic "longest run" Upper longestRun
  ]

-- | An observed statistic beside the null distribution it has to stand out
-- from.
data Verdict = Verdict
  { verdictName :: String
  , verdictObserved :: Double
  , verdictMean :: Double
  , verdictSd :: Double
  , verdictZ :: Double
  , verdictP :: Double
  }
  deriving (Eq, Show)

-- | The share of the null sample that matched or beat the observation.
--
-- Reported beside the z score because these statistics are counts over 72
-- letters: their null distributions are lumpy and discrete, and a z score
-- quietly assumes they are neither.
assess :: Statistic -> [Letter] -> [[Letter]] -> Verdict
assess st ls samples = Verdict (statName st) observed mean sd z p
  where
    observed = statOf st ls
    values = map (statOf st) samples
    n = fromIntegral (max 1 (length values))
    mean = sum values / n
    sd = sqrt (max 1e-15 (sum [(v - mean) ^ (2 :: Int) | v <- values] / n))
    z = (observed - mean) / sd
    beaten = case statTail st of
      Upper -> length (filter (>= observed) values)
      Lower -> length (filter (<= observed) values)
    p = fromIntegral beaten / n

-- | Run every statistic against a sample of uniform random texts.
triage :: Int -> [Letter] -> Seed -> [Verdict]
triage trials ls s0 = [assess st ls samples | st <- statistics]
  where
    samples = take trials (randomKeys (length ls) s0)

-- | Evenly spaced, non-overlapping windows of a corpus.
--
-- Triage compares the text against noise, which says whether it is structured.
-- The other half of the question needs the opposite comparison: against real
-- language, cut to the same length. A cipher that preserves letter counts —
-- any simple substitution, any transposition, and any stack of the two — hands
-- these statistics through untouched, so a text that cannot pass for language
-- here cannot have come from one of those.
windows :: Int -> Int -> [Letter] -> [[Letter]]
windows width count corpus
  | width <= 0 || count <= 0 = []
  | otherwise = take count [c | (i, c) <- zip [0 :: Int ..] chunks, i `mod` stride == 0]
  where
    chunks = chunksOf width corpus
    stride = max 1 (length chunks `div` count)
    chunksOf n xs = case splitAt n xs of
      (chunk, rest)
        | length chunk < n -> []
        | otherwise -> chunk : chunksOf n rest
