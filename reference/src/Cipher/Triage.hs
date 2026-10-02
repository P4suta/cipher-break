-- SPDX-License-Identifier: MIT OR Apache-2.0

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

data Statistic = Statistic
  { statName :: String
  , statTail :: Tail
  , statOf :: [Letter] -> Double
  }

data Tail = Upper | Lower
  deriving (Eq, Show)

doubles :: [Letter] -> Double
doubles ls = fromIntegral (length (filter id (zipWith (==) ls (drop 1 ls))))

repetition :: Int -> [Letter] -> Double
repetition n ls = fromIntegral (total - M.size table)
  where
    grams = [take n s | s <- suffixes, length s >= n]
    suffixes = takeWhile (not . null) (iterate (drop 1) ls)
    table = M.fromListWith (+) [(g, 1 :: Int) | g <- grams]
    total = length grams

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

vowels :: [Letter] -> Double
vowels ls = fromIntegral (length [l | l <- ls, l `elem` [0, 4, 8, 14, 20]])

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

longestRun :: [Letter] -> Double
longestRun = fromIntegral . foldr step (0 :: Int) . runs
  where
    runs ls = [length g | g <- group ls]
    step n acc = max n acc

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

data Verdict = Verdict
  { verdictName :: String
  , verdictObserved :: Double
  , verdictMean :: Double
  , verdictSd :: Double
  , verdictZ :: Double
  , verdictP :: Double
  }
  deriving (Eq, Show)

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

triage :: Int -> [Letter] -> Seed -> [Verdict]
triage trials ls s0 = [assess st ls samples | st <- statistics]
  where
    samples = take trials (randomKeys (length ls) s0)

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
