-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | The attacks themselves, each returning ranked 'Candidate's.
module Cipher.Attack
  ( Candidate (..)
  , icByPeriod
  , chiKey
  , periodAttack
  , climb
  , climbAttack
  , searchKeys
  , rescore
  , rank
  ) where

import Cipher.Alphabet (Letter, alphabetSize, fromLetters)
import Cipher.Periodic (Family, columns, decipher, families)
import Cipher.Random (randomKeys, seed)
import Cipher.Stats (chiSquared, indexOfCoincidence)
import Data.List (sortOn)
import qualified Data.Set as S

-- | One reading of the ciphertext, with the score that earned its place.
data Candidate = Candidate
  { candFamily :: Family
  , candKey :: [Letter]
  , candPlain :: [Letter]
  , candScore :: Double
  }
  deriving (Eq, Show)

-- | Mean index of coincidence across the columns a period would create.
--
-- At the true period every column is a simple shift of English and the mean
-- rises towards @0.066@; at a wrong period the columns stay mixed and it sits
-- near @0.038@.
icByPeriod :: [Letter] -> Int -> Double
icByPeriod ls n
  | null usable = 0
  | otherwise = sum (map indexOfCoincidence usable) / fromIntegral (length usable)
  where
    usable = [c | c <- columns n ls, length c >= 2]

-- | The key a chi-squared fit picks for a given family and period.
--
-- Each column is solved on its own, which is exactly the reduction a repeating
-- key permits.
chiKey :: Family -> Int -> [Letter] -> [Letter]
chiKey fam n ct = map solveColumn (columns n ct)
  where
    solveColumn col =
      snd (minimum [(chiSquared (decipher fam [k] col), k) | k <- [0 .. alphabetSize - 1]])

-- | Solve every family at every period in the given range.
periodAttack :: ([Letter] -> Double) -> [Int] -> [Letter] -> [Candidate]
periodAttack score periods ct =
  [ Candidate fam key plain (score plain)
  | fam <- families
  , n <- periods
  , let key = chiKey fam n ct
  , let plain = decipher fam key ct
  ]

-- | Improve a key one position at a time until no single change helps.
--
-- The chi-squared fit judges each column alone, which is all a column of 18
-- letters can support; this judges the whole plaintext instead, so a key
-- letter is chosen for the words it completes rather than for the histogram it
-- flattens. The two are complementary, and the fit is the natural start.
climb :: ([Letter] -> Double) -> Family -> [Letter] -> [Letter] -> ([Letter], Double)
climb score fam ct start = settle start (score (decipher fam start ct))
  where
    settle key best =
      let (key', best') = sweep key best
       in if best' > best then settle key' best' else (key, best)
    sweep key best = foldl improveAt (key, best) [0 .. length key - 1]
    improveAt (key, best) i =
      let (s, key') = maximum [(score (decipher fam k ct), k) | l <- [0 .. alphabetSize - 1], let k = substitute i l key]
       in if s > best then (key', s) else (key, best)
    substitute i l key = take i key ++ [l] ++ drop (i + 1) key

-- | Hill-climb every family at every period, from several starting keys.
--
-- The chi-squared key is one start and the rest are drawn from a fixed seed:
-- coordinate ascent can stall in a local maximum, and the cheapest way out is
-- to have begun somewhere else.
climbAttack :: ([Letter] -> Double) -> Int -> [Int] -> [Letter] -> [Candidate]
climbAttack score restarts periods ct =
  [ Candidate fam key (decipher fam key ct) s
  | fam <- families
  , n <- periods
  , let starts = chiKey fam n ct : replicate n 0 : take restarts (randomKeys n (seed (fromIntegral n * 6364136223846793005)))
  , (key, s) <- map (climb score fam ct) starts
  ]

-- | Score a stream of key proposals and keep only the best @k@.
--
-- The stream is far too long to sort: a word list is a few hundred thousand
-- keys and every family multiplies it again. Holding a bounded set instead
-- lets the plaintexts that lose be collected as soon as they are scored, so
-- the search costs memory proportional to @k@ and not to the word list.
searchKeys :: ([Letter] -> Double) -> Int -> [Letter] -> [(Family, [Letter])] -> [Candidate]
searchKeys score k ct proposals = map materialise (S.toDescList best)
  where
    best = foldl' step S.empty proposals
    step acc (fam, key)
      | null key = acc
      | otherwise =
          let s = score (decipher fam key ct)
              acc' = S.insert (s, key, fam) acc
           in if S.size acc' > k then S.deleteMin acc' else acc'
    materialise (s, key, fam) = Candidate fam key (decipher fam key ct) s

-- | Replace every candidate's score, for a second pass with a costlier judge.
rescore :: ([Letter] -> Double) -> [Candidate] -> [Candidate]
rescore score = map (\c -> c {candScore = score (candPlain c)})

-- | The best candidates, highest score first, one entry per distinct plaintext.
rank :: Int -> [Candidate] -> [Candidate]
rank n = take n . dedupe . sortOn (negate . candScore)
  where
    dedupe = go S.empty
    go _ [] = []
    go seen (c : cs)
      | plain `S.member` seen = go seen cs
      | otherwise = c : go (S.insert plain seen) cs
      where
        plain = fromLetters (candPlain c)
