-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | How English a candidate plaintext looks.
--
-- Letter frequency alone is a weak judge over 72 letters, so the judge here is
-- a word list: the best split of the text into dictionary words, scoring a
-- word of length @n@ as @n^2@ and charging a flat penalty for every letter
-- left over. Squaring is what makes the measure discriminating, because a long
-- real word beats any pile of two-letter fragments that covers the same span.
module Cipher.Fitness
  ( Lexicon (..)
  , loadLexicon
  , lexiconFrom
  , cover
  , wordCover
  , segment
  ) where

import Cipher.Alphabet (Letter, fromLetters)
import Data.Array (Array, listArray, (!))
import Data.Char (isAsciiUpper, toLower, toUpper)
import Data.List (maximumBy)
import Data.Ord (comparing)
import qualified Data.Set as S

-- | A word list, upper-cased, with the longest entry length it holds.
data Lexicon = Lexicon
  { lexWords :: S.Set String
  , lexMaxLen :: Int
  }

-- | Every letter left outside a word costs this much.
gapPenalty :: Double
gapPenalty = -6

-- | Entries longer than this are dropped; nothing that long helps the split.
lengthCap :: Int
lengthCap = 14

loadLexicon :: FilePath -> IO Lexicon
loadLexicon path = lexiconFrom . lines <$> readFile path

-- | Build a lexicon from raw lines, keeping only plain ASCII words.
--
-- One-letter entries are limited to @A@, @I@ and @O@: a word list that admits
-- every single letter as a word can cover any text at all and stops judging.
lexiconFrom :: [String] -> Lexicon
lexiconFrom ws = Lexicon (S.fromList kept) lengthCap
  where
    kept = [u | w <- ws, let u = map toUpper (trim w), all isAsciiUpper u, acceptable u]
    acceptable u =
      let n = length u
       in (n >= 2 && n <= lengthCap) || u `elem` ["A", "I", "O"]
    trim = filter (`notElem` " \t\r\n")

-- | The best split of a text: its score, and the pieces it was split into.
--
-- Unmatched letters appear in the split in lower case, so a near miss is
-- readable rather than merely low-scoring.
cover :: Lexicon -> [Letter] -> (Double, [String])
cover _ [] = (0, [])
cover lex' ls = table ! 0
  where
    n = length ls
    txt :: Array Int Char
    txt = listArray (0, n - 1) (fromLetters ls)
    table :: Array Int (Double, [String])
    table = listArray (0, n) [go i | i <- [0 .. n]]
    go i
      | i == n = (0, [])
      | otherwise = maximumBy (comparing fst) (skip : matches)
      where
        skip =
          let (s, ws) = table ! (i + 1)
           in (s + gapPenalty, [toLower (txt ! i)] : ws)
        matches =
          [ (fromIntegral (l * l) + s, w : ws)
          | l <- [1 .. min (lexMaxLen lex') (n - i)]
          , let w = [txt ! j | j <- [i .. i + l - 1]]
          , S.member w (lexWords lex')
          , let (s, ws) = table ! (i + l)
          ]

-- | 'cover' as a per-letter score, so texts of different lengths compare.
wordCover :: Lexicon -> [Letter] -> Double
wordCover lex' ls = fst (cover lex' ls) / fromIntegral (max 1 (length ls))

-- | The pieces 'cover' split the text into.
segment :: Lexicon -> [Letter] -> [String]
segment lex' = snd . cover lex'
