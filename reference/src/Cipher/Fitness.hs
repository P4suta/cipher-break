-- SPDX-License-Identifier: MIT OR Apache-2.0

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

data Lexicon = Lexicon
  { lexWords :: S.Set String
  , lexMaxLen :: Int
  }

gapPenalty :: Double
gapPenalty = -6

lengthCap :: Int
lengthCap = 14

loadLexicon :: FilePath -> IO Lexicon
loadLexicon path = lexiconFrom . lines <$> readFile path

lexiconFrom :: [String] -> Lexicon
lexiconFrom ws = Lexicon (S.fromList kept) lengthCap
  where
    kept = [u | w <- ws, let u = map toUpper (trim w), all isAsciiUpper u, acceptable u]
    acceptable u =
      let n = length u
       in (n >= 2 && n <= lengthCap) || u `elem` ["A", "I", "O"]
    trim = filter (`notElem` " \t\r\n")

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

wordCover :: Lexicon -> [Letter] -> Double
wordCover lex' ls = fst (cover lex' ls) / fromIntegral (max 1 (length ls))

segment :: Lexicon -> [Letter] -> [String]
segment lex' = snd . cover lex'
