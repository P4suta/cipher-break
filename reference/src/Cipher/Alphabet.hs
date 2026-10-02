-- SPDX-License-Identifier: MIT OR Apache-2.0

module Cipher.Alphabet
  ( Letter
  , alphabetSize
  , charLetter
  , letterChar
  , toLetters
  , fromLetters
  ) where

import Data.Char (chr, isAsciiLower, isAsciiUpper, ord)
import Data.Maybe (mapMaybe)

type Letter = Int

alphabetSize :: Int
alphabetSize = 26

charLetter :: Char -> Maybe Letter
charLetter c
  | isAsciiUpper c = Just (ord c - ord 'A')
  | isAsciiLower c = Just (ord c - ord 'a')
  | otherwise = Nothing

letterChar :: Letter -> Char
letterChar n = chr (ord 'A' + n `mod` alphabetSize)

toLetters :: String -> [Letter]
toLetters = mapMaybe charLetter

fromLetters :: [Letter] -> String
fromLetters = map letterChar
