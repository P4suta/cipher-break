-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | Letters as residues modulo 26.
--
-- Every attack in this package consumes @['Letter']@ and never a 'String'.
-- Case, spacing and punctuation are decided once, here, at the boundary, so no
-- attack has to carry a rule about them.
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

-- | One letter of the Latin alphabet, held as @0..25@ with @A = 0@.
type Letter = Int

alphabetSize :: Int
alphabetSize = 26

-- | The letter a character stands for, or 'Nothing' for anything that is not
-- an ASCII letter.
charLetter :: Char -> Maybe Letter
charLetter c
  | isAsciiUpper c = Just (ord c - ord 'A')
  | isAsciiLower c = Just (ord c - ord 'a')
  | otherwise = Nothing

-- | The upper-case character for a letter, reducing out-of-range input.
letterChar :: Letter -> Char
letterChar n = chr (ord 'A' + n `mod` alphabetSize)

-- | Keep the letters of a string and drop everything else.
toLetters :: String -> [Letter]
toLetters = mapMaybe charLetter

fromLetters :: [Letter] -> String
fromLetters = map letterChar
