-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | Judging a candidate plaintext without being told the language.
--
-- The index of coincidence is the only wholly language-free measure available,
-- and it is weak: it counts letters and ignores their order, so it cannot tell
-- a plaintext from an anagram of one. Swapping the rows of a Hill deciphering
-- matrix swaps the letters inside every digraph and leaves it untouched, which
-- is exactly how a true key can fail to come first in a sweep that trusts it.
--
-- The cure is not to guess the language but to carry all of them. A bank of
-- n-gram models scores a candidate under each in turn and keeps the best fit;
-- a text that is a language will fit its own, and a text that is not will fit
-- none of them.
module Cipher.Polyglot
  ( Polyglot (..)
  , loadPolyglot
  , identify
  , polyglotScore
  , languages
  ) where

import Cipher.Alphabet (Letter)
import Cipher.Ngram (Model, loadModel, score)
import Data.List (isSuffixOf, maximumBy, sort)
import Data.Ord (comparing)
import System.Directory (listDirectory)
import System.FilePath (takeBaseName, (</>))

-- | One n-gram model per language, named by its file.
newtype Polyglot = Polyglot {polyglotModels :: [(String, Model)]}

languages :: Polyglot -> [String]
languages = map fst . polyglotModels

-- | Read every model in a directory.
loadPolyglot :: FilePath -> IO Polyglot
loadPolyglot dir = do
  names <- sort . filter (".txt" `isSuffixOf`) <$> listDirectory dir
  loaded <- mapM load names
  pure (Polyglot [(name, m) | (name, Just m) <- loaded])
  where
    load name = (,) (takeBaseName name) <$> loadModel (dir </> name)

-- | The language that fits best, and how well it fits.
identify :: Polyglot -> [Letter] -> (String, Double)
identify (Polyglot ms) ls
  | null ms = ("none", -1 / 0)
  | otherwise = maximumBy (comparing snd) [(name, score m ls) | (name, m) <- ms]

polyglotScore :: Polyglot -> [Letter] -> Double
polyglotScore p = snd . identify p
