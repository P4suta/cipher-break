-- SPDX-License-Identifier: MIT OR Apache-2.0

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

newtype Polyglot = Polyglot {polyglotModels :: [(String, Model)]}

languages :: Polyglot -> [String]
languages = map fst . polyglotModels

loadPolyglot :: FilePath -> IO Polyglot
loadPolyglot dir = do
  names <- sort . filter (".txt" `isSuffixOf`) <$> listDirectory dir
  loaded <- mapM load names
  pure (Polyglot [(name, m) | (name, Just m) <- loaded])
  where
    load name = (,) (takeBaseName name) <$> loadModel (dir </> name)

identify :: Polyglot -> [Letter] -> (String, Double)
identify (Polyglot ms) ls
  | null ms = ("none", -1 / 0)
  | otherwise = maximumBy (comparing snd) [(name, score m ls) | (name, m) <- ms]

polyglotScore :: Polyglot -> [Letter] -> Double
polyglotScore p = snd . identify p
