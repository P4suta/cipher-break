-- SPDX-License-Identifier: MIT OR Apache-2.0

module Cipher.EnigmaTypes
  ( Indicator
  , Ring
  , Offset
  , indicator
  , ring
  , indicatorValue
  , ringValue
  , offsetValue
  , step
  , against
  , withRing
  , through
  ) where

import Cipher.Alphabet (Letter, alphabetSize)
import Data.Array (Array, (!))

newtype Indicator = Indicator Letter
  deriving (Eq, Ord, Show)

newtype Ring = Ring Letter
  deriving (Eq, Ord, Show)

newtype Offset = Offset Letter
  deriving (Eq, Ord, Show)

indicator :: Letter -> Indicator
indicator = Indicator . (`mod` alphabetSize)

ring :: Letter -> Ring
ring = Ring . (`mod` alphabetSize)

indicatorValue :: Indicator -> Letter
indicatorValue (Indicator v) = v

ringValue :: Ring -> Letter
ringValue (Ring v) = v

offsetValue :: Offset -> Letter
offsetValue (Offset v) = v

step :: Indicator -> Indicator
step (Indicator v) = Indicator ((v + 1) `mod` alphabetSize)

against :: Indicator -> Ring -> Offset
against (Indicator i) (Ring r) = Offset ((i - r) `mod` alphabetSize)

withRing :: Offset -> Ring -> Indicator
withRing (Offset o) (Ring r) = Indicator ((o + r) `mod` alphabetSize)

through :: Offset -> Array Int Letter -> Letter -> Letter
through (Offset o) wiring l =
  (wiring ! ((l + o) `mod` alphabetSize) - o) `mod` alphabetSize
