-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | The three numbers an Enigma rotor has, kept apart by the type system.
--
-- A rotor carries an indicator — the letter in its window — and a ring
-- setting, and enters its wiring at the difference between them.
-- All three are numbers modulo 26, all three are written as single letters, and mixing them up produces a machine that runs perfectly and deciphers nothing.
--
-- This module exists because that mistake was made in the Rust implementation: a shader stepped the indicator and then used it as the wiring offset, which is correct for every message whose ring setting is @A@ and wrong for every other one.
-- It is a bug that passes its round-trip test, passes its textbook vector, and fails only on real traffic.
--
-- So the three are different types.
-- An 'Offset' can only be made by taking a 'Ring' away from an 'Indicator'; a notch can only be tested against an 'Indicator'; a wiring can only be entered at an 'Offset'.
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

-- | The letter showing in a rotor's window, which is what its notch fires on
-- and what steps with every keypress.
newtype Indicator = Indicator Letter
  deriving (Eq, Ord, Show)

-- | Where a rotor's alphabet ring is clamped, which is fixed for a message.
newtype Ring = Ring Letter
  deriving (Eq, Ord, Show)

-- | How far into its wiring a rotor is entered: the indicator less the ring.
--
-- There is deliberately no exported way to build one from a number.
-- It comes from an indicator and a ring or it does not exist.
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

-- | The next letter in the window.
step :: Indicator -> Indicator
step (Indicator v) = Indicator ((v + 1) `mod` alphabetSize)

-- | Where the wiring is entered, given where the ring sits.
--
-- The only constructor of an 'Offset', on purpose.
against :: Indicator -> Ring -> Offset
against (Indicator i) (Ring r) = Offset ((i - r) `mod` alphabetSize)

-- | The indicator that produces an offset against a given ring.
--
-- The inverse of 'against', and the operation a ring search is made of: hold
-- the wiring where the rotor sweep found it and move only the moment the notch
-- fires.
withRing :: Offset -> Ring -> Indicator
withRing (Offset o) (Ring r) = Indicator ((o + r) `mod` alphabetSize)

-- | Enter a wiring at an offset and leave it at the same one.
--
-- Both halves of the shift live here together, which is the other way this
-- arithmetic goes wrong: shifting in and forgetting to shift out produces a
-- machine that is its own inverse and reads nothing.
through :: Offset -> Array Int Letter -> Letter -> Letter
through (Offset o) wiring l =
  (wiring ! ((l + o) `mod` alphabetSize) - o) `mod` alphabetSize
