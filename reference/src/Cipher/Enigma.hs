-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | The Enigma machine, written to be read.
--
-- This is the reference for the Rust implementation, and the place to look
-- when the two disagree.
-- Every count comes from the tables it is a count of, and the three numbers a rotor carries are three types, so the confusion that cost the Rust version a working GPU kernel cannot be written here either.
--
-- The four-rotor naval machine needs no separate implementation.
-- Its Greek rotor never turns, so that rotor and the thin reflector behind it are one fixed permutation for the length of a message — and still an involution, because the reflector is.
-- An M4 is an M3 with one of @2 × 26 × 2@ reflectors, which is what turns a key space of billions into a sweep of six hundred million.
module Cipher.Enigma
  ( -- * The parts
    rotorSpecs
  , reflectorSpecs
  , greekSpecs
  , thinSpecs
  , rotorCount
  , reflectorCount
  , navalReflectorCount
    -- * A machine
  , Triple (..)
  , toTriple
  , tripleList
  , Rotor (..)
  , Plugboard
  , emptyBoard
  , connect
  , plug
  , plugPairs
  , Settings (..)
  , settingsAt
  , Enigma
  , machine
  , machineWith
  , press
  , run
    -- * Attacks lean on these
  , rotorOrders
  , navalReflectors
  , compositeReflector
  , compatible
  ) where

import Cipher.Alphabet (Letter, alphabetSize)
import Cipher.EnigmaTypes
  ( Indicator
  , Offset
  , Ring
  , against
  , indicator
  , indicatorValue
  , ring
  , step
  , through
  )
import Data.Array (Array, elems, listArray, (!), (//))
import Data.Char (ord)

-- | The five Wehrmacht rotors and the three Naval ones, with the notch
-- positions at which each turns the rotor to its left.
rotorSpecs :: [(String, String)]
rotorSpecs =
  [ ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q")
  , ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E")
  , ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V")
  , ("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J")
  , ("VZBRGITYUPSDNHLXAWMJQOFECK", "Z")
  , ("JPGVOUMFYQBENHZRDKASXLICTW", "ZM")
  , ("NZJHGRCXMYSWBOUFAIVLPEKQDT", "ZM")
  , ("FKQHTLXOCBJSPDZRAMEWNIUYGV", "ZM")
  ]

-- | Reflectors B and C.
reflectorSpecs :: [String]
reflectorSpecs =
  [ "YRUHQSLDPXNGOKMIEBFZCWVJAT"
  , "FVPJIAOYEDRZXWGCTKUQSBNMHL"
  ]

-- | The two Greek rotors, which sit to the left of the other three and never
-- turn.
greekSpecs :: [String]
greekSpecs =
  [ "LEYJVCNIXWPBQMDRTAKZGFUHOS"
  , "FSOKANUERHMBTIYCWLQPZXVGJD"
  ]

-- | The thin reflectors the four-rotor machine uses in place of B and C.
thinSpecs :: [String]
thinSpecs =
  [ "ENKQAUYWJICOPBLMDXZVFTHRGS"
  , "RDOBJNTKVEHMLFCWZAXGYIPSUQ"
  ]

rotorCount :: Int
rotorCount = length rotorSpecs

reflectorCount :: Int
reflectorCount = length reflectorSpecs

-- | How many reflectors a four-rotor machine presents once its Greek rotor and
-- thin reflector are folded together.
navalReflectorCount :: Int
navalReflectorCount = length greekSpecs * length thinSpecs * alphabetSize

wiring :: String -> Array Int Letter
wiring s = listArray (0, alphabetSize - 1) [ord c - ord 'A' | c <- s]

invert :: Array Int Letter -> Array Int Letter
invert w = listArray (0, alphabetSize - 1) (elems inverted)
  where
    inverted =
      listArray (0, alphabetSize - 1) (replicate alphabetSize 0)
        // [(v, i) | (i, v) <- zip [0 ..] (elems w)]

-- | The three slots a machine has, which is exactly three.
--
-- Written as a type rather than as a list because a list of three is a list
-- that might be two, and the compiler then asks what the machine does with two
-- rotors — a question with no answer that every pattern match has to pretend
-- to have one for.
data Triple a = Triple a a a
  deriving (Eq, Show)

instance Functor Triple where
  fmap f (Triple a b c) = Triple (f a) (f b) (f c)

instance Foldable Triple where
  foldr f z (Triple a b c) = f a (f b (f c z))

-- | Take the first three of a list, or nothing.
toTriple :: [a] -> Maybe (Triple a)
toTriple (a : b : c : _) = Just (Triple a b c)
toTriple _ = Nothing

tripleList :: Triple a -> [a]
tripleList (Triple a b c) = [a, b, c]

-- | Pair two triples slot by slot.
zipTriple :: (a -> b -> c) -> Triple a -> Triple b -> Triple c
zipTriple f (Triple a b c) (Triple x y z) = Triple (f a x) (f b y) (f c z)

-- | One rotor, wired both ways with its notches resolved.
data Rotor = Rotor
  { rotorForward :: Array Int Letter
  , rotorBackward :: Array Int Letter
  , rotorNotches :: [Letter]
  }

rotorAt :: Int -> Rotor
rotorAt i = Rotor forward (invert forward) [ord c - ord 'A' | c <- notch]
  where
    (spec, notch) = rotorSpecs !! (i `mod` rotorCount)
    forward = wiring spec

-- | A plugboard: an involution on the alphabet.
newtype Plugboard = Plugboard (Array Int Letter)
  deriving (Eq)

emptyBoard :: Plugboard
emptyBoard = Plugboard (listArray (0, alphabetSize - 1) [0 .. alphabetSize - 1])

-- | Add a lead, releasing whatever either letter was joined to.
connect :: Letter -> Letter -> Plugboard -> Plugboard
connect a b (Plugboard m) = Plugboard (m // [(oa, oa), (ob, ob), (a, b), (b, a)])
  where
    oa = m ! a
    ob = m ! b

plug :: Plugboard -> Letter -> Letter
plug (Plugboard m) l = m ! (l `mod` alphabetSize)

-- | The pairs the board joins.
plugPairs :: Plugboard -> [(Letter, Letter)]
plugPairs (Plugboard m) = [(a, m ! a) | a <- [0 .. alphabetSize - 1], m ! a > a]

-- | Everything that has to be chosen before a message can be read.
data Settings = Settings
  { settingRotors :: Triple Int
  , settingReflector :: Int
  , settingRings :: Triple Ring
  , settingPositions :: Triple Indicator
  }

-- | Settings written the way a key sheet writes them, as letters.
settingsAt :: Triple Int -> Int -> Triple Letter -> Triple Letter -> Settings
settingsAt rotors reflector rings positions =
  Settings rotors reflector (fmap ring rings) (fmap indicator positions)

-- | A machine, set up and ready to run.
data Enigma = Enigma
  { enigmaRotors :: Triple Rotor
  , enigmaReflector :: Array Int Letter
  , enigmaRings :: Triple Ring
  , enigmaPositions :: Triple Indicator
  , enigmaBoard :: Plugboard
  }

machine :: Settings -> Plugboard -> Enigma
machine s = machineWith s (wiring (reflectorSpecs !! (settingReflector s `mod` reflectorCount)))

-- | A machine with a reflector given outright, for the four-rotor case.
machineWith :: Settings -> Array Int Letter -> Plugboard -> Enigma
machineWith s reflector board =
  Enigma (fmap rotorAt (settingRotors s)) reflector (settingRings s) (settingPositions s) board

-- | Advance the rotors, including the double step a middle rotor takes when it
-- is sitting on its own notch.
advance :: Enigma -> Enigma
advance e = e {enigmaPositions = Triple left' middle' right'}
  where
    Triple left middle right = enigmaPositions e
    Triple _ middleRotor rightRotor = enigmaRotors e
    atNotch rotor i = indicatorValue i `elem` rotorNotches rotor
    middleAtNotch = atNotch middleRotor middle
    rightAtNotch = atNotch rightRotor right
    (left', middle')
      | middleAtNotch = (step left, step middle)
      | rightAtNotch = (left, step middle)
      | otherwise = (left, middle)
    right' = step right

-- | Where each rotor's wiring is entered, right now.
offsets :: Enigma -> Triple Offset
offsets e = zipTriple against (enigmaPositions e) (enigmaRings e)

-- | Encipher one letter, advancing the machine first as a keypress does.
--
-- Enigma is its own inverse, so this deciphers too.
press :: Enigma -> Letter -> (Enigma, Letter)
press e l = (moved, plug (enigmaBoard moved) back)
  where
    moved = advance e
    shifts = offsets moved
    entered = plug (enigmaBoard moved) l
    paired = tripleList (zipTriple (,) shifts (enigmaRotors moved))
    forward = foldr (\(o, r) c -> through o (rotorForward r) c) entered paired
    reflected = enigmaReflector moved ! forward
    back = foldl (\c (o, r) -> through o (rotorBackward r) c) reflected paired

-- | Run a whole message.
run :: Enigma -> [Letter] -> [Letter]
run _ [] = []
run e (l : ls) = let (e', c) = press e l in c : run e' ls

-- | Every rotor order that can be drawn from the first @available@ rotors.
rotorOrders :: Int -> [Triple Int]
rotorOrders available =
  [ Triple a b c
  | a <- [0 .. available - 1]
  , b <- [0 .. available - 1]
  , b /= a
  , c <- [0 .. available - 1]
  , c /= a
  , c /= b
  ]

-- | Fold a Greek rotor, its setting and a thin reflector into one reflector.
compositeReflector :: Int -> Letter -> Int -> Array Int Letter
compositeReflector greek setting thin =
  listABounds [composed c | c <- [0 .. alphabetSize - 1]]
  where
    listABounds = listArray (0, alphabetSize - 1)
    g = wiring (greekSpecs !! (greek `mod` length greekSpecs))
    gInv = invert g
    t = wiring (thinSpecs !! (thin `mod` length thinSpecs))
    shift = setting `mod` alphabetSize
    composed c =
      let a = (g ! ((c + shift) `mod` alphabetSize) - shift) `mod` alphabetSize
          b = t ! a
       in (gInv ! ((b + shift) `mod` alphabetSize) - shift) `mod` alphabetSize

-- | Every reflector a four-rotor machine can present, with the name of each.
navalReflectors :: [(String, Array Int Letter)]
navalReflectors =
  [ (gname ++ "/" ++ [toChar setting] ++ " " ++ tname, compositeReflector g setting t)
  | (g, gname) <- zip [0 ..] ["beta", "gamma"]
  , (t, tname) <- zip [0 ..] ["B-thin", "C-thin"]
  , setting <- [0 .. alphabetSize - 1]
  ]
  where
    toChar n = toEnum (ord 'A' + n)

-- | Whether a plaintext could have come from a ciphertext through an Enigma.
--
-- The reflector can never send a letter back to itself, so no position of a
-- true decipherment agrees with the ciphertext.
-- One pass, no key, and it refutes outright rather than by degree.
compatible :: [Letter] -> [Letter] -> Bool
compatible ct pt = and (zipWith (/=) ct pt)
