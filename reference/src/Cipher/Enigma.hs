-- SPDX-License-Identifier: MIT OR Apache-2.0

module Cipher.Enigma
  (
    rotorSpecs
  , reflectorSpecs
  , greekSpecs
  , thinSpecs
  , rotorCount
  , reflectorCount
  , navalReflectorCount
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

reflectorSpecs :: [String]
reflectorSpecs =
  [ "YRUHQSLDPXNGOKMIEBFZCWVJAT"
  , "FVPJIAOYEDRZXWGCTKUQSBNMHL"
  ]

greekSpecs :: [String]
greekSpecs =
  [ "LEYJVCNIXWPBQMDRTAKZGFUHOS"
  , "FSOKANUERHMBTIYCWLQPZXVGJD"
  ]

thinSpecs :: [String]
thinSpecs =
  [ "ENKQAUYWJICOPBLMDXZVFTHRGS"
  , "RDOBJNTKVEHMLFCWZAXGYIPSUQ"
  ]

rotorCount :: Int
rotorCount = length rotorSpecs

reflectorCount :: Int
reflectorCount = length reflectorSpecs

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

data Triple a = Triple a a a
  deriving (Eq, Show)

instance Functor Triple where
  fmap f (Triple a b c) = Triple (f a) (f b) (f c)

instance Foldable Triple where
  foldr f z (Triple a b c) = f a (f b (f c z))

toTriple :: [a] -> Maybe (Triple a)
toTriple (a : b : c : _) = Just (Triple a b c)
toTriple _ = Nothing

tripleList :: Triple a -> [a]
tripleList (Triple a b c) = [a, b, c]

zipTriple :: (a -> b -> c) -> Triple a -> Triple b -> Triple c
zipTriple f (Triple a b c) (Triple x y z) = Triple (f a x) (f b y) (f c z)

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

newtype Plugboard = Plugboard (Array Int Letter)
  deriving (Eq)

emptyBoard :: Plugboard
emptyBoard = Plugboard (listArray (0, alphabetSize - 1) [0 .. alphabetSize - 1])

connect :: Letter -> Letter -> Plugboard -> Plugboard
connect a b (Plugboard m) = Plugboard (m // [(oa, oa), (ob, ob), (a, b), (b, a)])
  where
    oa = m ! a
    ob = m ! b

plug :: Plugboard -> Letter -> Letter
plug (Plugboard m) l = m ! (l `mod` alphabetSize)

plugPairs :: Plugboard -> [(Letter, Letter)]
plugPairs (Plugboard m) = [(a, m ! a) | a <- [0 .. alphabetSize - 1], m ! a > a]

data Settings = Settings
  { settingRotors :: Triple Int
  , settingReflector :: Int
  , settingRings :: Triple Ring
  , settingPositions :: Triple Indicator
  }

settingsAt :: Triple Int -> Int -> Triple Letter -> Triple Letter -> Settings
settingsAt rotors reflector rings positions =
  Settings rotors reflector (fmap ring rings) (fmap indicator positions)

data Enigma = Enigma
  { enigmaRotors :: Triple Rotor
  , enigmaReflector :: Array Int Letter
  , enigmaRings :: Triple Ring
  , enigmaPositions :: Triple Indicator
  , enigmaBoard :: Plugboard
  }

machine :: Settings -> Plugboard -> Enigma
machine s = machineWith s (wiring (reflectorSpecs !! (settingReflector s `mod` reflectorCount)))

machineWith :: Settings -> Array Int Letter -> Plugboard -> Enigma
machineWith s reflector board =
  Enigma (fmap rotorAt (settingRotors s)) reflector (settingRings s) (settingPositions s) board

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

offsets :: Enigma -> Triple Offset
offsets e = zipTriple against (enigmaPositions e) (enigmaRings e)

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

run :: Enigma -> [Letter] -> [Letter]
run _ [] = []
run e (l : ls) = let (e', c) = press e l in c : run e' ls

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

navalReflectors :: [(String, Array Int Letter)]
navalReflectors =
  [ (gname ++ "/" ++ [toChar setting] ++ " " ++ tname, compositeReflector g setting t)
  | (g, gname) <- zip [0 ..] ["beta", "gamma"]
  , (t, tname) <- zip [0 ..] ["B-thin", "C-thin"]
  , setting <- [0 .. alphabetSize - 1]
  ]
  where
    toChar n = toEnum (ord 'A' + n)

compatible :: [Letter] -> [Letter] -> Bool
compatible ct pt = and (zipWith (/=) ct pt)
