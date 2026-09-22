-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | Checks with no dependency beyond base, so the suite runs wherever GHC does.
module Main (main) where

import Cipher.Alphabet (fromLetters, toLetters)
import Cipher.Attack (Candidate (..), chiKey, icByPeriod, rank, searchKeys)
import Cipher.Fitness (lexiconFrom, segment, wordCover)
import Cipher.Kasiski (Repeat (..), factorTally, repeats)
import Cipher.Ngram (Model (..), parseModel, render, score, train)
import Cipher.Periodic (Family (..), columns, decipher, encipher, every, families)
import Cipher.Random (nextWord, randomKey, seed, shuffle)
import Cipher.Stats (chiSquared, counts, indexOfCoincidence)
import Cipher.Superpose (alignment, merge, mutualIC, significance, sigZ)
import Cipher.Triage (Verdict (..), assess, statistics)
import Control.Monad (unless)
import Data.List (sort)
import Data.Maybe (isJust)
import System.Exit (exitFailure)

-- | A stretch of ordinary English, long enough for a column statistic to bite.
plaintext :: String
plaintext =
  "ITISACAPITALMISTAKETOTHEORIZEBEFOREONEHASDATAINSENSIBLYONEBEGINS\
  \TOTWISTFACTSTOSUITTHEORIESINSTEADOFTHEORIESTOSUITFACTSTHEWORLDIS\
  \FULLOFOBVIOUSTHINGSWHICHNOBODYBYANYCHANCEEVEROBSERVES"

sampleLexicon :: [String]
sampleLexicon = ["THE", "QUICK", "BROWN", "FOX", "OX", "ROW", "ICK", "HE", "UI"]

main :: IO ()
main = do
  let results = checks
  mapM_ (\(name, ok) -> putStrLn ((if ok then "ok   " else "FAIL ") ++ name)) results
  unless (all snd results) exitFailure

checks :: [(String, Bool)]
checks =
  [ ("toLetters keeps letters and drops the rest", toLetters "Attack at dawn!" == toLetters "ATTACKATDAWN")
  , ("fromLetters inverts toLetters", fromLetters (toLetters "Attack at dawn!") == "ATTACKATDAWN")
  , ( "Vigenere matches the textbook vector"
    , fromLetters (encipher Vigenere (toLetters "LEMON") (toLetters "ATTACKATDAWN")) == "LXFOPVEFRNHR"
    )
  , ( "decipher inverts encipher for every family"
    , and
        [ decipher fam key (encipher fam key msg) == msg
        | fam <- families
        , key <- map toLetters ["A", "LEMON", "ZZ", "CRYPTO"]
        , let msg = toLetters plaintext
        ]
    )
  , ( "Beaufort is its own inverse"
    , let key = toLetters "LEMON"
          msg = toLetters plaintext
       in encipher Beaufort key (encipher Beaufort key msg) == msg
    )
  , ("an empty key enciphers to itself", encipher Vigenere [] (toLetters plaintext) == toLetters plaintext)
  , ("every 1 is the identity", every 1 (toLetters plaintext) == toLetters plaintext)
  , ("columns partition the text", sort (concat (columns 5 [1 :: Int .. 23])) == [1 .. 23])
  , ("columns has one entry per period", length (columns 7 [1 :: Int .. 23]) == 7)
  , ("counts sums to the length", sum (counts (toLetters plaintext)) == length (toLetters plaintext))
  , ("a single repeated letter has IC one", indexOfCoincidence (toLetters "AAAAAA") == 1)
  , ("English scores a higher IC than its ciphertext", indexOfCoincidence (toLetters plaintext) > indexOfCoincidence (encipher Vigenere (toLetters "CRYPTO") (toLetters plaintext)))
  , ("chi-squared is zero on empty input", chiSquared [] == 0)
  , ("chi-squared prefers English to its ciphertext", chiSquared (toLetters plaintext) < chiSquared (encipher Vigenere (toLetters "CRYPTO") (toLetters plaintext)))
  , ( "the true period stands out by IC"
    , let ct = encipher Vigenere (toLetters "LEMON") (toLetters plaintext)
       in icByPeriod ct 5 > icByPeriod ct 4 && icByPeriod ct 5 > icByPeriod ct 6
    )
  , ( "chi-squared recovers a known key"
    , and
        [ chiKey fam 5 (encipher fam (toLetters "LEMON") (toLetters plaintext)) == toLetters "LEMON"
        | fam <- families
        ]
    )
  , ( "repeats finds a planted repetition"
    , map repeatDistances (repeats 3 (toLetters "ABCDEFABCDEF")) == [[6], [6], [6], [6]]
    )
  , ("repeats finds nothing when nothing repeats", null (repeats 3 (toLetters "ABCDEF")))
  , ("factorTally counts the divisors that fit", lookup 6 (factorTally 8 [6, 12, 18]) == Just 3)
  , ("factorTally ignores distances it cannot divide", lookup 5 (factorTally 8 [6, 12, 18]) == Just 0)
  , ( "the word cover finds the intended split"
    , segment (lexiconFrom sampleLexicon) (toLetters "THEQUICKBROWNFOX") == ["THE", "QUICK", "BROWN", "FOX"]
    )
  , ( "the word cover marks letters it could not place"
    , segment (lexiconFrom sampleLexicon) (toLetters "THEZZ") == ["THE", "z", "z"]
    )
  , ( "a covered text outscores an uncoverable one"
    , let lx = lexiconFrom sampleLexicon
       in wordCover lx (toLetters "THEQUICKBROWNFOX") > wordCover lx (toLetters "ZZZZZZZZZZZZZZZZ")
    )
  , ( "searchKeys picks the key that was used"
    , let lx = lexiconFrom sampleLexicon
          ct = encipher Vigenere (toLetters "LEMON") (toLetters plaintext)
          proposals = [(fam, toLetters w) | fam <- families, w <- ["LEMON", "MELON", "CRYPTO", "A"]]
       in case searchKeys (wordCover lx) 4 ct proposals of
            (best : _) -> candFamily best == Vigenere && fromLetters (candKey best) == "LEMON"
            [] -> False
    )
  , ( "searchKeys keeps at most the requested number"
    , let ct = encipher Vigenere (toLetters "LEMON") (toLetters plaintext)
          proposals = [(fam, toLetters w) | fam <- families, w <- ["LEMON", "MELON", "CRYPTO", "A"]]
       in length (searchKeys (negate . chiSquared) 3 ct proposals) == 3
    )
  , ( "rank drops a duplicate plaintext"
    , let one = Candidate Vigenere [0] (toLetters "ABC") 1
          two = Candidate Beaufort [1] (toLetters "ABC") 0
       in length (rank 5 [one, two]) == 1
    )
  , ( "rank puts the highest score first"
    , let low = Candidate Vigenere [0] (toLetters "ABC") 1
          high = Candidate Beaufort [1] (toLetters "XYZ") 9
       in map candScore (rank 5 [low, high]) == [9, 1]
    )
  , ( "the n-gram model prefers the text it was trained on"
    , let m = train 3 (toLetters plaintext)
       in score m (toLetters plaintext) > score m (toLetters "ZQXJZQXJZQXJZQXJ")
    )
  , ( "a rendered model parses back to the same scores"
    , let m = train 3 (toLetters plaintext)
       in case parseModel (render 1 m) of
            Just m' -> modelOrder m' == 3 && abs (score m' (toLetters plaintext) - score m (toLetters plaintext)) < 1e-9
            Nothing -> False
    )
  , ("a model renders a header even when nothing meets the cutoff", isJust (parseModel (render 999 (train 3 (toLetters plaintext)))))
  , ("the same seed gives the same key", randomKey 8 (seed 42) == randomKey 8 (seed 42))
  , ("different seeds differ", fst (randomKey 8 (seed 1)) /= fst (randomKey 8 (seed 2)))
  , ("the generator moves", fst (nextWord (seed 7)) /= fst (nextWord (seed 8)))
  , ("a shuffle keeps every letter", sort (fst (shuffle (toLetters plaintext) (seed 5))) == sort (toLetters plaintext))
  , ("a shuffle of a short list keeps its length", length (fst (shuffle [1 :: Int .. 9] (seed 3))) == 9)
  , ( "the mutual IC peaks at the true offset"
    , let a = toLetters plaintext
          b = map (\c -> (c + 7) `mod` 26) a
       in snd (maximum [(mutualIC a b d, d) | d <- [0 .. 25]]) == 7
    )
  , ( "superposition recovers the key up to its first letter"
    , let ct = encipher Vigenere (toLetters "LEMON") (toLetters plaintext)
       in alignment 5 ct == [0, 19, 1, 3, 2]
    )
  , ( "superposition leaves a text with the language's IC"
    , let ct = encipher Vigenere (toLetters "LEMON") (toLetters plaintext)
       in indexOfCoincidence (merge 5 (alignment 5 ct) ct) > 0.06
    )
  , ("a period of one aligns to nothing", alignment 1 (toLetters plaintext) == [0])
  , ( "superposition finds the planted period significant"
    , let ct = encipher Vigenere (toLetters "LEMON") (toLetters plaintext)
       in sigZ (significance 50 5 ct (seed 11)) > 3
    )
  , ( "triage sees nothing unusual in its own null"
    , let sample = take 40 (map (fst . randomKey 60) (map seed [1 .. 40]))
       in case (statistics, sample) of
            (st : _, s0 : rest) -> verdictP (assess st s0 rest) > 0.01
            _ -> False
    )
  , ( "triage flags a text that is all one letter"
    , let sample = take 40 (map (fst . randomKey 60) (map seed [1 .. 40]))
       in case statistics of
            (st : _) -> verdictP (assess st (replicate 60 0) sample) < 0.05
            _ -> False
    )
  ]
