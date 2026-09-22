-- SPDX-License-Identifier: MIT OR Apache-2.0

-- | Checks with no dependency beyond base, so the suite runs wherever GHC does.
module Main (main) where

import Cipher.Alphabet (fromLetters, toLetters)
import Cipher.Attack (Candidate (..), chiKey, icByPeriod, rank, searchKeys)
import Cipher.Autokey (Priming (..), decipherAuto, encipherAuto, primings)
import qualified Cipher.Bifid as Bifid
import qualified Cipher.Hill as Hill
import qualified Cipher.Porta as Porta
import Cipher.Sweep (Trial (..), best, topScore)
import Cipher.Fitness (lexiconFrom, segment, wordCover)
import Cipher.Kasiski (Repeat (..), factorTally, repeats)
import Cipher.Ngram (Model (..), parseModel, render, score, train)
import Cipher.Periodic (Family (..), columns, decipher, encipher, every, families)
import Cipher.Random (nextWord, randomKey, seed, shuffle)
import Cipher.Stats (chiSquared, counts, indexOfCoincidence)
import Cipher.Superpose (alignment, familywise, fwP, merge, mutualIC, sigZ, significance)
import Cipher.Triage (Verdict (..), assess, statistics)
import Control.Monad (replicateM, unless)
import Data.List (sort)
import Data.Maybe (isJust)
import System.Exit (exitFailure)

-- | A stretch of ordinary English, long enough for a column statistic to bite.
plaintext :: String
plaintext =
  "ITISACAPITALMISTAKETOTHEORIZEBEFOREONEHASDATAINSENSIBLYONEBEGINS\
  \TOTWISTFACTSTOSUITTHEORIESINSTEADOFTHEORIESTOSUITFACTSTHEWORLDIS\
  \FULLOFOBVIOUSTHINGSWHICHNOBODYBYANYCHANCEEVEROBSERVES"

-- | More English, so a model trained inside the suite has something to learn
-- from beyond the sentence it is asked about.
corpus :: String
corpus =
  plaintext
    ++ "THEREISNOTHINGMOREDECEPTIVETHANANOBVIOUSFACTITHASLONGBEENANAXIOMOFMINE\
       \THATTHELITTLETHINGSAREINFINITELYTHEMOSTIMPORTANTWHENYOUHAVEELIMINATED\
       \THEIMPOSSIBLEWHATEVERREMAINSHOWEVERIMPROBABLEMUSTBETHETRUTHITISACAPITAL\
       \MISTAKETOTHEORIZEBEFOREYOUHAVEALLTHEEVIDENCEITBIASESTHEJUDGMENT"

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
  , ( "an autokey deciphers back to the plaintext"
    , and
        [ decipherAuto priming fam primer (encipherAuto priming fam primer msg) == msg
        | priming <- primings
        , fam <- families
        , primer <- map toLetters ["K", "LEMON", "ZZ"]
        , let msg = toLetters plaintext
        ]
    )
  , ( "an autokey with an empty primer changes nothing"
    , encipherAuto PlaintextAuto Vigenere [] (toLetters plaintext) == toLetters plaintext
    )
  , ( "the two primings differ"
    , encipherAuto PlaintextAuto Vigenere (toLetters "K") (toLetters plaintext)
        /= encipherAuto CiphertextAuto Vigenere (toLetters "K") (toLetters plaintext)
    )
  , ( "an exhaustive autokey search finds a planted primer"
    , let ct = encipherAuto PlaintextAuto Vigenere (toLetters "QX") (toLetters plaintext)
          proposals =
            [ (fromLetters primer, decipherAuto PlaintextAuto Vigenere primer ct)
            | primer <- replicateM 2 [0 .. 25]
            ]
       in case best 1 indexOfCoincidence proposals of
            (t : _) -> trialLabel t == "QX" && trialPlain t == toLetters plaintext
            [] -> False
    )
  , ("there are 157248 invertible two-by-two matrices", length Hill.matrices == 157248)
  , ("a singular matrix is rejected", not (Hill.invertible (Hill.Matrix 2 4 6 8)))
  , ("the determinant is taken modulo 26", Hill.determinant (Hill.Matrix 3 3 2 5) == 9)
  , ( "a matrix and its inverse undo each other"
    , let m = Hill.Matrix 3 3 2 5
          inverse = Hill.Matrix 15 17 20 9
       in Hill.apply inverse (Hill.apply m (toLetters plaintext)) == toLetters plaintext
    )
  , ("Hill leaves a trailing odd letter alone", length (Hill.apply (Hill.Matrix 3 3 2 5) (toLetters "ABC")) == 3)
  , ( "an exhaustive Hill search brings a planted key within reach"
    , -- The index of coincidence cannot pick the key out on its own: swapping
      -- the rows of the deciphering matrix swaps the letters within every
      -- digraph, which leaves the letter counts and so the statistic exactly
      -- as they were. It is a filter, not a verdict, and this is the property
      -- a sweep may lean on.
      let ct = Hill.apply (Hill.Matrix 3 3 2 5) (toLetters plaintext)
          top = best 40 indexOfCoincidence [(show m, Hill.apply m ct) | m <- Hill.matrices]
       in any ((== toLetters plaintext) . trialPlain) top
    )
  , ( "an n-gram model picks the planted Hill key out of that shortlist"
    , let ct = Hill.apply (Hill.Matrix 3 3 2 5) (toLetters plaintext)
          model = train 3 (toLetters corpus)
          top = best 40 indexOfCoincidence [(show m, Hill.apply m ct) | m <- Hill.matrices]
       in case best 1 (score model) [(trialLabel t, trialPlain t) | t <- top] of
            (t : _) -> trialPlain t == toLetters plaintext
            [] -> False
    )
  , ("a Porta table is its own inverse", and [Porta.substitute t (Porta.substitute t l) == l | t <- [0 .. 12], l <- [0 .. 25]])
  , ("Porta maps the halves of the alphabet across", Porta.substitute 0 0 == 13 && Porta.substitute 0 13 == 0)
  , ( "Porta enciphers and deciphers alike"
    , let key = [3, 7, 1]
       in Porta.apply key (Porta.apply key (toLetters plaintext)) == toLetters plaintext
    )
  , ("an empty Porta key changes nothing", Porta.apply [] (toLetters plaintext) == toLetters plaintext)
  , ( "bifid deciphers back to the plaintext"
    , -- A square holds 25 letters, so the omitted one has to be gone from the
      -- text too; a text still carrying it has no coordinates to encipher.
      and
        [ Bifid.decipherBifid n sq (Bifid.encipherBifid n sq msg) == msg
        | n <- [1, 2, 5, 7]
        , (missing, sq) <- Bifid.standardSquares
        , let msg = filter (/= missing) (toLetters plaintext)
        ]
    )
  , ("a bifid square omits exactly one letter", length (Bifid.squareOmitting 8) == 25 && notElem 8 (Bifid.squareOmitting 8))
  , ("bifid flattens the index of coincidence", indexOfCoincidence (Bifid.encipherBifid 7 (Bifid.squareOmitting 8) (filter (/= 8) (toLetters plaintext))) < indexOfCoincidence (toLetters plaintext))
  , ( "a sweep keeps only the best it was asked for"
    , length (best 3 indexOfCoincidence [(show i, replicate i 0 ++ toLetters plaintext) | i <- [1 .. 10]]) == 3
    )
  , ( "the top score agrees with the best trial"
    , let proposals = [(show i, drop i (toLetters plaintext)) | i <- [0 .. 9]]
       in case best 1 indexOfCoincidence proposals of
            (t : _) -> abs (trialScore t - topScore indexOfCoincidence proposals) < 1e-12
            [] -> False
    )
  , ( "the family-wise test does not flag a text with no period"
    , fwP (familywise icByPeriod 40 [2 .. 8] (toLetters plaintext) (seed 99)) > 0.0
    )
  , ( "the family-wise test flags a planted period"
    , let ct = encipher Vigenere (toLetters "LEMON") (toLetters plaintext)
       in fwP (familywise icByPeriod 60 [2 .. 10] ct (seed 77)) < 0.05
    )
  ]
