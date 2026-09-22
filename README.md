<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# cipher-break

Break a classical cipher, or find out honestly that you cannot.

```console
$ cb WKHTXLFNEURZQIRAMXPSVRYHUWKHODCBGRJDQGWKHQUXQVDZDBLQWRWKHIRUHVW

VERDICT ──────────────────────────────────────────────────────────────
  READ  affine and caesar
  key       a=1 b=23
  language  en  (fit +33.1s, text of this length reaches +30.2s)

  THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDTHENRUNSAWAYINTOTHEFOREST
```

Hand it a ciphertext — as a file, as a literal run of letters, or on standard input — and it runs its whole catalogue, calibrates itself against the machine it is on, and tells you either what the message is or exactly what it ruled out on the way to not knowing.

No corpus to point it at, no language to declare, no key length to guess.
Twenty-six language models are built into the binary.

## Install

```console
$ cargo install --path .                  # cb
$ cargo install --path . --features gpu   # cb, with the GPU backend
```

## Use

```
cb <ciphertext|file|->                run the whole catalogue and report
cb solve   <input> [options]          the same, spelled out
cb report  <input>                    diagnostics only: what the text is
cb crib    <input> [--word W]         where a guessed word could sit, and could not
cb try     <attack> <input>           run one attack by name
cb list                               every attack in the catalogue
cb devices                            what this machine can compute with
cb train   [--order N] [--cutoff N]   learn a model from a corpus on stdin
```

| option | |
| --- | --- |
| `--effort quick\|normal\|deep\|max` | how hard to search |
| `--depth N` | exhaust keys up to N letters long |
| `--nulls N` | shuffles each attack is calibrated against |
| `--gpu` | run the big exhaustive sweeps on the GPU |
| `--language de` | a language you already know, for a sharper judge |
| `--trace` | say what each stage of each attack did |
| `--models DIR` | language models instead of the built-in bank |
| `--seed N`, `--top N`, `--plain` | reproducibility, how much to show, no colour |

## What it knows

| family | attacks | coverage |
| --- | --- | --- |
| monoalphabetic | Caesar, Atbash, affine, simple substitution | every affine key; substitution by annealing |
| periodic | Vigenere, Beaufort, variant Beaufort, Porta | every key to the depth you ask for, then hill climbing to period 16 |
| autokey | plaintext- and ciphertext-primed, all three families | every primer to the depth you ask for |
| polygraphic | Hill 2×2, Playfair, four-square | all 157,248 Hill keys; squares by annealing |
| fractionating | bifid, keyed and unkeyed | every unkeyed square and period; keyed by annealing |
| transposition | columnar to width 8, rail fence | every column order and every height |
| concealment | null ciphers: every nth letter, forwards and back | every stride and offset to 12 |
| rotor | Enigma M3 and naval M4, eight rotors, both reflectors | rotors and rings exhausted, plugboard grown a lead at a time |
| rotor, with a crib | Turing's bombe, with the diagonal board | every rotor setting refuted or not, exactly, whatever the plugboard |

Adding one means writing an `Attack`: a name, a key space, and a way of searching it.
Everything else — the calibration, the nulls, the ranking, the trace, the report — works on it the day it arrives.

## The three ideas it is built on

**Nothing is evidence until its null is known.** Keeping the best of 157,248 keys is not a finding: the largest of 157,248 draws from a harmless distribution is large too.
Every attack runs twice, once on the ciphertext and once on shuffles of it, and the margin between them is what decides.
This is not decoration.
On a 72-letter message, annealing a bifid square reaches a score that would pass for a language — and reaches the same score on noise.

**The judge must not assume a language.** Twenty-six n-gram models ship inside the binary, from Czech to Japanese romaji, and every candidate is scored under all of them.
Scores are in deviations above what random letters *of the same length* achieve, so a twelve-letter fragment and a seventy-letter message compare without the short one winning for being short.

**Freedom costs.** A search with more parameters fits anything better, so more parameters must cost more.
A plugboard lead is charged log(325) nats when candidates are ranked; a sixteen-letter Vigenere key is ranked by its margin over its own null rather than by its score.

All three were earned rather than designed.
The bifid attack silently did not work until a planted key was demanded of it; the tool read a plain Caesar cipher as a sixteen-letter Vigenere key until selection changed; it missed a message hidden as every third letter until scores were made length-aware; and it read a German Enigma signal fourth behind three texts that were no language at all until `--language` was allowed to decide.
Each is now a test.

## Enigma

The machine is complete: eight rotors, reflectors B and C, ring settings, the double step a middle rotor takes on its own notch, and a plugboard.
The naval M4 needs no separate implementation — the Greek rotor never turns, so it and the thin reflector behind it are one fixed permutation for a message, and still an involution.
An M4 is an M3 with one of 104 reflectors.

The attack exhausts the rotors with the board empty, then grows the board one lead at a time, then searches the ring settings, then grows the board again.
On planted messages it recovers everything:

| planted | letters | swept | recovered |
| --- | --- | --- | --- |
| M4, right ring A | 69 | 614 M settings | rotors, Greek rotor, reflector, start, all three leads |
| M4, right ring A | 201 | 614 M settings | the same, first by 17 σ |
| M4, right ring T | 201 | 16 G settings | the same, including the ring |

The limit is measured rather than assumed.
A rank diagnostic reports where the true setting lands in the sweep: 146th of six hundred million for the short message, first for the long one, seventh of sixteen billion when the ring is swept too.
A right ring away from `A` on a seventy-letter message is past what the evidence supports, and the report says so instead of guessing.

## The bombe

Every other Enigma attack needs the decipherment to look like a language, and on a short message with a full plugboard it never does: the board sends twenty of twenty-six letters somewhere else.
The bombe does not look at the decipherment.
Given a crib it asks whether *any* plugboard could turn this ciphertext into those words under this rotor setting, and answers by contradiction — which is exact, and which does not weaken as the board grows.

```console
$ cb bombe message.txt --word KEINEBESONDERENVORKOMMNISSE
  KEINEBESONDERENVORKOMMNISSE  19 placements, 7 closures
  bombe on KEINEBESONDERENVORKOMMNISSE   11631734784 all   -inf   -inf   -
```

`-inf` there is the strongest answer this tool can give: eleven billion settings, every one refuted, so those words are not in that message under any four-rotor Enigma and any plugboard whatever.

It needs a crib that is really there and one long enough to close loops in its menu.
A menu contradicts only where it forces a letter twice, so a crib of sixteen distinct-ish letters over twenty-odd nodes is a forest and refutes nothing; `cb bombe` refuses one that closes nothing rather than running it and looking busy.
That is why `cb crib` and `cb bombe` draw on different word lists.

## Speed

Apple M5 Pro, 18 cores, on a 72-letter message:

| sweep | keys | CPU | GPU |
| --- | --- | --- | --- |
| Vigenere period 4 | 1,370,928 | 0.04 s | — |
| Vigenere period 6 | 926,747,328 | 20.8 s | **2.8 s** |
| Vigenere period 7 | 24,095,430,528 | ~9 min | **72 s** |
| Vigenere period 8 | 626,481,193,728 | — | **~30 min** |
| Enigma M4 rotor sweep | 614,335,744 | 65 s | **2.3 s** |
| Enigma bombe, one naval crib | 13,511,866,368 | 35 min | — |

337 million Vigenere keys a second on the device, and the two backends agree key for key — which is what the tests assert, for the sweeps and for the plugboard climb.

Two changes account for most of it.
The eighteen language models are interleaved so every language's value for a gram sits together, turning eighteen scattered cache lines per gram into two adjacent ones.
And the kernels hold nothing in function-scope arrays: the first rotor kernel kept its key and accumulators in 192 bytes a thread, spilled out of registers, and beat eighteen CPU cores by a factor of two; register-only it manages twenty-eight.

## Types, traces and tests

The interesting bugs here were all one kind: two different things carried as the same type.

`enigma_types` keeps a rotor's three numbers apart.
An `Offset` — where a wiring is entered — can only be made by taking a `Ring` from an `Indicator`, and a notch can only be tested against an `Indicator`.
A kernel that stepped the indicator and then entered the wiring at it used to compile; it does not now.

`Trace` records what each stage of an attack did.
The question "which half lost the answer" is `--trace` rather than a throwaway test.

Tests plant keys in real ciphers and demand them back — a Caesar shift, a Vigenere key, a Porta key, an autokey primer, a Hill matrix, a rail fence, a columnar order, a hidden null cipher, a keyed bifid square, and three Enigma settings — and require the tool to say nothing about random letters.
`njutest verify` runs the mutation-testing gate over it.

## Two implementations

`reference/` is Haskell: the same algorithms, written to be read.
The root is Rust: the same algorithms, written to be fast.
They share `data/`, so a model trained by either is read by both, and `mise run agree` checks that they still answer alike.

## Licence

MIT or Apache-2.0, at your option.
