import Std

set_option warningAsError true

namespace CipherProofs

def conjugate (forward backward reflector : Letter → Letter) (letter : Letter) :=
  backward (reflector (forward letter))

theorem conjugating_a_reflector_preserves_its_involution
    (forward backward reflector : Letter → Letter)
    (inverse : ∀ letter, forward (backward letter) = letter)
    (reverseInverse : ∀ letter, backward (forward letter) = letter)
    (involution : ∀ letter, reflector (reflector letter) = letter)
    (letter : Letter) :
    conjugate forward backward reflector (conjugate forward backward reflector letter) = letter := by
  simp only [conjugate, inverse, involution, reverseInverse]

theorem conjugating_a_reflector_preserves_the_absence_of_fixed_points
    (forward backward reflector : Letter → Letter)
    (inverse : ∀ letter, forward (backward letter) = letter)
    (noFixedPoints : ∀ letter, reflector letter ≠ letter)
    (letter : Letter) : conjugate forward backward reflector letter ≠ letter := by
  intro same
  have image := congrArg forward same
  simp only [conjugate, inverse] at image
  exact noFixedPoints (forward letter) image

def trace (step : State → State) (view : State → View) : State → Nat → List View
  | _, 0 => []
  | state, n + 1 => view (step state) :: trace step view (step state) n

theorem trace_length (step : State → State) (view : State → View)
    (state : State) (n : Nat) : (trace step view state n).length = n := by
  induction n generalizing state with
  | zero => rfl
  | succ n ih => simp [trace, ih]

theorem normalization_preserves_every_trace
    (step : State → State) (normalizedStep : Normalized → Normalized)
    (view : State → View) (normalizedView : Normalized → View)
    (normalize : State → Normalized)
    (stepCommutes : ∀ state, normalize (step state) = normalizedStep (normalize state))
    (viewAgrees : ∀ state, view state = normalizedView (normalize state))
    (state : State) (n : Nat) :
    trace step view state n = trace normalizedStep normalizedView (normalize state) n := by
  induction n generalizing state with
  | zero => rfl
  | succ n ih =>
    simp only [trace]
    rw [viewAgrees, ih, stepCommutes]

def representatives [DecidableEq Tag] (key : Candidate → Tag) :
    List Tag → List Candidate → List Candidate
  | _, [] => []
  | seen, candidate :: rest =>
    if key candidate ∈ seen then representatives key seen rest
    else candidate :: representatives key (key candidate :: seen) rest

theorem seen_or_represented [DecidableEq Tag] (key : Candidate → Tag)
    (input : List Candidate) (seen : List Tag) (candidate : Candidate)
    (present : candidate ∈ input) :
    key candidate ∈ seen ∨
      ∃ kept ∈ representatives key seen input, key kept = key candidate := by
  induction input generalizing seen with
  | nil => simp at present
  | cons first rest ih =>
    by_cases already : key first ∈ seen
    · simp only [representatives, ite_eq_left already]
      rcases List.mem_cons.mp present with same | later
      · subst candidate
        exact Or.inl already
      · exact ih seen later
    · simp only [representatives, ite_eq_right already]
      rcases List.mem_cons.mp present with same | later
      · subst candidate
        exact Or.inr ⟨first, List.mem_cons_self, rfl⟩
      · rcases ih (key first :: seen) later with old | ⟨kept, keptPresent, same⟩
        · rcases List.mem_cons.mp old with same | old
          · exact Or.inr ⟨first, List.mem_cons_self, same.symm⟩
          · exact Or.inl old
        · exact Or.inr ⟨kept, List.mem_cons_of_mem first keptPresent, same⟩

theorem deduplication_preserves_every_key [DecidableEq Tag]
    (key : Candidate → Tag) (input : List Candidate)
    (candidate : Candidate) (present : candidate ∈ input) :
    ∃ kept ∈ representatives key [] input, key kept = key candidate := by
  rcases seen_or_represented key input [] candidate present with impossible | kept
  · simp at impossible
  · exact kept

theorem a_finishing_cap_can_discard_the_true_candidate :
    false ∈ ([true, false] : List Bool) ∧
      false ∉ ([true, false] : List Bool).take 1 := by
  decide

#print axioms trace_length
#print axioms conjugating_a_reflector_preserves_its_involution
#print axioms conjugating_a_reflector_preserves_the_absence_of_fixed_points
#print axioms normalization_preserves_every_trace
#print axioms deduplication_preserves_every_key
#print axioms a_finishing_cap_can_discard_the_true_candidate

end CipherProofs
