(* Machine-checked core of Theorem S1 (STRUCTURAL_QUOTIENT_THEORY.md) and of
   Lemma L (taint criterion), for the straight-line IR toy-ir-v1.

   Coq 8.18.0, standard library only.

   Setting: everything is POINTWISE in the state x and the challenge r, so
   register contents are elements of a commutative ring K (for the IR, the
   field GF(2^m); no field property is used in this file, and no assumption
   on the characteristic).

   What is proved:
     tangent_exact   If two register maps differ by   delta * c   and the
                     program satisfies the semantic linearity condition
                     along its execution, then after the program they differ
                     by   delta * (tangent of c).   Exact, any delta.
     taint_sound     The bit-level taint pass over-approximates the support
                     of the tangent, and its side condition (no multiplication
                     with two tainted operands) implies the linearity
                     condition.
     fault_effect    Theorem S1: for a fault that replaces the value written
                     at one site by that value plus delta, every register
                     after the suffix equals the fault-free value plus
                     delta * J, with J independent of delta.

     duality, reverse_is_forward
                     Lemma R: the reverse pass of the implementation
                     (take the destination's adjoint, clear it, add it times
                     the partial derivative to each operand) computes that J.
     fault_effect_reverse
                     S1 as used by the generator and the checker: faulted
                     value = fault-free value + delta * reverse-pass adjoint.

   What is NOT proved: that the Python implementations realise these
   definitions; that polynomial identities on reduced polynomials coincide
   with pointwise identities (true for a field of q elements, used on
   paper); anything about the witness search. *)

Require Import Ring List Bool Arith Lia.
Import ListNotations.

Section Propagation.

Variable K : Type.
Variables (kO kI : K) (kadd kmul ksub : K -> K -> K) (kopp : K -> K).
Hypothesis Kring : ring_theory kO kI kadd kmul ksub kopp (@eq K).
Add Ring Kr : Kring.

Notation "0" := kO.
Notation "1" := kI.
Infix "+" := kadd.
Infix "*" := kmul.

Notation reg := nat.
Definition state := reg -> K.

Inductive instr :=
| Const (d : reg) (c : K)
| Mov   (d a : reg)
| Add   (d a b : reg)
| Mul   (d a b : reg).

Definition dst (i : instr) : reg :=
  match i with Const d _ | Mov d _ | Add d _ _ | Mul d _ _ => d end.

Definition upd {A} (s : reg -> A) (d : reg) (v : A) : reg -> A :=
  fun r => if Nat.eqb r d then v else s r.

Definition value (s : state) (i : instr) : K :=
  match i with
  | Const _ c => c
  | Mov _ a => s a
  | Add _ a b => s a + s b
  | Mul _ a b => s a * s b
  end.

Definition step (s : state) (i : instr) : state := upd s (dst i) (value s i).

Fixpoint run (p : list instr) (s : state) : state :=
  match p with [] => s | i :: p' => run p' (step s i) end.

(* Forward tangent: how a perturbation coefficient map c propagates. *)
Definition tvalue (s c : state) (i : instr) : K :=
  match i with
  | Const _ _ => 0
  | Mov _ a => c a
  | Add _ a b => c a + c b
  | Mul _ a b => c a * s b + s a * c b
  end.

Definition tstep (s c : state) (i : instr) : state := upd c (dst i) (tvalue s c i).

Fixpoint tangent (p : list instr) (s c : state) : state :=
  match p with [] => c | i :: p' => tangent p' (step s i) (tstep s c i) end.

(* Semantic linearity condition: at every multiplication, the product of the
   two operands' perturbation coefficients vanishes. *)
Definition lin1 (c : state) (i : instr) : Prop :=
  match i with Mul _ a b => c a * c b = 0 | _ => True end.

Fixpoint linear (p : list instr) (s c : state) : Prop :=
  match p with
  | [] => True
  | i :: p' => lin1 c i /\ linear p' (step s i) (tstep s c i)
  end.

Lemma step_exact (delta : K) (s s' c : state) (i : instr) :
  (forall r, s' r = s r + delta * c r) ->
  lin1 c i ->
  forall r, step s' i r = step s i r + delta * tstep s c i r.
Proof.
  intros H L r. unfold step, tstep, upd.
  destruct (Nat.eqb r (dst i)); [| apply H].
  destruct i as [d k | d a | d a b | d a b]; simpl in *.
  - ring.
  - apply H.
  - rewrite (H a), (H b). ring.
  - rewrite (H a), (H b).
    transitivity (s a * s b + delta * (c a * s b + s a * c b)
                  + delta * delta * (c a * c b)); [ring |].
    rewrite L. ring.
Qed.

Theorem tangent_exact (delta : K) (p : list instr) :
  forall s s' c,
    (forall r, s' r = s r + delta * c r) ->
    linear p s c ->
    forall r, run p s' r = run p s r + delta * tangent p s c r.
Proof.
  induction p as [| i p IH]; intros s s' c H L r; simpl.
  - apply H.
  - destruct L as [L1 L2].
    apply (IH (step s i) (step s' i) (tstep s c i)); [| exact L2].
    intro r0. apply step_exact; assumption.
Qed.

(* ---- taint: a decidable sufficient condition for [linear] ------------- *)

Definition taint := reg -> bool.

Definition tnext (t : taint) (i : instr) : taint :=
  upd t (dst i)
      (match i with
       | Const _ _ => false
       | Mov _ a => t a
       | Add _ a b | Mul _ a b => t a || t b
       end).

Definition ok1 (t : taint) (i : instr) : bool :=
  match i with Mul _ a b => negb (t a && t b) | _ => true end.

Fixpoint taint_ok (p : list instr) (t : taint) : bool :=
  match p with [] => true | i :: p' => ok1 t i && taint_ok p' (tnext t i) end.

Definition covers (t : taint) (c : state) : Prop := forall r, t r = false -> c r = 0.

Lemma covers_step (t : taint) (s c : state) (i : instr) :
  covers t c -> covers (tnext t i) (tstep s c i).
Proof.
  intros H r. unfold tnext, tstep, upd.
  destruct (Nat.eqb r (dst i)); [| apply H].
  destruct i as [d k | d a | d a b | d a b]; simpl; intro E.
  - reflexivity.
  - apply H, E.
  - apply orb_false_elim in E. destruct E as [Ea Eb].
    rewrite (H a Ea), (H b Eb). ring.
  - apply orb_false_elim in E. destruct E as [Ea Eb].
    rewrite (H a Ea), (H b Eb). ring.
Qed.

Theorem taint_sound (p : list instr) :
  forall t s c, covers t c -> taint_ok p t = true -> linear p s c.
Proof.
  induction p as [| i p IH]; intros t s c H Hok; simpl; [exact I |].
  simpl in Hok. apply andb_true_iff in Hok. destruct Hok as [O1 O2]. split.
  - destruct i as [d k | d a | d a b | d a b]; simpl; try exact I.
    simpl in O1. apply negb_true_iff in O1. apply andb_false_iff in O1.
    destruct O1 as [E | E]; rewrite (H _ E); ring.
  - apply (IH (tnext t i)); [apply covers_step; exact H | exact O2].
Qed.

(* ---- Theorem S1 ------------------------------------------------------- *)

(* A fault at one site: the fault-free state after the site is [s]; the
   faulted state is [s] with the destination holding its value plus delta.
   (bit flip: delta constant; result-zero: delta = the value; skip:
   delta = value - previous content.  All three are instances.) *)
Definition unit_at (d : reg) : state := fun r => if Nat.eqb r d then 1 else 0.
Definition seed_taint (d : reg) : taint := fun r => Nat.eqb r d.

Lemma seed_covers (d : reg) : covers (seed_taint d) (unit_at d).
Proof.
  intros r E. unfold seed_taint in E. unfold unit_at. rewrite E. reflexivity.
Qed.

Theorem fault_effect (suffix : list instr) (s : state) (d : reg) (delta : K) :
  taint_ok suffix (seed_taint d) = true ->
  forall r,
    run suffix (upd s d (s d + delta)) r
    = run suffix s r + delta * tangent suffix s (unit_at d) r.
Proof.
  intros Hok r.
  apply tangent_exact.
  - intro r0. unfold upd, unit_at. destruct (Nat.eqb r0 d) eqn:E.
    + apply Nat.eqb_eq in E. subst. ring.
    + ring.
  - apply (taint_sound suffix (seed_taint d)); [apply seed_covers | exact Hok].
Qed.

(* The coefficient J = tangent suffix s (unit_at d) r does not mention delta:
   it is the same for every fault at the site. *)

(* ---- the reverse pass ------------------------------------------------- *)

Definition pick (r a : reg) (x : K) : K := if Nat.eqb r a then x else 0.

Definition pull (s A : state) (i : instr) : state :=
  fun r =>
    (if Nat.eqb r (dst i) then 0 else A r)
    + match i with
      | Const _ _ => 0
      | Mov d a => pick r a (A d)
      | Add d a b => pick r a (A d) + pick r b (A d)
      | Mul d a b => pick r a (A d * s b) + pick r b (A d * s a)
      end.

Fixpoint adj (p : list instr) (s seed : state) : state :=
  match p with
  | [] => seed
  | i :: p' => pull s (adj p' (step s i) seed) i
  end.

(* ---- finite sums over registers 0 .. n-1 ------------------------------ *)

Fixpoint sum (n : nat) (f : reg -> K) : K :=
  match n with O => 0 | S m => sum m f + f m end.

Lemma sum_ext n f g : (forall r, r < n -> f r = g r) -> sum n f = sum n g.
Proof.
  induction n as [| n IH]; intro H; simpl; [reflexivity |].
  rewrite IH by (intros; apply H; lia). rewrite (H n) by lia. reflexivity.
Qed.

Lemma sum_add n f g : sum n (fun r => f r + g r) = sum n f + sum n g.
Proof. induction n as [| n IH]; simpl; [ring | rewrite IH; ring]. Qed.

Lemma sum_zero n : sum n (fun _ => 0) = 0.
Proof. induction n as [| n IH]; simpl; [reflexivity | rewrite IH; ring]. Qed.

Lemma sum_pick n a x (c : state) :
  a < n -> sum n (fun r => pick r a x * c r) = x * c a.
Proof.
  induction n as [| n IH]; intro H; [lia |]. simpl.
  destruct (Nat.eq_dec a n) as [E | E].
  - subst. unfold pick at 2. rewrite Nat.eqb_refl.
    rewrite (sum_ext n _ (fun _ => 0)).
    + rewrite sum_zero. ring.
    + intros r Hr. unfold pick. destruct (Nat.eqb r n) eqn:Q.
      * apply Nat.eqb_eq in Q. lia.
      * ring.
  - rewrite IH by lia. unfold pick. destruct (Nat.eqb n a) eqn:Q.
    + apply Nat.eqb_eq in Q. lia.
    + ring.
Qed.

Lemma sum_upd n (A c : state) d v :
  d < n ->
  sum n (fun r => A r * upd c d v r)
  = sum n (fun r => (if Nat.eqb r d then 0 else A r) * c r) + A d * v.
Proof.
  intro H.
  rewrite (sum_ext n _ (fun r => (if Nat.eqb r d then 0 else A r) * c r
                                 + pick r d (A d * v) * 1)).
  - rewrite sum_add. rewrite (sum_pick n d (A d * v) (fun _ => 1) H). ring.
  - intros r _. unfold upd, pick. destruct (Nat.eqb r d) eqn:Q.
    + apply Nat.eqb_eq in Q. subst. ring.
    + ring.
Qed.

Definition wf1 (n : nat) (i : instr) : Prop :=
  match i with
  | Const d _ => d < n
  | Mov d a => d < n /\ a < n
  | Add d a b | Mul d a b => d < n /\ a < n /\ b < n
  end.

Lemma dst_lt n i : wf1 n i -> dst i < n.
Proof. destruct i; simpl; intuition. Qed.

Lemma one_step n (s A c : state) (i : instr) :
  wf1 n i ->
  sum n (fun r => pull s A i r * c r) = sum n (fun r => A r * tstep s c i r).
Proof.
  intro W. unfold tstep. rewrite (sum_upd n A c (dst i) _ (dst_lt n i W)).
  unfold pull.
  destruct i as [d k | d a | d a b | d a b]; simpl in *.
  - rewrite (sum_ext n _ (fun r => (if Nat.eqb r d then 0 else A r) * c r))
      by (intros; ring).
    ring.
  - destruct W as [Wd Wa].
    rewrite (sum_ext n _ (fun r => (if Nat.eqb r d then 0 else A r) * c r
                                   + pick r a (A d) * c r)) by (intros; ring).
    rewrite sum_add, (sum_pick n a _ c Wa). ring.
  - destruct W as [Wd [Wa Wb]].
    rewrite (sum_ext n _ (fun r => ((if Nat.eqb r d then 0 else A r) * c r
                                    + pick r a (A d) * c r)
                                   + pick r b (A d) * c r)) by (intros; ring).
    rewrite !sum_add, (sum_pick n a _ c Wa), (sum_pick n b _ c Wb). ring.
  - destruct W as [Wd [Wa Wb]].
    rewrite (sum_ext n _ (fun r => ((if Nat.eqb r d then 0 else A r) * c r
                                    + pick r a (A d * s b) * c r)
                                   + pick r b (A d * s a) * c r)) by (intros; ring).
    rewrite !sum_add, (sum_pick n a _ c Wa), (sum_pick n b _ c Wb). ring.
Qed.

Theorem duality n (p : list instr) :
  Forall (wf1 n) p ->
  forall s seed c,
    sum n (fun r => adj p s seed r * c r)
    = sum n (fun r => seed r * tangent p s c r).
Proof.
  induction p as [| i p IH]; intros W s seed c; simpl; [reflexivity |].
  inversion W as [| ? ? W1 W2]; subst.
  rewrite (one_step n s _ c i W1). apply IH. exact W2.
Qed.

Lemma sum_unit_l n out (f : state) :
  out < n -> sum n (fun r => unit_at out r * f r) = f out.
Proof.
  intro H. rewrite (sum_ext n _ (fun r => pick r out 1 * f r)).
  - rewrite (sum_pick n out 1 f H). ring.
  - intros; unfold unit_at, pick; reflexivity.
Qed.

Lemma sum_unit_r n d (g : state) :
  d < n -> sum n (fun r => g r * unit_at d r) = g d.
Proof.
  intro H. rewrite (sum_ext n _ (fun r => pick r d 1 * g r)).
  - rewrite (sum_pick n d 1 g H). ring.
  - intros r _. unfold unit_at, pick. destruct (Nat.eqb r d); ring.
Qed.

Theorem reverse_is_forward n (p : list instr) (s : state) (d out : reg) :
  Forall (wf1 n) p -> d < n -> out < n ->
  adj p s (unit_at out) d = tangent p s (unit_at d) out.
Proof.
  intros W Hd Ho.
  rewrite <- (sum_unit_r n d (adj p s (unit_at out)) Hd).
  rewrite (duality n p W s (unit_at out) (unit_at d)).
  apply sum_unit_l. exact Ho.
Qed.


(* ---- Theorem S1 in the form the implementation uses ------------------- *)

Theorem fault_effect_reverse n (suffix : list instr) (s : state) (d out : reg)
        (delta : K) :
  Forall (wf1 n) suffix -> d < n -> out < n ->
  taint_ok suffix (seed_taint d) = true ->
  run suffix (upd s d (s d + delta)) out
  = run suffix s out + delta * adj suffix s (unit_at out) d.
Proof.
  intros W Hd Ho Hok.
  rewrite (reverse_is_forward n suffix s d out W Hd Ho).
  apply fault_effect. exact Hok.
Qed.

End Propagation.

Print Assumptions fault_effect_reverse.
