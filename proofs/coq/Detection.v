(* Machine-checked core of Theorems 1-2 / S2 (root sets and bounds).

   Coq 8.18.0 + mathcomp 2.1.0 (ssreflect, algebra).

   Everything is for ONE fixed state x: the faulted discrepancy as a
   polynomial in the challenge is
        g = (d * u) *: ('X^k * h)
   where d is the injected error at that state, u the unit content at that
   state, and h the class polynomial at that state.  F is any field.

   Proved:
     undetected_set    for d != 0 and u != 0, r is a root of g iff
                       (k > 0 and r = 0) or r is a root of h.  In particular
                       the set does not depend on d: delta-agnosticism.
     undetected_bound  any duplicate-free list of roots of g has at most
                       deg h + [k > 0] elements (h != 0).
     same_class        two faults with the same (k, h) at a state have the
                       same undetected set there, whatever their d and u.
     no_field_no_bound the hypothesis 'field' cannot be dropped: stated as a
                       remark with the Z/4 style counterexample in the tests
                       (tests/test_checker_field_validation.py); not a Coq
                       theorem.

   Not proved here: that 'wrong output at x' implies d != 0 and u != 0
   (the witness argument, a linear-combination step), and the link between
   polynomials reduced modulo X^q = X and functions on GF(q). *)

From mathcomp Require Import all_ssreflect all_algebra.
Set Implicit Arguments.
Unset Strict Implicit.
Unset Printing Implicit Defensive.
Import GRing.Theory.
Local Open Scope ring_scope.

Section Detection.
Variable F : fieldType.
Implicit Types (h : {poly F}) (d u r : F) (k : nat).

Definition faulted d u k h : {poly F} := (d * u) *: ('X^k * h).

Lemma root_Xn k r : root ('X^k : {poly F}) r = (0 < k)%N && (r == 0).
Proof. by rewrite rootE hornerXn expf_eq0. Qed.

Theorem undetected_set d u k h r :
  d != 0 -> u != 0 ->
  root (faulted d u k h) r = ((0 < k)%N && (r == 0)) || root h r.
Proof.
move=> d0 u0; rewrite /faulted rootZ ?mulf_neq0 //.
by rewrite rootM root_Xn.
Qed.

Corollary same_class d1 u1 d2 u2 k h r :
  d1 != 0 -> u1 != 0 -> d2 != 0 -> u2 != 0 ->
  root (faulted d1 u1 k h) r = root (faulted d2 u2 k h) r.
Proof. by move=> *; rewrite !undetected_set. Qed.

Theorem undetected_bound d u k h (rs : seq F) :
  d != 0 -> u != 0 -> h != 0 ->
  uniq rs -> all (root (faulted d u k h)) rs ->
  (size rs <= (size h).-1 + (0 < k)%N)%N.
Proof.
move=> d0 u0 h0 Urs /allP Hrs.
rewrite -(count_predC (root h) rs) -size_filter.
apply: leq_add.
  have: (size [seq x <- rs | root h x] < size h)%N.
    by apply: max_poly_roots => //; [exact: filter_all | exact: filter_uniq].
  by case: (size h).
have sub: {in rs, forall x, predC (root h) x -> (0 < k)%N && (x == 0)}.
  move=> x xin /= nh; move: (Hrs x xin); rewrite undetected_set //.
  by rewrite (negbTE nh) orbF.
case k0: (0 < k)%N; last first.
  rewrite leqn0 -[_ == 0%N]negbK -lt0n -has_count; apply/hasPn => x xin.
  by apply/negP => /(sub x xin); rewrite k0.
have H1: (count (predC (root h)) rs <= count (pred1 (0%R : F)) rs)%N.
  rewrite -!size_filter; apply: uniq_leq_size; first exact: filter_uniq.
  move=> x; rewrite !mem_filter => /andP[nh xin]; rewrite xin andbT /=.
  by case/andP: (sub x xin nh).
apply: (leq_trans H1).
by rewrite count_uniq_mem // leq_b1.
Qed.

End Detection.

Print Assumptions undetected_bound.
Print Assumptions undetected_set.
