#!/bin/sh
# Compile the machine-checked proofs. Requires Coq 8.18.0 and, for
# Detection.v, mathcomp 2.1.0 (Ubuntu 24.04: apt-get install coq
# libcoq-mathcomp-algebra). Prints the axioms each main theorem depends on;
# "Closed under the global context" means none.
set -e
cd "$(dirname "$0")"
coqc -q Propagation.v
coqc -q -w -all Detection.v
rm -f ./*.vo ./*.vok ./*.vos ./*.glob ./.*.aux
