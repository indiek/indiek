#!/bin/bash
# This script creates a new network with the following structure
# GENESIS author creates two text nodes e1 and e2.
# Anonymous author creates a text node e3 and an edge (e4) from e3 to e1.
# Anonymous author creates an edge tag (m1) to tag their edge (e4) with the tag "reaction".
# Genesis author creates a node tag to tag the nodes e1 and e3 with the tag "discussion".
ik --dot-env .env.genesis create_node --content "Dieu existe"  # e1
ik --dot-env .env.genesis create_node --content "Donc je suis divin"  # e2
ik --dot-env .env.anonymous1 create_node --content "Je ne vois aucune preuve de l'existence de Dieu"  # e3
ik --dot-env .env.anonymous1 create_edge --source-node e3 --target-node e1 --content "Pas d'accord"  # e4
ik --dot-env .env.anonymous1 create_edge_tag --name "reaction" --description "reaction to others' words"  # m1
ik --dot-env .env.anonymous1 set_tag --tag m1 --id e4  # m2 and m3
ik --dot-env .env.genesis create_node_tag --name "discussion" --description "discussion about God"  # m4
ik --dot-env .env.genesis set_tag --tag m4 --id e1
ik --dot-env .env.genesis set_tag --tag m4 --id e3
