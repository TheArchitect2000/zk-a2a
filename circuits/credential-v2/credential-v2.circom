pragma circom 2.1.8;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";
include "../lib/merkle.circom";

// Proves possession of an unrevoked credential whose hidden scope bitmap
// authorizes skillIndex. The nullifier is stable only within sessionScope;
// requestTag binds the same holder secret to the fresh A2A requestBinding.
template CredentialV2(depth, maxSkills) {
    signal input secret;
    signal input issuerId;
    signal input scopeBitmap;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    signal input issuerRoot;
    signal input skillIndex;
    signal input sessionScope;
    signal input requestBinding;

    signal output nullifier;
    signal output requestTag;

    component leafHash = Poseidon(3);
    leafHash.inputs[0] <== secret;
    leafHash.inputs[1] <== issuerId;
    leafHash.inputs[2] <== scopeBitmap;

    component path = MerklePath(depth);
    path.leaf <== leafHash.out;
    for (var i = 0; i < depth; i++) {
        path.pathElements[i] <== pathElements[i];
        path.pathIndices[i] <== pathIndices[i];
    }
    path.root === issuerRoot;

    component bits = Num2Bits(maxSkills);
    bits.in <== scopeBitmap;
    component selected[maxSkills];
    signal authorized[maxSkills + 1];
    authorized[0] <== 0;
    for (var j = 0; j < maxSkills; j++) {
        selected[j] = IsEqual();
        selected[j].in[0] <== j;
        selected[j].in[1] <== skillIndex;
        authorized[j + 1] <== authorized[j] + selected[j].out * bits.out[j];
    }
    authorized[maxSkills] === 1;

    component nullifierHash = Poseidon(2);
    nullifierHash.inputs[0] <== secret;
    nullifierHash.inputs[1] <== sessionScope;
    nullifier <== nullifierHash.out;

    component requestHash = Poseidon(2);
    requestHash.inputs[0] <== secret;
    requestHash.inputs[1] <== requestBinding;
    requestTag <== requestHash.out;
}

component main {public [issuerRoot, skillIndex, sessionScope, requestBinding]} =
    CredentialV2(20, 64);
