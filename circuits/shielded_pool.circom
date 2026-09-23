pragma circom 2.1.6;

include "circomlib/circuits/mimc.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/sha256/sha256.circom";

template LittleEndianBytes(N) {
    signal input value;
    signal output bits[N];
    component raw = Num2Bits(N);
    raw.in <== value;
    for (var byte = 0; byte < N / 8; byte++) {
        for (var bit = 0; bit < 8; bit++) {
            bits[byte * 8 + bit] <== raw.out[byte * 8 + 7 - bit];
        }
    }
}

// MiMC7 is used throughout because the same permutation is available in
// scrypt-ts-lib and can therefore bind the Groth16 statement in Bitcoin Script.
template Hash2() {
    signal input left;
    signal input right;
    signal output out;

    component h = MiMC7(91);
    h.x_in <== left;
    h.k <== right;
    out <== h.out;
}

template NoteCommitment() {
    signal input amount;
    signal input ownerKey;
    signal input lockHeight;
    signal input rho;
    signal output out;

    component h0 = Hash2();
    component h1 = Hash2();
    component h2 = Hash2();
    h0.left <== amount;
    h0.right <== ownerKey;
    h1.left <== h0.out;
    h1.right <== lockHeight;
    h2.left <== h1.out;
    h2.right <== rho;
    out <== h2.out;
}

template MerkleRoot(DEPTH) {
    signal input leaf;
    signal input index;
    signal input siblings[DEPTH];
    signal output root;

    component bits = Num2Bits(DEPTH);
    bits.in <== index;

    signal level[DEPTH + 1];
    signal left[DEPTH];
    signal right[DEPTH];
    component hashes[DEPTH];
    level[0] <== leaf;

    for (var i = 0; i < DEPTH; i++) {
        // bit=0: hash(level, sibling); bit=1: hash(sibling, level)
        left[i] <== level[i] + bits.out[i] * (siblings[i] - level[i]);
        right[i] <== siblings[i] + bits.out[i] * (level[i] - siblings[i]);
        hashes[i] = Hash2();
        hashes[i].left <== left[i];
        hashes[i].right <== right[i];
        level[i + 1] <== hashes[i].out;
    }

    root <== level[DEPTH];
}

// One universal 1-in/1-or-2-out join-split relation.
// mode: 0=shield, 1=private transfer, 2=unshield.
// The only Groth16 public input is `statement`; all transition fields are
// hash-bound to it and independently supplied to the covenant.
template ShieldedPool(DEPTH) {
    signal input statement;

    signal input mode;
    signal input outCount;
    signal input oldNoteRoot;
    signal input newNoteRoot;
    signal input oldNullifierRoot;
    signal input newNullifierRoot;
    signal input oldNextIndex;
    signal input newNextIndex;
    signal input nullifier;
    signal input outputCommitment0;
    signal input outputCommitment1;
    signal input publicIn;
    signal input publicOut;
    signal input recipient;
    signal input currentHeight;

    signal input inputAmount;
    signal input inputOwnerKey;
    signal input inputLockHeight;
    signal input inputRho;
    signal input inputIndex;
    signal input inputNoteSiblings[DEPTH];
    signal input inputNullifierSiblings[DEPTH];

    signal input output0Amount;
    signal input output0OwnerKey;
    signal input output0LockHeight;
    signal input output0Rho;
    signal input output1Amount;
    signal input output1OwnerKey;
    signal input output1LockHeight;
    signal input output1Rho;
    signal input append0Siblings[DEPTH];
    signal input append1Siblings[DEPTH];

    component modeBits = Num2Bits(2);
    component countBits = Num2Bits(2);
    component oldNextBits = Num2Bits(5);
    component newNextBits = Num2Bits(5);
    component oldWithinCapacity = LessEqThan(5);
    component newWithinCapacity = LessEqThan(5);
    modeBits.in <== mode;
    countBits.in <== outCount;
    oldNextBits.in <== oldNextIndex;
    newNextBits.in <== newNextIndex;
    oldWithinCapacity.in[0] <== oldNextIndex;
    oldWithinCapacity.in[1] <== 16;
    newWithinCapacity.in[0] <== newNextIndex;
    newWithinCapacity.in[1] <== 16;
    oldWithinCapacity.out === 1;
    newWithinCapacity.out === 1;

    component mode0 = IsEqual();
    component mode1 = IsEqual();
    component mode2 = IsEqual();
    mode0.in[0] <== mode; mode0.in[1] <== 0;
    mode1.in[0] <== mode; mode1.in[1] <== 1;
    mode2.in[0] <== mode; mode2.in[1] <== 2;
    mode0.out + mode1.out + mode2.out === 1;

    component count0 = IsEqual();
    component count1 = IsEqual();
    component count2 = IsEqual();
    count0.in[0] <== outCount; count0.in[1] <== 0;
    count1.in[0] <== outCount; count1.in[1] <== 1;
    count2.in[0] <== outCount; count2.in[1] <== 2;
    count0.out + count1.out + count2.out === 1;

    // Shield produces one note, transfer one or two, unshield zero or one change note.
    mode0.out * (1 - count1.out) === 0;
    mode1.out * (1 - count1.out - count2.out) === 0;
    mode2.out * (1 - count0.out - count1.out) === 0;

    signal spends;
    signal output0Enabled;
    signal output1Enabled;
    spends <== mode1.out + mode2.out;
    output0Enabled <== mode0.out + mode1.out + mode2.out * outCount;
    output1Enabled <== mode1.out;

    component inAmountBits = Num2Bits(64);
    component out0AmountBits = Num2Bits(64);
    component out1AmountBits = Num2Bits(64);
    component publicInBits = Num2Bits(64);
    component publicOutBits = Num2Bits(64);
    component inputLockBits = Num2Bits(32);
    component output0LockBits = Num2Bits(32);
    component output1LockBits = Num2Bits(32);
    component currentHeightBits = Num2Bits(32);
    inAmountBits.in <== inputAmount;
    out0AmountBits.in <== output0Amount;
    out1AmountBits.in <== output1Amount;
    publicInBits.in <== publicIn;
    publicOutBits.in <== publicOut;
    inputLockBits.in <== inputLockHeight;
    output0LockBits.in <== output0LockHeight;
    output1LockBits.in <== output1LockHeight;
    currentHeightBits.in <== currentHeight;

    // Locks are block heights, never timestamps. Bitcoin interprets values at
    // or above 500,000,000 as UNIX time, so keep every height below that line.
    component inputHeightIsBlock = LessThan(32);
    component output0HeightIsBlock = LessThan(32);
    component output1HeightIsBlock = LessThan(32);
    component currentHeightIsBlock = LessThan(32);
    inputHeightIsBlock.in[0] <== inputLockHeight;
    inputHeightIsBlock.in[1] <== 500000000;
    output0HeightIsBlock.in[0] <== output0LockHeight;
    output0HeightIsBlock.in[1] <== 500000000;
    output1HeightIsBlock.in[0] <== output1LockHeight;
    output1HeightIsBlock.in[1] <== 500000000;
    currentHeightIsBlock.in[0] <== currentHeight;
    currentHeightIsBlock.in[1] <== 500000000;
    inputHeightIsBlock.out === 1;
    output0HeightIsBlock.out === 1;
    output1HeightIsBlock.out === 1;
    currentHeightIsBlock.out === 1;

    // Disabled notes have zero value; enabled notes and pool crossings are nonzero.
    inputAmount * (1 - spends) === 0;
    inputLockHeight * (1 - spends) === 0;
    output0Amount * (1 - output0Enabled) === 0;
    output0LockHeight * (1 - output0Enabled) === 0;
    output1Amount * (1 - output1Enabled) === 0;
    output1LockHeight * (1 - output1Enabled) === 0;
    currentHeight * (1 - spends) === 0;

    component inputZero = IsZero();
    component output0Zero = IsZero();
    component output1Zero = IsZero();
    component publicInZero = IsZero();
    component publicOutZero = IsZero();
    inputZero.in <== inputAmount;
    output0Zero.in <== output0Amount;
    output1Zero.in <== output1Amount;
    publicInZero.in <== publicIn;
    publicOutZero.in <== publicOut;
    spends * inputZero.out === 0;
    output0Enabled * output0Zero.out === 0;
    output1Enabled * output1Zero.out === 0;
    mode0.out * publicInZero.out === 0;
    mode2.out * publicOutZero.out === 0;

    // Only shield has public input; only unshield has public output/recipient.
    publicIn * (1 - mode0.out) === 0;
    publicOut * (1 - mode2.out) === 0;
    recipient * (1 - mode2.out) === 0;

    // Value conservation, with all values range constrained above to avoid wraparound.
    inputAmount + publicIn === output0Amount + output1Amount + publicOut;

    component inputNote = NoteCommitment();
    inputNote.amount <== inputAmount;
    inputNote.ownerKey <== inputOwnerKey;
    inputNote.lockHeight <== inputLockHeight;
    inputNote.rho <== inputRho;

    // The lock height remains hidden in the note. The proof only reveals a
    // current height at which the note is mature enough to spend.
    component inputIsUnlocked = LessEqThan(32);
    inputIsUnlocked.in[0] <== inputLockHeight;
    inputIsUnlocked.in[1] <== currentHeight;
    spends * (1 - inputIsUnlocked.out) === 0;

    component inputMembership = MerkleRoot(DEPTH);
    inputMembership.leaf <== inputNote.out;
    inputMembership.index <== inputIndex;
    for (var i = 0; i < DEPTH; i++) {
        inputMembership.siblings[i] <== inputNoteSiblings[i];
    }
    spends * (inputMembership.root - oldNoteRoot) === 0;

    component nfHash = Hash2();
    nfHash.left <== inputNote.out;
    nfHash.right <== inputOwnerKey;
    nullifier === spends * nfHash.out;

    // Prove the corresponding nullifier slot was zero, then fill it.
    component nullifierBefore = MerkleRoot(DEPTH);
    component nullifierAfter = MerkleRoot(DEPTH);
    nullifierBefore.leaf <== 0;
    nullifierBefore.index <== inputIndex;
    nullifierAfter.leaf <== nullifier;
    nullifierAfter.index <== inputIndex;
    for (var j = 0; j < DEPTH; j++) {
        nullifierBefore.siblings[j] <== inputNullifierSiblings[j];
        nullifierAfter.siblings[j] <== inputNullifierSiblings[j];
    }
    spends * (nullifierBefore.root - oldNullifierRoot) === 0;
    newNullifierRoot === oldNullifierRoot + spends * (nullifierAfter.root - oldNullifierRoot);

    component outputNote0 = NoteCommitment();
    component outputNote1 = NoteCommitment();
    outputNote0.amount <== output0Amount;
    outputNote0.ownerKey <== output0OwnerKey;
    outputNote0.lockHeight <== output0LockHeight;
    outputNote0.rho <== output0Rho;
    outputNote1.amount <== output1Amount;
    outputNote1.ownerKey <== output1OwnerKey;
    outputNote1.lockHeight <== output1LockHeight;
    outputNote1.rho <== output1Rho;
    outputCommitment0 === output0Enabled * outputNote0.out;
    outputCommitment1 === output1Enabled * outputNote1.out;

    // Append output notes into proven-empty leaves at the public next indices.
    component append0Empty = MerkleRoot(DEPTH);
    component append0Filled = MerkleRoot(DEPTH);
    signal append0Index;
    append0Index <== output0Enabled * oldNextIndex;
    append0Empty.leaf <== 0;
    append0Filled.leaf <== outputCommitment0;
    append0Empty.index <== append0Index;
    append0Filled.index <== append0Index;
    for (var k = 0; k < DEPTH; k++) {
        append0Empty.siblings[k] <== append0Siblings[k];
        append0Filled.siblings[k] <== append0Siblings[k];
    }
    output0Enabled * (append0Empty.root - oldNoteRoot) === 0;

    signal rootAfter0;
    rootAfter0 <== oldNoteRoot + output0Enabled * (append0Filled.root - oldNoteRoot);

    component append1Empty = MerkleRoot(DEPTH);
    component append1Filled = MerkleRoot(DEPTH);
    signal append1Index;
    append1Index <== output1Enabled * (oldNextIndex + 1);
    append1Empty.leaf <== 0;
    append1Filled.leaf <== outputCommitment1;
    append1Empty.index <== append1Index;
    append1Filled.index <== append1Index;
    for (var m = 0; m < DEPTH; m++) {
        append1Empty.siblings[m] <== append1Siblings[m];
        append1Filled.siblings[m] <== append1Siblings[m];
    }
    output1Enabled * (append1Empty.root - rootAfter0) === 0;
    newNoteRoot === rootAfter0 + output1Enabled * (append1Filled.root - rootAfter0);
    newNextIndex === oldNextIndex + output0Enabled + output1Enabled;

    // Bind the public transition with native-SHA-compatible fixed-width bytes.
    // The first 31 digest bytes are interpreted as a positive little-endian
    // integer, keeping the single Groth16 public signal below the scalar field.
    component domainBytes = LittleEndianBytes(32);
    component modeBytes = LittleEndianBytes(8);
    component countBytes = LittleEndianBytes(8);
    component oldNoteRootBytes = LittleEndianBytes(256);
    component newNoteRootBytes = LittleEndianBytes(256);
    component oldNullifierRootBytes = LittleEndianBytes(256);
    component newNullifierRootBytes = LittleEndianBytes(256);
    component oldNextIndexBytes = LittleEndianBytes(8);
    component newNextIndexBytes = LittleEndianBytes(8);
    component nullifierBytes = LittleEndianBytes(256);
    component outputCommitment0Bytes = LittleEndianBytes(256);
    component outputCommitment1Bytes = LittleEndianBytes(256);
    component publicInBytes = LittleEndianBytes(64);
    component publicOutBytes = LittleEndianBytes(64);
    component recipientBytes = LittleEndianBytes(160);
    component currentHeightBytes = LittleEndianBytes(32);

    domainBytes.value <== 1447381314;
    modeBytes.value <== mode;
    countBytes.value <== outCount;
    oldNoteRootBytes.value <== oldNoteRoot;
    newNoteRootBytes.value <== newNoteRoot;
    oldNullifierRootBytes.value <== oldNullifierRoot;
    newNullifierRootBytes.value <== newNullifierRoot;
    oldNextIndexBytes.value <== oldNextIndex;
    newNextIndexBytes.value <== newNextIndex;
    nullifierBytes.value <== nullifier;
    outputCommitment0Bytes.value <== outputCommitment0;
    outputCommitment1Bytes.value <== outputCommitment1;
    publicInBytes.value <== publicIn;
    publicOutBytes.value <== publicOut;
    recipientBytes.value <== recipient;
    currentHeightBytes.value <== currentHeight;

    component statementSha = Sha256(2176);
    for (var s0 = 0; s0 < 32; s0++) statementSha.in[s0] <== domainBytes.bits[s0];
    for (var s1 = 0; s1 < 8; s1++) statementSha.in[32 + s1] <== modeBytes.bits[s1];
    for (var s2 = 0; s2 < 8; s2++) statementSha.in[40 + s2] <== countBytes.bits[s2];
    for (var s3 = 0; s3 < 256; s3++) statementSha.in[48 + s3] <== oldNoteRootBytes.bits[s3];
    for (var s4 = 0; s4 < 256; s4++) statementSha.in[304 + s4] <== newNoteRootBytes.bits[s4];
    for (var s5 = 0; s5 < 256; s5++) statementSha.in[560 + s5] <== oldNullifierRootBytes.bits[s5];
    for (var s6 = 0; s6 < 256; s6++) statementSha.in[816 + s6] <== newNullifierRootBytes.bits[s6];
    for (var s7 = 0; s7 < 8; s7++) statementSha.in[1072 + s7] <== oldNextIndexBytes.bits[s7];
    for (var s8 = 0; s8 < 8; s8++) statementSha.in[1080 + s8] <== newNextIndexBytes.bits[s8];
    for (var s9 = 0; s9 < 256; s9++) statementSha.in[1088 + s9] <== nullifierBytes.bits[s9];
    for (var s10 = 0; s10 < 256; s10++) statementSha.in[1344 + s10] <== outputCommitment0Bytes.bits[s10];
    for (var s11 = 0; s11 < 256; s11++) statementSha.in[1600 + s11] <== outputCommitment1Bytes.bits[s11];
    for (var s12 = 0; s12 < 64; s12++) statementSha.in[1856 + s12] <== publicInBytes.bits[s12];
    for (var s13 = 0; s13 < 64; s13++) statementSha.in[1920 + s13] <== publicOutBytes.bits[s13];
    for (var s14 = 0; s14 < 160; s14++) statementSha.in[1984 + s14] <== recipientBytes.bits[s14];
    for (var s15 = 0; s15 < 32; s15++) statementSha.in[2144 + s15] <== currentHeightBytes.bits[s15];

    component statementNumber = Bits2Num(248);
    for (var digestByte = 0; digestByte < 31; digestByte++) {
        for (var digestBit = 0; digestBit < 8; digestBit++) {
            statementNumber.in[digestByte * 8 + digestBit] <==
                statementSha.out[digestByte * 8 + 7 - digestBit];
        }
    }
    statement === statementNumber.out;
}

component main {public [statement]} = ShieldedPool(4);
