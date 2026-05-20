import * as __compactRuntime from '@midnight-ntwrk/compact-runtime';
__compactRuntime.checkRuntimeVersion('0.15.0');

export var HolderBindingProfile;
(function (HolderBindingProfile) {
  HolderBindingProfile[HolderBindingProfile['explicitDid'] = 0] = 'explicitDid';
  HolderBindingProfile[HolderBindingProfile['secretHolder'] = 1] = 'secretHolder';
  HolderBindingProfile[HolderBindingProfile['blindedSecretHolder'] = 2] = 'blindedSecretHolder';
})(HolderBindingProfile || (HolderBindingProfile = {}));

export var StatusType;
(function (StatusType) {
  StatusType[StatusType['revocationRegistry'] = 0] = 'revocationRegistry';
})(StatusType || (StatusType = {}));

const _descriptor_0 = new __compactRuntime.CompactTypeEnum(0, 0);

const _descriptor_1 = new __compactRuntime.CompactTypeBytes(32);

class _ContractAddress_0 {
  alignment() {
    return _descriptor_1.alignment();
  }
  fromValue(value_0) {
    return {
      bytes: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_1.toValue(value_0.bytes);
  }
}

const _descriptor_2 = new _ContractAddress_0();

class _VerificationMethodRef_0 {
  alignment() {
    return _descriptor_2.alignment().concat(_descriptor_1.alignment());
  }
  fromValue(value_0) {
    return {
      didContractAddress: _descriptor_2.fromValue(value_0),
      methodId: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_2.toValue(value_0.didContractAddress).concat(_descriptor_1.toValue(value_0.methodId));
  }
}

const _descriptor_3 = new _VerificationMethodRef_0();

class _StatusRegistryRef_0 {
  alignment() {
    return _descriptor_1.alignment().concat(_descriptor_3.alignment());
  }
  fromValue(value_0) {
    return {
      registryId: _descriptor_1.fromValue(value_0),
      authorityVerificationMethodRef: _descriptor_3.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_1.toValue(value_0.registryId).concat(_descriptor_3.toValue(value_0.authorityVerificationMethodRef));
  }
}

const _descriptor_4 = new _StatusRegistryRef_0();

class _RegistryBoundStatusBinding_0 {
  alignment() {
    return _descriptor_0.alignment().concat(_descriptor_4.alignment().concat(_descriptor_1.alignment()));
  }
  fromValue(value_0) {
    return {
      statusType: _descriptor_0.fromValue(value_0),
      registryRef: _descriptor_4.fromValue(value_0),
      statusHandleCommitment: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_0.toValue(value_0.statusType).concat(_descriptor_4.toValue(value_0.registryRef).concat(_descriptor_1.toValue(value_0.statusHandleCommitment)));
  }
}

const _descriptor_5 = new _RegistryBoundStatusBinding_0();

class _NoStatusBinding_0 {
  alignment() {
    return [];
  }
  fromValue(value_0) {
    return {
    }
  }
  toValue(value_0) {
    return [];
  }
}

const _descriptor_6 = new _NoStatusBinding_0();

const _descriptor_7 = new __compactRuntime.CompactTypeUnsignedInteger(65535n, 2);

const _descriptor_8 = __compactRuntime.CompactTypeBoolean;

const _descriptor_9 = new __compactRuntime.CompactTypeUnsignedInteger(18446744073709551615n, 8);

class _ProtocolMessageEnvelope_0 {
  alignment() {
    return _descriptor_7.alignment().concat(_descriptor_1.alignment().concat(_descriptor_1.alignment().concat(_descriptor_8.alignment().concat(_descriptor_1.alignment().concat(_descriptor_9.alignment().concat(_descriptor_8.alignment().concat(_descriptor_9.alignment())))))));
  }
  fromValue(value_0) {
    return {
      version: _descriptor_7.fromValue(value_0),
      messageId: _descriptor_1.fromValue(value_0),
      threadId: _descriptor_1.fromValue(value_0),
      initialMessage: _descriptor_8.fromValue(value_0),
      respondsToMessageId: _descriptor_1.fromValue(value_0),
      createdAt: _descriptor_9.fromValue(value_0),
      hasExpiresAt: _descriptor_8.fromValue(value_0),
      expiresAt: _descriptor_9.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_7.toValue(value_0.version).concat(_descriptor_1.toValue(value_0.messageId).concat(_descriptor_1.toValue(value_0.threadId).concat(_descriptor_8.toValue(value_0.initialMessage).concat(_descriptor_1.toValue(value_0.respondsToMessageId).concat(_descriptor_9.toValue(value_0.createdAt).concat(_descriptor_8.toValue(value_0.hasExpiresAt).concat(_descriptor_9.toValue(value_0.expiresAt))))))));
  }
}

const _descriptor_10 = new _ProtocolMessageEnvelope_0();

class _SchemaRef_0 {
  alignment() {
    return _descriptor_1.alignment().concat(_descriptor_1.alignment().concat(_descriptor_7.alignment().concat(_descriptor_7.alignment())));
  }
  fromValue(value_0) {
    return {
      packageId: _descriptor_1.fromValue(value_0),
      schemaId: _descriptor_1.fromValue(value_0),
      majorVersion: _descriptor_7.fromValue(value_0),
      minorVersion: _descriptor_7.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_1.toValue(value_0.packageId).concat(_descriptor_1.toValue(value_0.schemaId).concat(_descriptor_7.toValue(value_0.majorVersion).concat(_descriptor_7.toValue(value_0.minorVersion))));
  }
}

const _descriptor_11 = new _SchemaRef_0();

class _SecretHolderBinding_0 {
  alignment() {
    return _descriptor_1.alignment().concat(_descriptor_1.alignment());
  }
  fromValue(value_0) {
    return {
      holderSecretCommitment: _descriptor_1.fromValue(value_0),
      requestChallengeResponse: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_1.toValue(value_0.holderSecretCommitment).concat(_descriptor_1.toValue(value_0.requestChallengeResponse));
  }
}

const _descriptor_12 = new _SecretHolderBinding_0();

class _BlindedSecretHolderBinding_0 {
  alignment() {
    return _descriptor_1.alignment().concat(_descriptor_1.alignment().concat(_descriptor_1.alignment()));
  }
  fromValue(value_0) {
    return {
      blindedHolderSecretCommitment: _descriptor_1.fromValue(value_0),
      issuerNonce: _descriptor_1.fromValue(value_0),
      requestChallengeResponse: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_1.toValue(value_0.blindedHolderSecretCommitment).concat(_descriptor_1.toValue(value_0.issuerNonce).concat(_descriptor_1.toValue(value_0.requestChallengeResponse)));
  }
}

const _descriptor_13 = new _BlindedSecretHolderBinding_0();

const _descriptor_14 = __compactRuntime.CompactTypeJubjubPoint;

class _OffchainMidnightHolderBinding_0 {
  alignment() {
    return _descriptor_1.alignment().concat(_descriptor_1.alignment().concat(_descriptor_14.alignment()));
  }
  fromValue(value_0) {
    return {
      holderDidStateHash: _descriptor_1.fromValue(value_0),
      holderMethodId: _descriptor_1.fromValue(value_0),
      holderPublicKey: _descriptor_14.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_1.toValue(value_0.holderDidStateHash).concat(_descriptor_1.toValue(value_0.holderMethodId).concat(_descriptor_14.toValue(value_0.holderPublicKey)));
  }
}

const _descriptor_15 = new _OffchainMidnightHolderBinding_0();

const _descriptor_16 = __compactRuntime.CompactTypeField;

class _Signature_0 {
  alignment() {
    return _descriptor_14.alignment().concat(_descriptor_16.alignment());
  }
  fromValue(value_0) {
    return {
      r: _descriptor_14.fromValue(value_0),
      s: _descriptor_16.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_14.toValue(value_0.r).concat(_descriptor_16.toValue(value_0.s));
  }
}

const _descriptor_17 = new _Signature_0();

class _Proof_0 {
  alignment() {
    return _descriptor_3.alignment().concat(_descriptor_9.alignment().concat(_descriptor_1.alignment().concat(_descriptor_14.alignment().concat(_descriptor_17.alignment()))));
  }
  fromValue(value_0) {
    return {
      signerVerificationMethodRef: _descriptor_3.fromValue(value_0),
      createdAt: _descriptor_9.fromValue(value_0),
      challengeHash: _descriptor_1.fromValue(value_0),
      publicKey: _descriptor_14.fromValue(value_0),
      signature: _descriptor_17.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_3.toValue(value_0.signerVerificationMethodRef).concat(_descriptor_9.toValue(value_0.createdAt).concat(_descriptor_1.toValue(value_0.challengeHash).concat(_descriptor_14.toValue(value_0.publicKey).concat(_descriptor_17.toValue(value_0.signature)))));
  }
}

const _descriptor_18 = new _Proof_0();

class _JubjubHolderBinding_0 {
  alignment() {
    return _descriptor_14.alignment();
  }
  fromValue(value_0) {
    return {
      holderPublicKey: _descriptor_14.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_14.toValue(value_0.holderPublicKey);
  }
}

const _descriptor_19 = new _JubjubHolderBinding_0();

class _ExplicitHolderBinding_0 {
  alignment() {
    return _descriptor_3.alignment();
  }
  fromValue(value_0) {
    return {
      holderVerificationMethodRef: _descriptor_3.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_3.toValue(value_0.holderVerificationMethodRef);
  }
}

const _descriptor_20 = new _ExplicitHolderBinding_0();

const _descriptor_21 = new __compactRuntime.CompactTypeVector(3, _descriptor_1);

const _descriptor_22 = new __compactRuntime.CompactTypeVector(4, _descriptor_1);

const _descriptor_23 = new __compactRuntime.CompactTypeVector(5, _descriptor_1);

class _Either_0 {
  alignment() {
    return _descriptor_8.alignment().concat(_descriptor_1.alignment().concat(_descriptor_1.alignment()));
  }
  fromValue(value_0) {
    return {
      is_left: _descriptor_8.fromValue(value_0),
      left: _descriptor_1.fromValue(value_0),
      right: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_8.toValue(value_0.is_left).concat(_descriptor_1.toValue(value_0.left).concat(_descriptor_1.toValue(value_0.right)));
  }
}

const _descriptor_24 = new _Either_0();

const _descriptor_25 = new __compactRuntime.CompactTypeUnsignedInteger(340282366920938463463374607431768211455n, 16);

const _descriptor_26 = new __compactRuntime.CompactTypeUnsignedInteger(255n, 1);

export class Contract {
  witnesses;
  constructor(...args_0) {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`Contract constructor: expected 1 argument, received ${args_0.length}`);
    }
    const witnesses_0 = args_0[0];
    if (typeof(witnesses_0) !== 'object') {
      throw new __compactRuntime.CompactError('first (witnesses) argument to Contract constructor is not an object');
    }
    this.witnesses = witnesses_0;
    this.circuits = {
      verifySignature(context, ...args_1) {
        return { result: pureCircuits.verifySignature(...args_1), context };
      },
      issuanceContextTag(context, ...args_1) {
        return { result: pureCircuits.issuanceContextTag(...args_1), context };
      },
      presentationContextTag(context, ...args_1) {
        return { result: pureCircuits.presentationContextTag(...args_1), context };
      },
      statusAttestationContextTag(context, ...args_1) {
        return { result: pureCircuits.statusAttestationContextTag(...args_1), context };
      },
      issuanceProofPayloadRoot(context, ...args_1) {
        return { result: pureCircuits.issuanceProofPayloadRoot(...args_1), context };
      },
      presentationProofPayloadRoot(context, ...args_1) {
        return { result: pureCircuits.presentationProofPayloadRoot(...args_1), context };
      },
      issuanceProofChallenge(context, ...args_1) {
        return { result: pureCircuits.issuanceProofChallenge(...args_1), context };
      },
      presentationProofChallenge(context, ...args_1) {
        return { result: pureCircuits.presentationProofChallenge(...args_1), context };
      },
      assertValidIssuanceContextProof(context, ...args_1) {
        return { result: pureCircuits.assertValidIssuanceContextProof(...args_1), context };
      },
      assertValidPresentationContextProof(context, ...args_1) {
        return { result: pureCircuits.assertValidPresentationContextProof(...args_1), context };
      },
      statusAttestationProofPayloadRoot(context, ...args_1) {
        return { result: pureCircuits.statusAttestationProofPayloadRoot(...args_1), context };
      },
      statusAttestationProofChallenge(context, ...args_1) {
        return { result: pureCircuits.statusAttestationProofChallenge(...args_1), context };
      },
      assertValidStatusAttestationContextProof(context, ...args_1) {
        return { result: pureCircuits.assertValidStatusAttestationContextProof(...args_1), context };
      },
      assertValidExplicitHolderBinding(context, ...args_1) {
        return { result: pureCircuits.assertValidExplicitHolderBinding(...args_1), context };
      },
      assertMatchingExplicitHolderBindings(context, ...args_1) {
        return { result: pureCircuits.assertMatchingExplicitHolderBindings(...args_1), context };
      },
      assertProofMatchesExplicitHolderBinding(context, ...args_1) {
        return { result: pureCircuits.assertProofMatchesExplicitHolderBinding(...args_1), context };
      },
      assertValidJubjubHolderBinding(context, ...args_1) {
        return { result: pureCircuits.assertValidJubjubHolderBinding(...args_1), context };
      },
      assertMatchingJubjubHolderBindings(context, ...args_1) {
        return { result: pureCircuits.assertMatchingJubjubHolderBindings(...args_1), context };
      },
      assertProofMatchesJubjubHolderBinding(context, ...args_1) {
        return { result: pureCircuits.assertProofMatchesJubjubHolderBinding(...args_1), context };
      },
      assertValidOffchainMidnightHolderBinding(context, ...args_1) {
        return { result: pureCircuits.assertValidOffchainMidnightHolderBinding(...args_1), context };
      },
      assertMatchingOffchainMidnightHolderBindings(context, ...args_1) {
        return { result: pureCircuits.assertMatchingOffchainMidnightHolderBindings(...args_1), context };
      },
      assertProofMatchesOffchainMidnightHolderBinding(context, ...args_1) {
        return { result: pureCircuits.assertProofMatchesOffchainMidnightHolderBinding(...args_1), context };
      },
      noSecretHolderChallengeResponse(context, ...args_1) {
        return { result: pureCircuits.noSecretHolderChallengeResponse(...args_1), context };
      },
      secretHolderBindingCommitment(context, ...args_1) {
        return { result: pureCircuits.secretHolderBindingCommitment(...args_1), context };
      },
      secretHolderBindingChallengeResponse(context, ...args_1) {
        return { result: pureCircuits.secretHolderBindingChallengeResponse(...args_1), context };
      },
      verifierScopedPseudonym(context, ...args_1) {
        return { result: pureCircuits.verifierScopedPseudonym(...args_1), context };
      },
      assertVerifierScopedPseudonym(context, ...args_1) {
        return { result: pureCircuits.assertVerifierScopedPseudonym(...args_1), context };
      },
      blindedSecretHolderCommitment(context, ...args_1) {
        return { result: pureCircuits.blindedSecretHolderCommitment(...args_1), context };
      },
      assertValidSecretHolderCredentialBinding(context, ...args_1) {
        return { result: pureCircuits.assertValidSecretHolderCredentialBinding(...args_1), context };
      },
      assertValidSecretHolderPresentationBinding(context, ...args_1) {
        return { result: pureCircuits.assertValidSecretHolderPresentationBinding(...args_1), context };
      },
      assertMatchingSecretHolderBindings(context, ...args_1) {
        return { result: pureCircuits.assertMatchingSecretHolderBindings(...args_1), context };
      },
      assertValidBlindedSecretHolderCredentialBinding(context, ...args_1) {
        return { result: pureCircuits.assertValidBlindedSecretHolderCredentialBinding(...args_1), context };
      },
      assertValidBlindedSecretHolderPresentationBinding(context, ...args_1) {
        return { result: pureCircuits.assertValidBlindedSecretHolderPresentationBinding(...args_1), context };
      },
      assertMatchingBlindedSecretHolderBindings(context, ...args_1) {
        return { result: pureCircuits.assertMatchingBlindedSecretHolderBindings(...args_1), context };
      },
      assertSecretHolderBindingWitness(context, ...args_1) {
        return { result: pureCircuits.assertSecretHolderBindingWitness(...args_1), context };
      },
      assertBlindedSecretHolderBindingWitness(context, ...args_1) {
        return { result: pureCircuits.assertBlindedSecretHolderBindingWitness(...args_1), context };
      },
      noProtocolResponseReference(context, ...args_1) {
        return { result: pureCircuits.noProtocolResponseReference(...args_1), context };
      },
      assertValidVerificationMethodRef(context, ...args_1) {
        return { result: pureCircuits.assertValidVerificationMethodRef(...args_1), context };
      },
      assertMatchingSchemaRefs(context, ...args_1) {
        return { result: pureCircuits.assertMatchingSchemaRefs(...args_1), context };
      },
      assertValidProtocolMessageEnvelope(context, ...args_1) {
        return { result: pureCircuits.assertValidProtocolMessageEnvelope(...args_1), context };
      },
      assertProtocolResponseEnvelope(context, ...args_1) {
        return { result: pureCircuits.assertProtocolResponseEnvelope(...args_1), context };
      },
      assertValidStatusRegistryRef(context, ...args_1) {
        return { result: pureCircuits.assertValidStatusRegistryRef(...args_1), context };
      },
      assertValidNoStatusBinding(context, ...args_1) {
        return { result: pureCircuits.assertValidNoStatusBinding(...args_1), context };
      },
      assertValidRegistryBoundStatusBinding(context, ...args_1) {
        return { result: pureCircuits.assertValidRegistryBoundStatusBinding(...args_1), context };
      },
      registryBoundStatusBindingRoot(context, ...args_1) {
        return { result: pureCircuits.registryBoundStatusBindingRoot(...args_1), context };
      }
    };
    this.impureCircuits = {};
    this.provableCircuits = {};
  }
  initialState(...args_0) {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const constructorContext_0 = args_0[0];
    if (typeof(constructorContext_0) !== 'object') {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'constructorContext' in argument 1 (as invoked from Typescript) to be an object`);
    }
    if (!('initialZswapLocalState' in constructorContext_0)) {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'initialZswapLocalState' in argument 1 (as invoked from Typescript)`);
    }
    if (typeof(constructorContext_0.initialZswapLocalState) !== 'object') {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'initialZswapLocalState' in argument 1 (as invoked from Typescript) to be an object`);
    }
    const state_0 = new __compactRuntime.ContractState();
    let stateValue_0 = __compactRuntime.StateValue.newArray();
    state_0.data = new __compactRuntime.ChargedState(stateValue_0);
    const context = __compactRuntime.createCircuitContext(__compactRuntime.dummyContractAddress(), constructorContext_0.initialZswapLocalState.coinPublicKey, state_0.data, constructorContext_0.initialPrivateState);
    const partialProofData = {
      input: { value: [], alignment: [] },
      output: undefined,
      publicTranscript: [],
      privateTranscriptOutputs: []
    };
    state_0.data = new __compactRuntime.ChargedState(context.currentQueryContext.state.state);
    return {
      currentContractState: state_0,
      currentPrivateState: context.currentPrivateState,
      currentZswapLocalState: context.currentZswapLocalState
    }
  }
  _transientHash_0(value_0) {
    const result_0 = __compactRuntime.transientHash(_descriptor_14, value_0);
    return result_0;
  }
  _transientHash_1(value_0) {
    const result_0 = __compactRuntime.transientHash(_descriptor_9, value_0);
    return result_0;
  }
  _persistentHash_0(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_23, value_0);
    return result_0;
  }
  _persistentHash_1(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_3, value_0);
    return result_0;
  }
  _persistentHash_2(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_21, value_0);
    return result_0;
  }
  _persistentHash_3(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_22, value_0);
    return result_0;
  }
  _persistentHash_4(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_5, value_0);
    return result_0;
  }
  _persistentCommit_0(value_0, rand_0) {
    const result_0 = __compactRuntime.persistentCommit(_descriptor_1,
                                                       value_0,
                                                       rand_0);
    return result_0;
  }
  _degradeToTransient_0(x_0) {
    const result_0 = __compactRuntime.degradeToTransient(x_0);
    return result_0;
  }
  _upgradeFromTransient_0(x_0) {
    const result_0 = __compactRuntime.upgradeFromTransient(x_0);
    return result_0;
  }
  _jubjubPointX_0(np_0) {
    const result_0 = __compactRuntime.jubjubPointX(np_0);
    return result_0;
  }
  _jubjubPointY_0(np_0) {
    const result_0 = __compactRuntime.jubjubPointY(np_0);
    return result_0;
  }
  _ecAdd_0(a_0, b_0) {
    const result_0 = __compactRuntime.ecAdd(a_0, b_0);
    return result_0;
  }
  _ecMul_0(a_0, b_0) {
    const result_0 = __compactRuntime.ecMul(a_0, b_0);
    return result_0;
  }
  _ecMulGenerator_0(b_0) {
    const result_0 = __compactRuntime.ecMulGenerator(b_0);
    return result_0;
  }
  _verifySignature_0(pk_0, signature_0, challenge_0) {
    const leftSide_0 = this._ecMulGenerator_0(signature_0.s);
    const cPk_0 = this._ecMul_0(pk_0, challenge_0);
    const rightSide_0 = this._ecAdd_0(signature_0.r, cPk_0);
    const xMatches_0 = this._jubjubPointX_0(leftSide_0)
                       ===
                       this._jubjubPointX_0(rightSide_0);
    const yMatches_0 = this._jubjubPointY_0(leftSide_0)
                       ===
                       this._jubjubPointY_0(rightSide_0);
    __compactRuntime.assert(xMatches_0 && yMatches_0,
                            'Signature verification failed');
    return xMatches_0 && yMatches_0;
  }
  _issuanceContextTag_0() {
    return new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 118, 99, 58, 105, 115, 115, 117, 97, 110, 99, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  }
  _presentationContextTag_0() {
    return new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 118, 99, 58, 112, 114, 101, 115, 101, 110, 116, 97, 116, 105, 111, 110, 0, 0, 0, 0, 0, 0, 0, 0]);
  }
  _statusAttestationContextTag_0() {
    return new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 118, 99, 58, 115, 116, 97, 116, 117, 115, 45, 97, 116, 116, 101, 115, 116, 97, 116, 105, 111, 110, 0, 0]);
  }
  _proofPayloadRootForContext_0(bodyRoot_0, contextTag_0, proof_0) {
    return this._persistentHash_0([bodyRoot_0,
                                   contextTag_0,
                                   this._persistentHash_1(proof_0.signerVerificationMethodRef),
                                   this._upgradeFromTransient_0(this._transientHash_1(proof_0.createdAt)),
                                   proof_0.challengeHash]);
  }
  _proofChallengeForContext_0(bodyRoot_0, contextTag_0, proof_0) {
    return this._degradeToTransient_0(this._persistentHash_2([this._proofPayloadRootForContext_0(bodyRoot_0,
                                                                                                 contextTag_0,
                                                                                                 proof_0),
                                                              this._upgradeFromTransient_0(this._transientHash_0(proof_0.publicKey)),
                                                              this._upgradeFromTransient_0(this._transientHash_0(proof_0.signature.r))]));
  }
  _assertValidProofForContext_0(bodyRoot_0, contextTag_0, proof_0) {
    __compactRuntime.assert(this._verifySignature_0(proof_0.publicKey,
                                                    proof_0.signature,
                                                    this._proofChallengeForContext_0(bodyRoot_0,
                                                                                     contextTag_0,
                                                                                     proof_0)),
                            'Proof verification failed');
    return [];
  }
  _issuanceProofPayloadRoot_0(bodyRoot_0, proof_0) {
    return this._proofPayloadRootForContext_0(bodyRoot_0,
                                              this._issuanceContextTag_0(),
                                              proof_0);
  }
  _presentationProofPayloadRoot_0(bodyRoot_0, proof_0) {
    return this._proofPayloadRootForContext_0(bodyRoot_0,
                                              this._presentationContextTag_0(),
                                              proof_0);
  }
  _issuanceProofChallenge_0(bodyRoot_0, proof_0) {
    return this._proofChallengeForContext_0(bodyRoot_0,
                                            this._issuanceContextTag_0(),
                                            proof_0);
  }
  _presentationProofChallenge_0(bodyRoot_0, proof_0) {
    return this._proofChallengeForContext_0(bodyRoot_0,
                                            this._presentationContextTag_0(),
                                            proof_0);
  }
  _assertValidIssuanceContextProof_0(bodyRoot_0, proof_0) {
    this._assertValidProofForContext_0(bodyRoot_0,
                                       this._issuanceContextTag_0(),
                                       proof_0);
    return [];
  }
  _assertValidPresentationContextProof_0(bodyRoot_0, proof_0) {
    this._assertValidProofForContext_0(bodyRoot_0,
                                       this._presentationContextTag_0(),
                                       proof_0);
    return [];
  }
  _statusAttestationProofPayloadRoot_0(bodyRoot_0, proof_0) {
    return this._proofPayloadRootForContext_0(bodyRoot_0,
                                              this._statusAttestationContextTag_0(),
                                              proof_0);
  }
  _statusAttestationProofChallenge_0(bodyRoot_0, proof_0) {
    return this._proofChallengeForContext_0(bodyRoot_0,
                                            this._statusAttestationContextTag_0(),
                                            proof_0);
  }
  _assertValidStatusAttestationContextProof_0(bodyRoot_0, proof_0) {
    this._assertValidProofForContext_0(bodyRoot_0,
                                       this._statusAttestationContextTag_0(),
                                       proof_0);
    return [];
  }
  _assertValidExplicitHolderBinding_0(binding_0) {
    __compactRuntime.assert(!this._equal_0(binding_0.holderVerificationMethodRef.didContractAddress.bytes,
                                           new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Explicit holder binding DID contract address must be set');
    __compactRuntime.assert(!this._equal_1(binding_0.holderVerificationMethodRef.methodId,
                                           new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Explicit holder binding method reference must be set');
    return [];
  }
  _assertMatchingExplicitHolderBindings_0(credentialBinding_0,
                                          presentationBinding_0)
  {
    __compactRuntime.assert(this._equal_2(presentationBinding_0.holderVerificationMethodRef.didContractAddress,
                                          credentialBinding_0.holderVerificationMethodRef.didContractAddress),
                            'Presentation holder contract does not match credential holder binding');
    __compactRuntime.assert(this._equal_3(presentationBinding_0.holderVerificationMethodRef.methodId,
                                          credentialBinding_0.holderVerificationMethodRef.methodId),
                            'Presentation holder method reference does not match credential holder binding');
    return [];
  }
  _assertProofMatchesExplicitHolderBinding_0(binding_0, presentationProof_0) {
    __compactRuntime.assert(this._equal_4(binding_0.holderVerificationMethodRef.didContractAddress,
                                          presentationProof_0.signerVerificationMethodRef.didContractAddress),
                            'Presentation proof signer must match holder binding');
    __compactRuntime.assert(this._equal_5(binding_0.holderVerificationMethodRef.methodId,
                                          presentationProof_0.signerVerificationMethodRef.methodId),
                            'Presentation proof signer method reference must match holder binding');
    return [];
  }
  _assertValidJubjubHolderBinding_0(binding_0) {
    __compactRuntime.assert(this._jubjubPointX_0(binding_0.holderPublicKey)
                            !==
                            0n
                            ||
                            this._jubjubPointY_0(binding_0.holderPublicKey)
                            !==
                            0n,
                            'Jubjub holder binding public key must be set');
    return [];
  }
  _assertMatchingJubjubHolderBindings_0(credentialBinding_0,
                                        presentationBinding_0)
  {
    __compactRuntime.assert(this._jubjubPointX_0(presentationBinding_0.holderPublicKey)
                            ===
                            this._jubjubPointX_0(credentialBinding_0.holderPublicKey)
                            &&
                            this._jubjubPointY_0(presentationBinding_0.holderPublicKey)
                            ===
                            this._jubjubPointY_0(credentialBinding_0.holderPublicKey),
                            'Presentation Jubjub holder key does not match the credential holder binding');
    return [];
  }
  _assertProofMatchesJubjubHolderBinding_0(binding_0, presentationProof_0) {
    __compactRuntime.assert(this._jubjubPointX_0(binding_0.holderPublicKey)
                            ===
                            this._jubjubPointX_0(presentationProof_0.publicKey)
                            &&
                            this._jubjubPointY_0(binding_0.holderPublicKey)
                            ===
                            this._jubjubPointY_0(presentationProof_0.publicKey),
                            'Presentation proof public key must match the Jubjub holder binding');
    return [];
  }
  _assertValidOffchainMidnightHolderBinding_0(binding_0) {
    __compactRuntime.assert(!this._equal_6(binding_0.holderDidStateHash,
                                           new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Offchain Midnight holder state hash must be set');
    __compactRuntime.assert(!this._equal_7(binding_0.holderMethodId,
                                           new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Offchain Midnight holder method id must be set');
    const jubjubBinding_0 = { holderPublicKey: binding_0.holderPublicKey };
    this._assertValidJubjubHolderBinding_0(jubjubBinding_0);
    return [];
  }
  _assertMatchingOffchainMidnightHolderBindings_0(credentialBinding_0,
                                                  presentationBinding_0)
  {
    __compactRuntime.assert(this._equal_8(presentationBinding_0.holderDidStateHash,
                                          credentialBinding_0.holderDidStateHash),
                            'Offchain Midnight holder state hash does not match the credential holder binding');
    __compactRuntime.assert(this._equal_9(presentationBinding_0.holderMethodId,
                                          credentialBinding_0.holderMethodId),
                            'Offchain Midnight holder method id does not match the credential holder binding');
    const credentialJubjubBinding_0 = { holderPublicKey:
                                          credentialBinding_0.holderPublicKey };
    const presentationJubjubBinding_0 = { holderPublicKey:
                                            presentationBinding_0.holderPublicKey };
    this._assertMatchingJubjubHolderBindings_0(credentialJubjubBinding_0,
                                               presentationJubjubBinding_0);
    return [];
  }
  _assertProofMatchesOffchainMidnightHolderBinding_0(binding_0,
                                                     presentationProof_0)
  {
    const jubjubBinding_0 = { holderPublicKey: binding_0.holderPublicKey };
    this._assertProofMatchesJubjubHolderBinding_0(jubjubBinding_0,
                                                  presentationProof_0);
    return [];
  }
  _noSecretHolderChallengeResponse_0() {
    return new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 118, 99, 58, 110, 111, 45, 104, 111, 108, 100, 101, 114, 45, 114, 101, 115, 112, 111, 110, 115, 101, 0, 0]);
  }
  _secretHolderBindingCommitment_0(holderSecret_0, opening_0) {
    return this._persistentCommit_0(holderSecret_0, opening_0);
  }
  _secretHolderBindingChallengeResponse_0(holderSecret_0,
                                          verifierChallengeHash_0)
  {
    return this._persistentHash_2([new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 118, 99, 58, 104, 111, 108, 100, 101, 114, 45, 99, 104, 97, 108, 108, 0, 0, 0, 0, 0, 0, 0, 0]),
                                   holderSecret_0,
                                   verifierChallengeHash_0]);
  }
  _verifierScopedPseudonym_0(holderSecret_0, verifierDomainHash_0) {
    return this._persistentHash_2([new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 118, 99, 58, 104, 111, 108, 100, 101, 114, 45, 112, 115, 101, 117, 100, 111, 110, 121, 109, 0, 0, 0, 0]),
                                   holderSecret_0,
                                   verifierDomainHash_0]);
  }
  _assertVerifierScopedPseudonym_0(pseudonym_0,
                                   holderSecret_0,
                                   verifierDomainHash_0)
  {
    __compactRuntime.assert(this._equal_10(pseudonym_0,
                                           this._verifierScopedPseudonym_0(holderSecret_0,
                                                                           verifierDomainHash_0)),
                            'Verifier-scoped pseudonym does not match the holder secret and verifier domain');
    return [];
  }
  _blindedSecretHolderCommitment_0(holderSecretCommitment_0,
                                   issuerNonce_0,
                                   blindingFactor_0)
  {
    return this._persistentHash_3([new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 118, 99, 58, 98, 108, 105, 110, 100, 45, 104, 111, 108, 100, 101, 114, 0, 0, 0, 0, 0, 0, 0, 0]),
                                   holderSecretCommitment_0,
                                   issuerNonce_0,
                                   blindingFactor_0]);
  }
  _assertValidSecretHolderCredentialBinding_0(binding_0) {
    __compactRuntime.assert(this._equal_11(binding_0.requestChallengeResponse,
                                           this._noSecretHolderChallengeResponse_0()),
                            'Credential secret holder binding must not embed a request challenge response');
    return [];
  }
  _assertValidSecretHolderPresentationBinding_0(binding_0) {
    __compactRuntime.assert(!this._equal_12(binding_0.requestChallengeResponse,
                                            this._noSecretHolderChallengeResponse_0()),
                            'Presentation secret holder binding must include a request challenge response');
    return [];
  }
  _assertMatchingSecretHolderBindings_0(credentialBinding_0,
                                        presentationBinding_0)
  {
    __compactRuntime.assert(this._equal_13(credentialBinding_0.holderSecretCommitment,
                                           presentationBinding_0.holderSecretCommitment),
                            'Presentation holder secret commitment does not match the credential holder binding');
    return [];
  }
  _assertValidBlindedSecretHolderCredentialBinding_0(binding_0) {
    __compactRuntime.assert(this._equal_14(binding_0.requestChallengeResponse,
                                           this._noSecretHolderChallengeResponse_0()),
                            'Credential blinded holder binding must not embed a request challenge response');
    return [];
  }
  _assertValidBlindedSecretHolderPresentationBinding_0(binding_0) {
    __compactRuntime.assert(!this._equal_15(binding_0.requestChallengeResponse,
                                            this._noSecretHolderChallengeResponse_0()),
                            'Presentation blinded holder binding must include a request challenge response');
    return [];
  }
  _assertMatchingBlindedSecretHolderBindings_0(credentialBinding_0,
                                               presentationBinding_0)
  {
    __compactRuntime.assert(this._equal_16(credentialBinding_0.blindedHolderSecretCommitment,
                                           presentationBinding_0.blindedHolderSecretCommitment),
                            'Presentation blinded holder commitment does not match the credential holder binding');
    __compactRuntime.assert(this._equal_17(credentialBinding_0.issuerNonce,
                                           presentationBinding_0.issuerNonce),
                            'Presentation issuer nonce does not match the credential holder binding');
    return [];
  }
  _assertSecretHolderBindingWitness_0(binding_0,
                                      verifierChallengeHash_0,
                                      holderSecret_0,
                                      opening_0)
  {
    __compactRuntime.assert(this._equal_18(this._secretHolderBindingCommitment_0(holderSecret_0,
                                                                                 opening_0),
                                           binding_0.holderSecretCommitment),
                            'Holder secret witness does not match the holder-binding commitment');
    __compactRuntime.assert(this._equal_19(this._secretHolderBindingChallengeResponse_0(holderSecret_0,
                                                                                        verifierChallengeHash_0),
                                           binding_0.requestChallengeResponse),
                            'Holder secret challenge response does not match the verifier challenge');
    return [];
  }
  _assertBlindedSecretHolderBindingWitness_0(binding_0,
                                             verifierChallengeHash_0,
                                             holderSecret_0,
                                             opening_0,
                                             blindingFactor_0)
  {
    const holderCommitment_0 = this._secretHolderBindingCommitment_0(holderSecret_0,
                                                                     opening_0);
    __compactRuntime.assert(this._equal_20(this._blindedSecretHolderCommitment_0(holderCommitment_0,
                                                                                 binding_0.issuerNonce,
                                                                                 blindingFactor_0),
                                           binding_0.blindedHolderSecretCommitment),
                            'Blinded holder commitment does not match the hidden holder secret witness');
    __compactRuntime.assert(this._equal_21(this._secretHolderBindingChallengeResponse_0(holderSecret_0,
                                                                                        verifierChallengeHash_0),
                                           binding_0.requestChallengeResponse),
                            'Blinded holder challenge response does not match the verifier challenge');
    return [];
  }
  _noProtocolResponseReference_0() {
    return new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 118, 99, 58, 112, 114, 111, 116, 111, 99, 111, 108, 58, 110, 111, 110, 101, 0, 0, 0, 0, 0, 0, 0]);
  }
  _assertValidVerificationMethodRef_0(verificationMethodRef_0) {
    __compactRuntime.assert(!this._equal_22(verificationMethodRef_0.methodId,
                                            new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Verification method reference must be set');
    return [];
  }
  _assertMatchingSchemaRefs_0(expected_0, actual_0) {
    __compactRuntime.assert(this._equal_23(expected_0.packageId,
                                           actual_0.packageId)
                            &&
                            this._equal_24(expected_0.schemaId,
                                           actual_0.schemaId)
                            &&
                            this._equal_25(expected_0.majorVersion,
                                           actual_0.majorVersion)
                            &&
                            this._equal_26(expected_0.minorVersion,
                                           actual_0.minorVersion),
                            'Schema reference mismatch');
    return [];
  }
  _assertValidProtocolMessageEnvelope_0(envelope_0) {
    const noResponse_0 = this._noProtocolResponseReference_0();
    __compactRuntime.assert(this._equal_27(envelope_0.version, 1n),
                            'Protocol message version mismatch');
    __compactRuntime.assert(!this._equal_28(envelope_0.messageId, noResponse_0),
                            'Protocol message id must be set');
    __compactRuntime.assert(!this._equal_29(envelope_0.threadId, noResponse_0),
                            'Protocol thread id must be set');
    if (envelope_0.initialMessage) {
      __compactRuntime.assert(this._equal_30(envelope_0.respondsToMessageId,
                                             noResponse_0),
                              'Initial protocol message must not reference a previous message');
    } else {
      __compactRuntime.assert(!this._equal_31(envelope_0.respondsToMessageId,
                                              noResponse_0),
                              'Protocol response message must reference a previous message');
    }
    if (envelope_0.hasExpiresAt) {
      let t_0;
      __compactRuntime.assert((t_0 = envelope_0.expiresAt,
                               t_0 >= envelope_0.createdAt),
                              'Protocol message expiration must not precede creation');
    }
    return [];
  }
  _assertProtocolResponseEnvelope_0(requestEnvelope_0, responseEnvelope_0) {
    this._assertValidProtocolMessageEnvelope_0(requestEnvelope_0);
    this._assertValidProtocolMessageEnvelope_0(responseEnvelope_0);
    __compactRuntime.assert(!responseEnvelope_0.initialMessage,
                            'Protocol response must not be initial');
    __compactRuntime.assert(this._equal_32(responseEnvelope_0.threadId,
                                           requestEnvelope_0.threadId),
                            'Protocol response thread id does not match the request thread id');
    __compactRuntime.assert(this._equal_33(responseEnvelope_0.respondsToMessageId,
                                           requestEnvelope_0.messageId),
                            'Protocol response does not reference the request message id');
    let t_0;
    __compactRuntime.assert((t_0 = responseEnvelope_0.createdAt,
                             t_0 >= requestEnvelope_0.createdAt),
                            'Protocol response creation time must not precede the request');
    return [];
  }
  _assertValidStatusRegistryRef_0(registryRef_0) {
    __compactRuntime.assert(!this._equal_34(registryRef_0.registryId,
                                            new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Status registry id must be set');
    this._assertValidVerificationMethodRef_0(registryRef_0.authorityVerificationMethodRef);
    return [];
  }
  _assertValidNoStatusBinding_0(binding_0) { return []; }
  _assertValidRegistryBoundStatusBinding_0(binding_0) {
    __compactRuntime.assert(binding_0.statusType === 0,
                            'Registry-bound status type must be revocationRegistry');
    this._assertValidStatusRegistryRef_0(binding_0.registryRef);
    __compactRuntime.assert(!this._equal_35(binding_0.statusHandleCommitment,
                                            new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Status handle commitment must be set');
    return [];
  }
  _registryBoundStatusBindingRoot_0(binding_0) {
    this._assertValidRegistryBoundStatusBinding_0(binding_0);
    return this._persistentHash_4(binding_0);
  }
  _equal_0(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_1(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_2(x0, y0) {
    {
      let x1 = x0.bytes;
      let y1 = y0.bytes;
      if (!x1.every((x, i) => y1[i] === x)) { return false; }
    }
    return true;
  }
  _equal_3(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_4(x0, y0) {
    {
      let x1 = x0.bytes;
      let y1 = y0.bytes;
      if (!x1.every((x, i) => y1[i] === x)) { return false; }
    }
    return true;
  }
  _equal_5(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_6(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_7(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_8(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_9(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_10(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_11(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_12(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_13(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_14(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_15(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_16(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_17(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_18(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_19(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_20(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_21(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_22(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_23(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_24(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_25(x0, y0) {
    if (x0 !== y0) { return false; }
    return true;
  }
  _equal_26(x0, y0) {
    if (x0 !== y0) { return false; }
    return true;
  }
  _equal_27(x0, y0) {
    if (x0 !== y0) { return false; }
    return true;
  }
  _equal_28(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_29(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_30(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_31(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_32(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_33(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_34(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_35(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
}
export function ledger(stateOrChargedState) {
  const state = stateOrChargedState instanceof __compactRuntime.StateValue ? stateOrChargedState : stateOrChargedState.state;
  const chargedState = stateOrChargedState instanceof __compactRuntime.StateValue ? new __compactRuntime.ChargedState(stateOrChargedState) : stateOrChargedState;
  const context = {
    currentQueryContext: new __compactRuntime.QueryContext(chargedState, __compactRuntime.dummyContractAddress()),
    costModel: __compactRuntime.CostModel.initialCostModel()
  };
  const partialProofData = {
    input: { value: [], alignment: [] },
    output: undefined,
    publicTranscript: [],
    privateTranscriptOutputs: []
  };
  return {
  };
}
const _emptyContext = {
  currentQueryContext: new __compactRuntime.QueryContext(new __compactRuntime.ContractState().data, __compactRuntime.dummyContractAddress())
};
const _dummyContract = new Contract({ });
export const pureCircuits = {
  verifySignature: (...args_0) => {
    if (args_0.length !== 3) {
      throw new __compactRuntime.CompactError(`verifySignature: expected 3 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const pk_0 = args_0[0];
    const signature_0 = args_0[1];
    const challenge_0 = args_0[2];
    if (!(typeof(signature_0) === 'object' && true && typeof(signature_0.s) === 'bigint' && signature_0.s >= 0 && signature_0.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('verifySignature',
                                 'argument 2',
                                 'proofs.compact line 4 char 1',
                                 'struct Signature<r: Opaque<"JubjubPoint">, s: Field>',
                                 signature_0)
    }
    if (!(typeof(challenge_0) === 'bigint' && challenge_0 >= 0 && challenge_0 <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('verifySignature',
                                 'argument 3',
                                 'proofs.compact line 4 char 1',
                                 'Field',
                                 challenge_0)
    }
    return _dummyContract._verifySignature_0(pk_0, signature_0, challenge_0);
  },
  issuanceContextTag: (...args_0) => {
    if (args_0.length !== 0) {
      throw new __compactRuntime.CompactError(`issuanceContextTag: expected 0 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    return _dummyContract._issuanceContextTag_0();
  },
  presentationContextTag: (...args_0) => {
    if (args_0.length !== 0) {
      throw new __compactRuntime.CompactError(`presentationContextTag: expected 0 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    return _dummyContract._presentationContextTag_0();
  },
  statusAttestationContextTag: (...args_0) => {
    if (args_0.length !== 0) {
      throw new __compactRuntime.CompactError(`statusAttestationContextTag: expected 0 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    return _dummyContract._statusAttestationContextTag_0();
  },
  issuanceProofPayloadRoot: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`issuanceProofPayloadRoot: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const bodyRoot_0 = args_0[0];
    const proof_0 = args_0[1];
    if (!(bodyRoot_0.buffer instanceof ArrayBuffer && bodyRoot_0.BYTES_PER_ELEMENT === 1 && bodyRoot_0.length === 32)) {
      __compactRuntime.typeError('issuanceProofPayloadRoot',
                                 'argument 1',
                                 'proofs.compact line 80 char 1',
                                 'Bytes<32>',
                                 bodyRoot_0)
    }
    if (!(typeof(proof_0) === 'object' && typeof(proof_0.signerVerificationMethodRef) === 'object' && typeof(proof_0.signerVerificationMethodRef.didContractAddress) === 'object' && proof_0.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && proof_0.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.methodId.length === 32 && typeof(proof_0.createdAt) === 'bigint' && proof_0.createdAt >= 0n && proof_0.createdAt <= 18446744073709551615n && proof_0.challengeHash.buffer instanceof ArrayBuffer && proof_0.challengeHash.BYTES_PER_ELEMENT === 1 && proof_0.challengeHash.length === 32 && true && typeof(proof_0.signature) === 'object' && true && typeof(proof_0.signature.s) === 'bigint' && proof_0.signature.s >= 0 && proof_0.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('issuanceProofPayloadRoot',
                                 'argument 2',
                                 'proofs.compact line 80 char 1',
                                 'struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>',
                                 proof_0)
    }
    return _dummyContract._issuanceProofPayloadRoot_0(bodyRoot_0, proof_0);
  },
  presentationProofPayloadRoot: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`presentationProofPayloadRoot: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const bodyRoot_0 = args_0[0];
    const proof_0 = args_0[1];
    if (!(bodyRoot_0.buffer instanceof ArrayBuffer && bodyRoot_0.BYTES_PER_ELEMENT === 1 && bodyRoot_0.length === 32)) {
      __compactRuntime.typeError('presentationProofPayloadRoot',
                                 'argument 1',
                                 'proofs.compact line 87 char 1',
                                 'Bytes<32>',
                                 bodyRoot_0)
    }
    if (!(typeof(proof_0) === 'object' && typeof(proof_0.signerVerificationMethodRef) === 'object' && typeof(proof_0.signerVerificationMethodRef.didContractAddress) === 'object' && proof_0.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && proof_0.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.methodId.length === 32 && typeof(proof_0.createdAt) === 'bigint' && proof_0.createdAt >= 0n && proof_0.createdAt <= 18446744073709551615n && proof_0.challengeHash.buffer instanceof ArrayBuffer && proof_0.challengeHash.BYTES_PER_ELEMENT === 1 && proof_0.challengeHash.length === 32 && true && typeof(proof_0.signature) === 'object' && true && typeof(proof_0.signature.s) === 'bigint' && proof_0.signature.s >= 0 && proof_0.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('presentationProofPayloadRoot',
                                 'argument 2',
                                 'proofs.compact line 87 char 1',
                                 'struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>',
                                 proof_0)
    }
    return _dummyContract._presentationProofPayloadRoot_0(bodyRoot_0, proof_0);
  },
  issuanceProofChallenge: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`issuanceProofChallenge: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const bodyRoot_0 = args_0[0];
    const proof_0 = args_0[1];
    if (!(bodyRoot_0.buffer instanceof ArrayBuffer && bodyRoot_0.BYTES_PER_ELEMENT === 1 && bodyRoot_0.length === 32)) {
      __compactRuntime.typeError('issuanceProofChallenge',
                                 'argument 1',
                                 'proofs.compact line 94 char 1',
                                 'Bytes<32>',
                                 bodyRoot_0)
    }
    if (!(typeof(proof_0) === 'object' && typeof(proof_0.signerVerificationMethodRef) === 'object' && typeof(proof_0.signerVerificationMethodRef.didContractAddress) === 'object' && proof_0.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && proof_0.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.methodId.length === 32 && typeof(proof_0.createdAt) === 'bigint' && proof_0.createdAt >= 0n && proof_0.createdAt <= 18446744073709551615n && proof_0.challengeHash.buffer instanceof ArrayBuffer && proof_0.challengeHash.BYTES_PER_ELEMENT === 1 && proof_0.challengeHash.length === 32 && true && typeof(proof_0.signature) === 'object' && true && typeof(proof_0.signature.s) === 'bigint' && proof_0.signature.s >= 0 && proof_0.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('issuanceProofChallenge',
                                 'argument 2',
                                 'proofs.compact line 94 char 1',
                                 'struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>',
                                 proof_0)
    }
    return _dummyContract._issuanceProofChallenge_0(bodyRoot_0, proof_0);
  },
  presentationProofChallenge: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`presentationProofChallenge: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const bodyRoot_0 = args_0[0];
    const proof_0 = args_0[1];
    if (!(bodyRoot_0.buffer instanceof ArrayBuffer && bodyRoot_0.BYTES_PER_ELEMENT === 1 && bodyRoot_0.length === 32)) {
      __compactRuntime.typeError('presentationProofChallenge',
                                 'argument 1',
                                 'proofs.compact line 101 char 1',
                                 'Bytes<32>',
                                 bodyRoot_0)
    }
    if (!(typeof(proof_0) === 'object' && typeof(proof_0.signerVerificationMethodRef) === 'object' && typeof(proof_0.signerVerificationMethodRef.didContractAddress) === 'object' && proof_0.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && proof_0.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.methodId.length === 32 && typeof(proof_0.createdAt) === 'bigint' && proof_0.createdAt >= 0n && proof_0.createdAt <= 18446744073709551615n && proof_0.challengeHash.buffer instanceof ArrayBuffer && proof_0.challengeHash.BYTES_PER_ELEMENT === 1 && proof_0.challengeHash.length === 32 && true && typeof(proof_0.signature) === 'object' && true && typeof(proof_0.signature.s) === 'bigint' && proof_0.signature.s >= 0 && proof_0.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('presentationProofChallenge',
                                 'argument 2',
                                 'proofs.compact line 101 char 1',
                                 'struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>',
                                 proof_0)
    }
    return _dummyContract._presentationProofChallenge_0(bodyRoot_0, proof_0);
  },
  assertValidIssuanceContextProof: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertValidIssuanceContextProof: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const bodyRoot_0 = args_0[0];
    const proof_0 = args_0[1];
    if (!(bodyRoot_0.buffer instanceof ArrayBuffer && bodyRoot_0.BYTES_PER_ELEMENT === 1 && bodyRoot_0.length === 32)) {
      __compactRuntime.typeError('assertValidIssuanceContextProof',
                                 'argument 1',
                                 'proofs.compact line 114 char 1',
                                 'Bytes<32>',
                                 bodyRoot_0)
    }
    if (!(typeof(proof_0) === 'object' && typeof(proof_0.signerVerificationMethodRef) === 'object' && typeof(proof_0.signerVerificationMethodRef.didContractAddress) === 'object' && proof_0.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && proof_0.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.methodId.length === 32 && typeof(proof_0.createdAt) === 'bigint' && proof_0.createdAt >= 0n && proof_0.createdAt <= 18446744073709551615n && proof_0.challengeHash.buffer instanceof ArrayBuffer && proof_0.challengeHash.BYTES_PER_ELEMENT === 1 && proof_0.challengeHash.length === 32 && true && typeof(proof_0.signature) === 'object' && true && typeof(proof_0.signature.s) === 'bigint' && proof_0.signature.s >= 0 && proof_0.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('assertValidIssuanceContextProof',
                                 'argument 2',
                                 'proofs.compact line 114 char 1',
                                 'struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>',
                                 proof_0)
    }
    return _dummyContract._assertValidIssuanceContextProof_0(bodyRoot_0, proof_0);
  },
  assertValidPresentationContextProof: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertValidPresentationContextProof: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const bodyRoot_0 = args_0[0];
    const proof_0 = args_0[1];
    if (!(bodyRoot_0.buffer instanceof ArrayBuffer && bodyRoot_0.BYTES_PER_ELEMENT === 1 && bodyRoot_0.length === 32)) {
      __compactRuntime.typeError('assertValidPresentationContextProof',
                                 'argument 1',
                                 'proofs.compact line 121 char 1',
                                 'Bytes<32>',
                                 bodyRoot_0)
    }
    if (!(typeof(proof_0) === 'object' && typeof(proof_0.signerVerificationMethodRef) === 'object' && typeof(proof_0.signerVerificationMethodRef.didContractAddress) === 'object' && proof_0.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && proof_0.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.methodId.length === 32 && typeof(proof_0.createdAt) === 'bigint' && proof_0.createdAt >= 0n && proof_0.createdAt <= 18446744073709551615n && proof_0.challengeHash.buffer instanceof ArrayBuffer && proof_0.challengeHash.BYTES_PER_ELEMENT === 1 && proof_0.challengeHash.length === 32 && true && typeof(proof_0.signature) === 'object' && true && typeof(proof_0.signature.s) === 'bigint' && proof_0.signature.s >= 0 && proof_0.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('assertValidPresentationContextProof',
                                 'argument 2',
                                 'proofs.compact line 121 char 1',
                                 'struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>',
                                 proof_0)
    }
    return _dummyContract._assertValidPresentationContextProof_0(bodyRoot_0,
                                                                 proof_0);
  },
  statusAttestationProofPayloadRoot: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`statusAttestationProofPayloadRoot: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const bodyRoot_0 = args_0[0];
    const proof_0 = args_0[1];
    if (!(bodyRoot_0.buffer instanceof ArrayBuffer && bodyRoot_0.BYTES_PER_ELEMENT === 1 && bodyRoot_0.length === 32)) {
      __compactRuntime.typeError('statusAttestationProofPayloadRoot',
                                 'argument 1',
                                 'proofs.compact line 128 char 1',
                                 'Bytes<32>',
                                 bodyRoot_0)
    }
    if (!(typeof(proof_0) === 'object' && typeof(proof_0.signerVerificationMethodRef) === 'object' && typeof(proof_0.signerVerificationMethodRef.didContractAddress) === 'object' && proof_0.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && proof_0.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.methodId.length === 32 && typeof(proof_0.createdAt) === 'bigint' && proof_0.createdAt >= 0n && proof_0.createdAt <= 18446744073709551615n && proof_0.challengeHash.buffer instanceof ArrayBuffer && proof_0.challengeHash.BYTES_PER_ELEMENT === 1 && proof_0.challengeHash.length === 32 && true && typeof(proof_0.signature) === 'object' && true && typeof(proof_0.signature.s) === 'bigint' && proof_0.signature.s >= 0 && proof_0.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('statusAttestationProofPayloadRoot',
                                 'argument 2',
                                 'proofs.compact line 128 char 1',
                                 'struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>',
                                 proof_0)
    }
    return _dummyContract._statusAttestationProofPayloadRoot_0(bodyRoot_0,
                                                               proof_0);
  },
  statusAttestationProofChallenge: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`statusAttestationProofChallenge: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const bodyRoot_0 = args_0[0];
    const proof_0 = args_0[1];
    if (!(bodyRoot_0.buffer instanceof ArrayBuffer && bodyRoot_0.BYTES_PER_ELEMENT === 1 && bodyRoot_0.length === 32)) {
      __compactRuntime.typeError('statusAttestationProofChallenge',
                                 'argument 1',
                                 'proofs.compact line 135 char 1',
                                 'Bytes<32>',
                                 bodyRoot_0)
    }
    if (!(typeof(proof_0) === 'object' && typeof(proof_0.signerVerificationMethodRef) === 'object' && typeof(proof_0.signerVerificationMethodRef.didContractAddress) === 'object' && proof_0.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && proof_0.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.methodId.length === 32 && typeof(proof_0.createdAt) === 'bigint' && proof_0.createdAt >= 0n && proof_0.createdAt <= 18446744073709551615n && proof_0.challengeHash.buffer instanceof ArrayBuffer && proof_0.challengeHash.BYTES_PER_ELEMENT === 1 && proof_0.challengeHash.length === 32 && true && typeof(proof_0.signature) === 'object' && true && typeof(proof_0.signature.s) === 'bigint' && proof_0.signature.s >= 0 && proof_0.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('statusAttestationProofChallenge',
                                 'argument 2',
                                 'proofs.compact line 135 char 1',
                                 'struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>',
                                 proof_0)
    }
    return _dummyContract._statusAttestationProofChallenge_0(bodyRoot_0, proof_0);
  },
  assertValidStatusAttestationContextProof: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertValidStatusAttestationContextProof: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const bodyRoot_0 = args_0[0];
    const proof_0 = args_0[1];
    if (!(bodyRoot_0.buffer instanceof ArrayBuffer && bodyRoot_0.BYTES_PER_ELEMENT === 1 && bodyRoot_0.length === 32)) {
      __compactRuntime.typeError('assertValidStatusAttestationContextProof',
                                 'argument 1',
                                 'proofs.compact line 142 char 1',
                                 'Bytes<32>',
                                 bodyRoot_0)
    }
    if (!(typeof(proof_0) === 'object' && typeof(proof_0.signerVerificationMethodRef) === 'object' && typeof(proof_0.signerVerificationMethodRef.didContractAddress) === 'object' && proof_0.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && proof_0.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && proof_0.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && proof_0.signerVerificationMethodRef.methodId.length === 32 && typeof(proof_0.createdAt) === 'bigint' && proof_0.createdAt >= 0n && proof_0.createdAt <= 18446744073709551615n && proof_0.challengeHash.buffer instanceof ArrayBuffer && proof_0.challengeHash.BYTES_PER_ELEMENT === 1 && proof_0.challengeHash.length === 32 && true && typeof(proof_0.signature) === 'object' && true && typeof(proof_0.signature.s) === 'bigint' && proof_0.signature.s >= 0 && proof_0.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('assertValidStatusAttestationContextProof',
                                 'argument 2',
                                 'proofs.compact line 142 char 1',
                                 'struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>',
                                 proof_0)
    }
    return _dummyContract._assertValidStatusAttestationContextProof_0(bodyRoot_0,
                                                                      proof_0);
  },
  assertValidExplicitHolderBinding: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidExplicitHolderBinding: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    if (!(typeof(binding_0) === 'object' && typeof(binding_0.holderVerificationMethodRef) === 'object' && typeof(binding_0.holderVerificationMethodRef.didContractAddress) === 'object' && binding_0.holderVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && binding_0.holderVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && binding_0.holderVerificationMethodRef.didContractAddress.bytes.length === 32 && binding_0.holderVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && binding_0.holderVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && binding_0.holderVerificationMethodRef.methodId.length === 32)) {
      __compactRuntime.typeError('assertValidExplicitHolderBinding',
                                 'argument 1',
                                 'holder-bindings.compact line 7 char 1',
                                 'struct ExplicitHolderBinding<holderVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>',
                                 binding_0)
    }
    return _dummyContract._assertValidExplicitHolderBinding_0(binding_0);
  },
  assertMatchingExplicitHolderBindings: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertMatchingExplicitHolderBindings: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const credentialBinding_0 = args_0[0];
    const presentationBinding_0 = args_0[1];
    if (!(typeof(credentialBinding_0) === 'object' && typeof(credentialBinding_0.holderVerificationMethodRef) === 'object' && typeof(credentialBinding_0.holderVerificationMethodRef.didContractAddress) === 'object' && credentialBinding_0.holderVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && credentialBinding_0.holderVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && credentialBinding_0.holderVerificationMethodRef.didContractAddress.bytes.length === 32 && credentialBinding_0.holderVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && credentialBinding_0.holderVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && credentialBinding_0.holderVerificationMethodRef.methodId.length === 32)) {
      __compactRuntime.typeError('assertMatchingExplicitHolderBindings',
                                 'argument 1',
                                 'holder-bindings.compact line 20 char 1',
                                 'struct ExplicitHolderBinding<holderVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>',
                                 credentialBinding_0)
    }
    if (!(typeof(presentationBinding_0) === 'object' && typeof(presentationBinding_0.holderVerificationMethodRef) === 'object' && typeof(presentationBinding_0.holderVerificationMethodRef.didContractAddress) === 'object' && presentationBinding_0.holderVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && presentationBinding_0.holderVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && presentationBinding_0.holderVerificationMethodRef.didContractAddress.bytes.length === 32 && presentationBinding_0.holderVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && presentationBinding_0.holderVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && presentationBinding_0.holderVerificationMethodRef.methodId.length === 32)) {
      __compactRuntime.typeError('assertMatchingExplicitHolderBindings',
                                 'argument 2',
                                 'holder-bindings.compact line 20 char 1',
                                 'struct ExplicitHolderBinding<holderVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>',
                                 presentationBinding_0)
    }
    return _dummyContract._assertMatchingExplicitHolderBindings_0(credentialBinding_0,
                                                                  presentationBinding_0);
  },
  assertProofMatchesExplicitHolderBinding: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertProofMatchesExplicitHolderBinding: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    const presentationProof_0 = args_0[1];
    if (!(typeof(binding_0) === 'object' && typeof(binding_0.holderVerificationMethodRef) === 'object' && typeof(binding_0.holderVerificationMethodRef.didContractAddress) === 'object' && binding_0.holderVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && binding_0.holderVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && binding_0.holderVerificationMethodRef.didContractAddress.bytes.length === 32 && binding_0.holderVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && binding_0.holderVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && binding_0.holderVerificationMethodRef.methodId.length === 32)) {
      __compactRuntime.typeError('assertProofMatchesExplicitHolderBinding',
                                 'argument 1',
                                 'holder-bindings.compact line 36 char 1',
                                 'struct ExplicitHolderBinding<holderVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>',
                                 binding_0)
    }
    if (!(typeof(presentationProof_0) === 'object' && typeof(presentationProof_0.signerVerificationMethodRef) === 'object' && typeof(presentationProof_0.signerVerificationMethodRef.didContractAddress) === 'object' && presentationProof_0.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && presentationProof_0.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && presentationProof_0.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && presentationProof_0.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && presentationProof_0.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && presentationProof_0.signerVerificationMethodRef.methodId.length === 32 && typeof(presentationProof_0.createdAt) === 'bigint' && presentationProof_0.createdAt >= 0n && presentationProof_0.createdAt <= 18446744073709551615n && presentationProof_0.challengeHash.buffer instanceof ArrayBuffer && presentationProof_0.challengeHash.BYTES_PER_ELEMENT === 1 && presentationProof_0.challengeHash.length === 32 && true && typeof(presentationProof_0.signature) === 'object' && true && typeof(presentationProof_0.signature.s) === 'bigint' && presentationProof_0.signature.s >= 0 && presentationProof_0.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('assertProofMatchesExplicitHolderBinding',
                                 'argument 2',
                                 'holder-bindings.compact line 36 char 1',
                                 'struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>',
                                 presentationProof_0)
    }
    return _dummyContract._assertProofMatchesExplicitHolderBinding_0(binding_0,
                                                                     presentationProof_0);
  },
  assertValidJubjubHolderBinding: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidJubjubHolderBinding: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    if (!(typeof(binding_0) === 'object' && true)) {
      __compactRuntime.typeError('assertValidJubjubHolderBinding',
                                 'argument 1',
                                 'holder-bindings.compact line 52 char 1',
                                 'struct JubjubHolderBinding<holderPublicKey: Opaque<"JubjubPoint">>',
                                 binding_0)
    }
    return _dummyContract._assertValidJubjubHolderBinding_0(binding_0);
  },
  assertMatchingJubjubHolderBindings: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertMatchingJubjubHolderBindings: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const credentialBinding_0 = args_0[0];
    const presentationBinding_0 = args_0[1];
    if (!(typeof(credentialBinding_0) === 'object' && true)) {
      __compactRuntime.typeError('assertMatchingJubjubHolderBindings',
                                 'argument 1',
                                 'holder-bindings.compact line 67 char 1',
                                 'struct JubjubHolderBinding<holderPublicKey: Opaque<"JubjubPoint">>',
                                 credentialBinding_0)
    }
    if (!(typeof(presentationBinding_0) === 'object' && true)) {
      __compactRuntime.typeError('assertMatchingJubjubHolderBindings',
                                 'argument 2',
                                 'holder-bindings.compact line 67 char 1',
                                 'struct JubjubHolderBinding<holderPublicKey: Opaque<"JubjubPoint">>',
                                 presentationBinding_0)
    }
    return _dummyContract._assertMatchingJubjubHolderBindings_0(credentialBinding_0,
                                                                presentationBinding_0);
  },
  assertProofMatchesJubjubHolderBinding: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertProofMatchesJubjubHolderBinding: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    const presentationProof_0 = args_0[1];
    if (!(typeof(binding_0) === 'object' && true)) {
      __compactRuntime.typeError('assertProofMatchesJubjubHolderBinding',
                                 'argument 1',
                                 'holder-bindings.compact line 80 char 1',
                                 'struct JubjubHolderBinding<holderPublicKey: Opaque<"JubjubPoint">>',
                                 binding_0)
    }
    if (!(typeof(presentationProof_0) === 'object' && typeof(presentationProof_0.signerVerificationMethodRef) === 'object' && typeof(presentationProof_0.signerVerificationMethodRef.didContractAddress) === 'object' && presentationProof_0.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && presentationProof_0.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && presentationProof_0.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && presentationProof_0.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && presentationProof_0.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && presentationProof_0.signerVerificationMethodRef.methodId.length === 32 && typeof(presentationProof_0.createdAt) === 'bigint' && presentationProof_0.createdAt >= 0n && presentationProof_0.createdAt <= 18446744073709551615n && presentationProof_0.challengeHash.buffer instanceof ArrayBuffer && presentationProof_0.challengeHash.BYTES_PER_ELEMENT === 1 && presentationProof_0.challengeHash.length === 32 && true && typeof(presentationProof_0.signature) === 'object' && true && typeof(presentationProof_0.signature.s) === 'bigint' && presentationProof_0.signature.s >= 0 && presentationProof_0.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('assertProofMatchesJubjubHolderBinding',
                                 'argument 2',
                                 'holder-bindings.compact line 80 char 1',
                                 'struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>',
                                 presentationProof_0)
    }
    return _dummyContract._assertProofMatchesJubjubHolderBinding_0(binding_0,
                                                                   presentationProof_0);
  },
  assertValidOffchainMidnightHolderBinding: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidOffchainMidnightHolderBinding: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    if (!(typeof(binding_0) === 'object' && binding_0.holderDidStateHash.buffer instanceof ArrayBuffer && binding_0.holderDidStateHash.BYTES_PER_ELEMENT === 1 && binding_0.holderDidStateHash.length === 32 && binding_0.holderMethodId.buffer instanceof ArrayBuffer && binding_0.holderMethodId.BYTES_PER_ELEMENT === 1 && binding_0.holderMethodId.length === 32 && true)) {
      __compactRuntime.typeError('assertValidOffchainMidnightHolderBinding',
                                 'argument 1',
                                 'holder-bindings.compact line 93 char 1',
                                 'struct OffchainMidnightHolderBinding<holderDidStateHash: Bytes<32>, holderMethodId: Bytes<32>, holderPublicKey: Opaque<"JubjubPoint">>',
                                 binding_0)
    }
    return _dummyContract._assertValidOffchainMidnightHolderBinding_0(binding_0);
  },
  assertMatchingOffchainMidnightHolderBindings: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertMatchingOffchainMidnightHolderBindings: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const credentialBinding_0 = args_0[0];
    const presentationBinding_0 = args_0[1];
    if (!(typeof(credentialBinding_0) === 'object' && credentialBinding_0.holderDidStateHash.buffer instanceof ArrayBuffer && credentialBinding_0.holderDidStateHash.BYTES_PER_ELEMENT === 1 && credentialBinding_0.holderDidStateHash.length === 32 && credentialBinding_0.holderMethodId.buffer instanceof ArrayBuffer && credentialBinding_0.holderMethodId.BYTES_PER_ELEMENT === 1 && credentialBinding_0.holderMethodId.length === 32 && true)) {
      __compactRuntime.typeError('assertMatchingOffchainMidnightHolderBindings',
                                 'argument 1',
                                 'holder-bindings.compact line 114 char 1',
                                 'struct OffchainMidnightHolderBinding<holderDidStateHash: Bytes<32>, holderMethodId: Bytes<32>, holderPublicKey: Opaque<"JubjubPoint">>',
                                 credentialBinding_0)
    }
    if (!(typeof(presentationBinding_0) === 'object' && presentationBinding_0.holderDidStateHash.buffer instanceof ArrayBuffer && presentationBinding_0.holderDidStateHash.BYTES_PER_ELEMENT === 1 && presentationBinding_0.holderDidStateHash.length === 32 && presentationBinding_0.holderMethodId.buffer instanceof ArrayBuffer && presentationBinding_0.holderMethodId.BYTES_PER_ELEMENT === 1 && presentationBinding_0.holderMethodId.length === 32 && true)) {
      __compactRuntime.typeError('assertMatchingOffchainMidnightHolderBindings',
                                 'argument 2',
                                 'holder-bindings.compact line 114 char 1',
                                 'struct OffchainMidnightHolderBinding<holderDidStateHash: Bytes<32>, holderMethodId: Bytes<32>, holderPublicKey: Opaque<"JubjubPoint">>',
                                 presentationBinding_0)
    }
    return _dummyContract._assertMatchingOffchainMidnightHolderBindings_0(credentialBinding_0,
                                                                          presentationBinding_0);
  },
  assertProofMatchesOffchainMidnightHolderBinding: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertProofMatchesOffchainMidnightHolderBinding: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    const presentationProof_0 = args_0[1];
    if (!(typeof(binding_0) === 'object' && binding_0.holderDidStateHash.buffer instanceof ArrayBuffer && binding_0.holderDidStateHash.BYTES_PER_ELEMENT === 1 && binding_0.holderDidStateHash.length === 32 && binding_0.holderMethodId.buffer instanceof ArrayBuffer && binding_0.holderMethodId.BYTES_PER_ELEMENT === 1 && binding_0.holderMethodId.length === 32 && true)) {
      __compactRuntime.typeError('assertProofMatchesOffchainMidnightHolderBinding',
                                 'argument 1',
                                 'holder-bindings.compact line 140 char 1',
                                 'struct OffchainMidnightHolderBinding<holderDidStateHash: Bytes<32>, holderMethodId: Bytes<32>, holderPublicKey: Opaque<"JubjubPoint">>',
                                 binding_0)
    }
    if (!(typeof(presentationProof_0) === 'object' && typeof(presentationProof_0.signerVerificationMethodRef) === 'object' && typeof(presentationProof_0.signerVerificationMethodRef.didContractAddress) === 'object' && presentationProof_0.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && presentationProof_0.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && presentationProof_0.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && presentationProof_0.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && presentationProof_0.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && presentationProof_0.signerVerificationMethodRef.methodId.length === 32 && typeof(presentationProof_0.createdAt) === 'bigint' && presentationProof_0.createdAt >= 0n && presentationProof_0.createdAt <= 18446744073709551615n && presentationProof_0.challengeHash.buffer instanceof ArrayBuffer && presentationProof_0.challengeHash.BYTES_PER_ELEMENT === 1 && presentationProof_0.challengeHash.length === 32 && true && typeof(presentationProof_0.signature) === 'object' && true && typeof(presentationProof_0.signature.s) === 'bigint' && presentationProof_0.signature.s >= 0 && presentationProof_0.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('assertProofMatchesOffchainMidnightHolderBinding',
                                 'argument 2',
                                 'holder-bindings.compact line 140 char 1',
                                 'struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>',
                                 presentationProof_0)
    }
    return _dummyContract._assertProofMatchesOffchainMidnightHolderBinding_0(binding_0,
                                                                             presentationProof_0);
  },
  noSecretHolderChallengeResponse: (...args_0) => {
    if (args_0.length !== 0) {
      throw new __compactRuntime.CompactError(`noSecretHolderChallengeResponse: expected 0 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    return _dummyContract._noSecretHolderChallengeResponse_0();
  },
  secretHolderBindingCommitment: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`secretHolderBindingCommitment: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const holderSecret_0 = args_0[0];
    const opening_0 = args_0[1];
    if (!(holderSecret_0.buffer instanceof ArrayBuffer && holderSecret_0.BYTES_PER_ELEMENT === 1 && holderSecret_0.length === 32)) {
      __compactRuntime.typeError('secretHolderBindingCommitment',
                                 'argument 1',
                                 'holder-bindings.compact line 157 char 1',
                                 'Bytes<32>',
                                 holderSecret_0)
    }
    if (!(opening_0.buffer instanceof ArrayBuffer && opening_0.BYTES_PER_ELEMENT === 1 && opening_0.length === 32)) {
      __compactRuntime.typeError('secretHolderBindingCommitment',
                                 'argument 2',
                                 'holder-bindings.compact line 157 char 1',
                                 'Bytes<32>',
                                 opening_0)
    }
    return _dummyContract._secretHolderBindingCommitment_0(holderSecret_0,
                                                           opening_0);
  },
  secretHolderBindingChallengeResponse: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`secretHolderBindingChallengeResponse: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const holderSecret_0 = args_0[0];
    const verifierChallengeHash_0 = args_0[1];
    if (!(holderSecret_0.buffer instanceof ArrayBuffer && holderSecret_0.BYTES_PER_ELEMENT === 1 && holderSecret_0.length === 32)) {
      __compactRuntime.typeError('secretHolderBindingChallengeResponse',
                                 'argument 1',
                                 'holder-bindings.compact line 164 char 1',
                                 'Bytes<32>',
                                 holderSecret_0)
    }
    if (!(verifierChallengeHash_0.buffer instanceof ArrayBuffer && verifierChallengeHash_0.BYTES_PER_ELEMENT === 1 && verifierChallengeHash_0.length === 32)) {
      __compactRuntime.typeError('secretHolderBindingChallengeResponse',
                                 'argument 2',
                                 'holder-bindings.compact line 164 char 1',
                                 'Bytes<32>',
                                 verifierChallengeHash_0)
    }
    return _dummyContract._secretHolderBindingChallengeResponse_0(holderSecret_0,
                                                                  verifierChallengeHash_0);
  },
  verifierScopedPseudonym: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`verifierScopedPseudonym: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const holderSecret_0 = args_0[0];
    const verifierDomainHash_0 = args_0[1];
    if (!(holderSecret_0.buffer instanceof ArrayBuffer && holderSecret_0.BYTES_PER_ELEMENT === 1 && holderSecret_0.length === 32)) {
      __compactRuntime.typeError('verifierScopedPseudonym',
                                 'argument 1',
                                 'holder-bindings.compact line 175 char 1',
                                 'Bytes<32>',
                                 holderSecret_0)
    }
    if (!(verifierDomainHash_0.buffer instanceof ArrayBuffer && verifierDomainHash_0.BYTES_PER_ELEMENT === 1 && verifierDomainHash_0.length === 32)) {
      __compactRuntime.typeError('verifierScopedPseudonym',
                                 'argument 2',
                                 'holder-bindings.compact line 175 char 1',
                                 'Bytes<32>',
                                 verifierDomainHash_0)
    }
    return _dummyContract._verifierScopedPseudonym_0(holderSecret_0,
                                                     verifierDomainHash_0);
  },
  assertVerifierScopedPseudonym: (...args_0) => {
    if (args_0.length !== 3) {
      throw new __compactRuntime.CompactError(`assertVerifierScopedPseudonym: expected 3 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const pseudonym_0 = args_0[0];
    const holderSecret_0 = args_0[1];
    const verifierDomainHash_0 = args_0[2];
    if (!(pseudonym_0.buffer instanceof ArrayBuffer && pseudonym_0.BYTES_PER_ELEMENT === 1 && pseudonym_0.length === 32)) {
      __compactRuntime.typeError('assertVerifierScopedPseudonym',
                                 'argument 1',
                                 'holder-bindings.compact line 186 char 1',
                                 'Bytes<32>',
                                 pseudonym_0)
    }
    if (!(holderSecret_0.buffer instanceof ArrayBuffer && holderSecret_0.BYTES_PER_ELEMENT === 1 && holderSecret_0.length === 32)) {
      __compactRuntime.typeError('assertVerifierScopedPseudonym',
                                 'argument 2',
                                 'holder-bindings.compact line 186 char 1',
                                 'Bytes<32>',
                                 holderSecret_0)
    }
    if (!(verifierDomainHash_0.buffer instanceof ArrayBuffer && verifierDomainHash_0.BYTES_PER_ELEMENT === 1 && verifierDomainHash_0.length === 32)) {
      __compactRuntime.typeError('assertVerifierScopedPseudonym',
                                 'argument 3',
                                 'holder-bindings.compact line 186 char 1',
                                 'Bytes<32>',
                                 verifierDomainHash_0)
    }
    return _dummyContract._assertVerifierScopedPseudonym_0(pseudonym_0,
                                                           holderSecret_0,
                                                           verifierDomainHash_0);
  },
  blindedSecretHolderCommitment: (...args_0) => {
    if (args_0.length !== 3) {
      throw new __compactRuntime.CompactError(`blindedSecretHolderCommitment: expected 3 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const holderSecretCommitment_0 = args_0[0];
    const issuerNonce_0 = args_0[1];
    const blindingFactor_0 = args_0[2];
    if (!(holderSecretCommitment_0.buffer instanceof ArrayBuffer && holderSecretCommitment_0.BYTES_PER_ELEMENT === 1 && holderSecretCommitment_0.length === 32)) {
      __compactRuntime.typeError('blindedSecretHolderCommitment',
                                 'argument 1',
                                 'holder-bindings.compact line 197 char 1',
                                 'Bytes<32>',
                                 holderSecretCommitment_0)
    }
    if (!(issuerNonce_0.buffer instanceof ArrayBuffer && issuerNonce_0.BYTES_PER_ELEMENT === 1 && issuerNonce_0.length === 32)) {
      __compactRuntime.typeError('blindedSecretHolderCommitment',
                                 'argument 2',
                                 'holder-bindings.compact line 197 char 1',
                                 'Bytes<32>',
                                 issuerNonce_0)
    }
    if (!(blindingFactor_0.buffer instanceof ArrayBuffer && blindingFactor_0.BYTES_PER_ELEMENT === 1 && blindingFactor_0.length === 32)) {
      __compactRuntime.typeError('blindedSecretHolderCommitment',
                                 'argument 3',
                                 'holder-bindings.compact line 197 char 1',
                                 'Bytes<32>',
                                 blindingFactor_0)
    }
    return _dummyContract._blindedSecretHolderCommitment_0(holderSecretCommitment_0,
                                                           issuerNonce_0,
                                                           blindingFactor_0);
  },
  assertValidSecretHolderCredentialBinding: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidSecretHolderCredentialBinding: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    if (!(typeof(binding_0) === 'object' && binding_0.holderSecretCommitment.buffer instanceof ArrayBuffer && binding_0.holderSecretCommitment.BYTES_PER_ELEMENT === 1 && binding_0.holderSecretCommitment.length === 32 && binding_0.requestChallengeResponse.buffer instanceof ArrayBuffer && binding_0.requestChallengeResponse.BYTES_PER_ELEMENT === 1 && binding_0.requestChallengeResponse.length === 32)) {
      __compactRuntime.typeError('assertValidSecretHolderCredentialBinding',
                                 'argument 1',
                                 'holder-bindings.compact line 213 char 1',
                                 'struct SecretHolderBinding<holderSecretCommitment: Bytes<32>, requestChallengeResponse: Bytes<32>>',
                                 binding_0)
    }
    return _dummyContract._assertValidSecretHolderCredentialBinding_0(binding_0);
  },
  assertValidSecretHolderPresentationBinding: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidSecretHolderPresentationBinding: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    if (!(typeof(binding_0) === 'object' && binding_0.holderSecretCommitment.buffer instanceof ArrayBuffer && binding_0.holderSecretCommitment.BYTES_PER_ELEMENT === 1 && binding_0.holderSecretCommitment.length === 32 && binding_0.requestChallengeResponse.buffer instanceof ArrayBuffer && binding_0.requestChallengeResponse.BYTES_PER_ELEMENT === 1 && binding_0.requestChallengeResponse.length === 32)) {
      __compactRuntime.typeError('assertValidSecretHolderPresentationBinding',
                                 'argument 1',
                                 'holder-bindings.compact line 222 char 1',
                                 'struct SecretHolderBinding<holderSecretCommitment: Bytes<32>, requestChallengeResponse: Bytes<32>>',
                                 binding_0)
    }
    return _dummyContract._assertValidSecretHolderPresentationBinding_0(binding_0);
  },
  assertMatchingSecretHolderBindings: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertMatchingSecretHolderBindings: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const credentialBinding_0 = args_0[0];
    const presentationBinding_0 = args_0[1];
    if (!(typeof(credentialBinding_0) === 'object' && credentialBinding_0.holderSecretCommitment.buffer instanceof ArrayBuffer && credentialBinding_0.holderSecretCommitment.BYTES_PER_ELEMENT === 1 && credentialBinding_0.holderSecretCommitment.length === 32 && credentialBinding_0.requestChallengeResponse.buffer instanceof ArrayBuffer && credentialBinding_0.requestChallengeResponse.BYTES_PER_ELEMENT === 1 && credentialBinding_0.requestChallengeResponse.length === 32)) {
      __compactRuntime.typeError('assertMatchingSecretHolderBindings',
                                 'argument 1',
                                 'holder-bindings.compact line 231 char 1',
                                 'struct SecretHolderBinding<holderSecretCommitment: Bytes<32>, requestChallengeResponse: Bytes<32>>',
                                 credentialBinding_0)
    }
    if (!(typeof(presentationBinding_0) === 'object' && presentationBinding_0.holderSecretCommitment.buffer instanceof ArrayBuffer && presentationBinding_0.holderSecretCommitment.BYTES_PER_ELEMENT === 1 && presentationBinding_0.holderSecretCommitment.length === 32 && presentationBinding_0.requestChallengeResponse.buffer instanceof ArrayBuffer && presentationBinding_0.requestChallengeResponse.BYTES_PER_ELEMENT === 1 && presentationBinding_0.requestChallengeResponse.length === 32)) {
      __compactRuntime.typeError('assertMatchingSecretHolderBindings',
                                 'argument 2',
                                 'holder-bindings.compact line 231 char 1',
                                 'struct SecretHolderBinding<holderSecretCommitment: Bytes<32>, requestChallengeResponse: Bytes<32>>',
                                 presentationBinding_0)
    }
    return _dummyContract._assertMatchingSecretHolderBindings_0(credentialBinding_0,
                                                                presentationBinding_0);
  },
  assertValidBlindedSecretHolderCredentialBinding: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidBlindedSecretHolderCredentialBinding: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    if (!(typeof(binding_0) === 'object' && binding_0.blindedHolderSecretCommitment.buffer instanceof ArrayBuffer && binding_0.blindedHolderSecretCommitment.BYTES_PER_ELEMENT === 1 && binding_0.blindedHolderSecretCommitment.length === 32 && binding_0.issuerNonce.buffer instanceof ArrayBuffer && binding_0.issuerNonce.BYTES_PER_ELEMENT === 1 && binding_0.issuerNonce.length === 32 && binding_0.requestChallengeResponse.buffer instanceof ArrayBuffer && binding_0.requestChallengeResponse.BYTES_PER_ELEMENT === 1 && binding_0.requestChallengeResponse.length === 32)) {
      __compactRuntime.typeError('assertValidBlindedSecretHolderCredentialBinding',
                                 'argument 1',
                                 'holder-bindings.compact line 241 char 1',
                                 'struct BlindedSecretHolderBinding<blindedHolderSecretCommitment: Bytes<32>, issuerNonce: Bytes<32>, requestChallengeResponse: Bytes<32>>',
                                 binding_0)
    }
    return _dummyContract._assertValidBlindedSecretHolderCredentialBinding_0(binding_0);
  },
  assertValidBlindedSecretHolderPresentationBinding: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidBlindedSecretHolderPresentationBinding: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    if (!(typeof(binding_0) === 'object' && binding_0.blindedHolderSecretCommitment.buffer instanceof ArrayBuffer && binding_0.blindedHolderSecretCommitment.BYTES_PER_ELEMENT === 1 && binding_0.blindedHolderSecretCommitment.length === 32 && binding_0.issuerNonce.buffer instanceof ArrayBuffer && binding_0.issuerNonce.BYTES_PER_ELEMENT === 1 && binding_0.issuerNonce.length === 32 && binding_0.requestChallengeResponse.buffer instanceof ArrayBuffer && binding_0.requestChallengeResponse.BYTES_PER_ELEMENT === 1 && binding_0.requestChallengeResponse.length === 32)) {
      __compactRuntime.typeError('assertValidBlindedSecretHolderPresentationBinding',
                                 'argument 1',
                                 'holder-bindings.compact line 250 char 1',
                                 'struct BlindedSecretHolderBinding<blindedHolderSecretCommitment: Bytes<32>, issuerNonce: Bytes<32>, requestChallengeResponse: Bytes<32>>',
                                 binding_0)
    }
    return _dummyContract._assertValidBlindedSecretHolderPresentationBinding_0(binding_0);
  },
  assertMatchingBlindedSecretHolderBindings: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertMatchingBlindedSecretHolderBindings: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const credentialBinding_0 = args_0[0];
    const presentationBinding_0 = args_0[1];
    if (!(typeof(credentialBinding_0) === 'object' && credentialBinding_0.blindedHolderSecretCommitment.buffer instanceof ArrayBuffer && credentialBinding_0.blindedHolderSecretCommitment.BYTES_PER_ELEMENT === 1 && credentialBinding_0.blindedHolderSecretCommitment.length === 32 && credentialBinding_0.issuerNonce.buffer instanceof ArrayBuffer && credentialBinding_0.issuerNonce.BYTES_PER_ELEMENT === 1 && credentialBinding_0.issuerNonce.length === 32 && credentialBinding_0.requestChallengeResponse.buffer instanceof ArrayBuffer && credentialBinding_0.requestChallengeResponse.BYTES_PER_ELEMENT === 1 && credentialBinding_0.requestChallengeResponse.length === 32)) {
      __compactRuntime.typeError('assertMatchingBlindedSecretHolderBindings',
                                 'argument 1',
                                 'holder-bindings.compact line 259 char 1',
                                 'struct BlindedSecretHolderBinding<blindedHolderSecretCommitment: Bytes<32>, issuerNonce: Bytes<32>, requestChallengeResponse: Bytes<32>>',
                                 credentialBinding_0)
    }
    if (!(typeof(presentationBinding_0) === 'object' && presentationBinding_0.blindedHolderSecretCommitment.buffer instanceof ArrayBuffer && presentationBinding_0.blindedHolderSecretCommitment.BYTES_PER_ELEMENT === 1 && presentationBinding_0.blindedHolderSecretCommitment.length === 32 && presentationBinding_0.issuerNonce.buffer instanceof ArrayBuffer && presentationBinding_0.issuerNonce.BYTES_PER_ELEMENT === 1 && presentationBinding_0.issuerNonce.length === 32 && presentationBinding_0.requestChallengeResponse.buffer instanceof ArrayBuffer && presentationBinding_0.requestChallengeResponse.BYTES_PER_ELEMENT === 1 && presentationBinding_0.requestChallengeResponse.length === 32)) {
      __compactRuntime.typeError('assertMatchingBlindedSecretHolderBindings',
                                 'argument 2',
                                 'holder-bindings.compact line 259 char 1',
                                 'struct BlindedSecretHolderBinding<blindedHolderSecretCommitment: Bytes<32>, issuerNonce: Bytes<32>, requestChallengeResponse: Bytes<32>>',
                                 presentationBinding_0)
    }
    return _dummyContract._assertMatchingBlindedSecretHolderBindings_0(credentialBinding_0,
                                                                       presentationBinding_0);
  },
  assertSecretHolderBindingWitness: (...args_0) => {
    if (args_0.length !== 4) {
      throw new __compactRuntime.CompactError(`assertSecretHolderBindingWitness: expected 4 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    const verifierChallengeHash_0 = args_0[1];
    const holderSecret_0 = args_0[2];
    const opening_0 = args_0[3];
    if (!(typeof(binding_0) === 'object' && binding_0.holderSecretCommitment.buffer instanceof ArrayBuffer && binding_0.holderSecretCommitment.BYTES_PER_ELEMENT === 1 && binding_0.holderSecretCommitment.length === 32 && binding_0.requestChallengeResponse.buffer instanceof ArrayBuffer && binding_0.requestChallengeResponse.BYTES_PER_ELEMENT === 1 && binding_0.requestChallengeResponse.length === 32)) {
      __compactRuntime.typeError('assertSecretHolderBindingWitness',
                                 'argument 1',
                                 'holder-bindings.compact line 279 char 1',
                                 'struct SecretHolderBinding<holderSecretCommitment: Bytes<32>, requestChallengeResponse: Bytes<32>>',
                                 binding_0)
    }
    if (!(verifierChallengeHash_0.buffer instanceof ArrayBuffer && verifierChallengeHash_0.BYTES_PER_ELEMENT === 1 && verifierChallengeHash_0.length === 32)) {
      __compactRuntime.typeError('assertSecretHolderBindingWitness',
                                 'argument 2',
                                 'holder-bindings.compact line 279 char 1',
                                 'Bytes<32>',
                                 verifierChallengeHash_0)
    }
    if (!(holderSecret_0.buffer instanceof ArrayBuffer && holderSecret_0.BYTES_PER_ELEMENT === 1 && holderSecret_0.length === 32)) {
      __compactRuntime.typeError('assertSecretHolderBindingWitness',
                                 'argument 3',
                                 'holder-bindings.compact line 279 char 1',
                                 'Bytes<32>',
                                 holderSecret_0)
    }
    if (!(opening_0.buffer instanceof ArrayBuffer && opening_0.BYTES_PER_ELEMENT === 1 && opening_0.length === 32)) {
      __compactRuntime.typeError('assertSecretHolderBindingWitness',
                                 'argument 4',
                                 'holder-bindings.compact line 279 char 1',
                                 'Bytes<32>',
                                 opening_0)
    }
    return _dummyContract._assertSecretHolderBindingWitness_0(binding_0,
                                                              verifierChallengeHash_0,
                                                              holderSecret_0,
                                                              opening_0);
  },
  assertBlindedSecretHolderBindingWitness: (...args_0) => {
    if (args_0.length !== 5) {
      throw new __compactRuntime.CompactError(`assertBlindedSecretHolderBindingWitness: expected 5 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    const verifierChallengeHash_0 = args_0[1];
    const holderSecret_0 = args_0[2];
    const opening_0 = args_0[3];
    const blindingFactor_0 = args_0[4];
    if (!(typeof(binding_0) === 'object' && binding_0.blindedHolderSecretCommitment.buffer instanceof ArrayBuffer && binding_0.blindedHolderSecretCommitment.BYTES_PER_ELEMENT === 1 && binding_0.blindedHolderSecretCommitment.length === 32 && binding_0.issuerNonce.buffer instanceof ArrayBuffer && binding_0.issuerNonce.BYTES_PER_ELEMENT === 1 && binding_0.issuerNonce.length === 32 && binding_0.requestChallengeResponse.buffer instanceof ArrayBuffer && binding_0.requestChallengeResponse.BYTES_PER_ELEMENT === 1 && binding_0.requestChallengeResponse.length === 32)) {
      __compactRuntime.typeError('assertBlindedSecretHolderBindingWitness',
                                 'argument 1',
                                 'holder-bindings.compact line 296 char 1',
                                 'struct BlindedSecretHolderBinding<blindedHolderSecretCommitment: Bytes<32>, issuerNonce: Bytes<32>, requestChallengeResponse: Bytes<32>>',
                                 binding_0)
    }
    if (!(verifierChallengeHash_0.buffer instanceof ArrayBuffer && verifierChallengeHash_0.BYTES_PER_ELEMENT === 1 && verifierChallengeHash_0.length === 32)) {
      __compactRuntime.typeError('assertBlindedSecretHolderBindingWitness',
                                 'argument 2',
                                 'holder-bindings.compact line 296 char 1',
                                 'Bytes<32>',
                                 verifierChallengeHash_0)
    }
    if (!(holderSecret_0.buffer instanceof ArrayBuffer && holderSecret_0.BYTES_PER_ELEMENT === 1 && holderSecret_0.length === 32)) {
      __compactRuntime.typeError('assertBlindedSecretHolderBindingWitness',
                                 'argument 3',
                                 'holder-bindings.compact line 296 char 1',
                                 'Bytes<32>',
                                 holderSecret_0)
    }
    if (!(opening_0.buffer instanceof ArrayBuffer && opening_0.BYTES_PER_ELEMENT === 1 && opening_0.length === 32)) {
      __compactRuntime.typeError('assertBlindedSecretHolderBindingWitness',
                                 'argument 4',
                                 'holder-bindings.compact line 296 char 1',
                                 'Bytes<32>',
                                 opening_0)
    }
    if (!(blindingFactor_0.buffer instanceof ArrayBuffer && blindingFactor_0.BYTES_PER_ELEMENT === 1 && blindingFactor_0.length === 32)) {
      __compactRuntime.typeError('assertBlindedSecretHolderBindingWitness',
                                 'argument 5',
                                 'holder-bindings.compact line 296 char 1',
                                 'Bytes<32>',
                                 blindingFactor_0)
    }
    return _dummyContract._assertBlindedSecretHolderBindingWitness_0(binding_0,
                                                                     verifierChallengeHash_0,
                                                                     holderSecret_0,
                                                                     opening_0,
                                                                     blindingFactor_0);
  },
  noProtocolResponseReference: (...args_0) => {
    if (args_0.length !== 0) {
      throw new __compactRuntime.CompactError(`noProtocolResponseReference: expected 0 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    return _dummyContract._noProtocolResponseReference_0();
  },
  assertValidVerificationMethodRef: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidVerificationMethodRef: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const verificationMethodRef_0 = args_0[0];
    if (!(typeof(verificationMethodRef_0) === 'object' && typeof(verificationMethodRef_0.didContractAddress) === 'object' && verificationMethodRef_0.didContractAddress.bytes.buffer instanceof ArrayBuffer && verificationMethodRef_0.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && verificationMethodRef_0.didContractAddress.bytes.length === 32 && verificationMethodRef_0.methodId.buffer instanceof ArrayBuffer && verificationMethodRef_0.methodId.BYTES_PER_ELEMENT === 1 && verificationMethodRef_0.methodId.length === 32)) {
      __compactRuntime.typeError('assertValidVerificationMethodRef',
                                 'argument 1',
                                 'protocols.compact line 32 char 1',
                                 'struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>',
                                 verificationMethodRef_0)
    }
    return _dummyContract._assertValidVerificationMethodRef_0(verificationMethodRef_0);
  },
  assertMatchingSchemaRefs: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertMatchingSchemaRefs: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const expected_0 = args_0[0];
    const actual_0 = args_0[1];
    if (!(typeof(expected_0) === 'object' && expected_0.packageId.buffer instanceof ArrayBuffer && expected_0.packageId.BYTES_PER_ELEMENT === 1 && expected_0.packageId.length === 32 && expected_0.schemaId.buffer instanceof ArrayBuffer && expected_0.schemaId.BYTES_PER_ELEMENT === 1 && expected_0.schemaId.length === 32 && typeof(expected_0.majorVersion) === 'bigint' && expected_0.majorVersion >= 0n && expected_0.majorVersion <= 65535n && typeof(expected_0.minorVersion) === 'bigint' && expected_0.minorVersion >= 0n && expected_0.minorVersion <= 65535n)) {
      __compactRuntime.typeError('assertMatchingSchemaRefs',
                                 'argument 1',
                                 'protocols.compact line 41 char 1',
                                 'struct SchemaRef<packageId: Bytes<32>, schemaId: Bytes<32>, majorVersion: Uint<0..65536>, minorVersion: Uint<0..65536>>',
                                 expected_0)
    }
    if (!(typeof(actual_0) === 'object' && actual_0.packageId.buffer instanceof ArrayBuffer && actual_0.packageId.BYTES_PER_ELEMENT === 1 && actual_0.packageId.length === 32 && actual_0.schemaId.buffer instanceof ArrayBuffer && actual_0.schemaId.BYTES_PER_ELEMENT === 1 && actual_0.schemaId.length === 32 && typeof(actual_0.majorVersion) === 'bigint' && actual_0.majorVersion >= 0n && actual_0.majorVersion <= 65535n && typeof(actual_0.minorVersion) === 'bigint' && actual_0.minorVersion >= 0n && actual_0.minorVersion <= 65535n)) {
      __compactRuntime.typeError('assertMatchingSchemaRefs',
                                 'argument 2',
                                 'protocols.compact line 41 char 1',
                                 'struct SchemaRef<packageId: Bytes<32>, schemaId: Bytes<32>, majorVersion: Uint<0..65536>, minorVersion: Uint<0..65536>>',
                                 actual_0)
    }
    return _dummyContract._assertMatchingSchemaRefs_0(expected_0, actual_0);
  },
  assertValidProtocolMessageEnvelope: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidProtocolMessageEnvelope: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const envelope_0 = args_0[0];
    if (!(typeof(envelope_0) === 'object' && typeof(envelope_0.version) === 'bigint' && envelope_0.version >= 0n && envelope_0.version <= 65535n && envelope_0.messageId.buffer instanceof ArrayBuffer && envelope_0.messageId.BYTES_PER_ELEMENT === 1 && envelope_0.messageId.length === 32 && envelope_0.threadId.buffer instanceof ArrayBuffer && envelope_0.threadId.BYTES_PER_ELEMENT === 1 && envelope_0.threadId.length === 32 && typeof(envelope_0.initialMessage) === 'boolean' && envelope_0.respondsToMessageId.buffer instanceof ArrayBuffer && envelope_0.respondsToMessageId.BYTES_PER_ELEMENT === 1 && envelope_0.respondsToMessageId.length === 32 && typeof(envelope_0.createdAt) === 'bigint' && envelope_0.createdAt >= 0n && envelope_0.createdAt <= 18446744073709551615n && typeof(envelope_0.hasExpiresAt) === 'boolean' && typeof(envelope_0.expiresAt) === 'bigint' && envelope_0.expiresAt >= 0n && envelope_0.expiresAt <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertValidProtocolMessageEnvelope',
                                 'argument 1',
                                 'protocols.compact line 54 char 1',
                                 'struct ProtocolMessageEnvelope<version: Uint<0..65536>, messageId: Bytes<32>, threadId: Bytes<32>, initialMessage: Boolean, respondsToMessageId: Bytes<32>, createdAt: Uint<0..18446744073709551616>, hasExpiresAt: Boolean, expiresAt: Uint<0..18446744073709551616>>',
                                 envelope_0)
    }
    return _dummyContract._assertValidProtocolMessageEnvelope_0(envelope_0);
  },
  assertProtocolResponseEnvelope: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertProtocolResponseEnvelope: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const requestEnvelope_0 = args_0[0];
    const responseEnvelope_0 = args_0[1];
    if (!(typeof(requestEnvelope_0) === 'object' && typeof(requestEnvelope_0.version) === 'bigint' && requestEnvelope_0.version >= 0n && requestEnvelope_0.version <= 65535n && requestEnvelope_0.messageId.buffer instanceof ArrayBuffer && requestEnvelope_0.messageId.BYTES_PER_ELEMENT === 1 && requestEnvelope_0.messageId.length === 32 && requestEnvelope_0.threadId.buffer instanceof ArrayBuffer && requestEnvelope_0.threadId.BYTES_PER_ELEMENT === 1 && requestEnvelope_0.threadId.length === 32 && typeof(requestEnvelope_0.initialMessage) === 'boolean' && requestEnvelope_0.respondsToMessageId.buffer instanceof ArrayBuffer && requestEnvelope_0.respondsToMessageId.BYTES_PER_ELEMENT === 1 && requestEnvelope_0.respondsToMessageId.length === 32 && typeof(requestEnvelope_0.createdAt) === 'bigint' && requestEnvelope_0.createdAt >= 0n && requestEnvelope_0.createdAt <= 18446744073709551615n && typeof(requestEnvelope_0.hasExpiresAt) === 'boolean' && typeof(requestEnvelope_0.expiresAt) === 'bigint' && requestEnvelope_0.expiresAt >= 0n && requestEnvelope_0.expiresAt <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertProtocolResponseEnvelope',
                                 'argument 1',
                                 'protocols.compact line 80 char 1',
                                 'struct ProtocolMessageEnvelope<version: Uint<0..65536>, messageId: Bytes<32>, threadId: Bytes<32>, initialMessage: Boolean, respondsToMessageId: Bytes<32>, createdAt: Uint<0..18446744073709551616>, hasExpiresAt: Boolean, expiresAt: Uint<0..18446744073709551616>>',
                                 requestEnvelope_0)
    }
    if (!(typeof(responseEnvelope_0) === 'object' && typeof(responseEnvelope_0.version) === 'bigint' && responseEnvelope_0.version >= 0n && responseEnvelope_0.version <= 65535n && responseEnvelope_0.messageId.buffer instanceof ArrayBuffer && responseEnvelope_0.messageId.BYTES_PER_ELEMENT === 1 && responseEnvelope_0.messageId.length === 32 && responseEnvelope_0.threadId.buffer instanceof ArrayBuffer && responseEnvelope_0.threadId.BYTES_PER_ELEMENT === 1 && responseEnvelope_0.threadId.length === 32 && typeof(responseEnvelope_0.initialMessage) === 'boolean' && responseEnvelope_0.respondsToMessageId.buffer instanceof ArrayBuffer && responseEnvelope_0.respondsToMessageId.BYTES_PER_ELEMENT === 1 && responseEnvelope_0.respondsToMessageId.length === 32 && typeof(responseEnvelope_0.createdAt) === 'bigint' && responseEnvelope_0.createdAt >= 0n && responseEnvelope_0.createdAt <= 18446744073709551615n && typeof(responseEnvelope_0.hasExpiresAt) === 'boolean' && typeof(responseEnvelope_0.expiresAt) === 'bigint' && responseEnvelope_0.expiresAt >= 0n && responseEnvelope_0.expiresAt <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertProtocolResponseEnvelope',
                                 'argument 2',
                                 'protocols.compact line 80 char 1',
                                 'struct ProtocolMessageEnvelope<version: Uint<0..65536>, messageId: Bytes<32>, threadId: Bytes<32>, initialMessage: Boolean, respondsToMessageId: Bytes<32>, createdAt: Uint<0..18446744073709551616>, hasExpiresAt: Boolean, expiresAt: Uint<0..18446744073709551616>>',
                                 responseEnvelope_0)
    }
    return _dummyContract._assertProtocolResponseEnvelope_0(requestEnvelope_0,
                                                            responseEnvelope_0);
  },
  assertValidStatusRegistryRef: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidStatusRegistryRef: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const registryRef_0 = args_0[0];
    if (!(typeof(registryRef_0) === 'object' && registryRef_0.registryId.buffer instanceof ArrayBuffer && registryRef_0.registryId.BYTES_PER_ELEMENT === 1 && registryRef_0.registryId.length === 32 && typeof(registryRef_0.authorityVerificationMethodRef) === 'object' && typeof(registryRef_0.authorityVerificationMethodRef.didContractAddress) === 'object' && registryRef_0.authorityVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && registryRef_0.authorityVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && registryRef_0.authorityVerificationMethodRef.didContractAddress.bytes.length === 32 && registryRef_0.authorityVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && registryRef_0.authorityVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && registryRef_0.authorityVerificationMethodRef.methodId.length === 32)) {
      __compactRuntime.typeError('assertValidStatusRegistryRef',
                                 'argument 1',
                                 'status-bindings.compact line 24 char 1',
                                 'struct StatusRegistryRef<registryId: Bytes<32>, authorityVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>',
                                 registryRef_0)
    }
    return _dummyContract._assertValidStatusRegistryRef_0(registryRef_0);
  },
  assertValidNoStatusBinding: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidNoStatusBinding: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    if (!(typeof(binding_0) === 'object')) {
      __compactRuntime.typeError('assertValidNoStatusBinding',
                                 'argument 1',
                                 'status-bindings.compact line 34 char 1',
                                 'struct NoStatusBinding<>',
                                 binding_0)
    }
    return _dummyContract._assertValidNoStatusBinding_0(binding_0);
  },
  assertValidRegistryBoundStatusBinding: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidRegistryBoundStatusBinding: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    if (!(typeof(binding_0) === 'object' && typeof(binding_0.statusType) === 'number' && binding_0.statusType >= 0 && binding_0.statusType <= 0 && typeof(binding_0.registryRef) === 'object' && binding_0.registryRef.registryId.buffer instanceof ArrayBuffer && binding_0.registryRef.registryId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.registryId.length === 32 && typeof(binding_0.registryRef.authorityVerificationMethodRef) === 'object' && typeof(binding_0.registryRef.authorityVerificationMethodRef.didContractAddress) === 'object' && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.length === 32 && binding_0.registryRef.authorityVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.methodId.length === 32 && binding_0.statusHandleCommitment.buffer instanceof ArrayBuffer && binding_0.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && binding_0.statusHandleCommitment.length === 32)) {
      __compactRuntime.typeError('assertValidRegistryBoundStatusBinding',
                                 'argument 1',
                                 'status-bindings.compact line 41 char 1',
                                 'struct RegistryBoundStatusBinding<statusType: Enum<StatusType, revocationRegistry>, registryRef: struct StatusRegistryRef<registryId: Bytes<32>, authorityVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>, statusHandleCommitment: Bytes<32>>',
                                 binding_0)
    }
    return _dummyContract._assertValidRegistryBoundStatusBinding_0(binding_0);
  },
  registryBoundStatusBindingRoot: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`registryBoundStatusBindingRoot: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    if (!(typeof(binding_0) === 'object' && typeof(binding_0.statusType) === 'number' && binding_0.statusType >= 0 && binding_0.statusType <= 0 && typeof(binding_0.registryRef) === 'object' && binding_0.registryRef.registryId.buffer instanceof ArrayBuffer && binding_0.registryRef.registryId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.registryId.length === 32 && typeof(binding_0.registryRef.authorityVerificationMethodRef) === 'object' && typeof(binding_0.registryRef.authorityVerificationMethodRef.didContractAddress) === 'object' && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.length === 32 && binding_0.registryRef.authorityVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.methodId.length === 32 && binding_0.statusHandleCommitment.buffer instanceof ArrayBuffer && binding_0.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && binding_0.statusHandleCommitment.length === 32)) {
      __compactRuntime.typeError('registryBoundStatusBindingRoot',
                                 'argument 1',
                                 'status-bindings.compact line 55 char 1',
                                 'struct RegistryBoundStatusBinding<statusType: Enum<StatusType, revocationRegistry>, registryRef: struct StatusRegistryRef<registryId: Bytes<32>, authorityVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>, statusHandleCommitment: Bytes<32>>',
                                 binding_0)
    }
    return _dummyContract._registryBoundStatusBindingRoot_0(binding_0);
  }
};
export const contractReferenceLocations =
  { tag: 'publicLedgerArray', indices: { } };
