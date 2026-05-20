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

export var StatusCapabilityKind;
(function (StatusCapabilityKind) {
  StatusCapabilityKind[StatusCapabilityKind['noStatus'] = 0] = 'noStatus';
  StatusCapabilityKind[StatusCapabilityKind['publicStatus'] = 1] = 'publicStatus';
  StatusCapabilityKind[StatusCapabilityKind['revokedSetNonMembership'] = 2] = 'revokedSetNonMembership';
  StatusCapabilityKind[StatusCapabilityKind['authorityAttestedStatus'] = 3] = 'authorityAttestedStatus';
})(StatusCapabilityKind || (StatusCapabilityKind = {}));

const _descriptor_0 = new __compactRuntime.CompactTypeUnsignedInteger(65535n, 2);

const _descriptor_1 = new __compactRuntime.CompactTypeBytes(32);

const _descriptor_2 = __compactRuntime.CompactTypeBoolean;

const _descriptor_3 = new __compactRuntime.CompactTypeUnsignedInteger(18446744073709551615n, 8);

class _RevocationRegistryState_0 {
  alignment() {
    return _descriptor_1.alignment().concat(_descriptor_1.alignment().concat(_descriptor_3.alignment()));
  }
  fromValue(value_0) {
    return {
      registryId: _descriptor_1.fromValue(value_0),
      revokedRoot: _descriptor_1.fromValue(value_0),
      registryVersion: _descriptor_3.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_1.toValue(value_0.registryId).concat(_descriptor_1.toValue(value_0.revokedRoot).concat(_descriptor_3.toValue(value_0.registryVersion)));
  }
}

const _descriptor_4 = new _RevocationRegistryState_0();

const _descriptor_5 = new __compactRuntime.CompactTypeEnum(3, 1);

class _VerifierStatusPolicy_0 {
  alignment() {
    return _descriptor_2.alignment().concat(_descriptor_5.alignment().concat(_descriptor_2.alignment().concat(_descriptor_1.alignment().concat(_descriptor_2.alignment().concat(_descriptor_3.alignment())))));
  }
  fromValue(value_0) {
    return {
      requireStatus: _descriptor_2.fromValue(value_0),
      acceptedStatusCapability: _descriptor_5.fromValue(value_0),
      enforceRegistryId: _descriptor_2.fromValue(value_0),
      acceptedRegistryId: _descriptor_1.fromValue(value_0),
      enforceAttestationMaxAge: _descriptor_2.fromValue(value_0),
      maxAttestationAge: _descriptor_3.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_2.toValue(value_0.requireStatus).concat(_descriptor_5.toValue(value_0.acceptedStatusCapability).concat(_descriptor_2.toValue(value_0.enforceRegistryId).concat(_descriptor_1.toValue(value_0.acceptedRegistryId).concat(_descriptor_2.toValue(value_0.enforceAttestationMaxAge).concat(_descriptor_3.toValue(value_0.maxAttestationAge))))));
  }
}

const _descriptor_6 = new _VerifierStatusPolicy_0();

const _descriptor_7 = new __compactRuntime.CompactTypeEnum(0, 0);

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

const _descriptor_8 = new _ContractAddress_0();

class _VerificationMethodRef_0 {
  alignment() {
    return _descriptor_8.alignment().concat(_descriptor_1.alignment());
  }
  fromValue(value_0) {
    return {
      didContractAddress: _descriptor_8.fromValue(value_0),
      methodId: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_8.toValue(value_0.didContractAddress).concat(_descriptor_1.toValue(value_0.methodId));
  }
}

const _descriptor_9 = new _VerificationMethodRef_0();

class _StatusRegistryRef_0 {
  alignment() {
    return _descriptor_1.alignment().concat(_descriptor_9.alignment());
  }
  fromValue(value_0) {
    return {
      registryId: _descriptor_1.fromValue(value_0),
      authorityVerificationMethodRef: _descriptor_9.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_1.toValue(value_0.registryId).concat(_descriptor_9.toValue(value_0.authorityVerificationMethodRef));
  }
}

const _descriptor_10 = new _StatusRegistryRef_0();

class _RegistryBoundStatusBinding_0 {
  alignment() {
    return _descriptor_7.alignment().concat(_descriptor_10.alignment().concat(_descriptor_1.alignment()));
  }
  fromValue(value_0) {
    return {
      statusType: _descriptor_7.fromValue(value_0),
      registryRef: _descriptor_10.fromValue(value_0),
      statusHandleCommitment: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_7.toValue(value_0.statusType).concat(_descriptor_10.toValue(value_0.registryRef).concat(_descriptor_1.toValue(value_0.statusHandleCommitment)));
  }
}

const _descriptor_11 = new _RegistryBoundStatusBinding_0();

class _RevokedSetStatusRequest_0 {
  alignment() {
    return _descriptor_4.alignment().concat(_descriptor_1.alignment());
  }
  fromValue(value_0) {
    return {
      registryState: _descriptor_4.fromValue(value_0),
      verifierChallengeHash: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_4.toValue(value_0.registryState).concat(_descriptor_1.toValue(value_0.verifierChallengeHash));
  }
}

const _descriptor_12 = new _RevokedSetStatusRequest_0();

class _AuthorityAttestedStatusStatement_0 {
  alignment() {
    return _descriptor_4.alignment().concat(_descriptor_1.alignment().concat(_descriptor_1.alignment().concat(_descriptor_2.alignment().concat(_descriptor_3.alignment()))));
  }
  fromValue(value_0) {
    return {
      registryState: _descriptor_4.fromValue(value_0),
      statusHandleCommitment: _descriptor_1.fromValue(value_0),
      verifierChallengeHash: _descriptor_1.fromValue(value_0),
      hasExpiration: _descriptor_2.fromValue(value_0),
      expiresAt: _descriptor_3.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_4.toValue(value_0.registryState).concat(_descriptor_1.toValue(value_0.statusHandleCommitment).concat(_descriptor_1.toValue(value_0.verifierChallengeHash).concat(_descriptor_2.toValue(value_0.hasExpiration).concat(_descriptor_3.toValue(value_0.expiresAt)))));
  }
}

const _descriptor_13 = new _AuthorityAttestedStatusStatement_0();

const _descriptor_14 = __compactRuntime.CompactTypeJubjubPoint;

const _descriptor_15 = __compactRuntime.CompactTypeField;

class _Signature_0 {
  alignment() {
    return _descriptor_14.alignment().concat(_descriptor_15.alignment());
  }
  fromValue(value_0) {
    return {
      r: _descriptor_14.fromValue(value_0),
      s: _descriptor_15.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_14.toValue(value_0.r).concat(_descriptor_15.toValue(value_0.s));
  }
}

const _descriptor_16 = new _Signature_0();

class _Proof_0 {
  alignment() {
    return _descriptor_9.alignment().concat(_descriptor_3.alignment().concat(_descriptor_1.alignment().concat(_descriptor_14.alignment().concat(_descriptor_16.alignment()))));
  }
  fromValue(value_0) {
    return {
      signerVerificationMethodRef: _descriptor_9.fromValue(value_0),
      createdAt: _descriptor_3.fromValue(value_0),
      challengeHash: _descriptor_1.fromValue(value_0),
      publicKey: _descriptor_14.fromValue(value_0),
      signature: _descriptor_16.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_9.toValue(value_0.signerVerificationMethodRef).concat(_descriptor_3.toValue(value_0.createdAt).concat(_descriptor_1.toValue(value_0.challengeHash).concat(_descriptor_14.toValue(value_0.publicKey).concat(_descriptor_16.toValue(value_0.signature)))));
  }
}

const _descriptor_17 = new _Proof_0();

class _AuthorityAttestedStatusProof_0 {
  alignment() {
    return _descriptor_13.alignment().concat(_descriptor_17.alignment());
  }
  fromValue(value_0) {
    return {
      statement: _descriptor_13.fromValue(value_0),
      proof: _descriptor_17.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_13.toValue(value_0.statement).concat(_descriptor_17.toValue(value_0.proof));
  }
}

const _descriptor_18 = new _AuthorityAttestedStatusProof_0();

class _AuthorityAttestedStatusProofProtocol_0 {
  alignment() {
    return _descriptor_12.alignment().concat(_descriptor_18.alignment());
  }
  fromValue(value_0) {
    return {
      request: _descriptor_12.fromValue(value_0),
      attestation: _descriptor_18.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_12.toValue(value_0.request).concat(_descriptor_18.toValue(value_0.attestation));
  }
}

const _descriptor_19 = new _AuthorityAttestedStatusProofProtocol_0();

class _LiveStatusWitnessInput_0 {
  alignment() {
    return _descriptor_1.alignment().concat(_descriptor_1.alignment());
  }
  fromValue(value_0) {
    return {
      statusHandle: _descriptor_1.fromValue(value_0),
      statusHandleOpening: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_1.toValue(value_0.statusHandle).concat(_descriptor_1.toValue(value_0.statusHandleOpening));
  }
}

const _descriptor_20 = new _LiveStatusWitnessInput_0();

class _RevokedSetNonMembershipWitnessInput_0 {
  alignment() {
    return _descriptor_4.alignment().concat(_descriptor_1.alignment().concat(_descriptor_1.alignment()));
  }
  fromValue(value_0) {
    return {
      registryState: _descriptor_4.fromValue(value_0),
      statusHandle: _descriptor_1.fromValue(value_0),
      statusHandleOpening: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_4.toValue(value_0.registryState).concat(_descriptor_1.toValue(value_0.statusHandle).concat(_descriptor_1.toValue(value_0.statusHandleOpening)));
  }
}

const _descriptor_21 = new _RevokedSetNonMembershipWitnessInput_0();

class _RevokedSetNonMembershipStatusProofProtocol_0 {
  alignment() {
    return _descriptor_12.alignment().concat(_descriptor_21.alignment());
  }
  fromValue(value_0) {
    return {
      request: _descriptor_12.fromValue(value_0),
      witnessInput: _descriptor_21.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_12.toValue(value_0.request).concat(_descriptor_21.toValue(value_0.witnessInput));
  }
}

const _descriptor_22 = new _RevokedSetNonMembershipStatusProofProtocol_0();

class _RevokedSetNonMembershipStatusCapability_0 {
  alignment() {
    return _descriptor_7.alignment().concat(_descriptor_10.alignment().concat(_descriptor_1.alignment()));
  }
  fromValue(value_0) {
    return {
      statusType: _descriptor_7.fromValue(value_0),
      registryRef: _descriptor_10.fromValue(value_0),
      statusHandleCommitment: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_7.toValue(value_0.statusType).concat(_descriptor_10.toValue(value_0.registryRef).concat(_descriptor_1.toValue(value_0.statusHandleCommitment)));
  }
}

const _descriptor_23 = new _RevokedSetNonMembershipStatusCapability_0();

class _AuthorityAttestedStatusCapability_0 {
  alignment() {
    return _descriptor_7.alignment().concat(_descriptor_10.alignment().concat(_descriptor_1.alignment()));
  }
  fromValue(value_0) {
    return {
      statusType: _descriptor_7.fromValue(value_0),
      registryRef: _descriptor_10.fromValue(value_0),
      statusHandleCommitment: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_7.toValue(value_0.statusType).concat(_descriptor_10.toValue(value_0.registryRef).concat(_descriptor_1.toValue(value_0.statusHandleCommitment)));
  }
}

const _descriptor_24 = new _AuthorityAttestedStatusCapability_0();

class _NoStatusCapability_0 {
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

const _descriptor_25 = new _NoStatusCapability_0();

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

const _descriptor_26 = new _NoStatusBinding_0();

class _ProtocolMessageEnvelope_0 {
  alignment() {
    return _descriptor_0.alignment().concat(_descriptor_1.alignment().concat(_descriptor_1.alignment().concat(_descriptor_2.alignment().concat(_descriptor_1.alignment().concat(_descriptor_3.alignment().concat(_descriptor_2.alignment().concat(_descriptor_3.alignment())))))));
  }
  fromValue(value_0) {
    return {
      version: _descriptor_0.fromValue(value_0),
      messageId: _descriptor_1.fromValue(value_0),
      threadId: _descriptor_1.fromValue(value_0),
      initialMessage: _descriptor_2.fromValue(value_0),
      respondsToMessageId: _descriptor_1.fromValue(value_0),
      createdAt: _descriptor_3.fromValue(value_0),
      hasExpiresAt: _descriptor_2.fromValue(value_0),
      expiresAt: _descriptor_3.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_0.toValue(value_0.version).concat(_descriptor_1.toValue(value_0.messageId).concat(_descriptor_1.toValue(value_0.threadId).concat(_descriptor_2.toValue(value_0.initialMessage).concat(_descriptor_1.toValue(value_0.respondsToMessageId).concat(_descriptor_3.toValue(value_0.createdAt).concat(_descriptor_2.toValue(value_0.hasExpiresAt).concat(_descriptor_3.toValue(value_0.expiresAt))))))));
  }
}

const _descriptor_27 = new _ProtocolMessageEnvelope_0();

class _SchemaRef_0 {
  alignment() {
    return _descriptor_1.alignment().concat(_descriptor_1.alignment().concat(_descriptor_0.alignment().concat(_descriptor_0.alignment())));
  }
  fromValue(value_0) {
    return {
      packageId: _descriptor_1.fromValue(value_0),
      schemaId: _descriptor_1.fromValue(value_0),
      majorVersion: _descriptor_0.fromValue(value_0),
      minorVersion: _descriptor_0.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_1.toValue(value_0.packageId).concat(_descriptor_1.toValue(value_0.schemaId).concat(_descriptor_0.toValue(value_0.majorVersion).concat(_descriptor_0.toValue(value_0.minorVersion))));
  }
}

const _descriptor_28 = new _SchemaRef_0();

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

const _descriptor_29 = new _SecretHolderBinding_0();

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

const _descriptor_30 = new _BlindedSecretHolderBinding_0();

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

const _descriptor_31 = new _OffchainMidnightHolderBinding_0();

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

const _descriptor_32 = new _JubjubHolderBinding_0();

class _ExplicitHolderBinding_0 {
  alignment() {
    return _descriptor_9.alignment();
  }
  fromValue(value_0) {
    return {
      holderVerificationMethodRef: _descriptor_9.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_9.toValue(value_0.holderVerificationMethodRef);
  }
}

const _descriptor_33 = new _ExplicitHolderBinding_0();

const _descriptor_34 = new __compactRuntime.CompactTypeVector(4, _descriptor_1);

const _descriptor_35 = new __compactRuntime.CompactTypeVector(3, _descriptor_1);

const _descriptor_36 = new __compactRuntime.CompactTypeVector(5, _descriptor_1);

class _Either_0 {
  alignment() {
    return _descriptor_2.alignment().concat(_descriptor_1.alignment().concat(_descriptor_1.alignment()));
  }
  fromValue(value_0) {
    return {
      is_left: _descriptor_2.fromValue(value_0),
      left: _descriptor_1.fromValue(value_0),
      right: _descriptor_1.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_2.toValue(value_0.is_left).concat(_descriptor_1.toValue(value_0.left).concat(_descriptor_1.toValue(value_0.right)));
  }
}

const _descriptor_37 = new _Either_0();

const _descriptor_38 = new __compactRuntime.CompactTypeUnsignedInteger(340282366920938463463374607431768211455n, 16);

class _MerkleTreeDigest_0 {
  alignment() {
    return _descriptor_15.alignment();
  }
  fromValue(value_0) {
    return {
      field: _descriptor_15.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_15.toValue(value_0.field);
  }
}

const _descriptor_39 = new _MerkleTreeDigest_0();

const _descriptor_40 = new __compactRuntime.CompactTypeUnsignedInteger(255n, 1);

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
      },
      assertValidNoStatusCapability(context, ...args_1) {
        return { result: pureCircuits.assertValidNoStatusCapability(...args_1), context };
      },
      assertValidRevokedSetNonMembershipStatusCapability(context, ...args_1) {
        return { result: pureCircuits.assertValidRevokedSetNonMembershipStatusCapability(...args_1), context };
      },
      assertValidAuthorityAttestedStatusCapability(context, ...args_1) {
        return { result: pureCircuits.assertValidAuthorityAttestedStatusCapability(...args_1), context };
      },
      assertValidVerifierStatusPolicy(context, ...args_1) {
        return { result: pureCircuits.assertValidVerifierStatusPolicy(...args_1), context };
      },
      assertValidRevocationRegistryState(context, ...args_1) {
        return { result: pureCircuits.assertValidRevocationRegistryState(...args_1), context };
      },
      assertValidRevokedSetStatusRequest(context, ...args_1) {
        return { result: pureCircuits.assertValidRevokedSetStatusRequest(...args_1), context };
      },
      revokedSetStatusHandleCommitment(context, ...args_1) {
        return { result: pureCircuits.revokedSetStatusHandleCommitment(...args_1), context };
      },
      revokedSetStatusHandle(context, ...args_1) {
        return { result: pureCircuits.revokedSetStatusHandle(...args_1), context };
      },
      assertValidRevokedSetNonMembershipWitnessInput(context, ...args_1) {
        return { result: pureCircuits.assertValidRevokedSetNonMembershipWitnessInput(...args_1), context };
      },
      assertValidLiveStatusWitnessInput(context, ...args_1) {
        return { result: pureCircuits.assertValidLiveStatusWitnessInput(...args_1), context };
      },
      assertValidRevokedSetNonMembershipStatusProofProtocol(context, ...args_1) {
        return { result: pureCircuits.assertValidRevokedSetNonMembershipStatusProofProtocol(...args_1), context };
      },
      assertRegistryBoundStatusBindingMatchesRevokedSetNonMembershipStatusProofProtocol(context, ...args_1) {
        return { result: pureCircuits.assertRegistryBoundStatusBindingMatchesRevokedSetNonMembershipStatusProofProtocol(...args_1), context };
      },
      assertRevokedSetNonMembershipWitnessMatchesBinding(context, ...args_1) {
        return { result: pureCircuits.assertRevokedSetNonMembershipWitnessMatchesBinding(...args_1), context };
      },
      assertLiveStatusWitnessMatchesBinding(context, ...args_1) {
        return { result: pureCircuits.assertLiveStatusWitnessMatchesBinding(...args_1), context };
      },
      authorityAttestedStatusStatementRoot(context, ...args_1) {
        return { result: pureCircuits.authorityAttestedStatusStatementRoot(...args_1), context };
      },
      assertValidAuthorityAttestedStatusStatement(context, ...args_1) {
        return { result: pureCircuits.assertValidAuthorityAttestedStatusStatement(...args_1), context };
      },
      assertValidAuthorityAttestedStatusProof(context, ...args_1) {
        return { result: pureCircuits.assertValidAuthorityAttestedStatusProof(...args_1), context };
      },
      assertValidAuthorityAttestedStatusProofProtocol(context, ...args_1) {
        return { result: pureCircuits.assertValidAuthorityAttestedStatusProofProtocol(...args_1), context };
      },
      assertRegistryBoundStatusBindingMatchesAuthorityAttestedStatusProofProtocol(context, ...args_1) {
        return { result: pureCircuits.assertRegistryBoundStatusBindingMatchesAuthorityAttestedStatusProofProtocol(...args_1), context };
      },
      assertAuthorityAttestedStatusProofMatchesBinding(context, ...args_1) {
        return { result: pureCircuits.assertAuthorityAttestedStatusProofMatchesBinding(...args_1), context };
      },
      assertAuthorityAttestedStatusProofMatchesRequest(context, ...args_1) {
        return { result: pureCircuits.assertAuthorityAttestedStatusProofMatchesRequest(...args_1), context };
      },
      assertAuthorityAttestedStatusProofFreshEnough(context, ...args_1) {
        return { result: pureCircuits.assertAuthorityAttestedStatusProofFreshEnough(...args_1), context };
      },
      assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipBinding(context, ...args_1) {
        return { result: pureCircuits.assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipBinding(...args_1), context };
      },
      assertVerifierStatusPolicyAcceptsLiveStatusBinding(context, ...args_1) {
        return { result: pureCircuits.assertVerifierStatusPolicyAcceptsLiveStatusBinding(...args_1), context };
      },
      assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipStatusProofProtocol(context, ...args_1) {
        return { result: pureCircuits.assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipStatusProofProtocol(...args_1), context };
      },
      assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusBinding(context, ...args_1) {
        return { result: pureCircuits.assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusBinding(...args_1), context };
      },
      assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusProofProtocol(context, ...args_1) {
        return { result: pureCircuits.assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusProofProtocol(...args_1), context };
      },
      initializeRegistry: (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`initializeRegistry: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const nextRegistryId_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.currentQueryContext != undefined)) {
          __compactRuntime.typeError('initializeRegistry',
                                     'argument 1 (as invoked from Typescript)',
                                     'revocation-registry.compact line 31 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(nextRegistryId_0.buffer instanceof ArrayBuffer && nextRegistryId_0.BYTES_PER_ELEMENT === 1 && nextRegistryId_0.length === 32)) {
          __compactRuntime.typeError('initializeRegistry',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'revocation-registry.compact line 31 char 1',
                                     'Bytes<32>',
                                     nextRegistryId_0)
        }
        const context = { ...contextOrig_0, gasCost: __compactRuntime.emptyRunningCost() };
        const partialProofData = {
          input: {
            value: _descriptor_1.toValue(nextRegistryId_0),
            alignment: _descriptor_1.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._initializeRegistry_0(context,
                                                    partialProofData,
                                                    nextRegistryId_0);
        partialProofData.output = { value: [], alignment: [] };
        return { result: result_0, context: context, proofData: partialProofData, gasCost: context.gasCost };
      },
      assertStateUsesThisRegistry: (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`assertStateUsesThisRegistry: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const state_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.currentQueryContext != undefined)) {
          __compactRuntime.typeError('assertStateUsesThisRegistry',
                                     'argument 1 (as invoked from Typescript)',
                                     'revocation-registry.compact line 50 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(state_0) === 'object' && state_0.registryId.buffer instanceof ArrayBuffer && state_0.registryId.BYTES_PER_ELEMENT === 1 && state_0.registryId.length === 32 && state_0.revokedRoot.buffer instanceof ArrayBuffer && state_0.revokedRoot.BYTES_PER_ELEMENT === 1 && state_0.revokedRoot.length === 32 && typeof(state_0.registryVersion) === 'bigint' && state_0.registryVersion >= 0n && state_0.registryVersion <= 18446744073709551615n)) {
          __compactRuntime.typeError('assertStateUsesThisRegistry',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'revocation-registry.compact line 50 char 1',
                                     'struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>',
                                     state_0)
        }
        const context = { ...contextOrig_0, gasCost: __compactRuntime.emptyRunningCost() };
        const partialProofData = {
          input: {
            value: _descriptor_4.toValue(state_0),
            alignment: _descriptor_4.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._assertStateUsesThisRegistry_0(context,
                                                             partialProofData,
                                                             state_0);
        partialProofData.output = { value: [], alignment: [] };
        return { result: result_0, context: context, proofData: partialProofData, gasCost: context.gasCost };
      },
      revokeStatusHandle: (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`revokeStatusHandle: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const statusHandle_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.currentQueryContext != undefined)) {
          __compactRuntime.typeError('revokeStatusHandle',
                                     'argument 1 (as invoked from Typescript)',
                                     'revocation-registry.compact line 65 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(statusHandle_0.buffer instanceof ArrayBuffer && statusHandle_0.BYTES_PER_ELEMENT === 1 && statusHandle_0.length === 32)) {
          __compactRuntime.typeError('revokeStatusHandle',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'revocation-registry.compact line 65 char 1',
                                     'Bytes<32>',
                                     statusHandle_0)
        }
        const context = { ...contextOrig_0, gasCost: __compactRuntime.emptyRunningCost() };
        const partialProofData = {
          input: {
            value: _descriptor_1.toValue(statusHandle_0),
            alignment: _descriptor_1.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._revokeStatusHandle_0(context,
                                                    partialProofData,
                                                    statusHandle_0);
        partialProofData.output = { value: [], alignment: [] };
        return { result: result_0, context: context, proofData: partialProofData, gasCost: context.gasCost };
      }
    };
    this.impureCircuits = {
      initializeRegistry: this.circuits.initializeRegistry,
      assertStateUsesThisRegistry: this.circuits.assertStateUsesThisRegistry,
      revokeStatusHandle: this.circuits.revokeStatusHandle
    };
    this.provableCircuits = this.impureCircuits;
    this.provableCircuits = {
      initializeRegistry: this.circuits.initializeRegistry,
      assertStateUsesThisRegistry: this.circuits.assertStateUsesThisRegistry,
      revokeStatusHandle: this.circuits.revokeStatusHandle
    };
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
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_0 = stateValue_0.arrayPush(__compactRuntime.StateValue.newNull());
    state_0.data = new __compactRuntime.ChargedState(stateValue_0);
    state_0.setOperation('initializeRegistry', new __compactRuntime.ContractOperation());
    state_0.setOperation('assertStateUsesThisRegistry', new __compactRuntime.ContractOperation());
    state_0.setOperation('revokeStatusHandle', new __compactRuntime.ContractOperation());
    const context = __compactRuntime.createCircuitContext(__compactRuntime.dummyContractAddress(), constructorContext_0.initialZswapLocalState.coinPublicKey, state_0.data, constructorContext_0.initialPrivateState);
    const partialProofData = {
      input: { value: [], alignment: [] },
      output: undefined,
      publicTranscript: [],
      privateTranscriptOutputs: []
    };
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_40.toValue(0n),
                                                                                              alignment: _descriptor_40.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(new Uint8Array(32)),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_40.toValue(1n),
                                                                                              alignment: _descriptor_40.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(false),
                                                                                              alignment: _descriptor_2.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_40.toValue(2n),
                                                                                              alignment: _descriptor_40.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(0n),
                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_40.toValue(3n),
                                                                                              alignment: _descriptor_40.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(0n),
                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_40.toValue(4n),
                                                                                              alignment: _descriptor_40.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newArray()
                                                          .arrayPush(__compactRuntime.StateValue.newBoundedMerkleTree(
                                                                       new __compactRuntime.StateBoundedMerkleTree(32)
                                                                     )).arrayPush(__compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(0n),
                                                                                                                        alignment: _descriptor_3.alignment() }))
                                                          .encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_40.toValue(0n),
                                                                                              alignment: _descriptor_40.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 118, 99, 58, 115, 116, 97, 116, 117, 115, 58, 117, 110, 115, 101, 116, 0, 0, 0, 0, 0, 0, 0, 0])),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_40.toValue(1n),
                                                                                              alignment: _descriptor_40.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(false),
                                                                                              alignment: _descriptor_2.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
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
    const result_0 = __compactRuntime.transientHash(_descriptor_3, value_0);
    return result_0;
  }
  _persistentHash_0(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_36, value_0);
    return result_0;
  }
  _persistentHash_1(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_9, value_0);
    return result_0;
  }
  _persistentHash_2(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_35, value_0);
    return result_0;
  }
  _persistentHash_3(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_11, value_0);
    return result_0;
  }
  _persistentHash_4(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_34, value_0);
    return result_0;
  }
  _persistentHash_5(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_13, value_0);
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
    return this._persistentHash_4([new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 118, 99, 58, 98, 108, 105, 110, 100, 45, 104, 111, 108, 100, 101, 114, 0, 0, 0, 0, 0, 0, 0, 0]),
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
    return this._persistentHash_3(binding_0);
  }
  _assertValidNoStatusCapability_0(capability_0) { return []; }
  _assertValidRevokedSetNonMembershipStatusCapability_0(capability_0) {
    __compactRuntime.assert(capability_0.statusType === 0,
                            'Revoked-set status capability type must be revocationRegistry');
    this._assertValidStatusRegistryRef_0(capability_0.registryRef);
    __compactRuntime.assert(!this._equal_36(capability_0.statusHandleCommitment,
                                            new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Status handle commitment must be set');
    return [];
  }
  _assertValidAuthorityAttestedStatusCapability_0(capability_0) {
    __compactRuntime.assert(capability_0.statusType === 0,
                            'Authority-attested status capability type must be revocationRegistry');
    this._assertValidStatusRegistryRef_0(capability_0.registryRef);
    __compactRuntime.assert(!this._equal_37(capability_0.statusHandleCommitment,
                                            new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Authority-attested status handle commitment must be set');
    return [];
  }
  _assertValidVerifierStatusPolicy_0(policy_0) {
    if (policy_0.requireStatus) {
      __compactRuntime.assert(policy_0.acceptedStatusCapability !== 0,
                              'Required status policy must request a real status capability');
    } else {
      __compactRuntime.assert(policy_0.acceptedStatusCapability === 0,
                              'Optional status policy must collapse to NoStatusCapability');
      __compactRuntime.assert(!policy_0.enforceRegistryId,
                              'Optional status policy must not enforce a registry');
      __compactRuntime.assert(!policy_0.enforceAttestationMaxAge,
                              'Optional status policy must not enforce attestation max-age');
      __compactRuntime.assert(this._equal_38(policy_0.maxAttestationAge, 0n),
                              'Optional status policy must not set attestation max-age');
    }
    if (policy_0.enforceRegistryId) {
      __compactRuntime.assert(!this._equal_39(policy_0.acceptedRegistryId,
                                              new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                              'Accepted status registry id must be set when enforced');
    }
    if (policy_0.enforceAttestationMaxAge) {
      __compactRuntime.assert(policy_0.acceptedStatusCapability === 3,
                              'Attestation max-age policy only applies to authority-attested status');
      let t_0;
      __compactRuntime.assert((t_0 = policy_0.maxAttestationAge, t_0 >= 1n),
                              'Attestation max-age policy must request a real freshness window');
    } else {
      __compactRuntime.assert(this._equal_40(policy_0.maxAttestationAge, 0n),
                              'Disabled attestation max-age policy must not carry a freshness window');
    }
    return [];
  }
  _assertValidRevocationRegistryState_0(state_0) {
    __compactRuntime.assert(!this._equal_41(state_0.registryId,
                                            new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Revocation registry id must be set');
    __compactRuntime.assert(this._equal_42(state_0.registryVersion, 0n)
                            ||
                            !this._equal_43(state_0.revokedRoot,
                                            new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Revocation registry root must be set after the registry version advances');
    return [];
  }
  _assertValidRevokedSetStatusRequest_0(request_0) {
    this._assertValidRevocationRegistryState_0(request_0.registryState);
    __compactRuntime.assert(!this._equal_44(request_0.verifierChallengeHash,
                                            new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Status request verifier challenge hash must be set');
    return [];
  }
  _revokedSetStatusHandleCommitment_0(statusHandle_0, opening_0) {
    return this._persistentCommit_0(statusHandle_0, opening_0);
  }
  _revokedSetStatusHandle_0(credentialClaimRoot_0,
                            registryId_0,
                            issuerStatusSalt_0)
  {
    return this._persistentHash_4([new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 118, 99, 58, 115, 116, 97, 116, 117, 115, 45, 104, 97, 110, 100, 108, 101, 0, 0, 0, 0, 0, 0, 0]),
                                   credentialClaimRoot_0,
                                   registryId_0,
                                   issuerStatusSalt_0]);
  }
  _assertValidRevokedSetNonMembershipWitnessInput_0(witnessInput_0) {
    this._assertValidRevocationRegistryState_0(witnessInput_0.registryState);
    __compactRuntime.assert(!this._equal_45(witnessInput_0.statusHandle,
                                            new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Revoked-set status handle witness must be set');
    __compactRuntime.assert(!this._equal_46(witnessInput_0.statusHandleOpening,
                                            new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Revoked-set status handle opening witness must be set');
    return [];
  }
  _assertValidLiveStatusWitnessInput_0(witnessInput_0) {
    __compactRuntime.assert(!this._equal_47(witnessInput_0.statusHandle,
                                            new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Live status handle witness must be set');
    __compactRuntime.assert(!this._equal_48(witnessInput_0.statusHandleOpening,
                                            new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Live status handle opening witness must be set');
    return [];
  }
  _assertValidRevokedSetNonMembershipStatusProofProtocol_0(protocol_0) {
    this._assertValidRevokedSetStatusRequest_0(protocol_0.request);
    this._assertValidRevokedSetNonMembershipWitnessInput_0(protocol_0.witnessInput);
    __compactRuntime.assert(this._equal_49(protocol_0.request.registryState.registryId,
                                           protocol_0.witnessInput.registryState.registryId),
                            'Revoked-set status proof protocol registry id does not match the verifier request');
    __compactRuntime.assert(this._equal_50(protocol_0.request.registryState.revokedRoot,
                                           protocol_0.witnessInput.registryState.revokedRoot),
                            'Revoked-set status proof protocol revoked root does not match the verifier request');
    __compactRuntime.assert(this._equal_51(protocol_0.request.registryState.registryVersion,
                                           protocol_0.witnessInput.registryState.registryVersion),
                            'Revoked-set status proof protocol registry version does not match the verifier request');
    return [];
  }
  _assertRegistryBoundStatusBindingMatchesRevokedSetNonMembershipStatusProofProtocol_0(binding_0,
                                                                                       protocol_0)
  {
    this._assertValidRegistryBoundStatusBinding_0(binding_0);
    this._assertValidRevokedSetNonMembershipStatusProofProtocol_0(protocol_0);
    __compactRuntime.assert(this._equal_52(binding_0.registryRef.registryId,
                                           protocol_0.request.registryState.registryId),
                            'Revoked-set status proof protocol registry does not match the status binding');
    __compactRuntime.assert(this._equal_53(binding_0.statusHandleCommitment,
                                           this._revokedSetStatusHandleCommitment_0(protocol_0.witnessInput.statusHandle,
                                                                                    protocol_0.witnessInput.statusHandleOpening)),
                            'Revoked-set status proof protocol does not match the status handle commitment');
    return [];
  }
  _assertRevokedSetNonMembershipWitnessMatchesBinding_0(binding_0,
                                                        witnessInput_0)
  {
    this._assertValidRegistryBoundStatusBinding_0(binding_0);
    this._assertValidRevokedSetNonMembershipWitnessInput_0(witnessInput_0);
    __compactRuntime.assert(this._equal_54(binding_0.registryRef.registryId,
                                           witnessInput_0.registryState.registryId),
                            'Revoked-set status witness registry does not match the status binding');
    __compactRuntime.assert(this._equal_55(binding_0.statusHandleCommitment,
                                           this._revokedSetStatusHandleCommitment_0(witnessInput_0.statusHandle,
                                                                                    witnessInput_0.statusHandleOpening)),
                            'Revoked-set status witness does not match the status binding handle commitment');
    return [];
  }
  _assertLiveStatusWitnessMatchesBinding_0(binding_0, witnessInput_0) {
    this._assertValidRegistryBoundStatusBinding_0(binding_0);
    this._assertValidLiveStatusWitnessInput_0(witnessInput_0);
    __compactRuntime.assert(this._equal_56(binding_0.statusHandleCommitment,
                                           this._revokedSetStatusHandleCommitment_0(witnessInput_0.statusHandle,
                                                                                    witnessInput_0.statusHandleOpening)),
                            'Live status witness does not match the status binding handle commitment');
    return [];
  }
  _authorityAttestedStatusStatementRoot_0(statement_0) {
    return this._persistentHash_5(statement_0);
  }
  _assertValidAuthorityAttestedStatusStatement_0(statement_0) {
    this._assertValidRevocationRegistryState_0(statement_0.registryState);
    __compactRuntime.assert(!this._equal_57(statement_0.statusHandleCommitment,
                                            new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Authority-attested status handle commitment must be set');
    __compactRuntime.assert(!this._equal_58(statement_0.verifierChallengeHash,
                                            new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Authority-attested verifier challenge hash must be set');
    if (statement_0.hasExpiration) {
      let t_0;
      __compactRuntime.assert((t_0 = statement_0.expiresAt, t_0 >= 1n),
                              'Authority-attested status expiration must be a real timestamp');
    }
    return [];
  }
  _assertValidAuthorityAttestedStatusProof_0(attestation_0) {
    this._assertValidAuthorityAttestedStatusStatement_0(attestation_0.statement);
    __compactRuntime.assert(this._equal_59(attestation_0.proof.challengeHash,
                                           attestation_0.statement.verifierChallengeHash),
                            'Authority-attested status proof challenge hash does not match the statement');
    if (attestation_0.statement.hasExpiration) {
      let t_0;
      __compactRuntime.assert((t_0 = attestation_0.statement.expiresAt,
                               t_0 >= attestation_0.proof.createdAt),
                              'Authority-attested status expiration must not precede proof creation');
    }
    this._assertValidStatusAttestationContextProof_0(this._authorityAttestedStatusStatementRoot_0(attestation_0.statement),
                                                     attestation_0.proof);
    return [];
  }
  _assertValidAuthorityAttestedStatusProofProtocol_0(protocol_0) {
    this._assertValidRevokedSetStatusRequest_0(protocol_0.request);
    this._assertValidAuthorityAttestedStatusProof_0(protocol_0.attestation);
    __compactRuntime.assert(this._equal_60(protocol_0.request.registryState.registryId,
                                           protocol_0.attestation.statement.registryState.registryId),
                            'Authority-attested status proof protocol registry id does not match the verifier request');
    __compactRuntime.assert(this._equal_61(protocol_0.request.registryState.revokedRoot,
                                           protocol_0.attestation.statement.registryState.revokedRoot),
                            'Authority-attested status proof protocol revoked root does not match the verifier request');
    __compactRuntime.assert(this._equal_62(protocol_0.request.registryState.registryVersion,
                                           protocol_0.attestation.statement.registryState.registryVersion),
                            'Authority-attested status proof protocol registry version does not match the verifier request');
    __compactRuntime.assert(this._equal_63(protocol_0.request.verifierChallengeHash,
                                           protocol_0.attestation.statement.verifierChallengeHash),
                            'Authority-attested status proof protocol challenge hash does not match the verifier request');
    return [];
  }
  _assertRegistryBoundStatusBindingMatchesAuthorityAttestedStatusProofProtocol_0(binding_0,
                                                                                 protocol_0,
                                                                                 currentTime_0)
  {
    this._assertValidRegistryBoundStatusBinding_0(binding_0);
    this._assertValidAuthorityAttestedStatusProofProtocol_0(protocol_0);
    this._assertAuthorityAttestedStatusProofMatchesRequest_0(protocol_0.request,
                                                             protocol_0.attestation,
                                                             currentTime_0);
    __compactRuntime.assert(this._equal_64(binding_0.registryRef.registryId,
                                           protocol_0.request.registryState.registryId),
                            'Authority-attested status proof protocol registry does not match the status binding');
    __compactRuntime.assert(this._equal_65(binding_0.statusHandleCommitment,
                                           protocol_0.attestation.statement.statusHandleCommitment),
                            'Authority-attested status handle commitment does not match the status binding');
    __compactRuntime.assert(this._equal_66(binding_0.registryRef.authorityVerificationMethodRef.didContractAddress,
                                           protocol_0.attestation.proof.signerVerificationMethodRef.didContractAddress),
                            'Authority-attested proof contract address does not match the status authority');
    __compactRuntime.assert(this._equal_67(binding_0.registryRef.authorityVerificationMethodRef.methodId,
                                           protocol_0.attestation.proof.signerVerificationMethodRef.methodId),
                            'Authority-attested proof method reference does not match the status authority');
    return [];
  }
  _assertAuthorityAttestedStatusProofMatchesBinding_0(binding_0, attestation_0)
  {
    this._assertValidRegistryBoundStatusBinding_0(binding_0);
    this._assertValidAuthorityAttestedStatusProof_0(attestation_0);
    __compactRuntime.assert(this._equal_68(binding_0.registryRef.registryId,
                                           attestation_0.statement.registryState.registryId),
                            'Authority-attested status registry does not match the status binding');
    __compactRuntime.assert(this._equal_69(binding_0.statusHandleCommitment,
                                           attestation_0.statement.statusHandleCommitment),
                            'Authority-attested status handle commitment does not match the status binding');
    __compactRuntime.assert(this._equal_70(binding_0.registryRef.authorityVerificationMethodRef.didContractAddress,
                                           attestation_0.proof.signerVerificationMethodRef.didContractAddress),
                            'Authority-attested proof contract address does not match the status authority');
    __compactRuntime.assert(this._equal_71(binding_0.registryRef.authorityVerificationMethodRef.methodId,
                                           attestation_0.proof.signerVerificationMethodRef.methodId),
                            'Authority-attested proof method reference does not match the status authority');
    return [];
  }
  _assertAuthorityAttestedStatusProofMatchesRequest_0(request_0,
                                                      attestation_0,
                                                      currentTime_0)
  {
    this._assertValidRevokedSetStatusRequest_0(request_0);
    this._assertValidAuthorityAttestedStatusProof_0(attestation_0);
    __compactRuntime.assert(this._equal_72(request_0.registryState.registryId,
                                           attestation_0.statement.registryState.registryId),
                            'Authority-attested status registry id does not match the verifier request');
    __compactRuntime.assert(this._equal_73(request_0.registryState.revokedRoot,
                                           attestation_0.statement.registryState.revokedRoot),
                            'Authority-attested revoked root does not match the verifier request');
    __compactRuntime.assert(this._equal_74(request_0.registryState.registryVersion,
                                           attestation_0.statement.registryState.registryVersion),
                            'Authority-attested registry version does not match the verifier request');
    __compactRuntime.assert(this._equal_75(request_0.verifierChallengeHash,
                                           attestation_0.statement.verifierChallengeHash),
                            'Authority-attested verifier challenge hash does not match the request');
    __compactRuntime.assert(currentTime_0 >= attestation_0.proof.createdAt,
                            'Authority-attested status proof creation time cannot be in the future');
    if (attestation_0.statement.hasExpiration) {
      __compactRuntime.assert(currentTime_0 <= attestation_0.statement.expiresAt,
                              'Authority-attested status proof has expired');
    }
    return [];
  }
  _assertAuthorityAttestedStatusProofFreshEnough_0(policy_0,
                                                   attestation_0,
                                                   currentTime_0)
  {
    this._assertValidVerifierStatusPolicy_0(policy_0);
    this._assertValidAuthorityAttestedStatusProof_0(attestation_0);
    __compactRuntime.assert(currentTime_0 >= attestation_0.proof.createdAt,
                            'Authority-attested status proof creation time cannot be in the future');
    if (policy_0.enforceAttestationMaxAge) {
      let t_0, t_1;
      __compactRuntime.assert((t_0 = (t_1 = attestation_0.proof.createdAt,
                                      (__compactRuntime.assert(currentTime_0
                                                               >=
                                                               t_1,
                                                               'result of subtraction would be negative'),
                                       currentTime_0 - t_1)),
                               t_0 <= policy_0.maxAttestationAge),
                              'Authority-attested status proof exceeds the verifier max-age policy');
    }
    return [];
  }
  _assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipBinding_0(policy_0,
                                                                     binding_0,
                                                                     witnessInput_0)
  {
    this._assertValidVerifierStatusPolicy_0(policy_0);
    this._assertRevokedSetNonMembershipWitnessMatchesBinding_0(binding_0,
                                                               witnessInput_0);
    __compactRuntime.assert(policy_0.requireStatus,
                            'Verifier status policy must require status for revoked-set non-membership');
    __compactRuntime.assert(policy_0.acceptedStatusCapability === 2,
                            'Verifier status policy does not accept revoked-set non-membership');
    if (policy_0.enforceRegistryId) {
      __compactRuntime.assert(this._equal_76(policy_0.acceptedRegistryId,
                                             binding_0.registryRef.registryId),
                              'Verifier status policy registry id does not match the supplied status binding');
      __compactRuntime.assert(this._equal_77(policy_0.acceptedRegistryId,
                                             witnessInput_0.registryState.registryId),
                              'Verifier status policy registry id does not match the supplied status registry');
    }
    return [];
  }
  _assertVerifierStatusPolicyAcceptsLiveStatusBinding_0(policy_0,
                                                        binding_0,
                                                        witnessInput_0)
  {
    this._assertValidVerifierStatusPolicy_0(policy_0);
    this._assertLiveStatusWitnessMatchesBinding_0(binding_0, witnessInput_0);
    __compactRuntime.assert(policy_0.requireStatus,
                            'Verifier status policy must require status for live revoked-set verification');
    __compactRuntime.assert(policy_0.acceptedStatusCapability === 2,
                            'Verifier status policy does not accept live revoked-set verification');
    if (policy_0.enforceRegistryId) {
      __compactRuntime.assert(this._equal_78(policy_0.acceptedRegistryId,
                                             binding_0.registryRef.registryId),
                              'Verifier status policy registry id does not match the supplied status binding');
    }
    return [];
  }
  _assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipStatusProofProtocol_0(policy_0,
                                                                                 binding_0,
                                                                                 protocol_0)
  {
    this._assertValidVerifierStatusPolicy_0(policy_0);
    this._assertRegistryBoundStatusBindingMatchesRevokedSetNonMembershipStatusProofProtocol_0(binding_0,
                                                                                              protocol_0);
    __compactRuntime.assert(policy_0.requireStatus,
                            'Verifier status policy must require status for revoked-set non-membership');
    __compactRuntime.assert(policy_0.acceptedStatusCapability === 2,
                            'Verifier status policy does not accept revoked-set non-membership');
    if (policy_0.enforceRegistryId) {
      __compactRuntime.assert(this._equal_79(policy_0.acceptedRegistryId,
                                             binding_0.registryRef.registryId),
                              'Verifier status policy registry id does not match the supplied status binding');
      __compactRuntime.assert(this._equal_80(policy_0.acceptedRegistryId,
                                             protocol_0.request.registryState.registryId),
                              'Verifier status policy registry id does not match the supplied status registry');
    }
    return [];
  }
  _assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusBinding_0(policy_0,
                                                                     binding_0,
                                                                     request_0,
                                                                     attestation_0,
                                                                     currentTime_0)
  {
    this._assertValidVerifierStatusPolicy_0(policy_0);
    this._assertAuthorityAttestedStatusProofMatchesBinding_0(binding_0,
                                                             attestation_0);
    this._assertAuthorityAttestedStatusProofMatchesRequest_0(request_0,
                                                             attestation_0,
                                                             currentTime_0);
    this._assertAuthorityAttestedStatusProofFreshEnough_0(policy_0,
                                                          attestation_0,
                                                          currentTime_0);
    __compactRuntime.assert(policy_0.requireStatus,
                            'Verifier status policy must require status for authority-attested status');
    __compactRuntime.assert(policy_0.acceptedStatusCapability === 3,
                            'Verifier status policy does not accept authority-attested status');
    if (policy_0.enforceRegistryId) {
      __compactRuntime.assert(this._equal_81(policy_0.acceptedRegistryId,
                                             binding_0.registryRef.registryId),
                              'Verifier status policy registry id does not match the supplied status binding');
      __compactRuntime.assert(this._equal_82(policy_0.acceptedRegistryId,
                                             request_0.registryState.registryId),
                              'Verifier status policy registry id does not match the verifier request');
    }
    return [];
  }
  _assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusProofProtocol_0(policy_0,
                                                                           binding_0,
                                                                           protocol_0,
                                                                           currentTime_0)
  {
    this._assertValidVerifierStatusPolicy_0(policy_0);
    this._assertRegistryBoundStatusBindingMatchesAuthorityAttestedStatusProofProtocol_0(binding_0,
                                                                                        protocol_0,
                                                                                        currentTime_0);
    this._assertAuthorityAttestedStatusProofFreshEnough_0(policy_0,
                                                          protocol_0.attestation,
                                                          currentTime_0);
    __compactRuntime.assert(policy_0.requireStatus,
                            'Verifier status policy must require status for authority-attested status');
    __compactRuntime.assert(policy_0.acceptedStatusCapability === 3,
                            'Verifier status policy does not accept authority-attested status');
    if (policy_0.enforceRegistryId) {
      __compactRuntime.assert(this._equal_83(policy_0.acceptedRegistryId,
                                             binding_0.registryRef.registryId),
                              'Verifier status policy registry id does not match the supplied status binding');
      __compactRuntime.assert(this._equal_84(policy_0.acceptedRegistryId,
                                             protocol_0.request.registryState.registryId),
                              'Verifier status policy registry id does not match the verifier request');
    }
    return [];
  }
  _initializeRegistry_0(context, partialProofData, nextRegistryId_0) {
    __compactRuntime.assert(!_descriptor_2.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                       partialProofData,
                                                                                       [
                                                                                        { dup: { n: 0 } },
                                                                                        { idx: { cached: false,
                                                                                                 pushPath: false,
                                                                                                 path: [
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_40.toValue(1n),
                                                                                                                   alignment: _descriptor_40.alignment() } }] } },
                                                                                        { popeq: { cached: false,
                                                                                                   result: undefined } }]).value),
                            'Revocation registry has already been initialized');
    __compactRuntime.assert(!this._equal_85(nextRegistryId_0,
                                            new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Revocation registry id must be set');
    __compactRuntime.assert(!this._equal_86(nextRegistryId_0,
                                            new Uint8Array([109, 105, 100, 110, 105, 103, 104, 116, 58, 118, 99, 58, 115, 116, 97, 116, 117, 115, 58, 117, 110, 115, 101, 116, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Revocation registry id must not reuse the unset sentinel');
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_40.toValue(0n),
                                                                                              alignment: _descriptor_40.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(nextRegistryId_0),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_40.toValue(1n),
                                                                                              alignment: _descriptor_40.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_2.toValue(true),
                                                                                              alignment: _descriptor_2.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } }]);
    return [];
  }
  _assertStateUsesThisRegistry_0(context, partialProofData, state_0) {
    __compactRuntime.assert(_descriptor_2.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_40.toValue(1n),
                                                                                                                  alignment: _descriptor_40.alignment() } }] } },
                                                                                       { popeq: { cached: false,
                                                                                                  result: undefined } }]).value),
                            'Revocation registry is not initialized');
    this._assertValidRevocationRegistryState_0(state_0);
    __compactRuntime.assert(this._equal_87(state_0.registryId,
                                           _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                                     partialProofData,
                                                                                                     [
                                                                                                      { dup: { n: 0 } },
                                                                                                      { idx: { cached: false,
                                                                                                               pushPath: false,
                                                                                                               path: [
                                                                                                                      { tag: 'value',
                                                                                                                        value: { value: _descriptor_40.toValue(0n),
                                                                                                                                 alignment: _descriptor_40.alignment() } }] } },
                                                                                                      { popeq: { cached: false,
                                                                                                                 result: undefined } }]).value)),
                            'Revocation registry state does not belong to this registry');
    __compactRuntime.assert(this._equal_88(state_0.registryVersion,
                                           _descriptor_3.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                                     partialProofData,
                                                                                                     [
                                                                                                      { dup: { n: 0 } },
                                                                                                      { idx: { cached: false,
                                                                                                               pushPath: false,
                                                                                                               path: [
                                                                                                                      { tag: 'value',
                                                                                                                        value: { value: _descriptor_40.toValue(2n),
                                                                                                                                 alignment: _descriptor_40.alignment() } }] } },
                                                                                                      { popeq: { cached: true,
                                                                                                                 result: undefined } }]).value)),
                            'Revocation registry state version does not match this registry');
    return [];
  }
  _revokeStatusHandle_0(context, partialProofData, statusHandle_0) {
    __compactRuntime.assert(_descriptor_2.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_40.toValue(1n),
                                                                                                                  alignment: _descriptor_40.alignment() } }] } },
                                                                                       { popeq: { cached: false,
                                                                                                  result: undefined } }]).value),
                            'Revocation registry is not initialized');
    __compactRuntime.assert(!this._equal_89(statusHandle_0,
                                            new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
                            'Revoked status handle must be set');
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_40.toValue(4n),
                                                                  alignment: _descriptor_40.alignment() } }] } },
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_40.toValue(0n),
                                                                  alignment: _descriptor_40.alignment() } }] } },
                                       { dup: { n: 2 } },
                                       { idx: { cached: false,
                                                pushPath: false,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_40.toValue(1n),
                                                                  alignment: _descriptor_40.alignment() } }] } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell(__compactRuntime.leafHash(
                                                                                              { value: _descriptor_1.toValue(statusHandle_0),
                                                                                                alignment: _descriptor_1.alignment() }
                                                                                            )).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } },
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_40.toValue(1n),
                                                                  alignment: _descriptor_40.alignment() } }] } },
                                       { addi: { immediate: 1 } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_0 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_40.toValue(3n),
                                                                  alignment: _descriptor_40.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_0.toValue(tmp_0),
                                                                alignment: _descriptor_0.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 1 } }]);
    const tmp_1 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_40.toValue(2n),
                                                                  alignment: _descriptor_40.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_0.toValue(tmp_1),
                                                                alignment: _descriptor_0.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
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
  _equal_36(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_37(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_38(x0, y0) {
    if (x0 !== y0) { return false; }
    return true;
  }
  _equal_39(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_40(x0, y0) {
    if (x0 !== y0) { return false; }
    return true;
  }
  _equal_41(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_42(x0, y0) {
    if (x0 !== y0) { return false; }
    return true;
  }
  _equal_43(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_44(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_45(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_46(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_47(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_48(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_49(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_50(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_51(x0, y0) {
    if (x0 !== y0) { return false; }
    return true;
  }
  _equal_52(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_53(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_54(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_55(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_56(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_57(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_58(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_59(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_60(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_61(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_62(x0, y0) {
    if (x0 !== y0) { return false; }
    return true;
  }
  _equal_63(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_64(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_65(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_66(x0, y0) {
    {
      let x1 = x0.bytes;
      let y1 = y0.bytes;
      if (!x1.every((x, i) => y1[i] === x)) { return false; }
    }
    return true;
  }
  _equal_67(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_68(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_69(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_70(x0, y0) {
    {
      let x1 = x0.bytes;
      let y1 = y0.bytes;
      if (!x1.every((x, i) => y1[i] === x)) { return false; }
    }
    return true;
  }
  _equal_71(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_72(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_73(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_74(x0, y0) {
    if (x0 !== y0) { return false; }
    return true;
  }
  _equal_75(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_76(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_77(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_78(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_79(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_80(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_81(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_82(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_83(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_84(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_85(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_86(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_87(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_88(x0, y0) {
    if (x0 !== y0) { return false; }
    return true;
  }
  _equal_89(x0, y0) {
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
    get registryId() {
      return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                       partialProofData,
                                                                       [
                                                                        { dup: { n: 0 } },
                                                                        { idx: { cached: false,
                                                                                 pushPath: false,
                                                                                 path: [
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_40.toValue(0n),
                                                                                                   alignment: _descriptor_40.alignment() } }] } },
                                                                        { popeq: { cached: false,
                                                                                   result: undefined } }]).value);
    },
    get initialized() {
      return _descriptor_2.fromValue(__compactRuntime.queryLedgerState(context,
                                                                       partialProofData,
                                                                       [
                                                                        { dup: { n: 0 } },
                                                                        { idx: { cached: false,
                                                                                 pushPath: false,
                                                                                 path: [
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_40.toValue(1n),
                                                                                                   alignment: _descriptor_40.alignment() } }] } },
                                                                        { popeq: { cached: false,
                                                                                   result: undefined } }]).value);
    },
    get version() {
      return _descriptor_3.fromValue(__compactRuntime.queryLedgerState(context,
                                                                       partialProofData,
                                                                       [
                                                                        { dup: { n: 0 } },
                                                                        { idx: { cached: false,
                                                                                 pushPath: false,
                                                                                 path: [
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_40.toValue(2n),
                                                                                                   alignment: _descriptor_40.alignment() } }] } },
                                                                        { popeq: { cached: true,
                                                                                   result: undefined } }]).value);
    },
    get revokedStatusHandleCount() {
      return _descriptor_3.fromValue(__compactRuntime.queryLedgerState(context,
                                                                       partialProofData,
                                                                       [
                                                                        { dup: { n: 0 } },
                                                                        { idx: { cached: false,
                                                                                 pushPath: false,
                                                                                 path: [
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_40.toValue(3n),
                                                                                                   alignment: _descriptor_40.alignment() } }] } },
                                                                        { popeq: { cached: true,
                                                                                   result: undefined } }]).value);
    },
    revokedStatusHandles: {
      isFull(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isFull: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_2.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_40.toValue(4n),
                                                                                                     alignment: _descriptor_40.alignment() } }] } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_40.toValue(1n),
                                                                                                     alignment: _descriptor_40.alignment() } }] } },
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(4294967296n),
                                                                                                                                 alignment: _descriptor_3.alignment() }).encode() } },
                                                                          'lt',
                                                                          'neg',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      checkRoot(...args_0) {
        if (args_0.length !== 1) {
          throw new __compactRuntime.CompactError(`checkRoot: expected 1 argument, received ${args_0.length}`);
        }
        const rt_0 = args_0[0];
        if (!(typeof(rt_0) === 'object' && typeof(rt_0.field) === 'bigint' && rt_0.field >= 0 && rt_0.field <= __compactRuntime.MAX_FIELD)) {
          __compactRuntime.typeError('checkRoot',
                                     'argument 1',
                                     'revocation-registry.compact line 12 char 1',
                                     'struct MerkleTreeDigest<field: Field>',
                                     rt_0)
        }
        return _descriptor_2.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_40.toValue(4n),
                                                                                                     alignment: _descriptor_40.alignment() } }] } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_40.toValue(0n),
                                                                                                     alignment: _descriptor_40.alignment() } }] } },
                                                                          'root',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_39.toValue(rt_0),
                                                                                                                                 alignment: _descriptor_39.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      root(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`root: expected 0 arguments, received ${args_0.length}`);
        }
        const self_0 = state.asArray()[4];
        return ((result) => result             ? __compactRuntime.CompactTypeMerkleTreeDigest.fromValue(result)             : undefined)(self_0.asArray()[0].asBoundedMerkleTree().rehash().root()?.value);
      },
      firstFree(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`first_free: expected 0 arguments, received ${args_0.length}`);
        }
        const self_0 = state.asArray()[4];
        return __compactRuntime.CompactTypeField.fromValue(self_0.asArray()[1].asCell().value);
      },
      pathForLeaf(...args_0) {
        if (args_0.length !== 2) {
          throw new __compactRuntime.CompactError(`path_for_leaf: expected 2 arguments, received ${args_0.length}`);
        }
        const index_0 = args_0[0];
        const leaf_0 = args_0[1];
        if (!(typeof(index_0) === 'bigint' && index_0 >= 0 && index_0 <= __compactRuntime.MAX_FIELD)) {
          __compactRuntime.typeError('path_for_leaf',
                                     'argument 1',
                                     'revocation-registry.compact line 12 char 1',
                                     'Field',
                                     index_0)
        }
        if (!(leaf_0.buffer instanceof ArrayBuffer && leaf_0.BYTES_PER_ELEMENT === 1 && leaf_0.length === 32)) {
          __compactRuntime.typeError('path_for_leaf',
                                     'argument 2',
                                     'revocation-registry.compact line 12 char 1',
                                     'Bytes<32>',
                                     leaf_0)
        }
        const self_0 = state.asArray()[4];
        return ((result) => result             ? new __compactRuntime.CompactTypeMerkleTreePath(32, _descriptor_1).fromValue(result)             : undefined)(  self_0.asArray()[0].asBoundedMerkleTree().rehash().pathForLeaf(    index_0,    {      value: _descriptor_1.toValue(leaf_0),      alignment: _descriptor_1.alignment()    }  )?.value);
      },
      findPathForLeaf(...args_0) {
        if (args_0.length !== 1) {
          throw new __compactRuntime.CompactError(`find_path_for_leaf: expected 1 argument, received ${args_0.length}`);
        }
        const leaf_0 = args_0[0];
        if (!(leaf_0.buffer instanceof ArrayBuffer && leaf_0.BYTES_PER_ELEMENT === 1 && leaf_0.length === 32)) {
          __compactRuntime.typeError('find_path_for_leaf',
                                     'argument 1',
                                     'revocation-registry.compact line 12 char 1',
                                     'Bytes<32>',
                                     leaf_0)
        }
        const self_0 = state.asArray()[4];
        return ((result) => result             ? new __compactRuntime.CompactTypeMerkleTreePath(32, _descriptor_1).fromValue(result)             : undefined)(  self_0.asArray()[0].asBoundedMerkleTree().rehash().findPathForLeaf(    {      value: _descriptor_1.toValue(leaf_0),      alignment: _descriptor_1.alignment()    }  )?.value);
      }
    }
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
  },
  assertValidNoStatusCapability: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidNoStatusCapability: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const capability_0 = args_0[0];
    if (!(typeof(capability_0) === 'object')) {
      __compactRuntime.typeError('assertValidNoStatusCapability',
                                 'argument 1',
                                 'status-proof-protocol.compact line 110 char 1',
                                 'struct NoStatusCapability<>',
                                 capability_0)
    }
    return _dummyContract._assertValidNoStatusCapability_0(capability_0);
  },
  assertValidRevokedSetNonMembershipStatusCapability: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidRevokedSetNonMembershipStatusCapability: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const capability_0 = args_0[0];
    if (!(typeof(capability_0) === 'object' && typeof(capability_0.statusType) === 'number' && capability_0.statusType >= 0 && capability_0.statusType <= 0 && typeof(capability_0.registryRef) === 'object' && capability_0.registryRef.registryId.buffer instanceof ArrayBuffer && capability_0.registryRef.registryId.BYTES_PER_ELEMENT === 1 && capability_0.registryRef.registryId.length === 32 && typeof(capability_0.registryRef.authorityVerificationMethodRef) === 'object' && typeof(capability_0.registryRef.authorityVerificationMethodRef.didContractAddress) === 'object' && capability_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && capability_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && capability_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.length === 32 && capability_0.registryRef.authorityVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && capability_0.registryRef.authorityVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && capability_0.registryRef.authorityVerificationMethodRef.methodId.length === 32 && capability_0.statusHandleCommitment.buffer instanceof ArrayBuffer && capability_0.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && capability_0.statusHandleCommitment.length === 32)) {
      __compactRuntime.typeError('assertValidRevokedSetNonMembershipStatusCapability',
                                 'argument 1',
                                 'status-proof-protocol.compact line 117 char 1',
                                 'struct RevokedSetNonMembershipStatusCapability<statusType: Enum<StatusType, revocationRegistry>, registryRef: struct StatusRegistryRef<registryId: Bytes<32>, authorityVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>, statusHandleCommitment: Bytes<32>>',
                                 capability_0)
    }
    return _dummyContract._assertValidRevokedSetNonMembershipStatusCapability_0(capability_0);
  },
  assertValidAuthorityAttestedStatusCapability: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidAuthorityAttestedStatusCapability: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const capability_0 = args_0[0];
    if (!(typeof(capability_0) === 'object' && typeof(capability_0.statusType) === 'number' && capability_0.statusType >= 0 && capability_0.statusType <= 0 && typeof(capability_0.registryRef) === 'object' && capability_0.registryRef.registryId.buffer instanceof ArrayBuffer && capability_0.registryRef.registryId.BYTES_PER_ELEMENT === 1 && capability_0.registryRef.registryId.length === 32 && typeof(capability_0.registryRef.authorityVerificationMethodRef) === 'object' && typeof(capability_0.registryRef.authorityVerificationMethodRef.didContractAddress) === 'object' && capability_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && capability_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && capability_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.length === 32 && capability_0.registryRef.authorityVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && capability_0.registryRef.authorityVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && capability_0.registryRef.authorityVerificationMethodRef.methodId.length === 32 && capability_0.statusHandleCommitment.buffer instanceof ArrayBuffer && capability_0.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && capability_0.statusHandleCommitment.length === 32)) {
      __compactRuntime.typeError('assertValidAuthorityAttestedStatusCapability',
                                 'argument 1',
                                 'status-proof-protocol.compact line 131 char 1',
                                 'struct AuthorityAttestedStatusCapability<statusType: Enum<StatusType, revocationRegistry>, registryRef: struct StatusRegistryRef<registryId: Bytes<32>, authorityVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>, statusHandleCommitment: Bytes<32>>',
                                 capability_0)
    }
    return _dummyContract._assertValidAuthorityAttestedStatusCapability_0(capability_0);
  },
  assertValidVerifierStatusPolicy: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidVerifierStatusPolicy: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const policy_0 = args_0[0];
    if (!(typeof(policy_0) === 'object' && typeof(policy_0.requireStatus) === 'boolean' && typeof(policy_0.acceptedStatusCapability) === 'number' && policy_0.acceptedStatusCapability >= 0 && policy_0.acceptedStatusCapability <= 3 && typeof(policy_0.enforceRegistryId) === 'boolean' && policy_0.acceptedRegistryId.buffer instanceof ArrayBuffer && policy_0.acceptedRegistryId.BYTES_PER_ELEMENT === 1 && policy_0.acceptedRegistryId.length === 32 && typeof(policy_0.enforceAttestationMaxAge) === 'boolean' && typeof(policy_0.maxAttestationAge) === 'bigint' && policy_0.maxAttestationAge >= 0n && policy_0.maxAttestationAge <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertValidVerifierStatusPolicy',
                                 'argument 1',
                                 'status-proof-protocol.compact line 145 char 1',
                                 'struct VerifierStatusPolicy<requireStatus: Boolean, acceptedStatusCapability: Enum<StatusCapabilityKind, noStatus, publicStatus, revokedSetNonMembership, authorityAttestedStatus>, enforceRegistryId: Boolean, acceptedRegistryId: Bytes<32>, enforceAttestationMaxAge: Boolean, maxAttestationAge: Uint<0..18446744073709551616>>',
                                 policy_0)
    }
    return _dummyContract._assertValidVerifierStatusPolicy_0(policy_0);
  },
  assertValidRevocationRegistryState: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidRevocationRegistryState: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const state_0 = args_0[0];
    if (!(typeof(state_0) === 'object' && state_0.registryId.buffer instanceof ArrayBuffer && state_0.registryId.BYTES_PER_ELEMENT === 1 && state_0.registryId.length === 32 && state_0.revokedRoot.buffer instanceof ArrayBuffer && state_0.revokedRoot.BYTES_PER_ELEMENT === 1 && state_0.revokedRoot.length === 32 && typeof(state_0.registryVersion) === 'bigint' && state_0.registryVersion >= 0n && state_0.registryVersion <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertValidRevocationRegistryState',
                                 'argument 1',
                                 'status-proof-protocol.compact line 196 char 1',
                                 'struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>',
                                 state_0)
    }
    return _dummyContract._assertValidRevocationRegistryState_0(state_0);
  },
  assertValidRevokedSetStatusRequest: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidRevokedSetStatusRequest: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const request_0 = args_0[0];
    if (!(typeof(request_0) === 'object' && typeof(request_0.registryState) === 'object' && request_0.registryState.registryId.buffer instanceof ArrayBuffer && request_0.registryState.registryId.BYTES_PER_ELEMENT === 1 && request_0.registryState.registryId.length === 32 && request_0.registryState.revokedRoot.buffer instanceof ArrayBuffer && request_0.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && request_0.registryState.revokedRoot.length === 32 && typeof(request_0.registryState.registryVersion) === 'bigint' && request_0.registryState.registryVersion >= 0n && request_0.registryState.registryVersion <= 18446744073709551615n && request_0.verifierChallengeHash.buffer instanceof ArrayBuffer && request_0.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && request_0.verifierChallengeHash.length === 32)) {
      __compactRuntime.typeError('assertValidRevokedSetStatusRequest',
                                 'argument 1',
                                 'status-proof-protocol.compact line 209 char 1',
                                 'struct RevokedSetStatusRequest<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, verifierChallengeHash: Bytes<32>>',
                                 request_0)
    }
    return _dummyContract._assertValidRevokedSetStatusRequest_0(request_0);
  },
  revokedSetStatusHandleCommitment: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`revokedSetStatusHandleCommitment: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const statusHandle_0 = args_0[0];
    const opening_0 = args_0[1];
    if (!(statusHandle_0.buffer instanceof ArrayBuffer && statusHandle_0.BYTES_PER_ELEMENT === 1 && statusHandle_0.length === 32)) {
      __compactRuntime.typeError('revokedSetStatusHandleCommitment',
                                 'argument 1',
                                 'status-proof-protocol.compact line 219 char 1',
                                 'Bytes<32>',
                                 statusHandle_0)
    }
    if (!(opening_0.buffer instanceof ArrayBuffer && opening_0.BYTES_PER_ELEMENT === 1 && opening_0.length === 32)) {
      __compactRuntime.typeError('revokedSetStatusHandleCommitment',
                                 'argument 2',
                                 'status-proof-protocol.compact line 219 char 1',
                                 'Bytes<32>',
                                 opening_0)
    }
    return _dummyContract._revokedSetStatusHandleCommitment_0(statusHandle_0,
                                                              opening_0);
  },
  revokedSetStatusHandle: (...args_0) => {
    if (args_0.length !== 3) {
      throw new __compactRuntime.CompactError(`revokedSetStatusHandle: expected 3 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const credentialClaimRoot_0 = args_0[0];
    const registryId_0 = args_0[1];
    const issuerStatusSalt_0 = args_0[2];
    if (!(credentialClaimRoot_0.buffer instanceof ArrayBuffer && credentialClaimRoot_0.BYTES_PER_ELEMENT === 1 && credentialClaimRoot_0.length === 32)) {
      __compactRuntime.typeError('revokedSetStatusHandle',
                                 'argument 1',
                                 'status-proof-protocol.compact line 226 char 1',
                                 'Bytes<32>',
                                 credentialClaimRoot_0)
    }
    if (!(registryId_0.buffer instanceof ArrayBuffer && registryId_0.BYTES_PER_ELEMENT === 1 && registryId_0.length === 32)) {
      __compactRuntime.typeError('revokedSetStatusHandle',
                                 'argument 2',
                                 'status-proof-protocol.compact line 226 char 1',
                                 'Bytes<32>',
                                 registryId_0)
    }
    if (!(issuerStatusSalt_0.buffer instanceof ArrayBuffer && issuerStatusSalt_0.BYTES_PER_ELEMENT === 1 && issuerStatusSalt_0.length === 32)) {
      __compactRuntime.typeError('revokedSetStatusHandle',
                                 'argument 3',
                                 'status-proof-protocol.compact line 226 char 1',
                                 'Bytes<32>',
                                 issuerStatusSalt_0)
    }
    return _dummyContract._revokedSetStatusHandle_0(credentialClaimRoot_0,
                                                    registryId_0,
                                                    issuerStatusSalt_0);
  },
  assertValidRevokedSetNonMembershipWitnessInput: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidRevokedSetNonMembershipWitnessInput: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const witnessInput_0 = args_0[0];
    if (!(typeof(witnessInput_0) === 'object' && typeof(witnessInput_0.registryState) === 'object' && witnessInput_0.registryState.registryId.buffer instanceof ArrayBuffer && witnessInput_0.registryState.registryId.BYTES_PER_ELEMENT === 1 && witnessInput_0.registryState.registryId.length === 32 && witnessInput_0.registryState.revokedRoot.buffer instanceof ArrayBuffer && witnessInput_0.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && witnessInput_0.registryState.revokedRoot.length === 32 && typeof(witnessInput_0.registryState.registryVersion) === 'bigint' && witnessInput_0.registryState.registryVersion >= 0n && witnessInput_0.registryState.registryVersion <= 18446744073709551615n && witnessInput_0.statusHandle.buffer instanceof ArrayBuffer && witnessInput_0.statusHandle.BYTES_PER_ELEMENT === 1 && witnessInput_0.statusHandle.length === 32 && witnessInput_0.statusHandleOpening.buffer instanceof ArrayBuffer && witnessInput_0.statusHandleOpening.BYTES_PER_ELEMENT === 1 && witnessInput_0.statusHandleOpening.length === 32)) {
      __compactRuntime.typeError('assertValidRevokedSetNonMembershipWitnessInput',
                                 'argument 1',
                                 'status-proof-protocol.compact line 239 char 1',
                                 'struct RevokedSetNonMembershipWitnessInput<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, statusHandle: Bytes<32>, statusHandleOpening: Bytes<32>>',
                                 witnessInput_0)
    }
    return _dummyContract._assertValidRevokedSetNonMembershipWitnessInput_0(witnessInput_0);
  },
  assertValidLiveStatusWitnessInput: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidLiveStatusWitnessInput: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const witnessInput_0 = args_0[0];
    if (!(typeof(witnessInput_0) === 'object' && witnessInput_0.statusHandle.buffer instanceof ArrayBuffer && witnessInput_0.statusHandle.BYTES_PER_ELEMENT === 1 && witnessInput_0.statusHandle.length === 32 && witnessInput_0.statusHandleOpening.buffer instanceof ArrayBuffer && witnessInput_0.statusHandleOpening.BYTES_PER_ELEMENT === 1 && witnessInput_0.statusHandleOpening.length === 32)) {
      __compactRuntime.typeError('assertValidLiveStatusWitnessInput',
                                 'argument 1',
                                 'status-proof-protocol.compact line 253 char 1',
                                 'struct LiveStatusWitnessInput<statusHandle: Bytes<32>, statusHandleOpening: Bytes<32>>',
                                 witnessInput_0)
    }
    return _dummyContract._assertValidLiveStatusWitnessInput_0(witnessInput_0);
  },
  assertValidRevokedSetNonMembershipStatusProofProtocol: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidRevokedSetNonMembershipStatusProofProtocol: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const protocol_0 = args_0[0];
    if (!(typeof(protocol_0) === 'object' && typeof(protocol_0.request) === 'object' && typeof(protocol_0.request.registryState) === 'object' && protocol_0.request.registryState.registryId.buffer instanceof ArrayBuffer && protocol_0.request.registryState.registryId.BYTES_PER_ELEMENT === 1 && protocol_0.request.registryState.registryId.length === 32 && protocol_0.request.registryState.revokedRoot.buffer instanceof ArrayBuffer && protocol_0.request.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && protocol_0.request.registryState.revokedRoot.length === 32 && typeof(protocol_0.request.registryState.registryVersion) === 'bigint' && protocol_0.request.registryState.registryVersion >= 0n && protocol_0.request.registryState.registryVersion <= 18446744073709551615n && protocol_0.request.verifierChallengeHash.buffer instanceof ArrayBuffer && protocol_0.request.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && protocol_0.request.verifierChallengeHash.length === 32 && typeof(protocol_0.witnessInput) === 'object' && typeof(protocol_0.witnessInput.registryState) === 'object' && protocol_0.witnessInput.registryState.registryId.buffer instanceof ArrayBuffer && protocol_0.witnessInput.registryState.registryId.BYTES_PER_ELEMENT === 1 && protocol_0.witnessInput.registryState.registryId.length === 32 && protocol_0.witnessInput.registryState.revokedRoot.buffer instanceof ArrayBuffer && protocol_0.witnessInput.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && protocol_0.witnessInput.registryState.revokedRoot.length === 32 && typeof(protocol_0.witnessInput.registryState.registryVersion) === 'bigint' && protocol_0.witnessInput.registryState.registryVersion >= 0n && protocol_0.witnessInput.registryState.registryVersion <= 18446744073709551615n && protocol_0.witnessInput.statusHandle.buffer instanceof ArrayBuffer && protocol_0.witnessInput.statusHandle.BYTES_PER_ELEMENT === 1 && protocol_0.witnessInput.statusHandle.length === 32 && protocol_0.witnessInput.statusHandleOpening.buffer instanceof ArrayBuffer && protocol_0.witnessInput.statusHandleOpening.BYTES_PER_ELEMENT === 1 && protocol_0.witnessInput.statusHandleOpening.length === 32)) {
      __compactRuntime.typeError('assertValidRevokedSetNonMembershipStatusProofProtocol',
                                 'argument 1',
                                 'status-proof-protocol.compact line 269 char 1',
                                 'struct RevokedSetNonMembershipStatusProofProtocol<request: struct RevokedSetStatusRequest<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, verifierChallengeHash: Bytes<32>>, witnessInput: struct RevokedSetNonMembershipWitnessInput<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, statusHandle: Bytes<32>, statusHandleOpening: Bytes<32>>>',
                                 protocol_0)
    }
    return _dummyContract._assertValidRevokedSetNonMembershipStatusProofProtocol_0(protocol_0);
  },
  assertRegistryBoundStatusBindingMatchesRevokedSetNonMembershipStatusProofProtocol: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertRegistryBoundStatusBindingMatchesRevokedSetNonMembershipStatusProofProtocol: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    const protocol_0 = args_0[1];
    if (!(typeof(binding_0) === 'object' && typeof(binding_0.statusType) === 'number' && binding_0.statusType >= 0 && binding_0.statusType <= 0 && typeof(binding_0.registryRef) === 'object' && binding_0.registryRef.registryId.buffer instanceof ArrayBuffer && binding_0.registryRef.registryId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.registryId.length === 32 && typeof(binding_0.registryRef.authorityVerificationMethodRef) === 'object' && typeof(binding_0.registryRef.authorityVerificationMethodRef.didContractAddress) === 'object' && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.length === 32 && binding_0.registryRef.authorityVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.methodId.length === 32 && binding_0.statusHandleCommitment.buffer instanceof ArrayBuffer && binding_0.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && binding_0.statusHandleCommitment.length === 32)) {
      __compactRuntime.typeError('assertRegistryBoundStatusBindingMatchesRevokedSetNonMembershipStatusProofProtocol',
                                 'argument 1',
                                 'status-proof-protocol.compact line 291 char 1',
                                 'struct RegistryBoundStatusBinding<statusType: Enum<StatusType, revocationRegistry>, registryRef: struct StatusRegistryRef<registryId: Bytes<32>, authorityVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>, statusHandleCommitment: Bytes<32>>',
                                 binding_0)
    }
    if (!(typeof(protocol_0) === 'object' && typeof(protocol_0.request) === 'object' && typeof(protocol_0.request.registryState) === 'object' && protocol_0.request.registryState.registryId.buffer instanceof ArrayBuffer && protocol_0.request.registryState.registryId.BYTES_PER_ELEMENT === 1 && protocol_0.request.registryState.registryId.length === 32 && protocol_0.request.registryState.revokedRoot.buffer instanceof ArrayBuffer && protocol_0.request.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && protocol_0.request.registryState.revokedRoot.length === 32 && typeof(protocol_0.request.registryState.registryVersion) === 'bigint' && protocol_0.request.registryState.registryVersion >= 0n && protocol_0.request.registryState.registryVersion <= 18446744073709551615n && protocol_0.request.verifierChallengeHash.buffer instanceof ArrayBuffer && protocol_0.request.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && protocol_0.request.verifierChallengeHash.length === 32 && typeof(protocol_0.witnessInput) === 'object' && typeof(protocol_0.witnessInput.registryState) === 'object' && protocol_0.witnessInput.registryState.registryId.buffer instanceof ArrayBuffer && protocol_0.witnessInput.registryState.registryId.BYTES_PER_ELEMENT === 1 && protocol_0.witnessInput.registryState.registryId.length === 32 && protocol_0.witnessInput.registryState.revokedRoot.buffer instanceof ArrayBuffer && protocol_0.witnessInput.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && protocol_0.witnessInput.registryState.revokedRoot.length === 32 && typeof(protocol_0.witnessInput.registryState.registryVersion) === 'bigint' && protocol_0.witnessInput.registryState.registryVersion >= 0n && protocol_0.witnessInput.registryState.registryVersion <= 18446744073709551615n && protocol_0.witnessInput.statusHandle.buffer instanceof ArrayBuffer && protocol_0.witnessInput.statusHandle.BYTES_PER_ELEMENT === 1 && protocol_0.witnessInput.statusHandle.length === 32 && protocol_0.witnessInput.statusHandleOpening.buffer instanceof ArrayBuffer && protocol_0.witnessInput.statusHandleOpening.BYTES_PER_ELEMENT === 1 && protocol_0.witnessInput.statusHandleOpening.length === 32)) {
      __compactRuntime.typeError('assertRegistryBoundStatusBindingMatchesRevokedSetNonMembershipStatusProofProtocol',
                                 'argument 2',
                                 'status-proof-protocol.compact line 291 char 1',
                                 'struct RevokedSetNonMembershipStatusProofProtocol<request: struct RevokedSetStatusRequest<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, verifierChallengeHash: Bytes<32>>, witnessInput: struct RevokedSetNonMembershipWitnessInput<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, statusHandle: Bytes<32>, statusHandleOpening: Bytes<32>>>',
                                 protocol_0)
    }
    return _dummyContract._assertRegistryBoundStatusBindingMatchesRevokedSetNonMembershipStatusProofProtocol_0(binding_0,
                                                                                                               protocol_0);
  },
  assertRevokedSetNonMembershipWitnessMatchesBinding: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertRevokedSetNonMembershipWitnessMatchesBinding: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    const witnessInput_0 = args_0[1];
    if (!(typeof(binding_0) === 'object' && typeof(binding_0.statusType) === 'number' && binding_0.statusType >= 0 && binding_0.statusType <= 0 && typeof(binding_0.registryRef) === 'object' && binding_0.registryRef.registryId.buffer instanceof ArrayBuffer && binding_0.registryRef.registryId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.registryId.length === 32 && typeof(binding_0.registryRef.authorityVerificationMethodRef) === 'object' && typeof(binding_0.registryRef.authorityVerificationMethodRef.didContractAddress) === 'object' && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.length === 32 && binding_0.registryRef.authorityVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.methodId.length === 32 && binding_0.statusHandleCommitment.buffer instanceof ArrayBuffer && binding_0.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && binding_0.statusHandleCommitment.length === 32)) {
      __compactRuntime.typeError('assertRevokedSetNonMembershipWitnessMatchesBinding',
                                 'argument 1',
                                 'status-proof-protocol.compact line 314 char 1',
                                 'struct RegistryBoundStatusBinding<statusType: Enum<StatusType, revocationRegistry>, registryRef: struct StatusRegistryRef<registryId: Bytes<32>, authorityVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>, statusHandleCommitment: Bytes<32>>',
                                 binding_0)
    }
    if (!(typeof(witnessInput_0) === 'object' && typeof(witnessInput_0.registryState) === 'object' && witnessInput_0.registryState.registryId.buffer instanceof ArrayBuffer && witnessInput_0.registryState.registryId.BYTES_PER_ELEMENT === 1 && witnessInput_0.registryState.registryId.length === 32 && witnessInput_0.registryState.revokedRoot.buffer instanceof ArrayBuffer && witnessInput_0.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && witnessInput_0.registryState.revokedRoot.length === 32 && typeof(witnessInput_0.registryState.registryVersion) === 'bigint' && witnessInput_0.registryState.registryVersion >= 0n && witnessInput_0.registryState.registryVersion <= 18446744073709551615n && witnessInput_0.statusHandle.buffer instanceof ArrayBuffer && witnessInput_0.statusHandle.BYTES_PER_ELEMENT === 1 && witnessInput_0.statusHandle.length === 32 && witnessInput_0.statusHandleOpening.buffer instanceof ArrayBuffer && witnessInput_0.statusHandleOpening.BYTES_PER_ELEMENT === 1 && witnessInput_0.statusHandleOpening.length === 32)) {
      __compactRuntime.typeError('assertRevokedSetNonMembershipWitnessMatchesBinding',
                                 'argument 2',
                                 'status-proof-protocol.compact line 314 char 1',
                                 'struct RevokedSetNonMembershipWitnessInput<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, statusHandle: Bytes<32>, statusHandleOpening: Bytes<32>>',
                                 witnessInput_0)
    }
    return _dummyContract._assertRevokedSetNonMembershipWitnessMatchesBinding_0(binding_0,
                                                                                witnessInput_0);
  },
  assertLiveStatusWitnessMatchesBinding: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertLiveStatusWitnessMatchesBinding: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    const witnessInput_0 = args_0[1];
    if (!(typeof(binding_0) === 'object' && typeof(binding_0.statusType) === 'number' && binding_0.statusType >= 0 && binding_0.statusType <= 0 && typeof(binding_0.registryRef) === 'object' && binding_0.registryRef.registryId.buffer instanceof ArrayBuffer && binding_0.registryRef.registryId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.registryId.length === 32 && typeof(binding_0.registryRef.authorityVerificationMethodRef) === 'object' && typeof(binding_0.registryRef.authorityVerificationMethodRef.didContractAddress) === 'object' && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.length === 32 && binding_0.registryRef.authorityVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.methodId.length === 32 && binding_0.statusHandleCommitment.buffer instanceof ArrayBuffer && binding_0.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && binding_0.statusHandleCommitment.length === 32)) {
      __compactRuntime.typeError('assertLiveStatusWitnessMatchesBinding',
                                 'argument 1',
                                 'status-proof-protocol.compact line 336 char 1',
                                 'struct RegistryBoundStatusBinding<statusType: Enum<StatusType, revocationRegistry>, registryRef: struct StatusRegistryRef<registryId: Bytes<32>, authorityVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>, statusHandleCommitment: Bytes<32>>',
                                 binding_0)
    }
    if (!(typeof(witnessInput_0) === 'object' && witnessInput_0.statusHandle.buffer instanceof ArrayBuffer && witnessInput_0.statusHandle.BYTES_PER_ELEMENT === 1 && witnessInput_0.statusHandle.length === 32 && witnessInput_0.statusHandleOpening.buffer instanceof ArrayBuffer && witnessInput_0.statusHandleOpening.BYTES_PER_ELEMENT === 1 && witnessInput_0.statusHandleOpening.length === 32)) {
      __compactRuntime.typeError('assertLiveStatusWitnessMatchesBinding',
                                 'argument 2',
                                 'status-proof-protocol.compact line 336 char 1',
                                 'struct LiveStatusWitnessInput<statusHandle: Bytes<32>, statusHandleOpening: Bytes<32>>',
                                 witnessInput_0)
    }
    return _dummyContract._assertLiveStatusWitnessMatchesBinding_0(binding_0,
                                                                   witnessInput_0);
  },
  authorityAttestedStatusStatementRoot: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`authorityAttestedStatusStatementRoot: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const statement_0 = args_0[0];
    if (!(typeof(statement_0) === 'object' && typeof(statement_0.registryState) === 'object' && statement_0.registryState.registryId.buffer instanceof ArrayBuffer && statement_0.registryState.registryId.BYTES_PER_ELEMENT === 1 && statement_0.registryState.registryId.length === 32 && statement_0.registryState.revokedRoot.buffer instanceof ArrayBuffer && statement_0.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && statement_0.registryState.revokedRoot.length === 32 && typeof(statement_0.registryState.registryVersion) === 'bigint' && statement_0.registryState.registryVersion >= 0n && statement_0.registryState.registryVersion <= 18446744073709551615n && statement_0.statusHandleCommitment.buffer instanceof ArrayBuffer && statement_0.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && statement_0.statusHandleCommitment.length === 32 && statement_0.verifierChallengeHash.buffer instanceof ArrayBuffer && statement_0.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && statement_0.verifierChallengeHash.length === 32 && typeof(statement_0.hasExpiration) === 'boolean' && typeof(statement_0.expiresAt) === 'bigint' && statement_0.expiresAt >= 0n && statement_0.expiresAt <= 18446744073709551615n)) {
      __compactRuntime.typeError('authorityAttestedStatusStatementRoot',
                                 'argument 1',
                                 'status-proof-protocol.compact line 354 char 1',
                                 'struct AuthorityAttestedStatusStatement<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, statusHandleCommitment: Bytes<32>, verifierChallengeHash: Bytes<32>, hasExpiration: Boolean, expiresAt: Uint<0..18446744073709551616>>',
                                 statement_0)
    }
    return _dummyContract._authorityAttestedStatusStatementRoot_0(statement_0);
  },
  assertValidAuthorityAttestedStatusStatement: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidAuthorityAttestedStatusStatement: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const statement_0 = args_0[0];
    if (!(typeof(statement_0) === 'object' && typeof(statement_0.registryState) === 'object' && statement_0.registryState.registryId.buffer instanceof ArrayBuffer && statement_0.registryState.registryId.BYTES_PER_ELEMENT === 1 && statement_0.registryState.registryId.length === 32 && statement_0.registryState.revokedRoot.buffer instanceof ArrayBuffer && statement_0.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && statement_0.registryState.revokedRoot.length === 32 && typeof(statement_0.registryState.registryVersion) === 'bigint' && statement_0.registryState.registryVersion >= 0n && statement_0.registryState.registryVersion <= 18446744073709551615n && statement_0.statusHandleCommitment.buffer instanceof ArrayBuffer && statement_0.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && statement_0.statusHandleCommitment.length === 32 && statement_0.verifierChallengeHash.buffer instanceof ArrayBuffer && statement_0.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && statement_0.verifierChallengeHash.length === 32 && typeof(statement_0.hasExpiration) === 'boolean' && typeof(statement_0.expiresAt) === 'bigint' && statement_0.expiresAt >= 0n && statement_0.expiresAt <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertValidAuthorityAttestedStatusStatement',
                                 'argument 1',
                                 'status-proof-protocol.compact line 360 char 1',
                                 'struct AuthorityAttestedStatusStatement<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, statusHandleCommitment: Bytes<32>, verifierChallengeHash: Bytes<32>, hasExpiration: Boolean, expiresAt: Uint<0..18446744073709551616>>',
                                 statement_0)
    }
    return _dummyContract._assertValidAuthorityAttestedStatusStatement_0(statement_0);
  },
  assertValidAuthorityAttestedStatusProof: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidAuthorityAttestedStatusProof: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const attestation_0 = args_0[0];
    if (!(typeof(attestation_0) === 'object' && typeof(attestation_0.statement) === 'object' && typeof(attestation_0.statement.registryState) === 'object' && attestation_0.statement.registryState.registryId.buffer instanceof ArrayBuffer && attestation_0.statement.registryState.registryId.BYTES_PER_ELEMENT === 1 && attestation_0.statement.registryState.registryId.length === 32 && attestation_0.statement.registryState.revokedRoot.buffer instanceof ArrayBuffer && attestation_0.statement.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && attestation_0.statement.registryState.revokedRoot.length === 32 && typeof(attestation_0.statement.registryState.registryVersion) === 'bigint' && attestation_0.statement.registryState.registryVersion >= 0n && attestation_0.statement.registryState.registryVersion <= 18446744073709551615n && attestation_0.statement.statusHandleCommitment.buffer instanceof ArrayBuffer && attestation_0.statement.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && attestation_0.statement.statusHandleCommitment.length === 32 && attestation_0.statement.verifierChallengeHash.buffer instanceof ArrayBuffer && attestation_0.statement.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && attestation_0.statement.verifierChallengeHash.length === 32 && typeof(attestation_0.statement.hasExpiration) === 'boolean' && typeof(attestation_0.statement.expiresAt) === 'bigint' && attestation_0.statement.expiresAt >= 0n && attestation_0.statement.expiresAt <= 18446744073709551615n && typeof(attestation_0.proof) === 'object' && typeof(attestation_0.proof.signerVerificationMethodRef) === 'object' && typeof(attestation_0.proof.signerVerificationMethodRef.didContractAddress) === 'object' && attestation_0.proof.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && attestation_0.proof.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && attestation_0.proof.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && attestation_0.proof.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && attestation_0.proof.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && attestation_0.proof.signerVerificationMethodRef.methodId.length === 32 && typeof(attestation_0.proof.createdAt) === 'bigint' && attestation_0.proof.createdAt >= 0n && attestation_0.proof.createdAt <= 18446744073709551615n && attestation_0.proof.challengeHash.buffer instanceof ArrayBuffer && attestation_0.proof.challengeHash.BYTES_PER_ELEMENT === 1 && attestation_0.proof.challengeHash.length === 32 && true && typeof(attestation_0.proof.signature) === 'object' && true && typeof(attestation_0.proof.signature.s) === 'bigint' && attestation_0.proof.signature.s >= 0 && attestation_0.proof.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('assertValidAuthorityAttestedStatusProof',
                                 'argument 1',
                                 'status-proof-protocol.compact line 380 char 1',
                                 'struct AuthorityAttestedStatusProof<statement: struct AuthorityAttestedStatusStatement<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, statusHandleCommitment: Bytes<32>, verifierChallengeHash: Bytes<32>, hasExpiration: Boolean, expiresAt: Uint<0..18446744073709551616>>, proof: struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>>',
                                 attestation_0)
    }
    return _dummyContract._assertValidAuthorityAttestedStatusProof_0(attestation_0);
  },
  assertValidAuthorityAttestedStatusProofProtocol: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`assertValidAuthorityAttestedStatusProofProtocol: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const protocol_0 = args_0[0];
    if (!(typeof(protocol_0) === 'object' && typeof(protocol_0.request) === 'object' && typeof(protocol_0.request.registryState) === 'object' && protocol_0.request.registryState.registryId.buffer instanceof ArrayBuffer && protocol_0.request.registryState.registryId.BYTES_PER_ELEMENT === 1 && protocol_0.request.registryState.registryId.length === 32 && protocol_0.request.registryState.revokedRoot.buffer instanceof ArrayBuffer && protocol_0.request.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && protocol_0.request.registryState.revokedRoot.length === 32 && typeof(protocol_0.request.registryState.registryVersion) === 'bigint' && protocol_0.request.registryState.registryVersion >= 0n && protocol_0.request.registryState.registryVersion <= 18446744073709551615n && protocol_0.request.verifierChallengeHash.buffer instanceof ArrayBuffer && protocol_0.request.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && protocol_0.request.verifierChallengeHash.length === 32 && typeof(protocol_0.attestation) === 'object' && typeof(protocol_0.attestation.statement) === 'object' && typeof(protocol_0.attestation.statement.registryState) === 'object' && protocol_0.attestation.statement.registryState.registryId.buffer instanceof ArrayBuffer && protocol_0.attestation.statement.registryState.registryId.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.statement.registryState.registryId.length === 32 && protocol_0.attestation.statement.registryState.revokedRoot.buffer instanceof ArrayBuffer && protocol_0.attestation.statement.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.statement.registryState.revokedRoot.length === 32 && typeof(protocol_0.attestation.statement.registryState.registryVersion) === 'bigint' && protocol_0.attestation.statement.registryState.registryVersion >= 0n && protocol_0.attestation.statement.registryState.registryVersion <= 18446744073709551615n && protocol_0.attestation.statement.statusHandleCommitment.buffer instanceof ArrayBuffer && protocol_0.attestation.statement.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.statement.statusHandleCommitment.length === 32 && protocol_0.attestation.statement.verifierChallengeHash.buffer instanceof ArrayBuffer && protocol_0.attestation.statement.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.statement.verifierChallengeHash.length === 32 && typeof(protocol_0.attestation.statement.hasExpiration) === 'boolean' && typeof(protocol_0.attestation.statement.expiresAt) === 'bigint' && protocol_0.attestation.statement.expiresAt >= 0n && protocol_0.attestation.statement.expiresAt <= 18446744073709551615n && typeof(protocol_0.attestation.proof) === 'object' && typeof(protocol_0.attestation.proof.signerVerificationMethodRef) === 'object' && typeof(protocol_0.attestation.proof.signerVerificationMethodRef.didContractAddress) === 'object' && protocol_0.attestation.proof.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && protocol_0.attestation.proof.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.proof.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && protocol_0.attestation.proof.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && protocol_0.attestation.proof.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.proof.signerVerificationMethodRef.methodId.length === 32 && typeof(protocol_0.attestation.proof.createdAt) === 'bigint' && protocol_0.attestation.proof.createdAt >= 0n && protocol_0.attestation.proof.createdAt <= 18446744073709551615n && protocol_0.attestation.proof.challengeHash.buffer instanceof ArrayBuffer && protocol_0.attestation.proof.challengeHash.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.proof.challengeHash.length === 32 && true && typeof(protocol_0.attestation.proof.signature) === 'object' && true && typeof(protocol_0.attestation.proof.signature.s) === 'bigint' && protocol_0.attestation.proof.signature.s >= 0 && protocol_0.attestation.proof.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('assertValidAuthorityAttestedStatusProofProtocol',
                                 'argument 1',
                                 'status-proof-protocol.compact line 400 char 1',
                                 'struct AuthorityAttestedStatusProofProtocol<request: struct RevokedSetStatusRequest<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, verifierChallengeHash: Bytes<32>>, attestation: struct AuthorityAttestedStatusProof<statement: struct AuthorityAttestedStatusStatement<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, statusHandleCommitment: Bytes<32>, verifierChallengeHash: Bytes<32>, hasExpiration: Boolean, expiresAt: Uint<0..18446744073709551616>>, proof: struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>>>',
                                 protocol_0)
    }
    return _dummyContract._assertValidAuthorityAttestedStatusProofProtocol_0(protocol_0);
  },
  assertRegistryBoundStatusBindingMatchesAuthorityAttestedStatusProofProtocol: (...args_0) => {
    if (args_0.length !== 3) {
      throw new __compactRuntime.CompactError(`assertRegistryBoundStatusBindingMatchesAuthorityAttestedStatusProofProtocol: expected 3 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    const protocol_0 = args_0[1];
    const currentTime_0 = args_0[2];
    if (!(typeof(binding_0) === 'object' && typeof(binding_0.statusType) === 'number' && binding_0.statusType >= 0 && binding_0.statusType <= 0 && typeof(binding_0.registryRef) === 'object' && binding_0.registryRef.registryId.buffer instanceof ArrayBuffer && binding_0.registryRef.registryId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.registryId.length === 32 && typeof(binding_0.registryRef.authorityVerificationMethodRef) === 'object' && typeof(binding_0.registryRef.authorityVerificationMethodRef.didContractAddress) === 'object' && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.length === 32 && binding_0.registryRef.authorityVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.methodId.length === 32 && binding_0.statusHandleCommitment.buffer instanceof ArrayBuffer && binding_0.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && binding_0.statusHandleCommitment.length === 32)) {
      __compactRuntime.typeError('assertRegistryBoundStatusBindingMatchesAuthorityAttestedStatusProofProtocol',
                                 'argument 1',
                                 'status-proof-protocol.compact line 427 char 1',
                                 'struct RegistryBoundStatusBinding<statusType: Enum<StatusType, revocationRegistry>, registryRef: struct StatusRegistryRef<registryId: Bytes<32>, authorityVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>, statusHandleCommitment: Bytes<32>>',
                                 binding_0)
    }
    if (!(typeof(protocol_0) === 'object' && typeof(protocol_0.request) === 'object' && typeof(protocol_0.request.registryState) === 'object' && protocol_0.request.registryState.registryId.buffer instanceof ArrayBuffer && protocol_0.request.registryState.registryId.BYTES_PER_ELEMENT === 1 && protocol_0.request.registryState.registryId.length === 32 && protocol_0.request.registryState.revokedRoot.buffer instanceof ArrayBuffer && protocol_0.request.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && protocol_0.request.registryState.revokedRoot.length === 32 && typeof(protocol_0.request.registryState.registryVersion) === 'bigint' && protocol_0.request.registryState.registryVersion >= 0n && protocol_0.request.registryState.registryVersion <= 18446744073709551615n && protocol_0.request.verifierChallengeHash.buffer instanceof ArrayBuffer && protocol_0.request.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && protocol_0.request.verifierChallengeHash.length === 32 && typeof(protocol_0.attestation) === 'object' && typeof(protocol_0.attestation.statement) === 'object' && typeof(protocol_0.attestation.statement.registryState) === 'object' && protocol_0.attestation.statement.registryState.registryId.buffer instanceof ArrayBuffer && protocol_0.attestation.statement.registryState.registryId.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.statement.registryState.registryId.length === 32 && protocol_0.attestation.statement.registryState.revokedRoot.buffer instanceof ArrayBuffer && protocol_0.attestation.statement.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.statement.registryState.revokedRoot.length === 32 && typeof(protocol_0.attestation.statement.registryState.registryVersion) === 'bigint' && protocol_0.attestation.statement.registryState.registryVersion >= 0n && protocol_0.attestation.statement.registryState.registryVersion <= 18446744073709551615n && protocol_0.attestation.statement.statusHandleCommitment.buffer instanceof ArrayBuffer && protocol_0.attestation.statement.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.statement.statusHandleCommitment.length === 32 && protocol_0.attestation.statement.verifierChallengeHash.buffer instanceof ArrayBuffer && protocol_0.attestation.statement.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.statement.verifierChallengeHash.length === 32 && typeof(protocol_0.attestation.statement.hasExpiration) === 'boolean' && typeof(protocol_0.attestation.statement.expiresAt) === 'bigint' && protocol_0.attestation.statement.expiresAt >= 0n && protocol_0.attestation.statement.expiresAt <= 18446744073709551615n && typeof(protocol_0.attestation.proof) === 'object' && typeof(protocol_0.attestation.proof.signerVerificationMethodRef) === 'object' && typeof(protocol_0.attestation.proof.signerVerificationMethodRef.didContractAddress) === 'object' && protocol_0.attestation.proof.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && protocol_0.attestation.proof.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.proof.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && protocol_0.attestation.proof.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && protocol_0.attestation.proof.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.proof.signerVerificationMethodRef.methodId.length === 32 && typeof(protocol_0.attestation.proof.createdAt) === 'bigint' && protocol_0.attestation.proof.createdAt >= 0n && protocol_0.attestation.proof.createdAt <= 18446744073709551615n && protocol_0.attestation.proof.challengeHash.buffer instanceof ArrayBuffer && protocol_0.attestation.proof.challengeHash.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.proof.challengeHash.length === 32 && true && typeof(protocol_0.attestation.proof.signature) === 'object' && true && typeof(protocol_0.attestation.proof.signature.s) === 'bigint' && protocol_0.attestation.proof.signature.s >= 0 && protocol_0.attestation.proof.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('assertRegistryBoundStatusBindingMatchesAuthorityAttestedStatusProofProtocol',
                                 'argument 2',
                                 'status-proof-protocol.compact line 427 char 1',
                                 'struct AuthorityAttestedStatusProofProtocol<request: struct RevokedSetStatusRequest<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, verifierChallengeHash: Bytes<32>>, attestation: struct AuthorityAttestedStatusProof<statement: struct AuthorityAttestedStatusStatement<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, statusHandleCommitment: Bytes<32>, verifierChallengeHash: Bytes<32>, hasExpiration: Boolean, expiresAt: Uint<0..18446744073709551616>>, proof: struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>>>',
                                 protocol_0)
    }
    if (!(typeof(currentTime_0) === 'bigint' && currentTime_0 >= 0n && currentTime_0 <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertRegistryBoundStatusBindingMatchesAuthorityAttestedStatusProofProtocol',
                                 'argument 3',
                                 'status-proof-protocol.compact line 427 char 1',
                                 'Uint<0..18446744073709551616>',
                                 currentTime_0)
    }
    return _dummyContract._assertRegistryBoundStatusBindingMatchesAuthorityAttestedStatusProofProtocol_0(binding_0,
                                                                                                         protocol_0,
                                                                                                         currentTime_0);
  },
  assertAuthorityAttestedStatusProofMatchesBinding: (...args_0) => {
    if (args_0.length !== 2) {
      throw new __compactRuntime.CompactError(`assertAuthorityAttestedStatusProofMatchesBinding: expected 2 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const binding_0 = args_0[0];
    const attestation_0 = args_0[1];
    if (!(typeof(binding_0) === 'object' && typeof(binding_0.statusType) === 'number' && binding_0.statusType >= 0 && binding_0.statusType <= 0 && typeof(binding_0.registryRef) === 'object' && binding_0.registryRef.registryId.buffer instanceof ArrayBuffer && binding_0.registryRef.registryId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.registryId.length === 32 && typeof(binding_0.registryRef.authorityVerificationMethodRef) === 'object' && typeof(binding_0.registryRef.authorityVerificationMethodRef.didContractAddress) === 'object' && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.length === 32 && binding_0.registryRef.authorityVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.methodId.length === 32 && binding_0.statusHandleCommitment.buffer instanceof ArrayBuffer && binding_0.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && binding_0.statusHandleCommitment.length === 32)) {
      __compactRuntime.typeError('assertAuthorityAttestedStatusProofMatchesBinding',
                                 'argument 1',
                                 'status-proof-protocol.compact line 460 char 1',
                                 'struct RegistryBoundStatusBinding<statusType: Enum<StatusType, revocationRegistry>, registryRef: struct StatusRegistryRef<registryId: Bytes<32>, authorityVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>, statusHandleCommitment: Bytes<32>>',
                                 binding_0)
    }
    if (!(typeof(attestation_0) === 'object' && typeof(attestation_0.statement) === 'object' && typeof(attestation_0.statement.registryState) === 'object' && attestation_0.statement.registryState.registryId.buffer instanceof ArrayBuffer && attestation_0.statement.registryState.registryId.BYTES_PER_ELEMENT === 1 && attestation_0.statement.registryState.registryId.length === 32 && attestation_0.statement.registryState.revokedRoot.buffer instanceof ArrayBuffer && attestation_0.statement.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && attestation_0.statement.registryState.revokedRoot.length === 32 && typeof(attestation_0.statement.registryState.registryVersion) === 'bigint' && attestation_0.statement.registryState.registryVersion >= 0n && attestation_0.statement.registryState.registryVersion <= 18446744073709551615n && attestation_0.statement.statusHandleCommitment.buffer instanceof ArrayBuffer && attestation_0.statement.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && attestation_0.statement.statusHandleCommitment.length === 32 && attestation_0.statement.verifierChallengeHash.buffer instanceof ArrayBuffer && attestation_0.statement.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && attestation_0.statement.verifierChallengeHash.length === 32 && typeof(attestation_0.statement.hasExpiration) === 'boolean' && typeof(attestation_0.statement.expiresAt) === 'bigint' && attestation_0.statement.expiresAt >= 0n && attestation_0.statement.expiresAt <= 18446744073709551615n && typeof(attestation_0.proof) === 'object' && typeof(attestation_0.proof.signerVerificationMethodRef) === 'object' && typeof(attestation_0.proof.signerVerificationMethodRef.didContractAddress) === 'object' && attestation_0.proof.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && attestation_0.proof.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && attestation_0.proof.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && attestation_0.proof.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && attestation_0.proof.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && attestation_0.proof.signerVerificationMethodRef.methodId.length === 32 && typeof(attestation_0.proof.createdAt) === 'bigint' && attestation_0.proof.createdAt >= 0n && attestation_0.proof.createdAt <= 18446744073709551615n && attestation_0.proof.challengeHash.buffer instanceof ArrayBuffer && attestation_0.proof.challengeHash.BYTES_PER_ELEMENT === 1 && attestation_0.proof.challengeHash.length === 32 && true && typeof(attestation_0.proof.signature) === 'object' && true && typeof(attestation_0.proof.signature.s) === 'bigint' && attestation_0.proof.signature.s >= 0 && attestation_0.proof.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('assertAuthorityAttestedStatusProofMatchesBinding',
                                 'argument 2',
                                 'status-proof-protocol.compact line 460 char 1',
                                 'struct AuthorityAttestedStatusProof<statement: struct AuthorityAttestedStatusStatement<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, statusHandleCommitment: Bytes<32>, verifierChallengeHash: Bytes<32>, hasExpiration: Boolean, expiresAt: Uint<0..18446744073709551616>>, proof: struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>>',
                                 attestation_0)
    }
    return _dummyContract._assertAuthorityAttestedStatusProofMatchesBinding_0(binding_0,
                                                                              attestation_0);
  },
  assertAuthorityAttestedStatusProofMatchesRequest: (...args_0) => {
    if (args_0.length !== 3) {
      throw new __compactRuntime.CompactError(`assertAuthorityAttestedStatusProofMatchesRequest: expected 3 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const request_0 = args_0[0];
    const attestation_0 = args_0[1];
    const currentTime_0 = args_0[2];
    if (!(typeof(request_0) === 'object' && typeof(request_0.registryState) === 'object' && request_0.registryState.registryId.buffer instanceof ArrayBuffer && request_0.registryState.registryId.BYTES_PER_ELEMENT === 1 && request_0.registryState.registryId.length === 32 && request_0.registryState.revokedRoot.buffer instanceof ArrayBuffer && request_0.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && request_0.registryState.revokedRoot.length === 32 && typeof(request_0.registryState.registryVersion) === 'bigint' && request_0.registryState.registryVersion >= 0n && request_0.registryState.registryVersion <= 18446744073709551615n && request_0.verifierChallengeHash.buffer instanceof ArrayBuffer && request_0.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && request_0.verifierChallengeHash.length === 32)) {
      __compactRuntime.typeError('assertAuthorityAttestedStatusProofMatchesRequest',
                                 'argument 1',
                                 'status-proof-protocol.compact line 486 char 1',
                                 'struct RevokedSetStatusRequest<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, verifierChallengeHash: Bytes<32>>',
                                 request_0)
    }
    if (!(typeof(attestation_0) === 'object' && typeof(attestation_0.statement) === 'object' && typeof(attestation_0.statement.registryState) === 'object' && attestation_0.statement.registryState.registryId.buffer instanceof ArrayBuffer && attestation_0.statement.registryState.registryId.BYTES_PER_ELEMENT === 1 && attestation_0.statement.registryState.registryId.length === 32 && attestation_0.statement.registryState.revokedRoot.buffer instanceof ArrayBuffer && attestation_0.statement.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && attestation_0.statement.registryState.revokedRoot.length === 32 && typeof(attestation_0.statement.registryState.registryVersion) === 'bigint' && attestation_0.statement.registryState.registryVersion >= 0n && attestation_0.statement.registryState.registryVersion <= 18446744073709551615n && attestation_0.statement.statusHandleCommitment.buffer instanceof ArrayBuffer && attestation_0.statement.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && attestation_0.statement.statusHandleCommitment.length === 32 && attestation_0.statement.verifierChallengeHash.buffer instanceof ArrayBuffer && attestation_0.statement.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && attestation_0.statement.verifierChallengeHash.length === 32 && typeof(attestation_0.statement.hasExpiration) === 'boolean' && typeof(attestation_0.statement.expiresAt) === 'bigint' && attestation_0.statement.expiresAt >= 0n && attestation_0.statement.expiresAt <= 18446744073709551615n && typeof(attestation_0.proof) === 'object' && typeof(attestation_0.proof.signerVerificationMethodRef) === 'object' && typeof(attestation_0.proof.signerVerificationMethodRef.didContractAddress) === 'object' && attestation_0.proof.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && attestation_0.proof.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && attestation_0.proof.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && attestation_0.proof.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && attestation_0.proof.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && attestation_0.proof.signerVerificationMethodRef.methodId.length === 32 && typeof(attestation_0.proof.createdAt) === 'bigint' && attestation_0.proof.createdAt >= 0n && attestation_0.proof.createdAt <= 18446744073709551615n && attestation_0.proof.challengeHash.buffer instanceof ArrayBuffer && attestation_0.proof.challengeHash.BYTES_PER_ELEMENT === 1 && attestation_0.proof.challengeHash.length === 32 && true && typeof(attestation_0.proof.signature) === 'object' && true && typeof(attestation_0.proof.signature.s) === 'bigint' && attestation_0.proof.signature.s >= 0 && attestation_0.proof.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('assertAuthorityAttestedStatusProofMatchesRequest',
                                 'argument 2',
                                 'status-proof-protocol.compact line 486 char 1',
                                 'struct AuthorityAttestedStatusProof<statement: struct AuthorityAttestedStatusStatement<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, statusHandleCommitment: Bytes<32>, verifierChallengeHash: Bytes<32>, hasExpiration: Boolean, expiresAt: Uint<0..18446744073709551616>>, proof: struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>>',
                                 attestation_0)
    }
    if (!(typeof(currentTime_0) === 'bigint' && currentTime_0 >= 0n && currentTime_0 <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertAuthorityAttestedStatusProofMatchesRequest',
                                 'argument 3',
                                 'status-proof-protocol.compact line 486 char 1',
                                 'Uint<0..18446744073709551616>',
                                 currentTime_0)
    }
    return _dummyContract._assertAuthorityAttestedStatusProofMatchesRequest_0(request_0,
                                                                              attestation_0,
                                                                              currentTime_0);
  },
  assertAuthorityAttestedStatusProofFreshEnough: (...args_0) => {
    if (args_0.length !== 3) {
      throw new __compactRuntime.CompactError(`assertAuthorityAttestedStatusProofFreshEnough: expected 3 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const policy_0 = args_0[0];
    const attestation_0 = args_0[1];
    const currentTime_0 = args_0[2];
    if (!(typeof(policy_0) === 'object' && typeof(policy_0.requireStatus) === 'boolean' && typeof(policy_0.acceptedStatusCapability) === 'number' && policy_0.acceptedStatusCapability >= 0 && policy_0.acceptedStatusCapability <= 3 && typeof(policy_0.enforceRegistryId) === 'boolean' && policy_0.acceptedRegistryId.buffer instanceof ArrayBuffer && policy_0.acceptedRegistryId.BYTES_PER_ELEMENT === 1 && policy_0.acceptedRegistryId.length === 32 && typeof(policy_0.enforceAttestationMaxAge) === 'boolean' && typeof(policy_0.maxAttestationAge) === 'bigint' && policy_0.maxAttestationAge >= 0n && policy_0.maxAttestationAge <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertAuthorityAttestedStatusProofFreshEnough',
                                 'argument 1',
                                 'status-proof-protocol.compact line 522 char 1',
                                 'struct VerifierStatusPolicy<requireStatus: Boolean, acceptedStatusCapability: Enum<StatusCapabilityKind, noStatus, publicStatus, revokedSetNonMembership, authorityAttestedStatus>, enforceRegistryId: Boolean, acceptedRegistryId: Bytes<32>, enforceAttestationMaxAge: Boolean, maxAttestationAge: Uint<0..18446744073709551616>>',
                                 policy_0)
    }
    if (!(typeof(attestation_0) === 'object' && typeof(attestation_0.statement) === 'object' && typeof(attestation_0.statement.registryState) === 'object' && attestation_0.statement.registryState.registryId.buffer instanceof ArrayBuffer && attestation_0.statement.registryState.registryId.BYTES_PER_ELEMENT === 1 && attestation_0.statement.registryState.registryId.length === 32 && attestation_0.statement.registryState.revokedRoot.buffer instanceof ArrayBuffer && attestation_0.statement.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && attestation_0.statement.registryState.revokedRoot.length === 32 && typeof(attestation_0.statement.registryState.registryVersion) === 'bigint' && attestation_0.statement.registryState.registryVersion >= 0n && attestation_0.statement.registryState.registryVersion <= 18446744073709551615n && attestation_0.statement.statusHandleCommitment.buffer instanceof ArrayBuffer && attestation_0.statement.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && attestation_0.statement.statusHandleCommitment.length === 32 && attestation_0.statement.verifierChallengeHash.buffer instanceof ArrayBuffer && attestation_0.statement.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && attestation_0.statement.verifierChallengeHash.length === 32 && typeof(attestation_0.statement.hasExpiration) === 'boolean' && typeof(attestation_0.statement.expiresAt) === 'bigint' && attestation_0.statement.expiresAt >= 0n && attestation_0.statement.expiresAt <= 18446744073709551615n && typeof(attestation_0.proof) === 'object' && typeof(attestation_0.proof.signerVerificationMethodRef) === 'object' && typeof(attestation_0.proof.signerVerificationMethodRef.didContractAddress) === 'object' && attestation_0.proof.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && attestation_0.proof.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && attestation_0.proof.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && attestation_0.proof.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && attestation_0.proof.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && attestation_0.proof.signerVerificationMethodRef.methodId.length === 32 && typeof(attestation_0.proof.createdAt) === 'bigint' && attestation_0.proof.createdAt >= 0n && attestation_0.proof.createdAt <= 18446744073709551615n && attestation_0.proof.challengeHash.buffer instanceof ArrayBuffer && attestation_0.proof.challengeHash.BYTES_PER_ELEMENT === 1 && attestation_0.proof.challengeHash.length === 32 && true && typeof(attestation_0.proof.signature) === 'object' && true && typeof(attestation_0.proof.signature.s) === 'bigint' && attestation_0.proof.signature.s >= 0 && attestation_0.proof.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('assertAuthorityAttestedStatusProofFreshEnough',
                                 'argument 2',
                                 'status-proof-protocol.compact line 522 char 1',
                                 'struct AuthorityAttestedStatusProof<statement: struct AuthorityAttestedStatusStatement<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, statusHandleCommitment: Bytes<32>, verifierChallengeHash: Bytes<32>, hasExpiration: Boolean, expiresAt: Uint<0..18446744073709551616>>, proof: struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>>',
                                 attestation_0)
    }
    if (!(typeof(currentTime_0) === 'bigint' && currentTime_0 >= 0n && currentTime_0 <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertAuthorityAttestedStatusProofFreshEnough',
                                 'argument 3',
                                 'status-proof-protocol.compact line 522 char 1',
                                 'Uint<0..18446744073709551616>',
                                 currentTime_0)
    }
    return _dummyContract._assertAuthorityAttestedStatusProofFreshEnough_0(policy_0,
                                                                           attestation_0,
                                                                           currentTime_0);
  },
  assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipBinding: (...args_0) => {
    if (args_0.length !== 3) {
      throw new __compactRuntime.CompactError(`assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipBinding: expected 3 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const policy_0 = args_0[0];
    const binding_0 = args_0[1];
    const witnessInput_0 = args_0[2];
    if (!(typeof(policy_0) === 'object' && typeof(policy_0.requireStatus) === 'boolean' && typeof(policy_0.acceptedStatusCapability) === 'number' && policy_0.acceptedStatusCapability >= 0 && policy_0.acceptedStatusCapability <= 3 && typeof(policy_0.enforceRegistryId) === 'boolean' && policy_0.acceptedRegistryId.buffer instanceof ArrayBuffer && policy_0.acceptedRegistryId.BYTES_PER_ELEMENT === 1 && policy_0.acceptedRegistryId.length === 32 && typeof(policy_0.enforceAttestationMaxAge) === 'boolean' && typeof(policy_0.maxAttestationAge) === 'bigint' && policy_0.maxAttestationAge >= 0n && policy_0.maxAttestationAge <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipBinding',
                                 'argument 1',
                                 'status-proof-protocol.compact line 547 char 1',
                                 'struct VerifierStatusPolicy<requireStatus: Boolean, acceptedStatusCapability: Enum<StatusCapabilityKind, noStatus, publicStatus, revokedSetNonMembership, authorityAttestedStatus>, enforceRegistryId: Boolean, acceptedRegistryId: Bytes<32>, enforceAttestationMaxAge: Boolean, maxAttestationAge: Uint<0..18446744073709551616>>',
                                 policy_0)
    }
    if (!(typeof(binding_0) === 'object' && typeof(binding_0.statusType) === 'number' && binding_0.statusType >= 0 && binding_0.statusType <= 0 && typeof(binding_0.registryRef) === 'object' && binding_0.registryRef.registryId.buffer instanceof ArrayBuffer && binding_0.registryRef.registryId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.registryId.length === 32 && typeof(binding_0.registryRef.authorityVerificationMethodRef) === 'object' && typeof(binding_0.registryRef.authorityVerificationMethodRef.didContractAddress) === 'object' && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.length === 32 && binding_0.registryRef.authorityVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.methodId.length === 32 && binding_0.statusHandleCommitment.buffer instanceof ArrayBuffer && binding_0.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && binding_0.statusHandleCommitment.length === 32)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipBinding',
                                 'argument 2',
                                 'status-proof-protocol.compact line 547 char 1',
                                 'struct RegistryBoundStatusBinding<statusType: Enum<StatusType, revocationRegistry>, registryRef: struct StatusRegistryRef<registryId: Bytes<32>, authorityVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>, statusHandleCommitment: Bytes<32>>',
                                 binding_0)
    }
    if (!(typeof(witnessInput_0) === 'object' && typeof(witnessInput_0.registryState) === 'object' && witnessInput_0.registryState.registryId.buffer instanceof ArrayBuffer && witnessInput_0.registryState.registryId.BYTES_PER_ELEMENT === 1 && witnessInput_0.registryState.registryId.length === 32 && witnessInput_0.registryState.revokedRoot.buffer instanceof ArrayBuffer && witnessInput_0.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && witnessInput_0.registryState.revokedRoot.length === 32 && typeof(witnessInput_0.registryState.registryVersion) === 'bigint' && witnessInput_0.registryState.registryVersion >= 0n && witnessInput_0.registryState.registryVersion <= 18446744073709551615n && witnessInput_0.statusHandle.buffer instanceof ArrayBuffer && witnessInput_0.statusHandle.BYTES_PER_ELEMENT === 1 && witnessInput_0.statusHandle.length === 32 && witnessInput_0.statusHandleOpening.buffer instanceof ArrayBuffer && witnessInput_0.statusHandleOpening.BYTES_PER_ELEMENT === 1 && witnessInput_0.statusHandleOpening.length === 32)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipBinding',
                                 'argument 3',
                                 'status-proof-protocol.compact line 547 char 1',
                                 'struct RevokedSetNonMembershipWitnessInput<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, statusHandle: Bytes<32>, statusHandleOpening: Bytes<32>>',
                                 witnessInput_0)
    }
    return _dummyContract._assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipBinding_0(policy_0,
                                                                                             binding_0,
                                                                                             witnessInput_0);
  },
  assertVerifierStatusPolicyAcceptsLiveStatusBinding: (...args_0) => {
    if (args_0.length !== 3) {
      throw new __compactRuntime.CompactError(`assertVerifierStatusPolicyAcceptsLiveStatusBinding: expected 3 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const policy_0 = args_0[0];
    const binding_0 = args_0[1];
    const witnessInput_0 = args_0[2];
    if (!(typeof(policy_0) === 'object' && typeof(policy_0.requireStatus) === 'boolean' && typeof(policy_0.acceptedStatusCapability) === 'number' && policy_0.acceptedStatusCapability >= 0 && policy_0.acceptedStatusCapability <= 3 && typeof(policy_0.enforceRegistryId) === 'boolean' && policy_0.acceptedRegistryId.buffer instanceof ArrayBuffer && policy_0.acceptedRegistryId.BYTES_PER_ELEMENT === 1 && policy_0.acceptedRegistryId.length === 32 && typeof(policy_0.enforceAttestationMaxAge) === 'boolean' && typeof(policy_0.maxAttestationAge) === 'bigint' && policy_0.maxAttestationAge >= 0n && policy_0.maxAttestationAge <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsLiveStatusBinding',
                                 'argument 1',
                                 'status-proof-protocol.compact line 581 char 1',
                                 'struct VerifierStatusPolicy<requireStatus: Boolean, acceptedStatusCapability: Enum<StatusCapabilityKind, noStatus, publicStatus, revokedSetNonMembership, authorityAttestedStatus>, enforceRegistryId: Boolean, acceptedRegistryId: Bytes<32>, enforceAttestationMaxAge: Boolean, maxAttestationAge: Uint<0..18446744073709551616>>',
                                 policy_0)
    }
    if (!(typeof(binding_0) === 'object' && typeof(binding_0.statusType) === 'number' && binding_0.statusType >= 0 && binding_0.statusType <= 0 && typeof(binding_0.registryRef) === 'object' && binding_0.registryRef.registryId.buffer instanceof ArrayBuffer && binding_0.registryRef.registryId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.registryId.length === 32 && typeof(binding_0.registryRef.authorityVerificationMethodRef) === 'object' && typeof(binding_0.registryRef.authorityVerificationMethodRef.didContractAddress) === 'object' && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.length === 32 && binding_0.registryRef.authorityVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.methodId.length === 32 && binding_0.statusHandleCommitment.buffer instanceof ArrayBuffer && binding_0.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && binding_0.statusHandleCommitment.length === 32)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsLiveStatusBinding',
                                 'argument 2',
                                 'status-proof-protocol.compact line 581 char 1',
                                 'struct RegistryBoundStatusBinding<statusType: Enum<StatusType, revocationRegistry>, registryRef: struct StatusRegistryRef<registryId: Bytes<32>, authorityVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>, statusHandleCommitment: Bytes<32>>',
                                 binding_0)
    }
    if (!(typeof(witnessInput_0) === 'object' && witnessInput_0.statusHandle.buffer instanceof ArrayBuffer && witnessInput_0.statusHandle.BYTES_PER_ELEMENT === 1 && witnessInput_0.statusHandle.length === 32 && witnessInput_0.statusHandleOpening.buffer instanceof ArrayBuffer && witnessInput_0.statusHandleOpening.BYTES_PER_ELEMENT === 1 && witnessInput_0.statusHandleOpening.length === 32)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsLiveStatusBinding',
                                 'argument 3',
                                 'status-proof-protocol.compact line 581 char 1',
                                 'struct LiveStatusWitnessInput<statusHandle: Bytes<32>, statusHandleOpening: Bytes<32>>',
                                 witnessInput_0)
    }
    return _dummyContract._assertVerifierStatusPolicyAcceptsLiveStatusBinding_0(policy_0,
                                                                                binding_0,
                                                                                witnessInput_0);
  },
  assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipStatusProofProtocol: (...args_0) => {
    if (args_0.length !== 3) {
      throw new __compactRuntime.CompactError(`assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipStatusProofProtocol: expected 3 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const policy_0 = args_0[0];
    const binding_0 = args_0[1];
    const protocol_0 = args_0[2];
    if (!(typeof(policy_0) === 'object' && typeof(policy_0.requireStatus) === 'boolean' && typeof(policy_0.acceptedStatusCapability) === 'number' && policy_0.acceptedStatusCapability >= 0 && policy_0.acceptedStatusCapability <= 3 && typeof(policy_0.enforceRegistryId) === 'boolean' && policy_0.acceptedRegistryId.buffer instanceof ArrayBuffer && policy_0.acceptedRegistryId.BYTES_PER_ELEMENT === 1 && policy_0.acceptedRegistryId.length === 32 && typeof(policy_0.enforceAttestationMaxAge) === 'boolean' && typeof(policy_0.maxAttestationAge) === 'bigint' && policy_0.maxAttestationAge >= 0n && policy_0.maxAttestationAge <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipStatusProofProtocol',
                                 'argument 1',
                                 'status-proof-protocol.compact line 607 char 1',
                                 'struct VerifierStatusPolicy<requireStatus: Boolean, acceptedStatusCapability: Enum<StatusCapabilityKind, noStatus, publicStatus, revokedSetNonMembership, authorityAttestedStatus>, enforceRegistryId: Boolean, acceptedRegistryId: Bytes<32>, enforceAttestationMaxAge: Boolean, maxAttestationAge: Uint<0..18446744073709551616>>',
                                 policy_0)
    }
    if (!(typeof(binding_0) === 'object' && typeof(binding_0.statusType) === 'number' && binding_0.statusType >= 0 && binding_0.statusType <= 0 && typeof(binding_0.registryRef) === 'object' && binding_0.registryRef.registryId.buffer instanceof ArrayBuffer && binding_0.registryRef.registryId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.registryId.length === 32 && typeof(binding_0.registryRef.authorityVerificationMethodRef) === 'object' && typeof(binding_0.registryRef.authorityVerificationMethodRef.didContractAddress) === 'object' && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.length === 32 && binding_0.registryRef.authorityVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.methodId.length === 32 && binding_0.statusHandleCommitment.buffer instanceof ArrayBuffer && binding_0.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && binding_0.statusHandleCommitment.length === 32)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipStatusProofProtocol',
                                 'argument 2',
                                 'status-proof-protocol.compact line 607 char 1',
                                 'struct RegistryBoundStatusBinding<statusType: Enum<StatusType, revocationRegistry>, registryRef: struct StatusRegistryRef<registryId: Bytes<32>, authorityVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>, statusHandleCommitment: Bytes<32>>',
                                 binding_0)
    }
    if (!(typeof(protocol_0) === 'object' && typeof(protocol_0.request) === 'object' && typeof(protocol_0.request.registryState) === 'object' && protocol_0.request.registryState.registryId.buffer instanceof ArrayBuffer && protocol_0.request.registryState.registryId.BYTES_PER_ELEMENT === 1 && protocol_0.request.registryState.registryId.length === 32 && protocol_0.request.registryState.revokedRoot.buffer instanceof ArrayBuffer && protocol_0.request.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && protocol_0.request.registryState.revokedRoot.length === 32 && typeof(protocol_0.request.registryState.registryVersion) === 'bigint' && protocol_0.request.registryState.registryVersion >= 0n && protocol_0.request.registryState.registryVersion <= 18446744073709551615n && protocol_0.request.verifierChallengeHash.buffer instanceof ArrayBuffer && protocol_0.request.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && protocol_0.request.verifierChallengeHash.length === 32 && typeof(protocol_0.witnessInput) === 'object' && typeof(protocol_0.witnessInput.registryState) === 'object' && protocol_0.witnessInput.registryState.registryId.buffer instanceof ArrayBuffer && protocol_0.witnessInput.registryState.registryId.BYTES_PER_ELEMENT === 1 && protocol_0.witnessInput.registryState.registryId.length === 32 && protocol_0.witnessInput.registryState.revokedRoot.buffer instanceof ArrayBuffer && protocol_0.witnessInput.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && protocol_0.witnessInput.registryState.revokedRoot.length === 32 && typeof(protocol_0.witnessInput.registryState.registryVersion) === 'bigint' && protocol_0.witnessInput.registryState.registryVersion >= 0n && protocol_0.witnessInput.registryState.registryVersion <= 18446744073709551615n && protocol_0.witnessInput.statusHandle.buffer instanceof ArrayBuffer && protocol_0.witnessInput.statusHandle.BYTES_PER_ELEMENT === 1 && protocol_0.witnessInput.statusHandle.length === 32 && protocol_0.witnessInput.statusHandleOpening.buffer instanceof ArrayBuffer && protocol_0.witnessInput.statusHandleOpening.BYTES_PER_ELEMENT === 1 && protocol_0.witnessInput.statusHandleOpening.length === 32)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipStatusProofProtocol',
                                 'argument 3',
                                 'status-proof-protocol.compact line 607 char 1',
                                 'struct RevokedSetNonMembershipStatusProofProtocol<request: struct RevokedSetStatusRequest<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, verifierChallengeHash: Bytes<32>>, witnessInput: struct RevokedSetNonMembershipWitnessInput<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, statusHandle: Bytes<32>, statusHandleOpening: Bytes<32>>>',
                                 protocol_0)
    }
    return _dummyContract._assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipStatusProofProtocol_0(policy_0,
                                                                                                         binding_0,
                                                                                                         protocol_0);
  },
  assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusBinding: (...args_0) => {
    if (args_0.length !== 5) {
      throw new __compactRuntime.CompactError(`assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusBinding: expected 5 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const policy_0 = args_0[0];
    const binding_0 = args_0[1];
    const request_0 = args_0[2];
    const attestation_0 = args_0[3];
    const currentTime_0 = args_0[4];
    if (!(typeof(policy_0) === 'object' && typeof(policy_0.requireStatus) === 'boolean' && typeof(policy_0.acceptedStatusCapability) === 'number' && policy_0.acceptedStatusCapability >= 0 && policy_0.acceptedStatusCapability <= 3 && typeof(policy_0.enforceRegistryId) === 'boolean' && policy_0.acceptedRegistryId.buffer instanceof ArrayBuffer && policy_0.acceptedRegistryId.BYTES_PER_ELEMENT === 1 && policy_0.acceptedRegistryId.length === 32 && typeof(policy_0.enforceAttestationMaxAge) === 'boolean' && typeof(policy_0.maxAttestationAge) === 'bigint' && policy_0.maxAttestationAge >= 0n && policy_0.maxAttestationAge <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusBinding',
                                 'argument 1',
                                 'status-proof-protocol.compact line 641 char 1',
                                 'struct VerifierStatusPolicy<requireStatus: Boolean, acceptedStatusCapability: Enum<StatusCapabilityKind, noStatus, publicStatus, revokedSetNonMembership, authorityAttestedStatus>, enforceRegistryId: Boolean, acceptedRegistryId: Bytes<32>, enforceAttestationMaxAge: Boolean, maxAttestationAge: Uint<0..18446744073709551616>>',
                                 policy_0)
    }
    if (!(typeof(binding_0) === 'object' && typeof(binding_0.statusType) === 'number' && binding_0.statusType >= 0 && binding_0.statusType <= 0 && typeof(binding_0.registryRef) === 'object' && binding_0.registryRef.registryId.buffer instanceof ArrayBuffer && binding_0.registryRef.registryId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.registryId.length === 32 && typeof(binding_0.registryRef.authorityVerificationMethodRef) === 'object' && typeof(binding_0.registryRef.authorityVerificationMethodRef.didContractAddress) === 'object' && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.length === 32 && binding_0.registryRef.authorityVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.methodId.length === 32 && binding_0.statusHandleCommitment.buffer instanceof ArrayBuffer && binding_0.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && binding_0.statusHandleCommitment.length === 32)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusBinding',
                                 'argument 2',
                                 'status-proof-protocol.compact line 641 char 1',
                                 'struct RegistryBoundStatusBinding<statusType: Enum<StatusType, revocationRegistry>, registryRef: struct StatusRegistryRef<registryId: Bytes<32>, authorityVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>, statusHandleCommitment: Bytes<32>>',
                                 binding_0)
    }
    if (!(typeof(request_0) === 'object' && typeof(request_0.registryState) === 'object' && request_0.registryState.registryId.buffer instanceof ArrayBuffer && request_0.registryState.registryId.BYTES_PER_ELEMENT === 1 && request_0.registryState.registryId.length === 32 && request_0.registryState.revokedRoot.buffer instanceof ArrayBuffer && request_0.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && request_0.registryState.revokedRoot.length === 32 && typeof(request_0.registryState.registryVersion) === 'bigint' && request_0.registryState.registryVersion >= 0n && request_0.registryState.registryVersion <= 18446744073709551615n && request_0.verifierChallengeHash.buffer instanceof ArrayBuffer && request_0.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && request_0.verifierChallengeHash.length === 32)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusBinding',
                                 'argument 3',
                                 'status-proof-protocol.compact line 641 char 1',
                                 'struct RevokedSetStatusRequest<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, verifierChallengeHash: Bytes<32>>',
                                 request_0)
    }
    if (!(typeof(attestation_0) === 'object' && typeof(attestation_0.statement) === 'object' && typeof(attestation_0.statement.registryState) === 'object' && attestation_0.statement.registryState.registryId.buffer instanceof ArrayBuffer && attestation_0.statement.registryState.registryId.BYTES_PER_ELEMENT === 1 && attestation_0.statement.registryState.registryId.length === 32 && attestation_0.statement.registryState.revokedRoot.buffer instanceof ArrayBuffer && attestation_0.statement.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && attestation_0.statement.registryState.revokedRoot.length === 32 && typeof(attestation_0.statement.registryState.registryVersion) === 'bigint' && attestation_0.statement.registryState.registryVersion >= 0n && attestation_0.statement.registryState.registryVersion <= 18446744073709551615n && attestation_0.statement.statusHandleCommitment.buffer instanceof ArrayBuffer && attestation_0.statement.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && attestation_0.statement.statusHandleCommitment.length === 32 && attestation_0.statement.verifierChallengeHash.buffer instanceof ArrayBuffer && attestation_0.statement.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && attestation_0.statement.verifierChallengeHash.length === 32 && typeof(attestation_0.statement.hasExpiration) === 'boolean' && typeof(attestation_0.statement.expiresAt) === 'bigint' && attestation_0.statement.expiresAt >= 0n && attestation_0.statement.expiresAt <= 18446744073709551615n && typeof(attestation_0.proof) === 'object' && typeof(attestation_0.proof.signerVerificationMethodRef) === 'object' && typeof(attestation_0.proof.signerVerificationMethodRef.didContractAddress) === 'object' && attestation_0.proof.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && attestation_0.proof.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && attestation_0.proof.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && attestation_0.proof.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && attestation_0.proof.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && attestation_0.proof.signerVerificationMethodRef.methodId.length === 32 && typeof(attestation_0.proof.createdAt) === 'bigint' && attestation_0.proof.createdAt >= 0n && attestation_0.proof.createdAt <= 18446744073709551615n && attestation_0.proof.challengeHash.buffer instanceof ArrayBuffer && attestation_0.proof.challengeHash.BYTES_PER_ELEMENT === 1 && attestation_0.proof.challengeHash.length === 32 && true && typeof(attestation_0.proof.signature) === 'object' && true && typeof(attestation_0.proof.signature.s) === 'bigint' && attestation_0.proof.signature.s >= 0 && attestation_0.proof.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusBinding',
                                 'argument 4',
                                 'status-proof-protocol.compact line 641 char 1',
                                 'struct AuthorityAttestedStatusProof<statement: struct AuthorityAttestedStatusStatement<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, statusHandleCommitment: Bytes<32>, verifierChallengeHash: Bytes<32>, hasExpiration: Boolean, expiresAt: Uint<0..18446744073709551616>>, proof: struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>>',
                                 attestation_0)
    }
    if (!(typeof(currentTime_0) === 'bigint' && currentTime_0 >= 0n && currentTime_0 <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusBinding',
                                 'argument 5',
                                 'status-proof-protocol.compact line 641 char 1',
                                 'Uint<0..18446744073709551616>',
                                 currentTime_0)
    }
    return _dummyContract._assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusBinding_0(policy_0,
                                                                                             binding_0,
                                                                                             request_0,
                                                                                             attestation_0,
                                                                                             currentTime_0);
  },
  assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusProofProtocol: (...args_0) => {
    if (args_0.length !== 4) {
      throw new __compactRuntime.CompactError(`assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusProofProtocol: expected 4 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const policy_0 = args_0[0];
    const binding_0 = args_0[1];
    const protocol_0 = args_0[2];
    const currentTime_0 = args_0[3];
    if (!(typeof(policy_0) === 'object' && typeof(policy_0.requireStatus) === 'boolean' && typeof(policy_0.acceptedStatusCapability) === 'number' && policy_0.acceptedStatusCapability >= 0 && policy_0.acceptedStatusCapability <= 3 && typeof(policy_0.enforceRegistryId) === 'boolean' && policy_0.acceptedRegistryId.buffer instanceof ArrayBuffer && policy_0.acceptedRegistryId.BYTES_PER_ELEMENT === 1 && policy_0.acceptedRegistryId.length === 32 && typeof(policy_0.enforceAttestationMaxAge) === 'boolean' && typeof(policy_0.maxAttestationAge) === 'bigint' && policy_0.maxAttestationAge >= 0n && policy_0.maxAttestationAge <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusProofProtocol',
                                 'argument 1',
                                 'status-proof-protocol.compact line 680 char 1',
                                 'struct VerifierStatusPolicy<requireStatus: Boolean, acceptedStatusCapability: Enum<StatusCapabilityKind, noStatus, publicStatus, revokedSetNonMembership, authorityAttestedStatus>, enforceRegistryId: Boolean, acceptedRegistryId: Bytes<32>, enforceAttestationMaxAge: Boolean, maxAttestationAge: Uint<0..18446744073709551616>>',
                                 policy_0)
    }
    if (!(typeof(binding_0) === 'object' && typeof(binding_0.statusType) === 'number' && binding_0.statusType >= 0 && binding_0.statusType <= 0 && typeof(binding_0.registryRef) === 'object' && binding_0.registryRef.registryId.buffer instanceof ArrayBuffer && binding_0.registryRef.registryId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.registryId.length === 32 && typeof(binding_0.registryRef.authorityVerificationMethodRef) === 'object' && typeof(binding_0.registryRef.authorityVerificationMethodRef.didContractAddress) === 'object' && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.didContractAddress.bytes.length === 32 && binding_0.registryRef.authorityVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && binding_0.registryRef.authorityVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && binding_0.registryRef.authorityVerificationMethodRef.methodId.length === 32 && binding_0.statusHandleCommitment.buffer instanceof ArrayBuffer && binding_0.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && binding_0.statusHandleCommitment.length === 32)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusProofProtocol',
                                 'argument 2',
                                 'status-proof-protocol.compact line 680 char 1',
                                 'struct RegistryBoundStatusBinding<statusType: Enum<StatusType, revocationRegistry>, registryRef: struct StatusRegistryRef<registryId: Bytes<32>, authorityVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>>, statusHandleCommitment: Bytes<32>>',
                                 binding_0)
    }
    if (!(typeof(protocol_0) === 'object' && typeof(protocol_0.request) === 'object' && typeof(protocol_0.request.registryState) === 'object' && protocol_0.request.registryState.registryId.buffer instanceof ArrayBuffer && protocol_0.request.registryState.registryId.BYTES_PER_ELEMENT === 1 && protocol_0.request.registryState.registryId.length === 32 && protocol_0.request.registryState.revokedRoot.buffer instanceof ArrayBuffer && protocol_0.request.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && protocol_0.request.registryState.revokedRoot.length === 32 && typeof(protocol_0.request.registryState.registryVersion) === 'bigint' && protocol_0.request.registryState.registryVersion >= 0n && protocol_0.request.registryState.registryVersion <= 18446744073709551615n && protocol_0.request.verifierChallengeHash.buffer instanceof ArrayBuffer && protocol_0.request.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && protocol_0.request.verifierChallengeHash.length === 32 && typeof(protocol_0.attestation) === 'object' && typeof(protocol_0.attestation.statement) === 'object' && typeof(protocol_0.attestation.statement.registryState) === 'object' && protocol_0.attestation.statement.registryState.registryId.buffer instanceof ArrayBuffer && protocol_0.attestation.statement.registryState.registryId.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.statement.registryState.registryId.length === 32 && protocol_0.attestation.statement.registryState.revokedRoot.buffer instanceof ArrayBuffer && protocol_0.attestation.statement.registryState.revokedRoot.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.statement.registryState.revokedRoot.length === 32 && typeof(protocol_0.attestation.statement.registryState.registryVersion) === 'bigint' && protocol_0.attestation.statement.registryState.registryVersion >= 0n && protocol_0.attestation.statement.registryState.registryVersion <= 18446744073709551615n && protocol_0.attestation.statement.statusHandleCommitment.buffer instanceof ArrayBuffer && protocol_0.attestation.statement.statusHandleCommitment.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.statement.statusHandleCommitment.length === 32 && protocol_0.attestation.statement.verifierChallengeHash.buffer instanceof ArrayBuffer && protocol_0.attestation.statement.verifierChallengeHash.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.statement.verifierChallengeHash.length === 32 && typeof(protocol_0.attestation.statement.hasExpiration) === 'boolean' && typeof(protocol_0.attestation.statement.expiresAt) === 'bigint' && protocol_0.attestation.statement.expiresAt >= 0n && protocol_0.attestation.statement.expiresAt <= 18446744073709551615n && typeof(protocol_0.attestation.proof) === 'object' && typeof(protocol_0.attestation.proof.signerVerificationMethodRef) === 'object' && typeof(protocol_0.attestation.proof.signerVerificationMethodRef.didContractAddress) === 'object' && protocol_0.attestation.proof.signerVerificationMethodRef.didContractAddress.bytes.buffer instanceof ArrayBuffer && protocol_0.attestation.proof.signerVerificationMethodRef.didContractAddress.bytes.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.proof.signerVerificationMethodRef.didContractAddress.bytes.length === 32 && protocol_0.attestation.proof.signerVerificationMethodRef.methodId.buffer instanceof ArrayBuffer && protocol_0.attestation.proof.signerVerificationMethodRef.methodId.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.proof.signerVerificationMethodRef.methodId.length === 32 && typeof(protocol_0.attestation.proof.createdAt) === 'bigint' && protocol_0.attestation.proof.createdAt >= 0n && protocol_0.attestation.proof.createdAt <= 18446744073709551615n && protocol_0.attestation.proof.challengeHash.buffer instanceof ArrayBuffer && protocol_0.attestation.proof.challengeHash.BYTES_PER_ELEMENT === 1 && protocol_0.attestation.proof.challengeHash.length === 32 && true && typeof(protocol_0.attestation.proof.signature) === 'object' && true && typeof(protocol_0.attestation.proof.signature.s) === 'bigint' && protocol_0.attestation.proof.signature.s >= 0 && protocol_0.attestation.proof.signature.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusProofProtocol',
                                 'argument 3',
                                 'status-proof-protocol.compact line 680 char 1',
                                 'struct AuthorityAttestedStatusProofProtocol<request: struct RevokedSetStatusRequest<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, verifierChallengeHash: Bytes<32>>, attestation: struct AuthorityAttestedStatusProof<statement: struct AuthorityAttestedStatusStatement<registryState: struct RevocationRegistryState<registryId: Bytes<32>, revokedRoot: Bytes<32>, registryVersion: Uint<0..18446744073709551616>>, statusHandleCommitment: Bytes<32>, verifierChallengeHash: Bytes<32>, hasExpiration: Boolean, expiresAt: Uint<0..18446744073709551616>>, proof: struct Proof<signerVerificationMethodRef: struct VerificationMethodRef<didContractAddress: struct ContractAddress<bytes: Bytes<32>>, methodId: Bytes<32>>, createdAt: Uint<0..18446744073709551616>, challengeHash: Bytes<32>, publicKey: Opaque<"JubjubPoint">, signature: struct Signature<r: Opaque<"JubjubPoint">, s: Field>>>>',
                                 protocol_0)
    }
    if (!(typeof(currentTime_0) === 'bigint' && currentTime_0 >= 0n && currentTime_0 <= 18446744073709551615n)) {
      __compactRuntime.typeError('assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusProofProtocol',
                                 'argument 4',
                                 'status-proof-protocol.compact line 680 char 1',
                                 'Uint<0..18446744073709551616>',
                                 currentTime_0)
    }
    return _dummyContract._assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusProofProtocol_0(policy_0,
                                                                                                   binding_0,
                                                                                                   protocol_0,
                                                                                                   currentTime_0);
  }
};
export const contractReferenceLocations =
  { tag: 'publicLedgerArray', indices: { } };
