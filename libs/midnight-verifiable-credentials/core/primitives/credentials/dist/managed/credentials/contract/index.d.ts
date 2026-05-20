import type * as __compactRuntime from '@midnight-ntwrk/compact-runtime';

export type SchemaRef = { packageId: Uint8Array;
                          schemaId: Uint8Array;
                          majorVersion: bigint;
                          minorVersion: bigint
                        };

export type VerificationMethodRef = { didContractAddress: { bytes: Uint8Array };
                                      methodId: Uint8Array
                                    };

export type NoPublicClaims = {  };

export type NoClaimCommitments = {  };

export type Signature = { r: __compactRuntime.JubjubPoint; s: bigint };

export type ExplicitHolderBinding = { holderVerificationMethodRef: VerificationMethodRef
                                    };

export type JubjubHolderBinding = { holderPublicKey: __compactRuntime.JubjubPoint
                                  };

export type OffchainMidnightHolderBinding = { holderDidStateHash: Uint8Array;
                                              holderMethodId: Uint8Array;
                                              holderPublicKey: __compactRuntime.JubjubPoint
                                            };

export type SecretHolderBinding = { holderSecretCommitment: Uint8Array;
                                    requestChallengeResponse: Uint8Array
                                  };

export type BlindedSecretHolderBinding = { blindedHolderSecretCommitment: Uint8Array;
                                           issuerNonce: Uint8Array;
                                           requestChallengeResponse: Uint8Array
                                         };

export type Proof = { signerVerificationMethodRef: VerificationMethodRef;
                      createdAt: bigint;
                      challengeHash: Uint8Array;
                      publicKey: __compactRuntime.JubjubPoint;
                      signature: Signature
                    };

export enum HolderBindingProfile { explicitDid = 0,
                                   secretHolder = 1,
                                   blindedSecretHolder = 2
}

export type CredentialProtocolFeatures = { supportsSelectiveDisclosure: boolean;
                                           supportsPredicateProofs: boolean;
                                           supportsVerifierScopedPseudonym: boolean;
                                           supportsSameHolderProof: boolean
                                         };

export type ProtocolMessageEnvelope = { version: bigint;
                                        messageId: Uint8Array;
                                        threadId: Uint8Array;
                                        initialMessage: boolean;
                                        respondsToMessageId: Uint8Array;
                                        createdAt: bigint;
                                        hasExpiresAt: boolean;
                                        expiresAt: bigint
                                      };

export type StatusRegistryRef = { registryId: Uint8Array;
                                  authorityVerificationMethodRef: VerificationMethodRef
                                };

export type NoStatusBinding = {  };

export enum StatusType { revocationRegistry = 0 }

export type RegistryBoundStatusBinding = { statusType: StatusType;
                                           registryRef: StatusRegistryRef;
                                           statusHandleCommitment: Uint8Array
                                         };

export type Witnesses<PS> = {
}

export type ImpureCircuits<PS> = {
}

export type ProvableCircuits<PS> = {
}

export type PureCircuits = {
  verifySignature(pk_0: __compactRuntime.JubjubPoint,
                  signature_0: Signature,
                  challenge_0: bigint): boolean;
  issuanceContextTag(): Uint8Array;
  presentationContextTag(): Uint8Array;
  statusAttestationContextTag(): Uint8Array;
  issuanceProofPayloadRoot(bodyRoot_0: Uint8Array, proof_0: Proof): Uint8Array;
  presentationProofPayloadRoot(bodyRoot_0: Uint8Array, proof_0: Proof): Uint8Array;
  issuanceProofChallenge(bodyRoot_0: Uint8Array, proof_0: Proof): bigint;
  presentationProofChallenge(bodyRoot_0: Uint8Array, proof_0: Proof): bigint;
  assertValidIssuanceContextProof(bodyRoot_0: Uint8Array, proof_0: Proof): [];
  assertValidPresentationContextProof(bodyRoot_0: Uint8Array, proof_0: Proof): [];
  statusAttestationProofPayloadRoot(bodyRoot_0: Uint8Array, proof_0: Proof): Uint8Array;
  statusAttestationProofChallenge(bodyRoot_0: Uint8Array, proof_0: Proof): bigint;
  assertValidStatusAttestationContextProof(bodyRoot_0: Uint8Array,
                                           proof_0: Proof): [];
  assertValidExplicitHolderBinding(binding_0: ExplicitHolderBinding): [];
  assertMatchingExplicitHolderBindings(credentialBinding_0: ExplicitHolderBinding,
                                       presentationBinding_0: ExplicitHolderBinding): [];
  assertProofMatchesExplicitHolderBinding(binding_0: ExplicitHolderBinding,
                                          presentationProof_0: Proof): [];
  assertValidJubjubHolderBinding(binding_0: JubjubHolderBinding): [];
  assertMatchingJubjubHolderBindings(credentialBinding_0: JubjubHolderBinding,
                                     presentationBinding_0: JubjubHolderBinding): [];
  assertProofMatchesJubjubHolderBinding(binding_0: JubjubHolderBinding,
                                        presentationProof_0: Proof): [];
  assertValidOffchainMidnightHolderBinding(binding_0: OffchainMidnightHolderBinding): [];
  assertMatchingOffchainMidnightHolderBindings(credentialBinding_0: OffchainMidnightHolderBinding,
                                               presentationBinding_0: OffchainMidnightHolderBinding): [];
  assertProofMatchesOffchainMidnightHolderBinding(binding_0: OffchainMidnightHolderBinding,
                                                  presentationProof_0: Proof): [];
  noSecretHolderChallengeResponse(): Uint8Array;
  secretHolderBindingCommitment(holderSecret_0: Uint8Array,
                                opening_0: Uint8Array): Uint8Array;
  secretHolderBindingChallengeResponse(holderSecret_0: Uint8Array,
                                       verifierChallengeHash_0: Uint8Array): Uint8Array;
  verifierScopedPseudonym(holderSecret_0: Uint8Array,
                          verifierDomainHash_0: Uint8Array): Uint8Array;
  assertVerifierScopedPseudonym(pseudonym_0: Uint8Array,
                                holderSecret_0: Uint8Array,
                                verifierDomainHash_0: Uint8Array): [];
  blindedSecretHolderCommitment(holderSecretCommitment_0: Uint8Array,
                                issuerNonce_0: Uint8Array,
                                blindingFactor_0: Uint8Array): Uint8Array;
  assertValidSecretHolderCredentialBinding(binding_0: SecretHolderBinding): [];
  assertValidSecretHolderPresentationBinding(binding_0: SecretHolderBinding): [];
  assertMatchingSecretHolderBindings(credentialBinding_0: SecretHolderBinding,
                                     presentationBinding_0: SecretHolderBinding): [];
  assertValidBlindedSecretHolderCredentialBinding(binding_0: BlindedSecretHolderBinding): [];
  assertValidBlindedSecretHolderPresentationBinding(binding_0: BlindedSecretHolderBinding): [];
  assertMatchingBlindedSecretHolderBindings(credentialBinding_0: BlindedSecretHolderBinding,
                                            presentationBinding_0: BlindedSecretHolderBinding): [];
  assertSecretHolderBindingWitness(binding_0: SecretHolderBinding,
                                   verifierChallengeHash_0: Uint8Array,
                                   holderSecret_0: Uint8Array,
                                   opening_0: Uint8Array): [];
  assertBlindedSecretHolderBindingWitness(binding_0: BlindedSecretHolderBinding,
                                          verifierChallengeHash_0: Uint8Array,
                                          holderSecret_0: Uint8Array,
                                          opening_0: Uint8Array,
                                          blindingFactor_0: Uint8Array): [];
  noProtocolResponseReference(): Uint8Array;
  assertValidVerificationMethodRef(verificationMethodRef_0: VerificationMethodRef): [];
  assertMatchingSchemaRefs(expected_0: SchemaRef, actual_0: SchemaRef): [];
  assertValidProtocolMessageEnvelope(envelope_0: ProtocolMessageEnvelope): [];
  assertProtocolResponseEnvelope(requestEnvelope_0: ProtocolMessageEnvelope,
                                 responseEnvelope_0: ProtocolMessageEnvelope): [];
  assertValidStatusRegistryRef(registryRef_0: StatusRegistryRef): [];
  assertValidNoStatusBinding(binding_0: NoStatusBinding): [];
  assertValidRegistryBoundStatusBinding(binding_0: RegistryBoundStatusBinding): [];
  registryBoundStatusBindingRoot(binding_0: RegistryBoundStatusBinding): Uint8Array;
}

export type Circuits<PS> = {
  verifySignature(context: __compactRuntime.CircuitContext<PS>,
                  pk_0: __compactRuntime.JubjubPoint,
                  signature_0: Signature,
                  challenge_0: bigint): __compactRuntime.CircuitResults<PS, boolean>;
  issuanceContextTag(context: __compactRuntime.CircuitContext<PS>): __compactRuntime.CircuitResults<PS, Uint8Array>;
  presentationContextTag(context: __compactRuntime.CircuitContext<PS>): __compactRuntime.CircuitResults<PS, Uint8Array>;
  statusAttestationContextTag(context: __compactRuntime.CircuitContext<PS>): __compactRuntime.CircuitResults<PS, Uint8Array>;
  issuanceProofPayloadRoot(context: __compactRuntime.CircuitContext<PS>,
                           bodyRoot_0: Uint8Array,
                           proof_0: Proof): __compactRuntime.CircuitResults<PS, Uint8Array>;
  presentationProofPayloadRoot(context: __compactRuntime.CircuitContext<PS>,
                               bodyRoot_0: Uint8Array,
                               proof_0: Proof): __compactRuntime.CircuitResults<PS, Uint8Array>;
  issuanceProofChallenge(context: __compactRuntime.CircuitContext<PS>,
                         bodyRoot_0: Uint8Array,
                         proof_0: Proof): __compactRuntime.CircuitResults<PS, bigint>;
  presentationProofChallenge(context: __compactRuntime.CircuitContext<PS>,
                             bodyRoot_0: Uint8Array,
                             proof_0: Proof): __compactRuntime.CircuitResults<PS, bigint>;
  assertValidIssuanceContextProof(context: __compactRuntime.CircuitContext<PS>,
                                  bodyRoot_0: Uint8Array,
                                  proof_0: Proof): __compactRuntime.CircuitResults<PS, []>;
  assertValidPresentationContextProof(context: __compactRuntime.CircuitContext<PS>,
                                      bodyRoot_0: Uint8Array,
                                      proof_0: Proof): __compactRuntime.CircuitResults<PS, []>;
  statusAttestationProofPayloadRoot(context: __compactRuntime.CircuitContext<PS>,
                                    bodyRoot_0: Uint8Array,
                                    proof_0: Proof): __compactRuntime.CircuitResults<PS, Uint8Array>;
  statusAttestationProofChallenge(context: __compactRuntime.CircuitContext<PS>,
                                  bodyRoot_0: Uint8Array,
                                  proof_0: Proof): __compactRuntime.CircuitResults<PS, bigint>;
  assertValidStatusAttestationContextProof(context: __compactRuntime.CircuitContext<PS>,
                                           bodyRoot_0: Uint8Array,
                                           proof_0: Proof): __compactRuntime.CircuitResults<PS, []>;
  assertValidExplicitHolderBinding(context: __compactRuntime.CircuitContext<PS>,
                                   binding_0: ExplicitHolderBinding): __compactRuntime.CircuitResults<PS, []>;
  assertMatchingExplicitHolderBindings(context: __compactRuntime.CircuitContext<PS>,
                                       credentialBinding_0: ExplicitHolderBinding,
                                       presentationBinding_0: ExplicitHolderBinding): __compactRuntime.CircuitResults<PS, []>;
  assertProofMatchesExplicitHolderBinding(context: __compactRuntime.CircuitContext<PS>,
                                          binding_0: ExplicitHolderBinding,
                                          presentationProof_0: Proof): __compactRuntime.CircuitResults<PS, []>;
  assertValidJubjubHolderBinding(context: __compactRuntime.CircuitContext<PS>,
                                 binding_0: JubjubHolderBinding): __compactRuntime.CircuitResults<PS, []>;
  assertMatchingJubjubHolderBindings(context: __compactRuntime.CircuitContext<PS>,
                                     credentialBinding_0: JubjubHolderBinding,
                                     presentationBinding_0: JubjubHolderBinding): __compactRuntime.CircuitResults<PS, []>;
  assertProofMatchesJubjubHolderBinding(context: __compactRuntime.CircuitContext<PS>,
                                        binding_0: JubjubHolderBinding,
                                        presentationProof_0: Proof): __compactRuntime.CircuitResults<PS, []>;
  assertValidOffchainMidnightHolderBinding(context: __compactRuntime.CircuitContext<PS>,
                                           binding_0: OffchainMidnightHolderBinding): __compactRuntime.CircuitResults<PS, []>;
  assertMatchingOffchainMidnightHolderBindings(context: __compactRuntime.CircuitContext<PS>,
                                               credentialBinding_0: OffchainMidnightHolderBinding,
                                               presentationBinding_0: OffchainMidnightHolderBinding): __compactRuntime.CircuitResults<PS, []>;
  assertProofMatchesOffchainMidnightHolderBinding(context: __compactRuntime.CircuitContext<PS>,
                                                  binding_0: OffchainMidnightHolderBinding,
                                                  presentationProof_0: Proof): __compactRuntime.CircuitResults<PS, []>;
  noSecretHolderChallengeResponse(context: __compactRuntime.CircuitContext<PS>): __compactRuntime.CircuitResults<PS, Uint8Array>;
  secretHolderBindingCommitment(context: __compactRuntime.CircuitContext<PS>,
                                holderSecret_0: Uint8Array,
                                opening_0: Uint8Array): __compactRuntime.CircuitResults<PS, Uint8Array>;
  secretHolderBindingChallengeResponse(context: __compactRuntime.CircuitContext<PS>,
                                       holderSecret_0: Uint8Array,
                                       verifierChallengeHash_0: Uint8Array): __compactRuntime.CircuitResults<PS, Uint8Array>;
  verifierScopedPseudonym(context: __compactRuntime.CircuitContext<PS>,
                          holderSecret_0: Uint8Array,
                          verifierDomainHash_0: Uint8Array): __compactRuntime.CircuitResults<PS, Uint8Array>;
  assertVerifierScopedPseudonym(context: __compactRuntime.CircuitContext<PS>,
                                pseudonym_0: Uint8Array,
                                holderSecret_0: Uint8Array,
                                verifierDomainHash_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  blindedSecretHolderCommitment(context: __compactRuntime.CircuitContext<PS>,
                                holderSecretCommitment_0: Uint8Array,
                                issuerNonce_0: Uint8Array,
                                blindingFactor_0: Uint8Array): __compactRuntime.CircuitResults<PS, Uint8Array>;
  assertValidSecretHolderCredentialBinding(context: __compactRuntime.CircuitContext<PS>,
                                           binding_0: SecretHolderBinding): __compactRuntime.CircuitResults<PS, []>;
  assertValidSecretHolderPresentationBinding(context: __compactRuntime.CircuitContext<PS>,
                                             binding_0: SecretHolderBinding): __compactRuntime.CircuitResults<PS, []>;
  assertMatchingSecretHolderBindings(context: __compactRuntime.CircuitContext<PS>,
                                     credentialBinding_0: SecretHolderBinding,
                                     presentationBinding_0: SecretHolderBinding): __compactRuntime.CircuitResults<PS, []>;
  assertValidBlindedSecretHolderCredentialBinding(context: __compactRuntime.CircuitContext<PS>,
                                                  binding_0: BlindedSecretHolderBinding): __compactRuntime.CircuitResults<PS, []>;
  assertValidBlindedSecretHolderPresentationBinding(context: __compactRuntime.CircuitContext<PS>,
                                                    binding_0: BlindedSecretHolderBinding): __compactRuntime.CircuitResults<PS, []>;
  assertMatchingBlindedSecretHolderBindings(context: __compactRuntime.CircuitContext<PS>,
                                            credentialBinding_0: BlindedSecretHolderBinding,
                                            presentationBinding_0: BlindedSecretHolderBinding): __compactRuntime.CircuitResults<PS, []>;
  assertSecretHolderBindingWitness(context: __compactRuntime.CircuitContext<PS>,
                                   binding_0: SecretHolderBinding,
                                   verifierChallengeHash_0: Uint8Array,
                                   holderSecret_0: Uint8Array,
                                   opening_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  assertBlindedSecretHolderBindingWitness(context: __compactRuntime.CircuitContext<PS>,
                                          binding_0: BlindedSecretHolderBinding,
                                          verifierChallengeHash_0: Uint8Array,
                                          holderSecret_0: Uint8Array,
                                          opening_0: Uint8Array,
                                          blindingFactor_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  noProtocolResponseReference(context: __compactRuntime.CircuitContext<PS>): __compactRuntime.CircuitResults<PS, Uint8Array>;
  assertValidVerificationMethodRef(context: __compactRuntime.CircuitContext<PS>,
                                   verificationMethodRef_0: VerificationMethodRef): __compactRuntime.CircuitResults<PS, []>;
  assertMatchingSchemaRefs(context: __compactRuntime.CircuitContext<PS>,
                           expected_0: SchemaRef,
                           actual_0: SchemaRef): __compactRuntime.CircuitResults<PS, []>;
  assertValidProtocolMessageEnvelope(context: __compactRuntime.CircuitContext<PS>,
                                     envelope_0: ProtocolMessageEnvelope): __compactRuntime.CircuitResults<PS, []>;
  assertProtocolResponseEnvelope(context: __compactRuntime.CircuitContext<PS>,
                                 requestEnvelope_0: ProtocolMessageEnvelope,
                                 responseEnvelope_0: ProtocolMessageEnvelope): __compactRuntime.CircuitResults<PS, []>;
  assertValidStatusRegistryRef(context: __compactRuntime.CircuitContext<PS>,
                               registryRef_0: StatusRegistryRef): __compactRuntime.CircuitResults<PS, []>;
  assertValidNoStatusBinding(context: __compactRuntime.CircuitContext<PS>,
                             binding_0: NoStatusBinding): __compactRuntime.CircuitResults<PS, []>;
  assertValidRegistryBoundStatusBinding(context: __compactRuntime.CircuitContext<PS>,
                                        binding_0: RegistryBoundStatusBinding): __compactRuntime.CircuitResults<PS, []>;
  registryBoundStatusBindingRoot(context: __compactRuntime.CircuitContext<PS>,
                                 binding_0: RegistryBoundStatusBinding): __compactRuntime.CircuitResults<PS, Uint8Array>;
}

export type Ledger = {
}

export type ContractReferenceLocations = any;

export declare const contractReferenceLocations : ContractReferenceLocations;

export declare class Contract<PS = any, W extends Witnesses<PS> = Witnesses<PS>> {
  witnesses: W;
  circuits: Circuits<PS>;
  impureCircuits: ImpureCircuits<PS>;
  provableCircuits: ProvableCircuits<PS>;
  constructor(witnesses: W);
  initialState(context: __compactRuntime.ConstructorContext<PS>): __compactRuntime.ConstructorResult<PS>;
}

export declare function ledger(state: __compactRuntime.StateValue | __compactRuntime.ChargedState): Ledger;
export declare const pureCircuits: PureCircuits;
