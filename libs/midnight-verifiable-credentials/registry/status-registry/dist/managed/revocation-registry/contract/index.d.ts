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

export enum StatusCapabilityKind { noStatus = 0,
                                   publicStatus = 1,
                                   revokedSetNonMembership = 2,
                                   authorityAttestedStatus = 3
}

export type NoStatusCapability = {  };

export type RevokedSetNonMembershipStatusCapability = { statusType: StatusType;
                                                        registryRef: StatusRegistryRef;
                                                        statusHandleCommitment: Uint8Array
                                                      };

export type AuthorityAttestedStatusCapability = { statusType: StatusType;
                                                  registryRef: StatusRegistryRef;
                                                  statusHandleCommitment: Uint8Array
                                                };

export type VerifierStatusPolicy = { requireStatus: boolean;
                                     acceptedStatusCapability: StatusCapabilityKind;
                                     enforceRegistryId: boolean;
                                     acceptedRegistryId: Uint8Array;
                                     enforceAttestationMaxAge: boolean;
                                     maxAttestationAge: bigint
                                   };

export type RevocationRegistryState = { registryId: Uint8Array;
                                        revokedRoot: Uint8Array;
                                        registryVersion: bigint
                                      };

export type RevokedSetStatusRequest = { registryState: RevocationRegistryState;
                                        verifierChallengeHash: Uint8Array
                                      };

export type RevokedSetNonMembershipWitnessInput = { registryState: RevocationRegistryState;
                                                    statusHandle: Uint8Array;
                                                    statusHandleOpening: Uint8Array
                                                  };

export type LiveStatusWitnessInput = { statusHandle: Uint8Array;
                                       statusHandleOpening: Uint8Array
                                     };

export type RevokedSetNonMembershipStatusProofProtocol = { request: RevokedSetStatusRequest;
                                                           witnessInput: RevokedSetNonMembershipWitnessInput
                                                         };

export type AuthorityAttestedStatusStatement = { registryState: RevocationRegistryState;
                                                 statusHandleCommitment: Uint8Array;
                                                 verifierChallengeHash: Uint8Array;
                                                 hasExpiration: boolean;
                                                 expiresAt: bigint
                                               };

export type AuthorityAttestedStatusProof = { statement: AuthorityAttestedStatusStatement;
                                             proof: Proof
                                           };

export type AuthorityAttestedStatusProofProtocol = { request: RevokedSetStatusRequest;
                                                     attestation: AuthorityAttestedStatusProof
                                                   };

export type Witnesses<PS> = {
}

export type ImpureCircuits<PS> = {
  initializeRegistry(context: __compactRuntime.CircuitContext<PS>,
                     nextRegistryId_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  assertStateUsesThisRegistry(context: __compactRuntime.CircuitContext<PS>,
                              state_0: RevocationRegistryState): __compactRuntime.CircuitResults<PS, []>;
  revokeStatusHandle(context: __compactRuntime.CircuitContext<PS>,
                     statusHandle_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
}

export type ProvableCircuits<PS> = {
  initializeRegistry(context: __compactRuntime.CircuitContext<PS>,
                     nextRegistryId_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  assertStateUsesThisRegistry(context: __compactRuntime.CircuitContext<PS>,
                              state_0: RevocationRegistryState): __compactRuntime.CircuitResults<PS, []>;
  revokeStatusHandle(context: __compactRuntime.CircuitContext<PS>,
                     statusHandle_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
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
  assertValidNoStatusCapability(capability_0: NoStatusCapability): [];
  assertValidRevokedSetNonMembershipStatusCapability(capability_0: RevokedSetNonMembershipStatusCapability): [];
  assertValidAuthorityAttestedStatusCapability(capability_0: AuthorityAttestedStatusCapability): [];
  assertValidVerifierStatusPolicy(policy_0: VerifierStatusPolicy): [];
  assertValidRevocationRegistryState(state_0: RevocationRegistryState): [];
  assertValidRevokedSetStatusRequest(request_0: RevokedSetStatusRequest): [];
  revokedSetStatusHandleCommitment(statusHandle_0: Uint8Array,
                                   opening_0: Uint8Array): Uint8Array;
  revokedSetStatusHandle(credentialClaimRoot_0: Uint8Array,
                         registryId_0: Uint8Array,
                         issuerStatusSalt_0: Uint8Array): Uint8Array;
  assertValidRevokedSetNonMembershipWitnessInput(witnessInput_0: RevokedSetNonMembershipWitnessInput): [];
  assertValidLiveStatusWitnessInput(witnessInput_0: LiveStatusWitnessInput): [];
  assertValidRevokedSetNonMembershipStatusProofProtocol(protocol_0: RevokedSetNonMembershipStatusProofProtocol): [];
  assertRegistryBoundStatusBindingMatchesRevokedSetNonMembershipStatusProofProtocol(binding_0: RegistryBoundStatusBinding,
                                                                                    protocol_0: RevokedSetNonMembershipStatusProofProtocol): [];
  assertRevokedSetNonMembershipWitnessMatchesBinding(binding_0: RegistryBoundStatusBinding,
                                                     witnessInput_0: RevokedSetNonMembershipWitnessInput): [];
  assertLiveStatusWitnessMatchesBinding(binding_0: RegistryBoundStatusBinding,
                                        witnessInput_0: LiveStatusWitnessInput): [];
  authorityAttestedStatusStatementRoot(statement_0: AuthorityAttestedStatusStatement): Uint8Array;
  assertValidAuthorityAttestedStatusStatement(statement_0: AuthorityAttestedStatusStatement): [];
  assertValidAuthorityAttestedStatusProof(attestation_0: AuthorityAttestedStatusProof): [];
  assertValidAuthorityAttestedStatusProofProtocol(protocol_0: AuthorityAttestedStatusProofProtocol): [];
  assertRegistryBoundStatusBindingMatchesAuthorityAttestedStatusProofProtocol(binding_0: RegistryBoundStatusBinding,
                                                                              protocol_0: AuthorityAttestedStatusProofProtocol,
                                                                              currentTime_0: bigint): [];
  assertAuthorityAttestedStatusProofMatchesBinding(binding_0: RegistryBoundStatusBinding,
                                                   attestation_0: AuthorityAttestedStatusProof): [];
  assertAuthorityAttestedStatusProofMatchesRequest(request_0: RevokedSetStatusRequest,
                                                   attestation_0: AuthorityAttestedStatusProof,
                                                   currentTime_0: bigint): [];
  assertAuthorityAttestedStatusProofFreshEnough(policy_0: VerifierStatusPolicy,
                                                attestation_0: AuthorityAttestedStatusProof,
                                                currentTime_0: bigint): [];
  assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipBinding(policy_0: VerifierStatusPolicy,
                                                                  binding_0: RegistryBoundStatusBinding,
                                                                  witnessInput_0: RevokedSetNonMembershipWitnessInput): [];
  assertVerifierStatusPolicyAcceptsLiveStatusBinding(policy_0: VerifierStatusPolicy,
                                                     binding_0: RegistryBoundStatusBinding,
                                                     witnessInput_0: LiveStatusWitnessInput): [];
  assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipStatusProofProtocol(policy_0: VerifierStatusPolicy,
                                                                              binding_0: RegistryBoundStatusBinding,
                                                                              protocol_0: RevokedSetNonMembershipStatusProofProtocol): [];
  assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusBinding(policy_0: VerifierStatusPolicy,
                                                                  binding_0: RegistryBoundStatusBinding,
                                                                  request_0: RevokedSetStatusRequest,
                                                                  attestation_0: AuthorityAttestedStatusProof,
                                                                  currentTime_0: bigint): [];
  assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusProofProtocol(policy_0: VerifierStatusPolicy,
                                                                        binding_0: RegistryBoundStatusBinding,
                                                                        protocol_0: AuthorityAttestedStatusProofProtocol,
                                                                        currentTime_0: bigint): [];
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
  assertValidNoStatusCapability(context: __compactRuntime.CircuitContext<PS>,
                                capability_0: NoStatusCapability): __compactRuntime.CircuitResults<PS, []>;
  assertValidRevokedSetNonMembershipStatusCapability(context: __compactRuntime.CircuitContext<PS>,
                                                     capability_0: RevokedSetNonMembershipStatusCapability): __compactRuntime.CircuitResults<PS, []>;
  assertValidAuthorityAttestedStatusCapability(context: __compactRuntime.CircuitContext<PS>,
                                               capability_0: AuthorityAttestedStatusCapability): __compactRuntime.CircuitResults<PS, []>;
  assertValidVerifierStatusPolicy(context: __compactRuntime.CircuitContext<PS>,
                                  policy_0: VerifierStatusPolicy): __compactRuntime.CircuitResults<PS, []>;
  assertValidRevocationRegistryState(context: __compactRuntime.CircuitContext<PS>,
                                     state_0: RevocationRegistryState): __compactRuntime.CircuitResults<PS, []>;
  assertValidRevokedSetStatusRequest(context: __compactRuntime.CircuitContext<PS>,
                                     request_0: RevokedSetStatusRequest): __compactRuntime.CircuitResults<PS, []>;
  revokedSetStatusHandleCommitment(context: __compactRuntime.CircuitContext<PS>,
                                   statusHandle_0: Uint8Array,
                                   opening_0: Uint8Array): __compactRuntime.CircuitResults<PS, Uint8Array>;
  revokedSetStatusHandle(context: __compactRuntime.CircuitContext<PS>,
                         credentialClaimRoot_0: Uint8Array,
                         registryId_0: Uint8Array,
                         issuerStatusSalt_0: Uint8Array): __compactRuntime.CircuitResults<PS, Uint8Array>;
  assertValidRevokedSetNonMembershipWitnessInput(context: __compactRuntime.CircuitContext<PS>,
                                                 witnessInput_0: RevokedSetNonMembershipWitnessInput): __compactRuntime.CircuitResults<PS, []>;
  assertValidLiveStatusWitnessInput(context: __compactRuntime.CircuitContext<PS>,
                                    witnessInput_0: LiveStatusWitnessInput): __compactRuntime.CircuitResults<PS, []>;
  assertValidRevokedSetNonMembershipStatusProofProtocol(context: __compactRuntime.CircuitContext<PS>,
                                                        protocol_0: RevokedSetNonMembershipStatusProofProtocol): __compactRuntime.CircuitResults<PS, []>;
  assertRegistryBoundStatusBindingMatchesRevokedSetNonMembershipStatusProofProtocol(context: __compactRuntime.CircuitContext<PS>,
                                                                                    binding_0: RegistryBoundStatusBinding,
                                                                                    protocol_0: RevokedSetNonMembershipStatusProofProtocol): __compactRuntime.CircuitResults<PS, []>;
  assertRevokedSetNonMembershipWitnessMatchesBinding(context: __compactRuntime.CircuitContext<PS>,
                                                     binding_0: RegistryBoundStatusBinding,
                                                     witnessInput_0: RevokedSetNonMembershipWitnessInput): __compactRuntime.CircuitResults<PS, []>;
  assertLiveStatusWitnessMatchesBinding(context: __compactRuntime.CircuitContext<PS>,
                                        binding_0: RegistryBoundStatusBinding,
                                        witnessInput_0: LiveStatusWitnessInput): __compactRuntime.CircuitResults<PS, []>;
  authorityAttestedStatusStatementRoot(context: __compactRuntime.CircuitContext<PS>,
                                       statement_0: AuthorityAttestedStatusStatement): __compactRuntime.CircuitResults<PS, Uint8Array>;
  assertValidAuthorityAttestedStatusStatement(context: __compactRuntime.CircuitContext<PS>,
                                              statement_0: AuthorityAttestedStatusStatement): __compactRuntime.CircuitResults<PS, []>;
  assertValidAuthorityAttestedStatusProof(context: __compactRuntime.CircuitContext<PS>,
                                          attestation_0: AuthorityAttestedStatusProof): __compactRuntime.CircuitResults<PS, []>;
  assertValidAuthorityAttestedStatusProofProtocol(context: __compactRuntime.CircuitContext<PS>,
                                                  protocol_0: AuthorityAttestedStatusProofProtocol): __compactRuntime.CircuitResults<PS, []>;
  assertRegistryBoundStatusBindingMatchesAuthorityAttestedStatusProofProtocol(context: __compactRuntime.CircuitContext<PS>,
                                                                              binding_0: RegistryBoundStatusBinding,
                                                                              protocol_0: AuthorityAttestedStatusProofProtocol,
                                                                              currentTime_0: bigint): __compactRuntime.CircuitResults<PS, []>;
  assertAuthorityAttestedStatusProofMatchesBinding(context: __compactRuntime.CircuitContext<PS>,
                                                   binding_0: RegistryBoundStatusBinding,
                                                   attestation_0: AuthorityAttestedStatusProof): __compactRuntime.CircuitResults<PS, []>;
  assertAuthorityAttestedStatusProofMatchesRequest(context: __compactRuntime.CircuitContext<PS>,
                                                   request_0: RevokedSetStatusRequest,
                                                   attestation_0: AuthorityAttestedStatusProof,
                                                   currentTime_0: bigint): __compactRuntime.CircuitResults<PS, []>;
  assertAuthorityAttestedStatusProofFreshEnough(context: __compactRuntime.CircuitContext<PS>,
                                                policy_0: VerifierStatusPolicy,
                                                attestation_0: AuthorityAttestedStatusProof,
                                                currentTime_0: bigint): __compactRuntime.CircuitResults<PS, []>;
  assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipBinding(context: __compactRuntime.CircuitContext<PS>,
                                                                  policy_0: VerifierStatusPolicy,
                                                                  binding_0: RegistryBoundStatusBinding,
                                                                  witnessInput_0: RevokedSetNonMembershipWitnessInput): __compactRuntime.CircuitResults<PS, []>;
  assertVerifierStatusPolicyAcceptsLiveStatusBinding(context: __compactRuntime.CircuitContext<PS>,
                                                     policy_0: VerifierStatusPolicy,
                                                     binding_0: RegistryBoundStatusBinding,
                                                     witnessInput_0: LiveStatusWitnessInput): __compactRuntime.CircuitResults<PS, []>;
  assertVerifierStatusPolicyAcceptsRevokedSetNonMembershipStatusProofProtocol(context: __compactRuntime.CircuitContext<PS>,
                                                                              policy_0: VerifierStatusPolicy,
                                                                              binding_0: RegistryBoundStatusBinding,
                                                                              protocol_0: RevokedSetNonMembershipStatusProofProtocol): __compactRuntime.CircuitResults<PS, []>;
  assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusBinding(context: __compactRuntime.CircuitContext<PS>,
                                                                  policy_0: VerifierStatusPolicy,
                                                                  binding_0: RegistryBoundStatusBinding,
                                                                  request_0: RevokedSetStatusRequest,
                                                                  attestation_0: AuthorityAttestedStatusProof,
                                                                  currentTime_0: bigint): __compactRuntime.CircuitResults<PS, []>;
  assertVerifierStatusPolicyAcceptsAuthorityAttestedStatusProofProtocol(context: __compactRuntime.CircuitContext<PS>,
                                                                        policy_0: VerifierStatusPolicy,
                                                                        binding_0: RegistryBoundStatusBinding,
                                                                        protocol_0: AuthorityAttestedStatusProofProtocol,
                                                                        currentTime_0: bigint): __compactRuntime.CircuitResults<PS, []>;
  initializeRegistry(context: __compactRuntime.CircuitContext<PS>,
                     nextRegistryId_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  assertStateUsesThisRegistry(context: __compactRuntime.CircuitContext<PS>,
                              state_0: RevocationRegistryState): __compactRuntime.CircuitResults<PS, []>;
  revokeStatusHandle(context: __compactRuntime.CircuitContext<PS>,
                     statusHandle_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
}

export type Ledger = {
  readonly registryId: Uint8Array;
  readonly initialized: boolean;
  readonly version: bigint;
  readonly revokedStatusHandleCount: bigint;
  revokedStatusHandles: {
    isFull(): boolean;
    checkRoot(rt_0: { field: bigint }): boolean;
    root(): __compactRuntime.MerkleTreeDigest;
    firstFree(): bigint;
    pathForLeaf(index_0: bigint, leaf_0: Uint8Array): __compactRuntime.MerkleTreePath<Uint8Array>;
    findPathForLeaf(leaf_0: Uint8Array): __compactRuntime.MerkleTreePath<Uint8Array> | undefined
  };
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
