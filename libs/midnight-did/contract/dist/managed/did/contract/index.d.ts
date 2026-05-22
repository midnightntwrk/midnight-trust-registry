import type * as __compactRuntime from '@midnight-ntwrk/compact-runtime';

export enum VerificationMethodType { Undefined = 0, JsonWebKey = 1 }

export enum VerificationMethodRelation { Undefined = 0,
                                         Authentication = 1,
                                         AssertionMethod = 2,
                                         KeyAgreement = 3,
                                         CapabilityInvocation = 4,
                                         CapabilityDelegation = 5
}

export enum KeyType { EC = 0, RSA = 1, oct = 2, OKP = 3 }

export enum CurveType { Ed25519 = 0, Jubjub = 1, P256 = 2 }

export type PublicKeyJwk = { kty: KeyType; crv: CurveType; x: bigint; y: bigint
                           };

export type VerificationMethod = { id: string;
                                   typ: VerificationMethodType;
                                   publicKeyJwk: PublicKeyJwk
                                 };

export type Service = { id: string; typ: string; serviceEndpoint: string };

export type JubjubSignature = { r: __compactRuntime.JubjubPoint; s: bigint };

export type Witnesses<PS> = {
  getSchnorrReduction(context: __compactRuntime.WitnessContext<Ledger, PS>,
                      challengeHash_0: bigint): [PS, [bigint, bigint]];
  localSecretKey(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, Uint8Array];
  currentTimestamp(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, bigint];
}

export type ImpureCircuits<PS> = {
  verifyJubjubDigestSignature(context: __compactRuntime.CircuitContext<PS>,
                              pk_0: __compactRuntime.JubjubPoint,
                              signature_0: JubjubSignature,
                              digest_0: bigint[]): __compactRuntime.CircuitResults<PS, []>;
  addAlsoKnownAs(context: __compactRuntime.CircuitContext<PS>, value_0: string): __compactRuntime.CircuitResults<PS, []>;
  removeAlsoKnownAs(context: __compactRuntime.CircuitContext<PS>,
                    value_0: string): __compactRuntime.CircuitResults<PS, []>;
  addVerificationMethod(context: __compactRuntime.CircuitContext<PS>,
                        verificationMethod_0: VerificationMethod): __compactRuntime.CircuitResults<PS, []>;
  updateVerificationMethod(context: __compactRuntime.CircuitContext<PS>,
                           verificationMethod_0: VerificationMethod): __compactRuntime.CircuitResults<PS, []>;
  removeVerificationMethod(context: __compactRuntime.CircuitContext<PS>,
                           id_0: string): __compactRuntime.CircuitResults<PS, []>;
  addVerificationMethodRelation(context: __compactRuntime.CircuitContext<PS>,
                                relation_0: VerificationMethodRelation,
                                methodId_0: string): __compactRuntime.CircuitResults<PS, []>;
  removeVerificationMethodRelation(context: __compactRuntime.CircuitContext<PS>,
                                   relation_0: VerificationMethodRelation,
                                   methodId_0: string): __compactRuntime.CircuitResults<PS, []>;
  addService(context: __compactRuntime.CircuitContext<PS>, service_0: Service): __compactRuntime.CircuitResults<PS, []>;
  updateService(context: __compactRuntime.CircuitContext<PS>, service_0: Service): __compactRuntime.CircuitResults<PS, []>;
  removeService(context: __compactRuntime.CircuitContext<PS>, id_0: string): __compactRuntime.CircuitResults<PS, []>;
  deactivate(context: __compactRuntime.CircuitContext<PS>): __compactRuntime.CircuitResults<PS, []>;
}

export type ProvableCircuits<PS> = {
  addAlsoKnownAs(context: __compactRuntime.CircuitContext<PS>, value_0: string): __compactRuntime.CircuitResults<PS, []>;
  removeAlsoKnownAs(context: __compactRuntime.CircuitContext<PS>,
                    value_0: string): __compactRuntime.CircuitResults<PS, []>;
  addVerificationMethod(context: __compactRuntime.CircuitContext<PS>,
                        verificationMethod_0: VerificationMethod): __compactRuntime.CircuitResults<PS, []>;
  updateVerificationMethod(context: __compactRuntime.CircuitContext<PS>,
                           verificationMethod_0: VerificationMethod): __compactRuntime.CircuitResults<PS, []>;
  removeVerificationMethod(context: __compactRuntime.CircuitContext<PS>,
                           id_0: string): __compactRuntime.CircuitResults<PS, []>;
  addVerificationMethodRelation(context: __compactRuntime.CircuitContext<PS>,
                                relation_0: VerificationMethodRelation,
                                methodId_0: string): __compactRuntime.CircuitResults<PS, []>;
  removeVerificationMethodRelation(context: __compactRuntime.CircuitContext<PS>,
                                   relation_0: VerificationMethodRelation,
                                   methodId_0: string): __compactRuntime.CircuitResults<PS, []>;
  addService(context: __compactRuntime.CircuitContext<PS>, service_0: Service): __compactRuntime.CircuitResults<PS, []>;
  updateService(context: __compactRuntime.CircuitContext<PS>, service_0: Service): __compactRuntime.CircuitResults<PS, []>;
  removeService(context: __compactRuntime.CircuitContext<PS>, id_0: string): __compactRuntime.CircuitResults<PS, []>;
  deactivate(context: __compactRuntime.CircuitContext<PS>): __compactRuntime.CircuitResults<PS, []>;
}

export type PureCircuits = {
  jubjubSignatureDigestChallenge(ann_x_0: bigint,
                                 ann_y_0: bigint,
                                 pk_x_0: bigint,
                                 pk_y_0: bigint,
                                 digest_0: bigint[]): bigint;
  publicKey(sk_0: Uint8Array): Uint8Array;
  verifyJubjubSignature(pk_0: __compactRuntime.JubjubPoint,
                        signature_0: JubjubSignature,
                        challenge_0: bigint): boolean;
}

export type Circuits<PS> = {
  jubjubSignatureDigestChallenge(context: __compactRuntime.CircuitContext<PS>,
                                 ann_x_0: bigint,
                                 ann_y_0: bigint,
                                 pk_x_0: bigint,
                                 pk_y_0: bigint,
                                 digest_0: bigint[]): __compactRuntime.CircuitResults<PS, bigint>;
  publicKey(context: __compactRuntime.CircuitContext<PS>, sk_0: Uint8Array): __compactRuntime.CircuitResults<PS, Uint8Array>;
  verifyJubjubSignature(context: __compactRuntime.CircuitContext<PS>,
                        pk_0: __compactRuntime.JubjubPoint,
                        signature_0: JubjubSignature,
                        challenge_0: bigint): __compactRuntime.CircuitResults<PS, boolean>;
  verifyJubjubDigestSignature(context: __compactRuntime.CircuitContext<PS>,
                              pk_0: __compactRuntime.JubjubPoint,
                              signature_0: JubjubSignature,
                              digest_0: bigint[]): __compactRuntime.CircuitResults<PS, []>;
  addAlsoKnownAs(context: __compactRuntime.CircuitContext<PS>, value_0: string): __compactRuntime.CircuitResults<PS, []>;
  removeAlsoKnownAs(context: __compactRuntime.CircuitContext<PS>,
                    value_0: string): __compactRuntime.CircuitResults<PS, []>;
  addVerificationMethod(context: __compactRuntime.CircuitContext<PS>,
                        verificationMethod_0: VerificationMethod): __compactRuntime.CircuitResults<PS, []>;
  updateVerificationMethod(context: __compactRuntime.CircuitContext<PS>,
                           verificationMethod_0: VerificationMethod): __compactRuntime.CircuitResults<PS, []>;
  removeVerificationMethod(context: __compactRuntime.CircuitContext<PS>,
                           id_0: string): __compactRuntime.CircuitResults<PS, []>;
  addVerificationMethodRelation(context: __compactRuntime.CircuitContext<PS>,
                                relation_0: VerificationMethodRelation,
                                methodId_0: string): __compactRuntime.CircuitResults<PS, []>;
  removeVerificationMethodRelation(context: __compactRuntime.CircuitContext<PS>,
                                   relation_0: VerificationMethodRelation,
                                   methodId_0: string): __compactRuntime.CircuitResults<PS, []>;
  addService(context: __compactRuntime.CircuitContext<PS>, service_0: Service): __compactRuntime.CircuitResults<PS, []>;
  updateService(context: __compactRuntime.CircuitContext<PS>, service_0: Service): __compactRuntime.CircuitResults<PS, []>;
  removeService(context: __compactRuntime.CircuitContext<PS>, id_0: string): __compactRuntime.CircuitResults<PS, []>;
  deactivate(context: __compactRuntime.CircuitContext<PS>): __compactRuntime.CircuitResults<PS, []>;
}

export type Ledger = {
  readonly contractVersion: bigint;
  readonly controllerPublicKey: Uint8Array;
  readonly id: { bytes: Uint8Array };
  alsoKnownAs: {
    isEmpty(): boolean;
    size(): bigint;
    member(elem_0: string): boolean;
    [Symbol.iterator](): Iterator<string>
  };
  readonly version: bigint;
  readonly created: bigint;
  readonly updated: bigint;
  readonly deactivated: boolean;
  readonly active: boolean;
  readonly operationCount: bigint;
  verificationMethods: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: string): boolean;
    lookup(key_0: string): VerificationMethod;
    [Symbol.iterator](): Iterator<[string, VerificationMethod]>
  };
  authenticationRelation: {
    isEmpty(): boolean;
    size(): bigint;
    member(elem_0: string): boolean;
    [Symbol.iterator](): Iterator<string>
  };
  assertionMethodRelation: {
    isEmpty(): boolean;
    size(): bigint;
    member(elem_0: string): boolean;
    [Symbol.iterator](): Iterator<string>
  };
  keyAgreementRelation: {
    isEmpty(): boolean;
    size(): bigint;
    member(elem_0: string): boolean;
    [Symbol.iterator](): Iterator<string>
  };
  capabilityInvocationRelation: {
    isEmpty(): boolean;
    size(): bigint;
    member(elem_0: string): boolean;
    [Symbol.iterator](): Iterator<string>
  };
  capabilityDelegationRelation: {
    isEmpty(): boolean;
    size(): bigint;
    member(elem_0: string): boolean;
    [Symbol.iterator](): Iterator<string>
  };
  services: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: string): boolean;
    lookup(key_0: string): Service;
    [Symbol.iterator](): Iterator<[string, Service]>
  };
}

export type ContractReferenceLocations = any;

export declare const contractReferenceLocations : ContractReferenceLocations;

export declare class Contract<PS = any, W extends Witnesses<PS> = Witnesses<PS>> {
  witnesses: W;
  circuits: Circuits<PS>;
  impureCircuits: ImpureCircuits<PS>;
  provableCircuits: ImpureCircuits<PS>;
  provableCircuits: ProvableCircuits<PS>;
  constructor(witnesses: W);
  initialState(context: __compactRuntime.ConstructorContext<PS>): __compactRuntime.ConstructorResult<PS>;
}

export declare function ledger(state: __compactRuntime.StateValue | __compactRuntime.ChargedState): Ledger;
export declare const pureCircuits: PureCircuits;
