import * as __compactRuntime from '@midnight-ntwrk/compact-runtime';
__compactRuntime.checkRuntimeVersion('0.15.0');

export var VerificationMethodType;
(function (VerificationMethodType) {
  VerificationMethodType[VerificationMethodType['Undefined'] = 0] = 'Undefined';
  VerificationMethodType[VerificationMethodType['JsonWebKey'] = 1] = 'JsonWebKey';
})(VerificationMethodType || (VerificationMethodType = {}));

export var VerificationMethodRelation;
(function (VerificationMethodRelation) {
  VerificationMethodRelation[VerificationMethodRelation['Undefined'] = 0] = 'Undefined';
  VerificationMethodRelation[VerificationMethodRelation['Authentication'] = 1] = 'Authentication';
  VerificationMethodRelation[VerificationMethodRelation['AssertionMethod'] = 2] = 'AssertionMethod';
  VerificationMethodRelation[VerificationMethodRelation['KeyAgreement'] = 3] = 'KeyAgreement';
  VerificationMethodRelation[VerificationMethodRelation['CapabilityInvocation'] = 4] = 'CapabilityInvocation';
  VerificationMethodRelation[VerificationMethodRelation['CapabilityDelegation'] = 5] = 'CapabilityDelegation';
})(VerificationMethodRelation || (VerificationMethodRelation = {}));

export var KeyType;
(function (KeyType) {
  KeyType[KeyType['EC'] = 0] = 'EC';
  KeyType[KeyType['RSA'] = 1] = 'RSA';
  KeyType[KeyType['oct'] = 2] = 'oct';
  KeyType[KeyType['OKP'] = 3] = 'OKP';
})(KeyType || (KeyType = {}));

export var CurveType;
(function (CurveType) {
  CurveType[CurveType['Ed25519'] = 0] = 'Ed25519';
  CurveType[CurveType['Jubjub'] = 1] = 'Jubjub';
  CurveType[CurveType['P256'] = 2] = 'P256';
})(CurveType || (CurveType = {}));

const _descriptor_0 = new __compactRuntime.CompactTypeBytes(32);

const _descriptor_1 = __compactRuntime.CompactTypeBoolean;

const _descriptor_2 = new __compactRuntime.CompactTypeUnsignedInteger(65535n, 2);

const _descriptor_3 = __compactRuntime.CompactTypeOpaqueString;

class _Service_0 {
  alignment() {
    return _descriptor_3.alignment().concat(_descriptor_3.alignment().concat(_descriptor_3.alignment()));
  }
  fromValue(value_0) {
    return {
      id: _descriptor_3.fromValue(value_0),
      typ: _descriptor_3.fromValue(value_0),
      serviceEndpoint: _descriptor_3.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_3.toValue(value_0.id).concat(_descriptor_3.toValue(value_0.typ).concat(_descriptor_3.toValue(value_0.serviceEndpoint)));
  }
}

const _descriptor_4 = new _Service_0();

const _descriptor_5 = new __compactRuntime.CompactTypeUnsignedInteger(18446744073709551615n, 8);

const _descriptor_6 = new __compactRuntime.CompactTypeEnum(1, 1);

const _descriptor_7 = new __compactRuntime.CompactTypeEnum(3, 1);

const _descriptor_8 = new __compactRuntime.CompactTypeEnum(2, 1);

const _descriptor_9 = __compactRuntime.CompactTypeField;

class _PublicKeyJwk_0 {
  alignment() {
    return _descriptor_7.alignment().concat(_descriptor_8.alignment().concat(_descriptor_9.alignment().concat(_descriptor_9.alignment())));
  }
  fromValue(value_0) {
    return {
      kty: _descriptor_7.fromValue(value_0),
      crv: _descriptor_8.fromValue(value_0),
      x: _descriptor_9.fromValue(value_0),
      y: _descriptor_9.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_7.toValue(value_0.kty).concat(_descriptor_8.toValue(value_0.crv).concat(_descriptor_9.toValue(value_0.x).concat(_descriptor_9.toValue(value_0.y))));
  }
}

const _descriptor_10 = new _PublicKeyJwk_0();

class _VerificationMethod_0 {
  alignment() {
    return _descriptor_3.alignment().concat(_descriptor_6.alignment().concat(_descriptor_10.alignment()));
  }
  fromValue(value_0) {
    return {
      id: _descriptor_3.fromValue(value_0),
      typ: _descriptor_6.fromValue(value_0),
      publicKeyJwk: _descriptor_10.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_3.toValue(value_0.id).concat(_descriptor_6.toValue(value_0.typ).concat(_descriptor_10.toValue(value_0.publicKeyJwk)));
  }
}

const _descriptor_11 = new _VerificationMethod_0();

const _descriptor_12 = new __compactRuntime.CompactTypeEnum(5, 1);

const _descriptor_13 = __compactRuntime.CompactTypeJubjubPoint;

class _JubjubSignature_0 {
  alignment() {
    return _descriptor_13.alignment().concat(_descriptor_9.alignment());
  }
  fromValue(value_0) {
    return {
      r: _descriptor_13.fromValue(value_0),
      s: _descriptor_9.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_13.toValue(value_0.r).concat(_descriptor_9.toValue(value_0.s));
  }
}

const _descriptor_14 = new _JubjubSignature_0();

const _descriptor_15 = new __compactRuntime.CompactTypeVector(4, _descriptor_9);

class _SchnorrSignature_0 {
  alignment() {
    return _descriptor_13.alignment().concat(_descriptor_9.alignment());
  }
  fromValue(value_0) {
    return {
      announcement: _descriptor_13.fromValue(value_0),
      response: _descriptor_9.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_13.toValue(value_0.announcement).concat(_descriptor_9.toValue(value_0.response));
  }
}

const _descriptor_16 = new _SchnorrSignature_0();

const _descriptor_17 = new __compactRuntime.CompactTypeUnsignedInteger(452312848583266388373324160190187140051835877600158453279131187530910662655n, 31);

class _tuple_0 {
  alignment() {
    return _descriptor_9.alignment().concat(_descriptor_17.alignment());
  }
  fromValue(value_0) {
    return [
      _descriptor_9.fromValue(value_0),
      _descriptor_17.fromValue(value_0)
    ]
  }
  toValue(value_0) {
    return _descriptor_9.toValue(value_0[0]).concat(_descriptor_17.toValue(value_0[1]));
  }
}

const _descriptor_18 = new _tuple_0();

class _SchnorrHashInput_0 {
  alignment() {
    return _descriptor_9.alignment().concat(_descriptor_9.alignment().concat(_descriptor_9.alignment().concat(_descriptor_9.alignment().concat(_descriptor_15.alignment()))));
  }
  fromValue(value_0) {
    return {
      ann_x: _descriptor_9.fromValue(value_0),
      ann_y: _descriptor_9.fromValue(value_0),
      pk_x: _descriptor_9.fromValue(value_0),
      pk_y: _descriptor_9.fromValue(value_0),
      msg: _descriptor_15.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_9.toValue(value_0.ann_x).concat(_descriptor_9.toValue(value_0.ann_y).concat(_descriptor_9.toValue(value_0.pk_x).concat(_descriptor_9.toValue(value_0.pk_y).concat(_descriptor_15.toValue(value_0.msg)))));
  }
}

const _descriptor_19 = new _SchnorrHashInput_0();

const _descriptor_20 = new __compactRuntime.CompactTypeVector(2, _descriptor_0);

class _Either_0 {
  alignment() {
    return _descriptor_1.alignment().concat(_descriptor_0.alignment().concat(_descriptor_0.alignment()));
  }
  fromValue(value_0) {
    return {
      is_left: _descriptor_1.fromValue(value_0),
      left: _descriptor_0.fromValue(value_0),
      right: _descriptor_0.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_1.toValue(value_0.is_left).concat(_descriptor_0.toValue(value_0.left).concat(_descriptor_0.toValue(value_0.right)));
  }
}

const _descriptor_21 = new _Either_0();

const _descriptor_22 = new __compactRuntime.CompactTypeUnsignedInteger(340282366920938463463374607431768211455n, 16);

class _ContractAddress_0 {
  alignment() {
    return _descriptor_0.alignment();
  }
  fromValue(value_0) {
    return {
      bytes: _descriptor_0.fromValue(value_0)
    }
  }
  toValue(value_0) {
    return _descriptor_0.toValue(value_0.bytes);
  }
}

const _descriptor_23 = new _ContractAddress_0();

const _descriptor_24 = new __compactRuntime.CompactTypeUnsignedInteger(4294967295n, 4);

const _descriptor_25 = new __compactRuntime.CompactTypeUnsignedInteger(255n, 1);

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
    if (typeof(witnesses_0.getSchnorrReduction) !== 'function') {
      throw new __compactRuntime.CompactError('first (witnesses) argument to Contract constructor does not contain a function-valued field named getSchnorrReduction');
    }
    if (typeof(witnesses_0.localSecretKey) !== 'function') {
      throw new __compactRuntime.CompactError('first (witnesses) argument to Contract constructor does not contain a function-valued field named localSecretKey');
    }
    if (typeof(witnesses_0.currentTimestamp) !== 'function') {
      throw new __compactRuntime.CompactError('first (witnesses) argument to Contract constructor does not contain a function-valued field named currentTimestamp');
    }
    this.witnesses = witnesses_0;
    this.circuits = {
      jubjubSignatureDigestChallenge(context, ...args_1) {
        return { result: pureCircuits.jubjubSignatureDigestChallenge(...args_1), context };
      },
      publicKey(context, ...args_1) {
        return { result: pureCircuits.publicKey(...args_1), context };
      },
      verifyJubjubSignature(context, ...args_1) {
        return { result: pureCircuits.verifyJubjubSignature(...args_1), context };
      },
      verifyJubjubDigestSignature: (...args_1) => {
        if (args_1.length !== 4) {
          throw new __compactRuntime.CompactError(`verifyJubjubDigestSignature: expected 4 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const pk_0 = args_1[1];
        const signature_0 = args_1[2];
        const digest_0 = args_1[3];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.currentQueryContext != undefined)) {
          __compactRuntime.typeError('verifyJubjubDigestSignature',
                                     'argument 1 (as invoked from Typescript)',
                                     'did.compact line 133 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(signature_0) === 'object' && true && typeof(signature_0.s) === 'bigint' && signature_0.s >= 0 && signature_0.s <= __compactRuntime.MAX_FIELD)) {
          __compactRuntime.typeError('verifyJubjubDigestSignature',
                                     'argument 2 (argument 3 as invoked from Typescript)',
                                     'did.compact line 133 char 1',
                                     'struct JubjubSignature<r: Opaque<"JubjubPoint">, s: Field>',
                                     signature_0)
        }
        if (!(Array.isArray(digest_0) && digest_0.length === 4 && digest_0.every((t) => typeof(t) === 'bigint' && t >= 0 && t <= __compactRuntime.MAX_FIELD))) {
          __compactRuntime.typeError('verifyJubjubDigestSignature',
                                     'argument 3 (argument 4 as invoked from Typescript)',
                                     'did.compact line 133 char 1',
                                     'Vector<4, Field>',
                                     digest_0)
        }
        const context = { ...contextOrig_0, gasCost: __compactRuntime.emptyRunningCost() };
        const partialProofData = {
          input: {
            value: _descriptor_13.toValue(pk_0).concat(_descriptor_14.toValue(signature_0).concat(_descriptor_15.toValue(digest_0))),
            alignment: _descriptor_13.alignment().concat(_descriptor_14.alignment().concat(_descriptor_15.alignment()))
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._verifyJubjubDigestSignature_0(context,
                                                             partialProofData,
                                                             pk_0,
                                                             signature_0,
                                                             digest_0);
        partialProofData.output = { value: [], alignment: [] };
        return { result: result_0, context: context, proofData: partialProofData, gasCost: context.gasCost };
      },
      addAlsoKnownAs: (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`addAlsoKnownAs: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const value_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.currentQueryContext != undefined)) {
          __compactRuntime.typeError('addAlsoKnownAs',
                                     'argument 1 (as invoked from Typescript)',
                                     'did.compact line 146 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        const context = { ...contextOrig_0, gasCost: __compactRuntime.emptyRunningCost() };
        const partialProofData = {
          input: {
            value: _descriptor_3.toValue(value_0),
            alignment: _descriptor_3.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._addAlsoKnownAs_0(context,
                                                partialProofData,
                                                value_0);
        partialProofData.output = { value: [], alignment: [] };
        return { result: result_0, context: context, proofData: partialProofData, gasCost: context.gasCost };
      },
      removeAlsoKnownAs: (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`removeAlsoKnownAs: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const value_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.currentQueryContext != undefined)) {
          __compactRuntime.typeError('removeAlsoKnownAs',
                                     'argument 1 (as invoked from Typescript)',
                                     'did.compact line 159 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        const context = { ...contextOrig_0, gasCost: __compactRuntime.emptyRunningCost() };
        const partialProofData = {
          input: {
            value: _descriptor_3.toValue(value_0),
            alignment: _descriptor_3.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._removeAlsoKnownAs_0(context,
                                                   partialProofData,
                                                   value_0);
        partialProofData.output = { value: [], alignment: [] };
        return { result: result_0, context: context, proofData: partialProofData, gasCost: context.gasCost };
      },
      addVerificationMethod: (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`addVerificationMethod: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const verificationMethod_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.currentQueryContext != undefined)) {
          __compactRuntime.typeError('addVerificationMethod',
                                     'argument 1 (as invoked from Typescript)',
                                     'did.compact line 171 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(verificationMethod_0) === 'object' && true && typeof(verificationMethod_0.typ) === 'number' && verificationMethod_0.typ >= 0 && verificationMethod_0.typ <= 1 && typeof(verificationMethod_0.publicKeyJwk) === 'object' && typeof(verificationMethod_0.publicKeyJwk.kty) === 'number' && verificationMethod_0.publicKeyJwk.kty >= 0 && verificationMethod_0.publicKeyJwk.kty <= 3 && typeof(verificationMethod_0.publicKeyJwk.crv) === 'number' && verificationMethod_0.publicKeyJwk.crv >= 0 && verificationMethod_0.publicKeyJwk.crv <= 2 && typeof(verificationMethod_0.publicKeyJwk.x) === 'bigint' && verificationMethod_0.publicKeyJwk.x >= 0 && verificationMethod_0.publicKeyJwk.x <= __compactRuntime.MAX_FIELD && typeof(verificationMethod_0.publicKeyJwk.y) === 'bigint' && verificationMethod_0.publicKeyJwk.y >= 0 && verificationMethod_0.publicKeyJwk.y <= __compactRuntime.MAX_FIELD)) {
          __compactRuntime.typeError('addVerificationMethod',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'did.compact line 171 char 1',
                                     'struct VerificationMethod<id: Opaque<"string">, typ: Enum<VerificationMethodType, Undefined, JsonWebKey>, publicKeyJwk: struct PublicKeyJwk<kty: Enum<KeyType, EC, RSA, oct, OKP>, crv: Enum<CurveType, Ed25519, Jubjub, P256>, x: Field, y: Field>>',
                                     verificationMethod_0)
        }
        const context = { ...contextOrig_0, gasCost: __compactRuntime.emptyRunningCost() };
        const partialProofData = {
          input: {
            value: _descriptor_11.toValue(verificationMethod_0),
            alignment: _descriptor_11.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._addVerificationMethod_0(context,
                                                       partialProofData,
                                                       verificationMethod_0);
        partialProofData.output = { value: [], alignment: [] };
        return { result: result_0, context: context, proofData: partialProofData, gasCost: context.gasCost };
      },
      updateVerificationMethod: (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`updateVerificationMethod: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const verificationMethod_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.currentQueryContext != undefined)) {
          __compactRuntime.typeError('updateVerificationMethod',
                                     'argument 1 (as invoked from Typescript)',
                                     'did.compact line 193 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(verificationMethod_0) === 'object' && true && typeof(verificationMethod_0.typ) === 'number' && verificationMethod_0.typ >= 0 && verificationMethod_0.typ <= 1 && typeof(verificationMethod_0.publicKeyJwk) === 'object' && typeof(verificationMethod_0.publicKeyJwk.kty) === 'number' && verificationMethod_0.publicKeyJwk.kty >= 0 && verificationMethod_0.publicKeyJwk.kty <= 3 && typeof(verificationMethod_0.publicKeyJwk.crv) === 'number' && verificationMethod_0.publicKeyJwk.crv >= 0 && verificationMethod_0.publicKeyJwk.crv <= 2 && typeof(verificationMethod_0.publicKeyJwk.x) === 'bigint' && verificationMethod_0.publicKeyJwk.x >= 0 && verificationMethod_0.publicKeyJwk.x <= __compactRuntime.MAX_FIELD && typeof(verificationMethod_0.publicKeyJwk.y) === 'bigint' && verificationMethod_0.publicKeyJwk.y >= 0 && verificationMethod_0.publicKeyJwk.y <= __compactRuntime.MAX_FIELD)) {
          __compactRuntime.typeError('updateVerificationMethod',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'did.compact line 193 char 1',
                                     'struct VerificationMethod<id: Opaque<"string">, typ: Enum<VerificationMethodType, Undefined, JsonWebKey>, publicKeyJwk: struct PublicKeyJwk<kty: Enum<KeyType, EC, RSA, oct, OKP>, crv: Enum<CurveType, Ed25519, Jubjub, P256>, x: Field, y: Field>>',
                                     verificationMethod_0)
        }
        const context = { ...contextOrig_0, gasCost: __compactRuntime.emptyRunningCost() };
        const partialProofData = {
          input: {
            value: _descriptor_11.toValue(verificationMethod_0),
            alignment: _descriptor_11.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._updateVerificationMethod_0(context,
                                                          partialProofData,
                                                          verificationMethod_0);
        partialProofData.output = { value: [], alignment: [] };
        return { result: result_0, context: context, proofData: partialProofData, gasCost: context.gasCost };
      },
      removeVerificationMethod: (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`removeVerificationMethod: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const id_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.currentQueryContext != undefined)) {
          __compactRuntime.typeError('removeVerificationMethod',
                                     'argument 1 (as invoked from Typescript)',
                                     'did.compact line 216 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        const context = { ...contextOrig_0, gasCost: __compactRuntime.emptyRunningCost() };
        const partialProofData = {
          input: {
            value: _descriptor_3.toValue(id_0),
            alignment: _descriptor_3.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._removeVerificationMethod_0(context,
                                                          partialProofData,
                                                          id_0);
        partialProofData.output = { value: [], alignment: [] };
        return { result: result_0, context: context, proofData: partialProofData, gasCost: context.gasCost };
      },
      addVerificationMethodRelation: (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`addVerificationMethodRelation: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const relation_0 = args_1[1];
        const methodId_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.currentQueryContext != undefined)) {
          __compactRuntime.typeError('addVerificationMethodRelation',
                                     'argument 1 (as invoked from Typescript)',
                                     'did.compact line 238 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(relation_0) === 'number' && relation_0 >= 0 && relation_0 <= 5)) {
          __compactRuntime.typeError('addVerificationMethodRelation',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'did.compact line 238 char 1',
                                     'Enum<VerificationMethodRelation, Undefined, Authentication, AssertionMethod, KeyAgreement, CapabilityInvocation, CapabilityDelegation>',
                                     relation_0)
        }
        const context = { ...contextOrig_0, gasCost: __compactRuntime.emptyRunningCost() };
        const partialProofData = {
          input: {
            value: _descriptor_12.toValue(relation_0).concat(_descriptor_3.toValue(methodId_0)),
            alignment: _descriptor_12.alignment().concat(_descriptor_3.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._addVerificationMethodRelation_0(context,
                                                               partialProofData,
                                                               relation_0,
                                                               methodId_0);
        partialProofData.output = { value: [], alignment: [] };
        return { result: result_0, context: context, proofData: partialProofData, gasCost: context.gasCost };
      },
      removeVerificationMethodRelation: (...args_1) => {
        if (args_1.length !== 3) {
          throw new __compactRuntime.CompactError(`removeVerificationMethodRelation: expected 3 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const relation_0 = args_1[1];
        const methodId_0 = args_1[2];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.currentQueryContext != undefined)) {
          __compactRuntime.typeError('removeVerificationMethodRelation',
                                     'argument 1 (as invoked from Typescript)',
                                     'did.compact line 271 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(relation_0) === 'number' && relation_0 >= 0 && relation_0 <= 5)) {
          __compactRuntime.typeError('removeVerificationMethodRelation',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'did.compact line 271 char 1',
                                     'Enum<VerificationMethodRelation, Undefined, Authentication, AssertionMethod, KeyAgreement, CapabilityInvocation, CapabilityDelegation>',
                                     relation_0)
        }
        const context = { ...contextOrig_0, gasCost: __compactRuntime.emptyRunningCost() };
        const partialProofData = {
          input: {
            value: _descriptor_12.toValue(relation_0).concat(_descriptor_3.toValue(methodId_0)),
            alignment: _descriptor_12.alignment().concat(_descriptor_3.alignment())
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._removeVerificationMethodRelation_0(context,
                                                                  partialProofData,
                                                                  relation_0,
                                                                  methodId_0);
        partialProofData.output = { value: [], alignment: [] };
        return { result: result_0, context: context, proofData: partialProofData, gasCost: context.gasCost };
      },
      addService: (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`addService: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const service_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.currentQueryContext != undefined)) {
          __compactRuntime.typeError('addService',
                                     'argument 1 (as invoked from Typescript)',
                                     'did.compact line 304 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(service_0) === 'object' && true && true && true)) {
          __compactRuntime.typeError('addService',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'did.compact line 304 char 1',
                                     'struct Service<id: Opaque<"string">, typ: Opaque<"string">, serviceEndpoint: Opaque<"string">>',
                                     service_0)
        }
        const context = { ...contextOrig_0, gasCost: __compactRuntime.emptyRunningCost() };
        const partialProofData = {
          input: {
            value: _descriptor_4.toValue(service_0),
            alignment: _descriptor_4.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._addService_0(context, partialProofData, service_0);
        partialProofData.output = { value: [], alignment: [] };
        return { result: result_0, context: context, proofData: partialProofData, gasCost: context.gasCost };
      },
      updateService: (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`updateService: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const service_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.currentQueryContext != undefined)) {
          __compactRuntime.typeError('updateService',
                                     'argument 1 (as invoked from Typescript)',
                                     'did.compact line 316 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        if (!(typeof(service_0) === 'object' && true && true && true)) {
          __compactRuntime.typeError('updateService',
                                     'argument 1 (argument 2 as invoked from Typescript)',
                                     'did.compact line 316 char 1',
                                     'struct Service<id: Opaque<"string">, typ: Opaque<"string">, serviceEndpoint: Opaque<"string">>',
                                     service_0)
        }
        const context = { ...contextOrig_0, gasCost: __compactRuntime.emptyRunningCost() };
        const partialProofData = {
          input: {
            value: _descriptor_4.toValue(service_0),
            alignment: _descriptor_4.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._updateService_0(context,
                                               partialProofData,
                                               service_0);
        partialProofData.output = { value: [], alignment: [] };
        return { result: result_0, context: context, proofData: partialProofData, gasCost: context.gasCost };
      },
      removeService: (...args_1) => {
        if (args_1.length !== 2) {
          throw new __compactRuntime.CompactError(`removeService: expected 2 arguments (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        const id_0 = args_1[1];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.currentQueryContext != undefined)) {
          __compactRuntime.typeError('removeService',
                                     'argument 1 (as invoked from Typescript)',
                                     'did.compact line 329 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        const context = { ...contextOrig_0, gasCost: __compactRuntime.emptyRunningCost() };
        const partialProofData = {
          input: {
            value: _descriptor_3.toValue(id_0),
            alignment: _descriptor_3.alignment()
          },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._removeService_0(context, partialProofData, id_0);
        partialProofData.output = { value: [], alignment: [] };
        return { result: result_0, context: context, proofData: partialProofData, gasCost: context.gasCost };
      },
      deactivate: (...args_1) => {
        if (args_1.length !== 1) {
          throw new __compactRuntime.CompactError(`deactivate: expected 1 argument (as invoked from Typescript), received ${args_1.length}`);
        }
        const contextOrig_0 = args_1[0];
        if (!(typeof(contextOrig_0) === 'object' && contextOrig_0.currentQueryContext != undefined)) {
          __compactRuntime.typeError('deactivate',
                                     'argument 1 (as invoked from Typescript)',
                                     'did.compact line 341 char 1',
                                     'CircuitContext',
                                     contextOrig_0)
        }
        const context = { ...contextOrig_0, gasCost: __compactRuntime.emptyRunningCost() };
        const partialProofData = {
          input: { value: [], alignment: [] },
          output: undefined,
          publicTranscript: [],
          privateTranscriptOutputs: []
        };
        const result_0 = this._deactivate_0(context, partialProofData);
        partialProofData.output = { value: [], alignment: [] };
        return { result: result_0, context: context, proofData: partialProofData, gasCost: context.gasCost };
      }
    };
    this.impureCircuits = {
      verifyJubjubDigestSignature: this.circuits.verifyJubjubDigestSignature,
      addAlsoKnownAs: this.circuits.addAlsoKnownAs,
      removeAlsoKnownAs: this.circuits.removeAlsoKnownAs,
      addVerificationMethod: this.circuits.addVerificationMethod,
      updateVerificationMethod: this.circuits.updateVerificationMethod,
      removeVerificationMethod: this.circuits.removeVerificationMethod,
      addVerificationMethodRelation: this.circuits.addVerificationMethodRelation,
      removeVerificationMethodRelation: this.circuits.removeVerificationMethodRelation,
      addService: this.circuits.addService,
      updateService: this.circuits.updateService,
      removeService: this.circuits.removeService,
      deactivate: this.circuits.deactivate
    };
    this.provableCircuits = this.impureCircuits;
    this.provableCircuits = {
      addAlsoKnownAs: this.circuits.addAlsoKnownAs,
      removeAlsoKnownAs: this.circuits.removeAlsoKnownAs,
      addVerificationMethod: this.circuits.addVerificationMethod,
      updateVerificationMethod: this.circuits.updateVerificationMethod,
      removeVerificationMethod: this.circuits.removeVerificationMethod,
      addVerificationMethodRelation: this.circuits.addVerificationMethodRelation,
      removeVerificationMethodRelation: this.circuits.removeVerificationMethodRelation,
      addService: this.circuits.addService,
      updateService: this.circuits.updateService,
      removeService: this.circuits.removeService,
      deactivate: this.circuits.deactivate
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
    if (!('initialPrivateState' in constructorContext_0)) {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'initialPrivateState' in argument 1 (as invoked from Typescript)`);
    }
    if (!('initialZswapLocalState' in constructorContext_0)) {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'initialZswapLocalState' in argument 1 (as invoked from Typescript)`);
    }
    if (typeof(constructorContext_0.initialZswapLocalState) !== 'object') {
      throw new __compactRuntime.CompactError(`Contract state constructor: expected 'initialZswapLocalState' in argument 1 (as invoked from Typescript) to be an object`);
    }
    const state_0 = new __compactRuntime.ContractState();
    let stateValue_0 = __compactRuntime.StateValue.newArray();
    let stateValue_2 = __compactRuntime.StateValue.newArray();
    stateValue_2 = stateValue_2.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_2 = stateValue_2.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_0 = stateValue_0.arrayPush(stateValue_2);
    let stateValue_1 = __compactRuntime.StateValue.newArray();
    stateValue_1 = stateValue_1.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_1 = stateValue_1.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_1 = stateValue_1.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_1 = stateValue_1.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_1 = stateValue_1.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_1 = stateValue_1.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_1 = stateValue_1.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_1 = stateValue_1.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_1 = stateValue_1.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_1 = stateValue_1.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_1 = stateValue_1.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_1 = stateValue_1.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_1 = stateValue_1.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_1 = stateValue_1.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_1 = stateValue_1.arrayPush(__compactRuntime.StateValue.newNull());
    stateValue_0 = stateValue_0.arrayPush(stateValue_1);
    state_0.data = new __compactRuntime.ChargedState(stateValue_0);
    state_0.setOperation('addAlsoKnownAs', new __compactRuntime.ContractOperation());
    state_0.setOperation('removeAlsoKnownAs', new __compactRuntime.ContractOperation());
    state_0.setOperation('addVerificationMethod', new __compactRuntime.ContractOperation());
    state_0.setOperation('updateVerificationMethod', new __compactRuntime.ContractOperation());
    state_0.setOperation('removeVerificationMethod', new __compactRuntime.ContractOperation());
    state_0.setOperation('addVerificationMethodRelation', new __compactRuntime.ContractOperation());
    state_0.setOperation('removeVerificationMethodRelation', new __compactRuntime.ContractOperation());
    state_0.setOperation('addService', new __compactRuntime.ContractOperation());
    state_0.setOperation('updateService', new __compactRuntime.ContractOperation());
    state_0.setOperation('removeService', new __compactRuntime.ContractOperation());
    state_0.setOperation('deactivate', new __compactRuntime.ContractOperation());
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
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(0n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(0n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_24.toValue(0n),
                                                                                              alignment: _descriptor_24.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(0n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(1n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(new Uint8Array(32)),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(0n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_23.toValue({ bytes: new Uint8Array(32) }),
                                                                                              alignment: _descriptor_23.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(1n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(2n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(0n),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(3n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(0n),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(4n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(0n),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(5n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(false),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(6n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(false),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(7n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(0n),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(8n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(9n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(10n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(11n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(12n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(13n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(14n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newMap(
                                                          new __compactRuntime.StateMap()
                                                        ).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    const tmp_0 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(0n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(0n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_24.toValue(tmp_0),
                                                                                              alignment: _descriptor_24.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    const tmp_1 = _descriptor_23.fromValue(__compactRuntime.queryLedgerState(context,
                                                                             partialProofData,
                                                                             [
                                                                              { dup: { n: 2 } },
                                                                              { idx: { cached: true,
                                                                                       pushPath: false,
                                                                                       path: [
                                                                                              { tag: 'value',
                                                                                                value: { value: _descriptor_25.toValue(0n),
                                                                                                         alignment: _descriptor_25.alignment() } }] } },
                                                                              { popeq: { cached: true,
                                                                                         result: undefined } }]).value);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(0n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_23.toValue(tmp_1),
                                                                                              alignment: _descriptor_23.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(6n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(true),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(5n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(false),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    const tmp_2 = this._publicKey_0(this._localSecretKey_0(context,
                                                           partialProofData));
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(0n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(1n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_0.toValue(tmp_2),
                                                                                              alignment: _descriptor_0.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    const timestamp_0 = this._currentTimestamp_0(context, partialProofData);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(3n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(timestamp_0),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(4n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(timestamp_0),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    state_0.data = new __compactRuntime.ChargedState(context.currentQueryContext.state.state);
    return {
      currentContractState: state_0,
      currentPrivateState: context.currentPrivateState,
      currentZswapLocalState: context.currentZswapLocalState
    }
  }
  _transientHash_0(value_0) {
    const result_0 = __compactRuntime.transientHash(_descriptor_19, value_0);
    return result_0;
  }
  _persistentHash_0(value_0) {
    const result_0 = __compactRuntime.persistentHash(_descriptor_20, value_0);
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
  _getSchnorrReduction_0(context, partialProofData, challengeHash_0) {
    const witnessContext_0 = __compactRuntime.createWitnessContext(ledger(context.currentQueryContext.state), context.currentPrivateState, context.currentQueryContext.address);
    const [nextPrivateState_0, result_0] = this.witnesses.getSchnorrReduction(witnessContext_0,
                                                                              challengeHash_0);
    context.currentPrivateState = nextPrivateState_0;
    if (!(Array.isArray(result_0) && result_0.length === 2  && typeof(result_0[0]) === 'bigint' && result_0[0] >= 0 && result_0[0] <= __compactRuntime.MAX_FIELD && typeof(result_0[1]) === 'bigint' && result_0[1] >= 0n && result_0[1] <= 452312848583266388373324160190187140051835877600158453279131187530910662655n)) {
      __compactRuntime.typeError('getSchnorrReduction',
                                 'return value',
                                 'schnorr.compact line 32 char 3',
                                 '[Field, Uint<0..452312848583266388373324160190187140051835877600158453279131187530910662656>]',
                                 result_0)
    }
    partialProofData.privateTranscriptOutputs.push({
      value: _descriptor_18.toValue(result_0),
      alignment: _descriptor_18.alignment()
    });
    return result_0;
  }
  _schnorrVerify_0(context, partialProofData, msg_0, signature_0, pk_0) {
    const __compact_pattern_tmp2_0 = signature_0;
    const announcement_0 = __compact_pattern_tmp2_0.announcement;
    const response_0 = __compact_pattern_tmp2_0.response;
    const cFull_0 = this._transientHash_0({ ann_x:
                                              this._jubjubPointX_0(announcement_0),
                                            ann_y:
                                              this._jubjubPointY_0(announcement_0),
                                            pk_x: this._jubjubPointX_0(pk_0),
                                            pk_y: this._jubjubPointY_0(pk_0),
                                            msg: msg_0 });
    const TWO_248_0 = 452312848583266388373324160190187140051835877600158453279131187530910662656n;
    const __compact_pattern_tmp1_0 = this._getSchnorrReduction_0(context,
                                                                 partialProofData,
                                                                 cFull_0);
    const q_0 = __compact_pattern_tmp1_0[0];
    const cTruncated_0 = __compact_pattern_tmp1_0[1];
    __compactRuntime.assert(__compactRuntime.addField(__compactRuntime.mulField(q_0,
                                                                                TWO_248_0),
                                                      cTruncated_0)
                            ===
                            cFull_0,
                            'Invalid challenge reduction');
    const c_0 = cTruncated_0;
    const lhs_0 = this._ecMulGenerator_0(response_0);
    const rhs_0 = this._ecAdd_0(announcement_0, this._ecMul_0(pk_0, c_0));
    __compactRuntime.assert(this._jubjubPointX_0(lhs_0)
                            ===
                            this._jubjubPointX_0(rhs_0)
                            &&
                            this._jubjubPointY_0(lhs_0)
                            ===
                            this._jubjubPointY_0(rhs_0),
                            'Invalid Jubjub Schnorr signature');
    return [];
  }
  _schnorrVerifyDigest_0(context, partialProofData, digest_0, signature_0, pk_0)
  {
    this._schnorrVerify_0(context, partialProofData, digest_0, signature_0, pk_0);
    return [];
  }
  _schnorrChallengeDigest_0(ann_x_0, ann_y_0, pk_x_0, pk_y_0, digest_0) {
    return this._transientHash_0({ ann_x: ann_x_0,
                                   ann_y: ann_y_0,
                                   pk_x: pk_x_0,
                                   pk_y: pk_y_0,
                                   msg: digest_0 });
  }
  _localSecretKey_0(context, partialProofData) {
    const witnessContext_0 = __compactRuntime.createWitnessContext(ledger(context.currentQueryContext.state), context.currentPrivateState, context.currentQueryContext.address);
    const [nextPrivateState_0, result_0] = this.witnesses.localSecretKey(witnessContext_0);
    context.currentPrivateState = nextPrivateState_0;
    if (!(result_0.buffer instanceof ArrayBuffer && result_0.BYTES_PER_ELEMENT === 1 && result_0.length === 32)) {
      __compactRuntime.typeError('localSecretKey',
                                 'return value',
                                 'did.compact line 41 char 1',
                                 'Bytes<32>',
                                 result_0)
    }
    partialProofData.privateTranscriptOutputs.push({
      value: _descriptor_0.toValue(result_0),
      alignment: _descriptor_0.alignment()
    });
    return result_0;
  }
  _currentTimestamp_0(context, partialProofData) {
    const witnessContext_0 = __compactRuntime.createWitnessContext(ledger(context.currentQueryContext.state), context.currentPrivateState, context.currentQueryContext.address);
    const [nextPrivateState_0, result_0] = this.witnesses.currentTimestamp(witnessContext_0);
    context.currentPrivateState = nextPrivateState_0;
    if (!(typeof(result_0) === 'bigint' && result_0 >= 0n && result_0 <= 18446744073709551615n)) {
      __compactRuntime.typeError('currentTimestamp',
                                 'return value',
                                 'did.compact line 42 char 1',
                                 'Uint<0..18446744073709551616>',
                                 result_0)
    }
    partialProofData.privateTranscriptOutputs.push({
      value: _descriptor_5.toValue(result_0),
      alignment: _descriptor_5.alignment()
    });
    return result_0;
  }
  _jubjubSignatureDigestChallenge_0(ann_x_0, ann_y_0, pk_x_0, pk_y_0, digest_0)
  {
    return this._schnorrChallengeDigest_0(ann_x_0,
                                          ann_y_0,
                                          pk_x_0,
                                          pk_y_0,
                                          digest_0);
  }
  _publicKey_0(sk_0) {
    return this._persistentHash_0([new Uint8Array([100, 105, 100, 58, 99, 111, 110, 116, 114, 111, 108, 108, 101, 114, 58, 112, 107, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                                   sk_0]);
  }
  _verifyJubjubSignature_0(pk_0, signature_0, challenge_0) {
    const leftSide_0 = this._ecMulGenerator_0(signature_0.s);
    const cPk_0 = this._ecMul_0(pk_0, challenge_0);
    const rightSide_0 = this._ecAdd_0(signature_0.r, cPk_0);
    __compactRuntime.assert(leftSide_0 === rightSide_0,
                            'Jubjub signature verification failed');
    return leftSide_0 === rightSide_0;
  }
  _verifyJubjubDigestSignature_0(context,
                                 partialProofData,
                                 pk_0,
                                 signature_0,
                                 digest_0)
  {
    const schnorrSignature_0 = { announcement: signature_0.r,
                                 response: signature_0.s };
    this._schnorrVerifyDigest_0(context,
                                partialProofData,
                                digest_0,
                                schnorrSignature_0,
                                pk_0);
    return [];
  }
  _addAlsoKnownAs_0(context, partialProofData, value_0) {
    __compactRuntime.assert(this._equal_0(this._publicKey_0(this._localSecretKey_0(context,
                                                                                   partialProofData)),
                                          _descriptor_0.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                                    partialProofData,
                                                                                                    [
                                                                                                     { dup: { n: 0 } },
                                                                                                     { idx: { cached: false,
                                                                                                              pushPath: false,
                                                                                                              path: [
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(0n),
                                                                                                                                alignment: _descriptor_25.alignment() } },
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(1n),
                                                                                                                                alignment: _descriptor_25.alignment() } }] } },
                                                                                                     { popeq: { cached: false,
                                                                                                                result: undefined } }]).value)),
                            'DID controller is allowed to update the DID only');
    __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } },
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(6n),
                                                                                                                  alignment: _descriptor_25.alignment() } }] } },
                                                                                       { popeq: { cached: false,
                                                                                                  result: undefined } }]).value),
                            'Contract is not active');
    const alias_0 = value_0;
    __compactRuntime.assert(!_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                       partialProofData,
                                                                                       [
                                                                                        { dup: { n: 0 } },
                                                                                        { idx: { cached: false,
                                                                                                 pushPath: false,
                                                                                                 path: [
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_25.toValue(1n),
                                                                                                                   alignment: _descriptor_25.alignment() } },
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_25.toValue(1n),
                                                                                                                   alignment: _descriptor_25.alignment() } }] } },
                                                                                        { push: { storage: false,
                                                                                                  value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(alias_0),
                                                                                                                                               alignment: _descriptor_3.alignment() }).encode() } },
                                                                                        'member',
                                                                                        { popeq: { cached: true,
                                                                                                   result: undefined } }]).value),
                            'alsoKnownAs value already exists');
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(alias_0),
                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newNull().encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_0 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(7n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_0),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_1 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(2n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_1),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_2 = this._currentTimestamp_0(context, partialProofData);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(4n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(tmp_2),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  _removeAlsoKnownAs_0(context, partialProofData, value_0) {
    __compactRuntime.assert(this._equal_1(this._publicKey_0(this._localSecretKey_0(context,
                                                                                   partialProofData)),
                                          _descriptor_0.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                                    partialProofData,
                                                                                                    [
                                                                                                     { dup: { n: 0 } },
                                                                                                     { idx: { cached: false,
                                                                                                              pushPath: false,
                                                                                                              path: [
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(0n),
                                                                                                                                alignment: _descriptor_25.alignment() } },
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(1n),
                                                                                                                                alignment: _descriptor_25.alignment() } }] } },
                                                                                                     { popeq: { cached: false,
                                                                                                                result: undefined } }]).value)),
                            'DID controller is allowed to update the DID only');
    __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } },
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(6n),
                                                                                                                  alignment: _descriptor_25.alignment() } }] } },
                                                                                       { popeq: { cached: false,
                                                                                                  result: undefined } }]).value),
                            'Contract is not active');
    const alias_0 = value_0;
    __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } },
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } }] } },
                                                                                       { push: { storage: false,
                                                                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(alias_0),
                                                                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                                                                       'member',
                                                                                       { popeq: { cached: true,
                                                                                                  result: undefined } }]).value),
                            'alsoKnownAs value does not exist');
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(alias_0),
                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                       { rem: { cached: false } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_0 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(7n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_0),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_1 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(2n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_1),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_2 = this._currentTimestamp_0(context, partialProofData);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(4n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(tmp_2),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  _addVerificationMethod_0(context, partialProofData, verificationMethod_0) {
    __compactRuntime.assert(this._equal_2(this._publicKey_0(this._localSecretKey_0(context,
                                                                                   partialProofData)),
                                          _descriptor_0.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                                    partialProofData,
                                                                                                    [
                                                                                                     { dup: { n: 0 } },
                                                                                                     { idx: { cached: false,
                                                                                                              pushPath: false,
                                                                                                              path: [
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(0n),
                                                                                                                                alignment: _descriptor_25.alignment() } },
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(1n),
                                                                                                                                alignment: _descriptor_25.alignment() } }] } },
                                                                                                     { popeq: { cached: false,
                                                                                                                result: undefined } }]).value)),
                            'DID controller is allowed to update the DID only');
    __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } },
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(6n),
                                                                                                                  alignment: _descriptor_25.alignment() } }] } },
                                                                                       { popeq: { cached: false,
                                                                                                  result: undefined } }]).value),
                            'Contract is not active');
    const disclosedVerificationMethod_0 = verificationMethod_0;
    __compactRuntime.assert(disclosedVerificationMethod_0.typ === 1,
                            'Only JsonWebKey verification methods are supported');
    if (disclosedVerificationMethod_0.publicKeyJwk.kty === 3) {
      __compactRuntime.assert(disclosedVerificationMethod_0.publicKeyJwk.crv
                              ===
                              0,
                              'OKP keys must use Ed25519');
    } else {
      if (disclosedVerificationMethod_0.publicKeyJwk.kty === 0) {
        __compactRuntime.assert(disclosedVerificationMethod_0.publicKeyJwk.crv
                                ===
                                1
                                ||
                                disclosedVerificationMethod_0.publicKeyJwk.crv
                                ===
                                2,
                                'EC keys must use Jubjub or P-256');
      } else {
        __compactRuntime.assert(false,
                                'Only OKP (Ed25519) and EC (Jubjub/P-256) keys are supported');
      }
    }
    let tmp_0;
    __compactRuntime.assert(!(tmp_0 = disclosedVerificationMethod_0.id,
                              _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                        partialProofData,
                                                                                        [
                                                                                         { dup: { n: 0 } },
                                                                                         { idx: { cached: false,
                                                                                                  pushPath: false,
                                                                                                  path: [
                                                                                                         { tag: 'value',
                                                                                                           value: { value: _descriptor_25.toValue(1n),
                                                                                                                    alignment: _descriptor_25.alignment() } },
                                                                                                         { tag: 'value',
                                                                                                           value: { value: _descriptor_25.toValue(8n),
                                                                                                                    alignment: _descriptor_25.alignment() } }] } },
                                                                                         { push: { storage: false,
                                                                                                   value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(tmp_0),
                                                                                                                                                alignment: _descriptor_3.alignment() }).encode() } },
                                                                                         'member',
                                                                                         { popeq: { cached: true,
                                                                                                    result: undefined } }]).value)),
                            'Verification method already exists');
    const tmp_1 = disclosedVerificationMethod_0.id;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(8n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(tmp_1),
                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_11.toValue(disclosedVerificationMethod_0),
                                                                                              alignment: _descriptor_11.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_2 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(7n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_2),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_3 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(2n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_3),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_4 = this._currentTimestamp_0(context, partialProofData);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(4n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(tmp_4),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  _updateVerificationMethod_0(context, partialProofData, verificationMethod_0) {
    __compactRuntime.assert(this._equal_3(this._publicKey_0(this._localSecretKey_0(context,
                                                                                   partialProofData)),
                                          _descriptor_0.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                                    partialProofData,
                                                                                                    [
                                                                                                     { dup: { n: 0 } },
                                                                                                     { idx: { cached: false,
                                                                                                              pushPath: false,
                                                                                                              path: [
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(0n),
                                                                                                                                alignment: _descriptor_25.alignment() } },
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(1n),
                                                                                                                                alignment: _descriptor_25.alignment() } }] } },
                                                                                                     { popeq: { cached: false,
                                                                                                                result: undefined } }]).value)),
                            'DID controller is allowed to update the DID only');
    __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } },
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(6n),
                                                                                                                  alignment: _descriptor_25.alignment() } }] } },
                                                                                       { popeq: { cached: false,
                                                                                                  result: undefined } }]).value),
                            'Contract is not active');
    const disclosedVerificationMethod_0 = verificationMethod_0;
    __compactRuntime.assert(disclosedVerificationMethod_0.typ === 1,
                            'Only JsonWebKey verification methods are supported');
    if (disclosedVerificationMethod_0.publicKeyJwk.kty === 3) {
      __compactRuntime.assert(disclosedVerificationMethod_0.publicKeyJwk.crv
                              ===
                              0,
                              'OKP keys must use Ed25519');
    } else {
      if (disclosedVerificationMethod_0.publicKeyJwk.kty === 0) {
        __compactRuntime.assert(disclosedVerificationMethod_0.publicKeyJwk.crv
                                ===
                                1
                                ||
                                disclosedVerificationMethod_0.publicKeyJwk.crv
                                ===
                                2,
                                'EC keys must use Jubjub or P-256');
      } else {
        __compactRuntime.assert(false,
                                'Only OKP (Ed25519) and EC (Jubjub/P-256) keys are supported');
      }
    }
    let tmp_0;
    __compactRuntime.assert((tmp_0 = disclosedVerificationMethod_0.id,
                             _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                       partialProofData,
                                                                                       [
                                                                                        { dup: { n: 0 } },
                                                                                        { idx: { cached: false,
                                                                                                 pushPath: false,
                                                                                                 path: [
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_25.toValue(1n),
                                                                                                                   alignment: _descriptor_25.alignment() } },
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_25.toValue(8n),
                                                                                                                   alignment: _descriptor_25.alignment() } }] } },
                                                                                        { push: { storage: false,
                                                                                                  value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(tmp_0),
                                                                                                                                               alignment: _descriptor_3.alignment() }).encode() } },
                                                                                        'member',
                                                                                        { popeq: { cached: true,
                                                                                                   result: undefined } }]).value)),
                            'Verification method does not exist');
    const tmp_1 = disclosedVerificationMethod_0.id;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(8n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(tmp_1),
                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                       { rem: { cached: false } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_2 = disclosedVerificationMethod_0.id;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(8n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(tmp_2),
                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_11.toValue(disclosedVerificationMethod_0),
                                                                                              alignment: _descriptor_11.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_3 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(7n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_3),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_4 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(2n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_4),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_5 = this._currentTimestamp_0(context, partialProofData);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(4n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(tmp_5),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  _removeVerificationMethod_0(context, partialProofData, id_0) {
    __compactRuntime.assert(this._equal_4(this._publicKey_0(this._localSecretKey_0(context,
                                                                                   partialProofData)),
                                          _descriptor_0.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                                    partialProofData,
                                                                                                    [
                                                                                                     { dup: { n: 0 } },
                                                                                                     { idx: { cached: false,
                                                                                                              pushPath: false,
                                                                                                              path: [
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(0n),
                                                                                                                                alignment: _descriptor_25.alignment() } },
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(1n),
                                                                                                                                alignment: _descriptor_25.alignment() } }] } },
                                                                                                     { popeq: { cached: false,
                                                                                                                result: undefined } }]).value)),
                            'DID controller is allowed to update the DID only');
    __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } },
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(6n),
                                                                                                                  alignment: _descriptor_25.alignment() } }] } },
                                                                                       { popeq: { cached: false,
                                                                                                  result: undefined } }]).value),
                            'Contract is not active');
    const disclosedId_0 = id_0;
    __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } },
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(8n),
                                                                                                                  alignment: _descriptor_25.alignment() } }] } },
                                                                                       { push: { storage: false,
                                                                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedId_0),
                                                                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                                                                       'member',
                                                                                       { popeq: { cached: true,
                                                                                                  result: undefined } }]).value),
                            'Verification method does not exist');
    __compactRuntime.assert(!_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                       partialProofData,
                                                                                       [
                                                                                        { dup: { n: 0 } },
                                                                                        { idx: { cached: false,
                                                                                                 pushPath: false,
                                                                                                 path: [
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_25.toValue(1n),
                                                                                                                   alignment: _descriptor_25.alignment() } },
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_25.toValue(9n),
                                                                                                                   alignment: _descriptor_25.alignment() } }] } },
                                                                                        { push: { storage: false,
                                                                                                  value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedId_0),
                                                                                                                                               alignment: _descriptor_3.alignment() }).encode() } },
                                                                                        'member',
                                                                                        { popeq: { cached: true,
                                                                                                   result: undefined } }]).value),
                            'Verification method still referenced in authenticationRelation');
    __compactRuntime.assert(!_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                       partialProofData,
                                                                                       [
                                                                                        { dup: { n: 0 } },
                                                                                        { idx: { cached: false,
                                                                                                 pushPath: false,
                                                                                                 path: [
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_25.toValue(1n),
                                                                                                                   alignment: _descriptor_25.alignment() } },
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_25.toValue(10n),
                                                                                                                   alignment: _descriptor_25.alignment() } }] } },
                                                                                        { push: { storage: false,
                                                                                                  value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedId_0),
                                                                                                                                               alignment: _descriptor_3.alignment() }).encode() } },
                                                                                        'member',
                                                                                        { popeq: { cached: true,
                                                                                                   result: undefined } }]).value),
                            'Verification method still referenced in assertionMethodRelation');
    __compactRuntime.assert(!_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                       partialProofData,
                                                                                       [
                                                                                        { dup: { n: 0 } },
                                                                                        { idx: { cached: false,
                                                                                                 pushPath: false,
                                                                                                 path: [
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_25.toValue(1n),
                                                                                                                   alignment: _descriptor_25.alignment() } },
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_25.toValue(11n),
                                                                                                                   alignment: _descriptor_25.alignment() } }] } },
                                                                                        { push: { storage: false,
                                                                                                  value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedId_0),
                                                                                                                                               alignment: _descriptor_3.alignment() }).encode() } },
                                                                                        'member',
                                                                                        { popeq: { cached: true,
                                                                                                   result: undefined } }]).value),
                            'Verification method still referenced in keyAgreementRelation');
    __compactRuntime.assert(!_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                       partialProofData,
                                                                                       [
                                                                                        { dup: { n: 0 } },
                                                                                        { idx: { cached: false,
                                                                                                 pushPath: false,
                                                                                                 path: [
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_25.toValue(1n),
                                                                                                                   alignment: _descriptor_25.alignment() } },
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_25.toValue(12n),
                                                                                                                   alignment: _descriptor_25.alignment() } }] } },
                                                                                        { push: { storage: false,
                                                                                                  value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedId_0),
                                                                                                                                               alignment: _descriptor_3.alignment() }).encode() } },
                                                                                        'member',
                                                                                        { popeq: { cached: true,
                                                                                                   result: undefined } }]).value),
                            'Verification method still referenced in capabilityInvocationRelation');
    __compactRuntime.assert(!_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                       partialProofData,
                                                                                       [
                                                                                        { dup: { n: 0 } },
                                                                                        { idx: { cached: false,
                                                                                                 pushPath: false,
                                                                                                 path: [
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_25.toValue(1n),
                                                                                                                   alignment: _descriptor_25.alignment() } },
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_25.toValue(13n),
                                                                                                                   alignment: _descriptor_25.alignment() } }] } },
                                                                                        { push: { storage: false,
                                                                                                  value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedId_0),
                                                                                                                                               alignment: _descriptor_3.alignment() }).encode() } },
                                                                                        'member',
                                                                                        { popeq: { cached: true,
                                                                                                   result: undefined } }]).value),
                            'Verification method still referenced in capabilityDelegationRelation');
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(8n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedId_0),
                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                       { rem: { cached: false } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_0 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(7n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_0),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_1 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(2n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_1),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_2 = this._currentTimestamp_0(context, partialProofData);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(4n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(tmp_2),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  _addVerificationMethodRelation_0(context,
                                   partialProofData,
                                   relation_0,
                                   methodId_0)
  {
    __compactRuntime.assert(this._equal_5(this._publicKey_0(this._localSecretKey_0(context,
                                                                                   partialProofData)),
                                          _descriptor_0.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                                    partialProofData,
                                                                                                    [
                                                                                                     { dup: { n: 0 } },
                                                                                                     { idx: { cached: false,
                                                                                                              pushPath: false,
                                                                                                              path: [
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(0n),
                                                                                                                                alignment: _descriptor_25.alignment() } },
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(1n),
                                                                                                                                alignment: _descriptor_25.alignment() } }] } },
                                                                                                     { popeq: { cached: false,
                                                                                                                result: undefined } }]).value)),
                            'DID controller is allowed to update the DID only');
    __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } },
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(6n),
                                                                                                                  alignment: _descriptor_25.alignment() } }] } },
                                                                                       { popeq: { cached: false,
                                                                                                  result: undefined } }]).value),
                            'Contract is not active');
    const disclosedRelation_0 = relation_0;
    const disclosedMethodId_0 = methodId_0;
    __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } },
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(8n),
                                                                                                                  alignment: _descriptor_25.alignment() } }] } },
                                                                                       { push: { storage: false,
                                                                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                                                                       'member',
                                                                                       { popeq: { cached: true,
                                                                                                  result: undefined } }]).value),
                            'Verification method does not exist');
    __compactRuntime.assert(disclosedRelation_0 !== 0,
                            'Verification relation must be defined');
    if (disclosedRelation_0 === 1) {
      __compactRuntime.assert(!_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                         partialProofData,
                                                                                         [
                                                                                          { dup: { n: 0 } },
                                                                                          { idx: { cached: false,
                                                                                                   pushPath: false,
                                                                                                   path: [
                                                                                                          { tag: 'value',
                                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                                          { tag: 'value',
                                                                                                            value: { value: _descriptor_25.toValue(9n),
                                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                                          { push: { storage: false,
                                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                                                                 alignment: _descriptor_3.alignment() }).encode() } },
                                                                                          'member',
                                                                                          { popeq: { cached: true,
                                                                                                     result: undefined } }]).value),
                              'Verification method relation already exists');
      __compactRuntime.queryLedgerState(context,
                                        partialProofData,
                                        [
                                         { idx: { cached: false,
                                                  pushPath: true,
                                                  path: [
                                                         { tag: 'value',
                                                           value: { value: _descriptor_25.toValue(1n),
                                                                    alignment: _descriptor_25.alignment() } },
                                                         { tag: 'value',
                                                           value: { value: _descriptor_25.toValue(9n),
                                                                    alignment: _descriptor_25.alignment() } }] } },
                                         { push: { storage: false,
                                                   value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                alignment: _descriptor_3.alignment() }).encode() } },
                                         { push: { storage: true,
                                                   value: __compactRuntime.StateValue.newNull().encode() } },
                                         { ins: { cached: false, n: 1 } },
                                         { ins: { cached: true, n: 2 } }]);
    } else {
      if (disclosedRelation_0 === 2) {
        __compactRuntime.assert(!_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                           partialProofData,
                                                                                           [
                                                                                            { dup: { n: 0 } },
                                                                                            { idx: { cached: false,
                                                                                                     pushPath: false,
                                                                                                     path: [
                                                                                                            { tag: 'value',
                                                                                                              value: { value: _descriptor_25.toValue(1n),
                                                                                                                       alignment: _descriptor_25.alignment() } },
                                                                                                            { tag: 'value',
                                                                                                              value: { value: _descriptor_25.toValue(10n),
                                                                                                                       alignment: _descriptor_25.alignment() } }] } },
                                                                                            { push: { storage: false,
                                                                                                      value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                                                                   alignment: _descriptor_3.alignment() }).encode() } },
                                                                                            'member',
                                                                                            { popeq: { cached: true,
                                                                                                       result: undefined } }]).value),
                                'Verification method relation already exists');
        __compactRuntime.queryLedgerState(context,
                                          partialProofData,
                                          [
                                           { idx: { cached: false,
                                                    pushPath: true,
                                                    path: [
                                                           { tag: 'value',
                                                             value: { value: _descriptor_25.toValue(1n),
                                                                      alignment: _descriptor_25.alignment() } },
                                                           { tag: 'value',
                                                             value: { value: _descriptor_25.toValue(10n),
                                                                      alignment: _descriptor_25.alignment() } }] } },
                                           { push: { storage: false,
                                                     value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                  alignment: _descriptor_3.alignment() }).encode() } },
                                           { push: { storage: true,
                                                     value: __compactRuntime.StateValue.newNull().encode() } },
                                           { ins: { cached: false, n: 1 } },
                                           { ins: { cached: true, n: 2 } }]);
      } else {
        if (disclosedRelation_0 === 3) {
          __compactRuntime.assert(!_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                             partialProofData,
                                                                                             [
                                                                                              { dup: { n: 0 } },
                                                                                              { idx: { cached: false,
                                                                                                       pushPath: false,
                                                                                                       path: [
                                                                                                              { tag: 'value',
                                                                                                                value: { value: _descriptor_25.toValue(1n),
                                                                                                                         alignment: _descriptor_25.alignment() } },
                                                                                                              { tag: 'value',
                                                                                                                value: { value: _descriptor_25.toValue(11n),
                                                                                                                         alignment: _descriptor_25.alignment() } }] } },
                                                                                              { push: { storage: false,
                                                                                                        value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                                                                     alignment: _descriptor_3.alignment() }).encode() } },
                                                                                              'member',
                                                                                              { popeq: { cached: true,
                                                                                                         result: undefined } }]).value),
                                  'Verification method relation already exists');
          __compactRuntime.queryLedgerState(context,
                                            partialProofData,
                                            [
                                             { idx: { cached: false,
                                                      pushPath: true,
                                                      path: [
                                                             { tag: 'value',
                                                               value: { value: _descriptor_25.toValue(1n),
                                                                        alignment: _descriptor_25.alignment() } },
                                                             { tag: 'value',
                                                               value: { value: _descriptor_25.toValue(11n),
                                                                        alignment: _descriptor_25.alignment() } }] } },
                                             { push: { storage: false,
                                                       value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                    alignment: _descriptor_3.alignment() }).encode() } },
                                             { push: { storage: true,
                                                       value: __compactRuntime.StateValue.newNull().encode() } },
                                             { ins: { cached: false, n: 1 } },
                                             { ins: { cached: true, n: 2 } }]);
        } else {
          if (disclosedRelation_0 === 4) {
            __compactRuntime.assert(!_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                               partialProofData,
                                                                                               [
                                                                                                { dup: { n: 0 } },
                                                                                                { idx: { cached: false,
                                                                                                         pushPath: false,
                                                                                                         path: [
                                                                                                                { tag: 'value',
                                                                                                                  value: { value: _descriptor_25.toValue(1n),
                                                                                                                           alignment: _descriptor_25.alignment() } },
                                                                                                                { tag: 'value',
                                                                                                                  value: { value: _descriptor_25.toValue(12n),
                                                                                                                           alignment: _descriptor_25.alignment() } }] } },
                                                                                                { push: { storage: false,
                                                                                                          value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                                                                       alignment: _descriptor_3.alignment() }).encode() } },
                                                                                                'member',
                                                                                                { popeq: { cached: true,
                                                                                                           result: undefined } }]).value),
                                    'Verification method relation already exists');
            __compactRuntime.queryLedgerState(context,
                                              partialProofData,
                                              [
                                               { idx: { cached: false,
                                                        pushPath: true,
                                                        path: [
                                                               { tag: 'value',
                                                                 value: { value: _descriptor_25.toValue(1n),
                                                                          alignment: _descriptor_25.alignment() } },
                                                               { tag: 'value',
                                                                 value: { value: _descriptor_25.toValue(12n),
                                                                          alignment: _descriptor_25.alignment() } }] } },
                                               { push: { storage: false,
                                                         value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                      alignment: _descriptor_3.alignment() }).encode() } },
                                               { push: { storage: true,
                                                         value: __compactRuntime.StateValue.newNull().encode() } },
                                               { ins: { cached: false, n: 1 } },
                                               { ins: { cached: true, n: 2 } }]);
          } else {
            if (disclosedRelation_0 === 5) {
              __compactRuntime.assert(!_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                                 partialProofData,
                                                                                                 [
                                                                                                  { dup: { n: 0 } },
                                                                                                  { idx: { cached: false,
                                                                                                           pushPath: false,
                                                                                                           path: [
                                                                                                                  { tag: 'value',
                                                                                                                    value: { value: _descriptor_25.toValue(1n),
                                                                                                                             alignment: _descriptor_25.alignment() } },
                                                                                                                  { tag: 'value',
                                                                                                                    value: { value: _descriptor_25.toValue(13n),
                                                                                                                             alignment: _descriptor_25.alignment() } }] } },
                                                                                                  { push: { storage: false,
                                                                                                            value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                                                                         alignment: _descriptor_3.alignment() }).encode() } },
                                                                                                  'member',
                                                                                                  { popeq: { cached: true,
                                                                                                             result: undefined } }]).value),
                                      'Verification method relation already exists');
              __compactRuntime.queryLedgerState(context,
                                                partialProofData,
                                                [
                                                 { idx: { cached: false,
                                                          pushPath: true,
                                                          path: [
                                                                 { tag: 'value',
                                                                   value: { value: _descriptor_25.toValue(1n),
                                                                            alignment: _descriptor_25.alignment() } },
                                                                 { tag: 'value',
                                                                   value: { value: _descriptor_25.toValue(13n),
                                                                            alignment: _descriptor_25.alignment() } }] } },
                                                 { push: { storage: false,
                                                           value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                        alignment: _descriptor_3.alignment() }).encode() } },
                                                 { push: { storage: true,
                                                           value: __compactRuntime.StateValue.newNull().encode() } },
                                                 { ins: { cached: false, n: 1 } },
                                                 { ins: { cached: true, n: 2 } }]);
            }
          }
        }
      }
    }
    const tmp_0 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(7n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_0),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_1 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(2n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_1),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_2 = this._currentTimestamp_0(context, partialProofData);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(4n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(tmp_2),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  _removeVerificationMethodRelation_0(context,
                                      partialProofData,
                                      relation_0,
                                      methodId_0)
  {
    __compactRuntime.assert(this._equal_6(this._publicKey_0(this._localSecretKey_0(context,
                                                                                   partialProofData)),
                                          _descriptor_0.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                                    partialProofData,
                                                                                                    [
                                                                                                     { dup: { n: 0 } },
                                                                                                     { idx: { cached: false,
                                                                                                              pushPath: false,
                                                                                                              path: [
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(0n),
                                                                                                                                alignment: _descriptor_25.alignment() } },
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(1n),
                                                                                                                                alignment: _descriptor_25.alignment() } }] } },
                                                                                                     { popeq: { cached: false,
                                                                                                                result: undefined } }]).value)),
                            'DID controller is allowed to update the DID only');
    __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } },
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(6n),
                                                                                                                  alignment: _descriptor_25.alignment() } }] } },
                                                                                       { popeq: { cached: false,
                                                                                                  result: undefined } }]).value),
                            'Contract is not active');
    const disclosedRelation_0 = relation_0;
    const disclosedMethodId_0 = methodId_0;
    __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } },
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(8n),
                                                                                                                  alignment: _descriptor_25.alignment() } }] } },
                                                                                       { push: { storage: false,
                                                                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                                                                       'member',
                                                                                       { popeq: { cached: true,
                                                                                                  result: undefined } }]).value),
                            'Verification method does not exist');
    __compactRuntime.assert(disclosedRelation_0 !== 0,
                            'Verification relation must be defined');
    if (disclosedRelation_0 === 1) {
      __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                        partialProofData,
                                                                                        [
                                                                                         { dup: { n: 0 } },
                                                                                         { idx: { cached: false,
                                                                                                  pushPath: false,
                                                                                                  path: [
                                                                                                         { tag: 'value',
                                                                                                           value: { value: _descriptor_25.toValue(1n),
                                                                                                                    alignment: _descriptor_25.alignment() } },
                                                                                                         { tag: 'value',
                                                                                                           value: { value: _descriptor_25.toValue(9n),
                                                                                                                    alignment: _descriptor_25.alignment() } }] } },
                                                                                         { push: { storage: false,
                                                                                                   value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                                                                alignment: _descriptor_3.alignment() }).encode() } },
                                                                                         'member',
                                                                                         { popeq: { cached: true,
                                                                                                    result: undefined } }]).value),
                              'Verification method relation does not exist');
      __compactRuntime.queryLedgerState(context,
                                        partialProofData,
                                        [
                                         { idx: { cached: false,
                                                  pushPath: true,
                                                  path: [
                                                         { tag: 'value',
                                                           value: { value: _descriptor_25.toValue(1n),
                                                                    alignment: _descriptor_25.alignment() } },
                                                         { tag: 'value',
                                                           value: { value: _descriptor_25.toValue(9n),
                                                                    alignment: _descriptor_25.alignment() } }] } },
                                         { push: { storage: false,
                                                   value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                alignment: _descriptor_3.alignment() }).encode() } },
                                         { rem: { cached: false } },
                                         { ins: { cached: true, n: 2 } }]);
    } else {
      if (disclosedRelation_0 === 2) {
        __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                          partialProofData,
                                                                                          [
                                                                                           { dup: { n: 0 } },
                                                                                           { idx: { cached: false,
                                                                                                    pushPath: false,
                                                                                                    path: [
                                                                                                           { tag: 'value',
                                                                                                             value: { value: _descriptor_25.toValue(1n),
                                                                                                                      alignment: _descriptor_25.alignment() } },
                                                                                                           { tag: 'value',
                                                                                                             value: { value: _descriptor_25.toValue(10n),
                                                                                                                      alignment: _descriptor_25.alignment() } }] } },
                                                                                           { push: { storage: false,
                                                                                                     value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                                                                  alignment: _descriptor_3.alignment() }).encode() } },
                                                                                           'member',
                                                                                           { popeq: { cached: true,
                                                                                                      result: undefined } }]).value),
                                'Verification method relation does not exist');
        __compactRuntime.queryLedgerState(context,
                                          partialProofData,
                                          [
                                           { idx: { cached: false,
                                                    pushPath: true,
                                                    path: [
                                                           { tag: 'value',
                                                             value: { value: _descriptor_25.toValue(1n),
                                                                      alignment: _descriptor_25.alignment() } },
                                                           { tag: 'value',
                                                             value: { value: _descriptor_25.toValue(10n),
                                                                      alignment: _descriptor_25.alignment() } }] } },
                                           { push: { storage: false,
                                                     value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                  alignment: _descriptor_3.alignment() }).encode() } },
                                           { rem: { cached: false } },
                                           { ins: { cached: true, n: 2 } }]);
      } else {
        if (disclosedRelation_0 === 3) {
          __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                            partialProofData,
                                                                                            [
                                                                                             { dup: { n: 0 } },
                                                                                             { idx: { cached: false,
                                                                                                      pushPath: false,
                                                                                                      path: [
                                                                                                             { tag: 'value',
                                                                                                               value: { value: _descriptor_25.toValue(1n),
                                                                                                                        alignment: _descriptor_25.alignment() } },
                                                                                                             { tag: 'value',
                                                                                                               value: { value: _descriptor_25.toValue(11n),
                                                                                                                        alignment: _descriptor_25.alignment() } }] } },
                                                                                             { push: { storage: false,
                                                                                                       value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                                                                    alignment: _descriptor_3.alignment() }).encode() } },
                                                                                             'member',
                                                                                             { popeq: { cached: true,
                                                                                                        result: undefined } }]).value),
                                  'Verification method relation does not exist');
          __compactRuntime.queryLedgerState(context,
                                            partialProofData,
                                            [
                                             { idx: { cached: false,
                                                      pushPath: true,
                                                      path: [
                                                             { tag: 'value',
                                                               value: { value: _descriptor_25.toValue(1n),
                                                                        alignment: _descriptor_25.alignment() } },
                                                             { tag: 'value',
                                                               value: { value: _descriptor_25.toValue(11n),
                                                                        alignment: _descriptor_25.alignment() } }] } },
                                             { push: { storage: false,
                                                       value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                    alignment: _descriptor_3.alignment() }).encode() } },
                                             { rem: { cached: false } },
                                             { ins: { cached: true, n: 2 } }]);
        } else {
          if (disclosedRelation_0 === 4) {
            __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                              partialProofData,
                                                                                              [
                                                                                               { dup: { n: 0 } },
                                                                                               { idx: { cached: false,
                                                                                                        pushPath: false,
                                                                                                        path: [
                                                                                                               { tag: 'value',
                                                                                                                 value: { value: _descriptor_25.toValue(1n),
                                                                                                                          alignment: _descriptor_25.alignment() } },
                                                                                                               { tag: 'value',
                                                                                                                 value: { value: _descriptor_25.toValue(12n),
                                                                                                                          alignment: _descriptor_25.alignment() } }] } },
                                                                                               { push: { storage: false,
                                                                                                         value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                                                                      alignment: _descriptor_3.alignment() }).encode() } },
                                                                                               'member',
                                                                                               { popeq: { cached: true,
                                                                                                          result: undefined } }]).value),
                                    'Verification method relation does not exist');
            __compactRuntime.queryLedgerState(context,
                                              partialProofData,
                                              [
                                               { idx: { cached: false,
                                                        pushPath: true,
                                                        path: [
                                                               { tag: 'value',
                                                                 value: { value: _descriptor_25.toValue(1n),
                                                                          alignment: _descriptor_25.alignment() } },
                                                               { tag: 'value',
                                                                 value: { value: _descriptor_25.toValue(12n),
                                                                          alignment: _descriptor_25.alignment() } }] } },
                                               { push: { storage: false,
                                                         value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                      alignment: _descriptor_3.alignment() }).encode() } },
                                               { rem: { cached: false } },
                                               { ins: { cached: true, n: 2 } }]);
          } else {
            if (disclosedRelation_0 === 5) {
              __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                                partialProofData,
                                                                                                [
                                                                                                 { dup: { n: 0 } },
                                                                                                 { idx: { cached: false,
                                                                                                          pushPath: false,
                                                                                                          path: [
                                                                                                                 { tag: 'value',
                                                                                                                   value: { value: _descriptor_25.toValue(1n),
                                                                                                                            alignment: _descriptor_25.alignment() } },
                                                                                                                 { tag: 'value',
                                                                                                                   value: { value: _descriptor_25.toValue(13n),
                                                                                                                            alignment: _descriptor_25.alignment() } }] } },
                                                                                                 { push: { storage: false,
                                                                                                           value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                                                                        alignment: _descriptor_3.alignment() }).encode() } },
                                                                                                 'member',
                                                                                                 { popeq: { cached: true,
                                                                                                            result: undefined } }]).value),
                                      'Verification method relation does not exist');
              __compactRuntime.queryLedgerState(context,
                                                partialProofData,
                                                [
                                                 { idx: { cached: false,
                                                          pushPath: true,
                                                          path: [
                                                                 { tag: 'value',
                                                                   value: { value: _descriptor_25.toValue(1n),
                                                                            alignment: _descriptor_25.alignment() } },
                                                                 { tag: 'value',
                                                                   value: { value: _descriptor_25.toValue(13n),
                                                                            alignment: _descriptor_25.alignment() } }] } },
                                                 { push: { storage: false,
                                                           value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedMethodId_0),
                                                                                                        alignment: _descriptor_3.alignment() }).encode() } },
                                                 { rem: { cached: false } },
                                                 { ins: { cached: true, n: 2 } }]);
            }
          }
        }
      }
    }
    const tmp_0 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(7n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_0),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_1 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(2n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_1),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_2 = this._currentTimestamp_0(context, partialProofData);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(4n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(tmp_2),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  _addService_0(context, partialProofData, service_0) {
    __compactRuntime.assert(this._equal_7(this._publicKey_0(this._localSecretKey_0(context,
                                                                                   partialProofData)),
                                          _descriptor_0.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                                    partialProofData,
                                                                                                    [
                                                                                                     { dup: { n: 0 } },
                                                                                                     { idx: { cached: false,
                                                                                                              pushPath: false,
                                                                                                              path: [
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(0n),
                                                                                                                                alignment: _descriptor_25.alignment() } },
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(1n),
                                                                                                                                alignment: _descriptor_25.alignment() } }] } },
                                                                                                     { popeq: { cached: false,
                                                                                                                result: undefined } }]).value)),
                            'DID controller is allowed to update the DID only');
    __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } },
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(6n),
                                                                                                                  alignment: _descriptor_25.alignment() } }] } },
                                                                                       { popeq: { cached: false,
                                                                                                  result: undefined } }]).value),
                            'Contract is not active');
    const disclosedService_0 = service_0;
    let tmp_0;
    __compactRuntime.assert(!(tmp_0 = disclosedService_0.id,
                              _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                        partialProofData,
                                                                                        [
                                                                                         { dup: { n: 0 } },
                                                                                         { idx: { cached: false,
                                                                                                  pushPath: false,
                                                                                                  path: [
                                                                                                         { tag: 'value',
                                                                                                           value: { value: _descriptor_25.toValue(1n),
                                                                                                                    alignment: _descriptor_25.alignment() } },
                                                                                                         { tag: 'value',
                                                                                                           value: { value: _descriptor_25.toValue(14n),
                                                                                                                    alignment: _descriptor_25.alignment() } }] } },
                                                                                         { push: { storage: false,
                                                                                                   value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(tmp_0),
                                                                                                                                                alignment: _descriptor_3.alignment() }).encode() } },
                                                                                         'member',
                                                                                         { popeq: { cached: true,
                                                                                                    result: undefined } }]).value)),
                            'Service with a given id already exists');
    const tmp_1 = disclosedService_0.id;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(14n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(tmp_1),
                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_4.toValue(disclosedService_0),
                                                                                              alignment: _descriptor_4.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_2 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(7n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_2),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_3 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(2n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_3),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_4 = this._currentTimestamp_0(context, partialProofData);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(4n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(tmp_4),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  _updateService_0(context, partialProofData, service_0) {
    __compactRuntime.assert(this._equal_8(this._publicKey_0(this._localSecretKey_0(context,
                                                                                   partialProofData)),
                                          _descriptor_0.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                                    partialProofData,
                                                                                                    [
                                                                                                     { dup: { n: 0 } },
                                                                                                     { idx: { cached: false,
                                                                                                              pushPath: false,
                                                                                                              path: [
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(0n),
                                                                                                                                alignment: _descriptor_25.alignment() } },
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(1n),
                                                                                                                                alignment: _descriptor_25.alignment() } }] } },
                                                                                                     { popeq: { cached: false,
                                                                                                                result: undefined } }]).value)),
                            'DID controller is allowed to update the DID only');
    __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } },
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(6n),
                                                                                                                  alignment: _descriptor_25.alignment() } }] } },
                                                                                       { popeq: { cached: false,
                                                                                                  result: undefined } }]).value),
                            'Contract is not active');
    const disclosedService_0 = service_0;
    let tmp_0;
    __compactRuntime.assert((tmp_0 = disclosedService_0.id,
                             _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                       partialProofData,
                                                                                       [
                                                                                        { dup: { n: 0 } },
                                                                                        { idx: { cached: false,
                                                                                                 pushPath: false,
                                                                                                 path: [
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_25.toValue(1n),
                                                                                                                   alignment: _descriptor_25.alignment() } },
                                                                                                        { tag: 'value',
                                                                                                          value: { value: _descriptor_25.toValue(14n),
                                                                                                                   alignment: _descriptor_25.alignment() } }] } },
                                                                                        { push: { storage: false,
                                                                                                  value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(tmp_0),
                                                                                                                                               alignment: _descriptor_3.alignment() }).encode() } },
                                                                                        'member',
                                                                                        { popeq: { cached: true,
                                                                                                   result: undefined } }]).value)),
                            'Service with a given id does not exist');
    const tmp_1 = disclosedService_0.id;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(14n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(tmp_1),
                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                       { rem: { cached: false } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_2 = disclosedService_0.id;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(14n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(tmp_2),
                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_4.toValue(disclosedService_0),
                                                                                              alignment: _descriptor_4.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_3 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(7n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_3),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_4 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(2n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_4),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_5 = this._currentTimestamp_0(context, partialProofData);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(4n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(tmp_5),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  _removeService_0(context, partialProofData, id_0) {
    __compactRuntime.assert(this._equal_9(this._publicKey_0(this._localSecretKey_0(context,
                                                                                   partialProofData)),
                                          _descriptor_0.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                                    partialProofData,
                                                                                                    [
                                                                                                     { dup: { n: 0 } },
                                                                                                     { idx: { cached: false,
                                                                                                              pushPath: false,
                                                                                                              path: [
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(0n),
                                                                                                                                alignment: _descriptor_25.alignment() } },
                                                                                                                     { tag: 'value',
                                                                                                                       value: { value: _descriptor_25.toValue(1n),
                                                                                                                                alignment: _descriptor_25.alignment() } }] } },
                                                                                                     { popeq: { cached: false,
                                                                                                                result: undefined } }]).value)),
                            'DID controller is allowed to update the DID only');
    __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } },
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(6n),
                                                                                                                  alignment: _descriptor_25.alignment() } }] } },
                                                                                       { popeq: { cached: false,
                                                                                                  result: undefined } }]).value),
                            'Contract is not active');
    const disclosedId_0 = id_0;
    __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } },
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(14n),
                                                                                                                  alignment: _descriptor_25.alignment() } }] } },
                                                                                       { push: { storage: false,
                                                                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedId_0),
                                                                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                                                                       'member',
                                                                                       { popeq: { cached: true,
                                                                                                  result: undefined } }]).value),
                            'Service with a given id does not exist');
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(14n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(disclosedId_0),
                                                                                              alignment: _descriptor_3.alignment() }).encode() } },
                                       { rem: { cached: false } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_0 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(7n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_0),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_1 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(2n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_1),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_2 = this._currentTimestamp_0(context, partialProofData);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(4n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(tmp_2),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    return [];
  }
  _deactivate_0(context, partialProofData) {
    __compactRuntime.assert(this._equal_10(this._publicKey_0(this._localSecretKey_0(context,
                                                                                    partialProofData)),
                                           _descriptor_0.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                                     partialProofData,
                                                                                                     [
                                                                                                      { dup: { n: 0 } },
                                                                                                      { idx: { cached: false,
                                                                                                               pushPath: false,
                                                                                                               path: [
                                                                                                                      { tag: 'value',
                                                                                                                        value: { value: _descriptor_25.toValue(0n),
                                                                                                                                 alignment: _descriptor_25.alignment() } },
                                                                                                                      { tag: 'value',
                                                                                                                        value: { value: _descriptor_25.toValue(1n),
                                                                                                                                 alignment: _descriptor_25.alignment() } }] } },
                                                                                                      { popeq: { cached: false,
                                                                                                                 result: undefined } }]).value)),
                            'DID controller is allowed to update the DID only');
    __compactRuntime.assert(_descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                                      partialProofData,
                                                                                      [
                                                                                       { dup: { n: 0 } },
                                                                                       { idx: { cached: false,
                                                                                                pushPath: false,
                                                                                                path: [
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(1n),
                                                                                                                  alignment: _descriptor_25.alignment() } },
                                                                                                       { tag: 'value',
                                                                                                         value: { value: _descriptor_25.toValue(6n),
                                                                                                                  alignment: _descriptor_25.alignment() } }] } },
                                                                                       { popeq: { cached: false,
                                                                                                  result: undefined } }]).value),
                            'DID is already inactive');
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(6n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(false),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(5n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_1.toValue(true),
                                                                                              alignment: _descriptor_1.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
                                       { ins: { cached: true, n: 1 } }]);
    const tmp_0 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(7n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_0),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_1 = 1n;
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } },
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(2n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { addi: { immediate: parseInt(__compactRuntime.valueToBigInt(
                                                              { value: _descriptor_2.toValue(tmp_1),
                                                                alignment: _descriptor_2.alignment() }
                                                                .value
                                                            )) } },
                                       { ins: { cached: true, n: 2 } }]);
    const tmp_2 = this._currentTimestamp_0(context, partialProofData);
    __compactRuntime.queryLedgerState(context,
                                      partialProofData,
                                      [
                                       { idx: { cached: false,
                                                pushPath: true,
                                                path: [
                                                       { tag: 'value',
                                                         value: { value: _descriptor_25.toValue(1n),
                                                                  alignment: _descriptor_25.alignment() } }] } },
                                       { push: { storage: false,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_25.toValue(4n),
                                                                                              alignment: _descriptor_25.alignment() }).encode() } },
                                       { push: { storage: true,
                                                 value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(tmp_2),
                                                                                              alignment: _descriptor_5.alignment() }).encode() } },
                                       { ins: { cached: false, n: 1 } },
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
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_3(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
    return true;
  }
  _equal_4(x0, y0) {
    if (!x0.every((x, i) => y0[i] === x)) { return false; }
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
    get contractVersion() {
      return _descriptor_24.fromValue(__compactRuntime.queryLedgerState(context,
                                                                        partialProofData,
                                                                        [
                                                                         { dup: { n: 0 } },
                                                                         { idx: { cached: false,
                                                                                  pushPath: false,
                                                                                  path: [
                                                                                         { tag: 'value',
                                                                                           value: { value: _descriptor_25.toValue(0n),
                                                                                                    alignment: _descriptor_25.alignment() } },
                                                                                         { tag: 'value',
                                                                                           value: { value: _descriptor_25.toValue(0n),
                                                                                                    alignment: _descriptor_25.alignment() } }] } },
                                                                         { popeq: { cached: false,
                                                                                    result: undefined } }]).value);
    },
    get controllerPublicKey() {
      return _descriptor_0.fromValue(__compactRuntime.queryLedgerState(context,
                                                                       partialProofData,
                                                                       [
                                                                        { dup: { n: 0 } },
                                                                        { idx: { cached: false,
                                                                                 pushPath: false,
                                                                                 path: [
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_25.toValue(0n),
                                                                                                   alignment: _descriptor_25.alignment() } },
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_25.toValue(1n),
                                                                                                   alignment: _descriptor_25.alignment() } }] } },
                                                                        { popeq: { cached: false,
                                                                                   result: undefined } }]).value);
    },
    get id() {
      return _descriptor_23.fromValue(__compactRuntime.queryLedgerState(context,
                                                                        partialProofData,
                                                                        [
                                                                         { dup: { n: 0 } },
                                                                         { idx: { cached: false,
                                                                                  pushPath: false,
                                                                                  path: [
                                                                                         { tag: 'value',
                                                                                           value: { value: _descriptor_25.toValue(1n),
                                                                                                    alignment: _descriptor_25.alignment() } },
                                                                                         { tag: 'value',
                                                                                           value: { value: _descriptor_25.toValue(0n),
                                                                                                    alignment: _descriptor_25.alignment() } }] } },
                                                                         { popeq: { cached: false,
                                                                                    result: undefined } }]).value);
    },
    alsoKnownAs: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(0n),
                                                                                                                                 alignment: _descriptor_5.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          'size',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      member(...args_0) {
        if (args_0.length !== 1) {
          throw new __compactRuntime.CompactError(`member: expected 1 argument, received ${args_0.length}`);
        }
        const elem_0 = args_0[0];
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(elem_0),
                                                                                                                                 alignment: _descriptor_3.alignment() }).encode() } },
                                                                          'member',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      [Symbol.iterator](...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`iter: expected 0 arguments, received ${args_0.length}`);
        }
        const self_0 = state.asArray()[1].asArray()[1];
        return self_0.asMap().keys().map((elem) => _descriptor_3.fromValue(elem.value))[Symbol.iterator]();
      }
    },
    get version() {
      return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                       partialProofData,
                                                                       [
                                                                        { dup: { n: 0 } },
                                                                        { idx: { cached: false,
                                                                                 pushPath: false,
                                                                                 path: [
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_25.toValue(1n),
                                                                                                   alignment: _descriptor_25.alignment() } },
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_25.toValue(2n),
                                                                                                   alignment: _descriptor_25.alignment() } }] } },
                                                                        { popeq: { cached: true,
                                                                                   result: undefined } }]).value);
    },
    get created() {
      return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                       partialProofData,
                                                                       [
                                                                        { dup: { n: 0 } },
                                                                        { idx: { cached: false,
                                                                                 pushPath: false,
                                                                                 path: [
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_25.toValue(1n),
                                                                                                   alignment: _descriptor_25.alignment() } },
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_25.toValue(3n),
                                                                                                   alignment: _descriptor_25.alignment() } }] } },
                                                                        { popeq: { cached: false,
                                                                                   result: undefined } }]).value);
    },
    get updated() {
      return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                       partialProofData,
                                                                       [
                                                                        { dup: { n: 0 } },
                                                                        { idx: { cached: false,
                                                                                 pushPath: false,
                                                                                 path: [
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_25.toValue(1n),
                                                                                                   alignment: _descriptor_25.alignment() } },
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_25.toValue(4n),
                                                                                                   alignment: _descriptor_25.alignment() } }] } },
                                                                        { popeq: { cached: false,
                                                                                   result: undefined } }]).value);
    },
    get deactivated() {
      return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                       partialProofData,
                                                                       [
                                                                        { dup: { n: 0 } },
                                                                        { idx: { cached: false,
                                                                                 pushPath: false,
                                                                                 path: [
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_25.toValue(1n),
                                                                                                   alignment: _descriptor_25.alignment() } },
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_25.toValue(5n),
                                                                                                   alignment: _descriptor_25.alignment() } }] } },
                                                                        { popeq: { cached: false,
                                                                                   result: undefined } }]).value);
    },
    get active() {
      return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                       partialProofData,
                                                                       [
                                                                        { dup: { n: 0 } },
                                                                        { idx: { cached: false,
                                                                                 pushPath: false,
                                                                                 path: [
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_25.toValue(1n),
                                                                                                   alignment: _descriptor_25.alignment() } },
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_25.toValue(6n),
                                                                                                   alignment: _descriptor_25.alignment() } }] } },
                                                                        { popeq: { cached: false,
                                                                                   result: undefined } }]).value);
    },
    get operationCount() {
      return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                       partialProofData,
                                                                       [
                                                                        { dup: { n: 0 } },
                                                                        { idx: { cached: false,
                                                                                 pushPath: false,
                                                                                 path: [
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_25.toValue(1n),
                                                                                                   alignment: _descriptor_25.alignment() } },
                                                                                        { tag: 'value',
                                                                                          value: { value: _descriptor_25.toValue(7n),
                                                                                                   alignment: _descriptor_25.alignment() } }] } },
                                                                        { popeq: { cached: true,
                                                                                   result: undefined } }]).value);
    },
    verificationMethods: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(8n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(0n),
                                                                                                                                 alignment: _descriptor_5.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(8n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          'size',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      member(...args_0) {
        if (args_0.length !== 1) {
          throw new __compactRuntime.CompactError(`member: expected 1 argument, received ${args_0.length}`);
        }
        const key_0 = args_0[0];
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(8n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(key_0),
                                                                                                                                 alignment: _descriptor_3.alignment() }).encode() } },
                                                                          'member',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      lookup(...args_0) {
        if (args_0.length !== 1) {
          throw new __compactRuntime.CompactError(`lookup: expected 1 argument, received ${args_0.length}`);
        }
        const key_0 = args_0[0];
        return _descriptor_11.fromValue(__compactRuntime.queryLedgerState(context,
                                                                          partialProofData,
                                                                          [
                                                                           { dup: { n: 0 } },
                                                                           { idx: { cached: false,
                                                                                    pushPath: false,
                                                                                    path: [
                                                                                           { tag: 'value',
                                                                                             value: { value: _descriptor_25.toValue(1n),
                                                                                                      alignment: _descriptor_25.alignment() } },
                                                                                           { tag: 'value',
                                                                                             value: { value: _descriptor_25.toValue(8n),
                                                                                                      alignment: _descriptor_25.alignment() } }] } },
                                                                           { idx: { cached: false,
                                                                                    pushPath: false,
                                                                                    path: [
                                                                                           { tag: 'value',
                                                                                             value: { value: _descriptor_3.toValue(key_0),
                                                                                                      alignment: _descriptor_3.alignment() } }] } },
                                                                           { popeq: { cached: false,
                                                                                      result: undefined } }]).value);
      },
      [Symbol.iterator](...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`iter: expected 0 arguments, received ${args_0.length}`);
        }
        const self_0 = state.asArray()[1].asArray()[8];
        return self_0.asMap().keys().map(  (key) => {    const value = self_0.asMap().get(key).asCell();    return [      _descriptor_3.fromValue(key.value),      _descriptor_11.fromValue(value.value)    ];  })[Symbol.iterator]();
      }
    },
    authenticationRelation: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(9n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(0n),
                                                                                                                                 alignment: _descriptor_5.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(9n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          'size',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      member(...args_0) {
        if (args_0.length !== 1) {
          throw new __compactRuntime.CompactError(`member: expected 1 argument, received ${args_0.length}`);
        }
        const elem_0 = args_0[0];
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(9n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(elem_0),
                                                                                                                                 alignment: _descriptor_3.alignment() }).encode() } },
                                                                          'member',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      [Symbol.iterator](...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`iter: expected 0 arguments, received ${args_0.length}`);
        }
        const self_0 = state.asArray()[1].asArray()[9];
        return self_0.asMap().keys().map((elem) => _descriptor_3.fromValue(elem.value))[Symbol.iterator]();
      }
    },
    assertionMethodRelation: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(10n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(0n),
                                                                                                                                 alignment: _descriptor_5.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(10n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          'size',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      member(...args_0) {
        if (args_0.length !== 1) {
          throw new __compactRuntime.CompactError(`member: expected 1 argument, received ${args_0.length}`);
        }
        const elem_0 = args_0[0];
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(10n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(elem_0),
                                                                                                                                 alignment: _descriptor_3.alignment() }).encode() } },
                                                                          'member',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      [Symbol.iterator](...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`iter: expected 0 arguments, received ${args_0.length}`);
        }
        const self_0 = state.asArray()[1].asArray()[10];
        return self_0.asMap().keys().map((elem) => _descriptor_3.fromValue(elem.value))[Symbol.iterator]();
      }
    },
    keyAgreementRelation: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(11n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(0n),
                                                                                                                                 alignment: _descriptor_5.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(11n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          'size',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      member(...args_0) {
        if (args_0.length !== 1) {
          throw new __compactRuntime.CompactError(`member: expected 1 argument, received ${args_0.length}`);
        }
        const elem_0 = args_0[0];
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(11n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(elem_0),
                                                                                                                                 alignment: _descriptor_3.alignment() }).encode() } },
                                                                          'member',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      [Symbol.iterator](...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`iter: expected 0 arguments, received ${args_0.length}`);
        }
        const self_0 = state.asArray()[1].asArray()[11];
        return self_0.asMap().keys().map((elem) => _descriptor_3.fromValue(elem.value))[Symbol.iterator]();
      }
    },
    capabilityInvocationRelation: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(12n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(0n),
                                                                                                                                 alignment: _descriptor_5.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(12n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          'size',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      member(...args_0) {
        if (args_0.length !== 1) {
          throw new __compactRuntime.CompactError(`member: expected 1 argument, received ${args_0.length}`);
        }
        const elem_0 = args_0[0];
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(12n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(elem_0),
                                                                                                                                 alignment: _descriptor_3.alignment() }).encode() } },
                                                                          'member',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      [Symbol.iterator](...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`iter: expected 0 arguments, received ${args_0.length}`);
        }
        const self_0 = state.asArray()[1].asArray()[12];
        return self_0.asMap().keys().map((elem) => _descriptor_3.fromValue(elem.value))[Symbol.iterator]();
      }
    },
    capabilityDelegationRelation: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(13n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(0n),
                                                                                                                                 alignment: _descriptor_5.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(13n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          'size',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      member(...args_0) {
        if (args_0.length !== 1) {
          throw new __compactRuntime.CompactError(`member: expected 1 argument, received ${args_0.length}`);
        }
        const elem_0 = args_0[0];
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(13n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(elem_0),
                                                                                                                                 alignment: _descriptor_3.alignment() }).encode() } },
                                                                          'member',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      [Symbol.iterator](...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`iter: expected 0 arguments, received ${args_0.length}`);
        }
        const self_0 = state.asArray()[1].asArray()[13];
        return self_0.asMap().keys().map((elem) => _descriptor_3.fromValue(elem.value))[Symbol.iterator]();
      }
    },
    services: {
      isEmpty(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`isEmpty: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(14n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          'size',
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_5.toValue(0n),
                                                                                                                                 alignment: _descriptor_5.alignment() }).encode() } },
                                                                          'eq',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      size(...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`size: expected 0 arguments, received ${args_0.length}`);
        }
        return _descriptor_5.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(14n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          'size',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      member(...args_0) {
        if (args_0.length !== 1) {
          throw new __compactRuntime.CompactError(`member: expected 1 argument, received ${args_0.length}`);
        }
        const key_0 = args_0[0];
        return _descriptor_1.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(14n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          { push: { storage: false,
                                                                                    value: __compactRuntime.StateValue.newCell({ value: _descriptor_3.toValue(key_0),
                                                                                                                                 alignment: _descriptor_3.alignment() }).encode() } },
                                                                          'member',
                                                                          { popeq: { cached: true,
                                                                                     result: undefined } }]).value);
      },
      lookup(...args_0) {
        if (args_0.length !== 1) {
          throw new __compactRuntime.CompactError(`lookup: expected 1 argument, received ${args_0.length}`);
        }
        const key_0 = args_0[0];
        return _descriptor_4.fromValue(__compactRuntime.queryLedgerState(context,
                                                                         partialProofData,
                                                                         [
                                                                          { dup: { n: 0 } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(1n),
                                                                                                     alignment: _descriptor_25.alignment() } },
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_25.toValue(14n),
                                                                                                     alignment: _descriptor_25.alignment() } }] } },
                                                                          { idx: { cached: false,
                                                                                   pushPath: false,
                                                                                   path: [
                                                                                          { tag: 'value',
                                                                                            value: { value: _descriptor_3.toValue(key_0),
                                                                                                     alignment: _descriptor_3.alignment() } }] } },
                                                                          { popeq: { cached: false,
                                                                                     result: undefined } }]).value);
      },
      [Symbol.iterator](...args_0) {
        if (args_0.length !== 0) {
          throw new __compactRuntime.CompactError(`iter: expected 0 arguments, received ${args_0.length}`);
        }
        const self_0 = state.asArray()[1].asArray()[14];
        return self_0.asMap().keys().map(  (key) => {    const value = self_0.asMap().get(key).asCell();    return [      _descriptor_3.fromValue(key.value),      _descriptor_4.fromValue(value.value)    ];  })[Symbol.iterator]();
      }
    }
  };
}
const _emptyContext = {
  currentQueryContext: new __compactRuntime.QueryContext(new __compactRuntime.ContractState().data, __compactRuntime.dummyContractAddress())
};
const _dummyContract = new Contract({
  getSchnorrReduction: (...args) => undefined,
  localSecretKey: (...args) => undefined,
  currentTimestamp: (...args) => undefined
});
export const pureCircuits = {
  jubjubSignatureDigestChallenge: (...args_0) => {
    if (args_0.length !== 5) {
      throw new __compactRuntime.CompactError(`jubjubSignatureDigestChallenge: expected 5 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const ann_x_0 = args_0[0];
    const ann_y_0 = args_0[1];
    const pk_x_0 = args_0[2];
    const pk_y_0 = args_0[3];
    const digest_0 = args_0[4];
    if (!(typeof(ann_x_0) === 'bigint' && ann_x_0 >= 0 && ann_x_0 <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('jubjubSignatureDigestChallenge',
                                 'argument 1',
                                 'did.compact line 91 char 1',
                                 'Field',
                                 ann_x_0)
    }
    if (!(typeof(ann_y_0) === 'bigint' && ann_y_0 >= 0 && ann_y_0 <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('jubjubSignatureDigestChallenge',
                                 'argument 2',
                                 'did.compact line 91 char 1',
                                 'Field',
                                 ann_y_0)
    }
    if (!(typeof(pk_x_0) === 'bigint' && pk_x_0 >= 0 && pk_x_0 <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('jubjubSignatureDigestChallenge',
                                 'argument 3',
                                 'did.compact line 91 char 1',
                                 'Field',
                                 pk_x_0)
    }
    if (!(typeof(pk_y_0) === 'bigint' && pk_y_0 >= 0 && pk_y_0 <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('jubjubSignatureDigestChallenge',
                                 'argument 4',
                                 'did.compact line 91 char 1',
                                 'Field',
                                 pk_y_0)
    }
    if (!(Array.isArray(digest_0) && digest_0.length === 4 && digest_0.every((t) => typeof(t) === 'bigint' && t >= 0 && t <= __compactRuntime.MAX_FIELD))) {
      __compactRuntime.typeError('jubjubSignatureDigestChallenge',
                                 'argument 5',
                                 'did.compact line 91 char 1',
                                 'Vector<4, Field>',
                                 digest_0)
    }
    return _dummyContract._jubjubSignatureDigestChallenge_0(ann_x_0,
                                                            ann_y_0,
                                                            pk_x_0,
                                                            pk_y_0,
                                                            digest_0);
  },
  publicKey: (...args_0) => {
    if (args_0.length !== 1) {
      throw new __compactRuntime.CompactError(`publicKey: expected 1 argument (as invoked from Typescript), received ${args_0.length}`);
    }
    const sk_0 = args_0[0];
    if (!(sk_0.buffer instanceof ArrayBuffer && sk_0.BYTES_PER_ELEMENT === 1 && sk_0.length === 32)) {
      __compactRuntime.typeError('publicKey',
                                 'argument 1',
                                 'did.compact line 114 char 1',
                                 'Bytes<32>',
                                 sk_0)
    }
    return _dummyContract._publicKey_0(sk_0);
  },
  verifyJubjubSignature: (...args_0) => {
    if (args_0.length !== 3) {
      throw new __compactRuntime.CompactError(`verifyJubjubSignature: expected 3 arguments (as invoked from Typescript), received ${args_0.length}`);
    }
    const pk_0 = args_0[0];
    const signature_0 = args_0[1];
    const challenge_0 = args_0[2];
    if (!(typeof(signature_0) === 'object' && true && typeof(signature_0.s) === 'bigint' && signature_0.s >= 0 && signature_0.s <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('verifyJubjubSignature',
                                 'argument 2',
                                 'did.compact line 118 char 1',
                                 'struct JubjubSignature<r: Opaque<"JubjubPoint">, s: Field>',
                                 signature_0)
    }
    if (!(typeof(challenge_0) === 'bigint' && challenge_0 >= 0 && challenge_0 <= __compactRuntime.MAX_FIELD)) {
      __compactRuntime.typeError('verifyJubjubSignature',
                                 'argument 3',
                                 'did.compact line 118 char 1',
                                 'Field',
                                 challenge_0)
    }
    return _dummyContract._verifyJubjubSignature_0(pk_0,
                                                   signature_0,
                                                   challenge_0);
  }
};
export const contractReferenceLocations =
  { tag: 'publicLedgerArray', indices: { } };
