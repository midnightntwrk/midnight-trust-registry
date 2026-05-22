import {
  createLocalJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  jwtVerify,
  SignJWT,
  type JWK,
  type JWTPayload,
} from "jose";

import {
  EntityStatementPayloadSchema,
  FederationLeafConfigurationInputSchema,
  RecognitionTrustMarkInputSchema,
  SimpleTrustChainSchema,
  TrustMarkPayloadSchema,
  TrustRegistryEntityConfigurationInputSchema,
  AuthorizationSubordinateStatementInputSchema,
  type EntityStatementPayload,
  type FederationLeafConfigurationInput,
  type RecognitionTrustMarkInput,
  type TrustRegistryEntityConfigurationInput,
  type AuthorizationSubordinateStatementInput,
  type TrustMarkPayload,
} from "./schemas.js";

const DEFAULT_EXPIRES_IN_SECONDS = 3600;
type FederationJwkSet = {
  keys: JWK[];
};
type SigningKey = CryptoKey | Uint8Array;

const statementWindow = (
  nowInput: number | undefined,
  expiresInSecondsInput: number | undefined,
): Pick<EntityStatementPayload, "iat" | "exp"> => {
  const iat = nowInput ?? Math.floor(Date.now() / 1000);
  const exp = iat + (expiresInSecondsInput ?? DEFAULT_EXPIRES_IN_SECONDS);

  return { iat, exp };
};

const metadataFromUrl = (
  value: string,
): Pick<EntityStatementPayload, never> & {
  organization_uri?: string;
} => {
  try {
    return {
      organization_uri: new URL(value).toString(),
    };
  } catch {
    return {};
  }
};

export const buildFederationLeafConfigurationPayload = (
  input: FederationLeafConfigurationInput,
): EntityStatementPayload => {
  const parsed = FederationLeafConfigurationInputSchema.parse(input);
  const { iat, exp } = statementWindow(
    parsed.now,
    parsed.expiresInSeconds,
  );

  return EntityStatementPayloadSchema.parse({
    iss: parsed.entityId,
    sub: parsed.entityId,
    iat,
    exp,
    jwks: parsed.publicJwks,
    authority_hints: parsed.authorityHints,
    metadata: {
      federation_entity: {
        organization_name: parsed.organizationName ?? parsed.entityId,
        ...metadataFromUrl(parsed.organizationUri ?? parsed.entityId),
        contacts: parsed.contacts,
      },
    },
  });
};

export const buildTrustRegistryEntityConfigurationPayload = (
  input: TrustRegistryEntityConfigurationInput,
): EntityStatementPayload => {
  const parsed = TrustRegistryEntityConfigurationInputSchema.parse(input);
  const { iat, exp } = statementWindow(parsed.now, parsed.expiresInSeconds);
  const entityId = parsed.registry.serviceEndpoint;
  const fetchEndpoint = `${entityId.replace(/\/$/, "")}/federation/fetch`;

  return EntityStatementPayloadSchema.parse({
    iss: entityId,
    sub: entityId,
    iat,
    exp,
    jwks: parsed.publicJwks,
    authority_hints: parsed.authorityHints,
    metadata: {
      federation_entity: {
        organization_name: parsed.registry.name,
        organization_uri: entityId,
        homepage_uri: entityId,
        policy_uri: parsed.registry.policyUri,
        logo_uri: parsed.registry.logoUri,
        federation_fetch_endpoint: fetchEndpoint,
      },
      midnight_trust_registry: {
        statement_kind: "registry",
        registry_id: parsed.registry.registryId,
        registry_did: parsed.registry.registryDid,
        policy_uri: parsed.registry.policyUri,
        status: parsed.registry.status,
        controller_dids: parsed.registry.controllerDids,
        maintainer_dids: parsed.registry.maintainerDids,
      },
    },
  });
};

export const buildTrustRegistryPublicationMetadata = (input: {
  registry: TrustRegistryEntityConfigurationInput["registry"];
  policyId: string;
  bundle?: AuthorizationSubordinateStatementInput["bundle"];
  policyVersion: string;
}): EntityStatementPayload["metadata"] => {
  const bundle = input.bundle;

  return {
    federation_entity: {
      organization_name: input.registry.name,
      organization_uri: input.registry.serviceEndpoint,
      homepage_uri: input.registry.serviceEndpoint,
      policy_uri: input.registry.policyUri,
      logo_uri: input.registry.logoUri,
      federation_fetch_endpoint: `${input.registry.serviceEndpoint.replace(/\/$/, "")}/federation/fetch`,
    },
    midnight_trust_registry: {
      statement_kind: "registry-publication",
      registry_id: input.registry.registryId,
      registry_did: input.registry.registryDid,
      policy_id: input.policyId,
      policy_version: input.policyVersion,
      policy_uri: input.registry.policyUri,
      status: input.registry.status,
      authorization_bundle: bundle?.authorization !== undefined
        ? bundle
        : undefined,
      recognition_bundle: bundle?.recognition !== undefined
        ? bundle
        : undefined,
    },
  };
};

export const buildTrustRegistrySubordinateStatementPayload = (input: {
  issuerEntityId: string;
  sourceEndpoint: string;
  subjectEntityId: string;
  subjectPublicJwks: FederationJwkSet;
  registry: TrustRegistryEntityConfigurationInput["registry"];
  policyId: string;
  policyVersion: string;
  bundle?: AuthorizationSubordinateStatementInput["bundle"];
  now?: number;
  expiresInSeconds?: number;
}): EntityStatementPayload => {
  const { iat, exp } = statementWindow(input.now, input.expiresInSeconds);

  return EntityStatementPayloadSchema.parse({
    iss: input.issuerEntityId,
    sub: input.subjectEntityId,
    iat,
    exp,
    jwks: input.subjectPublicJwks,
    source_endpoint: input.sourceEndpoint,
    metadata: buildTrustRegistryPublicationMetadata({
      registry: input.registry,
      policyId: input.policyId,
      ...(input.bundle !== undefined ? { bundle: input.bundle } : {}),
      policyVersion: input.policyVersion,
    }),
  });
};

export const buildAuthorizationSubordinateStatementPayload = (
  input: AuthorizationSubordinateStatementInput,
): EntityStatementPayload => {
  const parsed = AuthorizationSubordinateStatementInputSchema.parse(input);
  const authorization = parsed.bundle.authorization;

  if (authorization === undefined) {
    throw new Error("authorization bundle is required");
  }

  const { iat, exp } = statementWindow(parsed.now, parsed.expiresInSeconds);

  return EntityStatementPayloadSchema.parse({
    iss: parsed.issuerEntityId,
    sub: parsed.bundle.subjectDid,
    iat,
    exp,
    jwks: parsed.subjectPublicJwks,
    source_endpoint: parsed.sourceEndpoint,
    metadata: {
      federation_entity: {
        organization_name: parsed.bundle.subjectDid,
        policy_uri: parsed.bundle.policy.policyUri,
      },
      midnight_trust_registry: {
        statement_kind: "authorization",
        registry_id: parsed.bundle.registryId,
        policy_id: parsed.bundle.policy.policyId,
        trust_level: authorization.trustLevel,
        status: authorization.status,
        role: authorization.role,
        resource_type: authorization.resourceType,
        resource_id: authorization.resourceId,
        referenced_status_registry_id: parsed.bundle.referencedStatusRegistryId,
      },
    },
  });
};

export const buildRecognitionTrustMarkPayload = (
  input: RecognitionTrustMarkInput,
): TrustMarkPayload => {
  const parsed = RecognitionTrustMarkInputSchema.parse(input);
  const recognition = parsed.bundle.recognition;

  if (recognition === undefined) {
    throw new Error("recognition bundle is required");
  }

  const { iat, exp } = statementWindow(parsed.now, parsed.expiresInSeconds);

  return TrustMarkPayloadSchema.parse({
    iss: parsed.issuerEntityId,
    sub: parsed.bundle.subjectDid,
    iat,
    exp,
    trust_mark_type: parsed.trustMarkType,
    ref: parsed.ref,
    logo_uri: parsed.logoUri,
    midnight_trust_registry: {
      statement_kind: "recognition",
      registry_id: parsed.bundle.registryId,
      policy_id: parsed.bundle.policy.policyId,
      trust_level: recognition.trustLevel,
      status: recognition.status,
      recognized_registry_id: recognition.recognizedRegistryId,
      scope_resource_type: recognition.scope.resourceType,
      scope_resource_id: recognition.scope.resourceId,
    },
  });
};

export const signTrustMark = async (input: {
  payload: TrustMarkPayload;
  privateKey: SigningKey;
  kid: string;
  alg: string;
}): Promise<string> => {
  const payload = TrustMarkPayloadSchema.parse(input.payload);

  return new SignJWT(payload as JWTPayload)
    .setProtectedHeader({
      typ: "trust-mark+jwt",
      alg: input.alg,
      kid: input.kid,
    })
    .sign(input.privateKey);
};

const parseTrustMarkJwt = (jwt: string): TrustMarkPayload =>
  TrustMarkPayloadSchema.parse(decodeJwt(jwt));

export const verifyTrustMark = async (input: {
  jwt: string;
  jwks: FederationJwkSet;
}): Promise<TrustMarkPayload> => {
  const result = await jwtVerify(input.jwt, createLocalJWKSet(input.jwks), {
    typ: "trust-mark+jwt",
  });

  return TrustMarkPayloadSchema.parse(result.payload);
};

const assertTrustMarkHeader = (jwt: string): void => {
  const header = decodeProtectedHeader(jwt);
  if (header.typ !== "trust-mark+jwt") {
    throw new Error("trust mark is missing trust-mark+jwt type");
  }
};

export const parseSignedTrustMark = (jwt: string): TrustMarkPayload => {
  assertTrustMarkHeader(jwt);
  return parseTrustMarkJwt(jwt);
};

export const parseSignedEntityStatement = (
  jwt: string,
): EntityStatementPayload => {
  const header = decodeProtectedHeader(jwt);
  if (header.typ !== "entity-statement+jwt") {
    throw new Error("entity statement is missing entity-statement+jwt type");
  }

  return parseEntityStatementJwt(jwt);
};

export const buildRecognitionMetadataProjection = (
  input: RecognitionTrustMarkInput,
): EntityStatementPayload["metadata"] => {
  const parsed = RecognitionTrustMarkInputSchema.parse(input);
  const recognition = parsed.bundle.recognition;

  if (recognition === undefined) {
    throw new Error("recognition bundle is required");
  }

  return {
    midnight_trust_registry: {
      statement_kind: "recognition",
      registry_id: parsed.bundle.registryId,
      policy_id: parsed.bundle.policy.policyId,
      trust_level: recognition.trustLevel,
      status: recognition.status,
      recognized_registry_id: recognition.recognizedRegistryId,
      scope_resource_type: recognition.scope.resourceType,
      scope_resource_id: recognition.scope.resourceId,
    },
    federation_entity: {
      organization_name: parsed.bundle.subjectDid,
      policy_uri: parsed.bundle.policy.policyUri,
    },
  };
};

export const signEntityStatement = async (input: {
  payload: EntityStatementPayload;
  privateKey: SigningKey;
  kid: string;
  alg: string;
}): Promise<string> => {
  const payload = EntityStatementPayloadSchema.parse(input.payload);

  return new SignJWT(payload as JWTPayload)
    .setProtectedHeader({
      typ: "entity-statement+jwt",
      alg: input.alg,
      kid: input.kid,
    })
    .sign(input.privateKey);
};

const parseEntityStatementJwt = (jwt: string): EntityStatementPayload =>
  EntityStatementPayloadSchema.parse(decodeJwt(jwt));

const verifyWithJwks = async (
  jwt: string,
  jwks: FederationJwkSet,
): Promise<EntityStatementPayload> => {
  const result = await jwtVerify(jwt, createLocalJWKSet(jwks), {
    typ: "entity-statement+jwt",
  });

  return EntityStatementPayloadSchema.parse(result.payload);
};

export const verifyEntityStatement = async (input: {
  jwt: string;
  jwks: FederationJwkSet;
}): Promise<EntityStatementPayload> =>
  verifyWithJwks(input.jwt, input.jwks);

export const verifySimpleTrustChain = async (
  chainInput: string[],
): Promise<EntityStatementPayload[]> => {
  const chain = SimpleTrustChainSchema.parse(chainInput);
  const decodedPayloads = chain.map(parseEntityStatementJwt);

  for (const jwt of chain) {
    const header = decodeProtectedHeader(jwt);
    if (header.typ !== "entity-statement+jwt") {
      throw new Error("trust chain member is missing entity-statement+jwt type");
    }
  }

  for (let index = 0; index < chain.length - 1; index += 1) {
    const current = decodedPayloads[index];
    const next = decodedPayloads[index + 1];
    const currentJwt = chain[index];

    if (current === undefined || next === undefined || currentJwt === undefined) {
      throw new Error("trust chain contains an unexpected empty slot");
    }

    if (current.iss !== next.sub) {
      throw new Error("trust chain iss/sub linkage is invalid");
    }

    await verifyWithJwks(currentJwt, next.jwks as FederationJwkSet);
  }

  const trustAnchor = decodedPayloads.at(-1);
  const trustAnchorJwt = chain.at(-1);
  if (trustAnchor === undefined || trustAnchorJwt === undefined) {
    throw new Error("trust chain cannot be empty");
  }
  await verifyWithJwks(trustAnchorJwt, trustAnchor.jwks as FederationJwkSet);

  const leaf = decodedPayloads[0];
  const superior = decodedPayloads[1];
  if (leaf === undefined || superior === undefined) {
    throw new Error("trust chain must contain a leaf and a superior statement");
  }
  if (
    leaf.authority_hints !== undefined
    && !leaf.authority_hints.includes(superior.iss)
  ) {
    throw new Error("leaf authority_hints do not include the superior issuer");
  }

  return decodedPayloads;
};

export type { JWK };
