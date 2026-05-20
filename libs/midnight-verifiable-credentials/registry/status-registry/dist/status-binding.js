import { pureCircuits, StatusType, } from "@midnight-ntwrk/midnight-did-credentials";
export const buildRegistryBoundStatusBinding = ({ registryRef, statusHandleCommitment, }) => {
    const binding = {
        statusType: StatusType.revocationRegistry,
        registryRef,
        statusHandleCommitment,
    };
    pureCircuits.assertValidRegistryBoundStatusBinding(binding);
    return binding;
};
//# sourceMappingURL=status-binding.js.map