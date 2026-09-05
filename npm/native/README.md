# Native release payloads

Release packaging places signed native binaries under the platform/architecture
directory. The first supported payload is `darwin-arm64/zcode-agentd`. `init`
fails closed before changing user state when its required payload is absent.
