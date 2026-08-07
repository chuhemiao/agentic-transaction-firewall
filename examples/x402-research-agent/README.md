# examples/x402-research-agent

**Status:** the protocol-neutral Agent-Commerce Payment Intent fixture is
implemented and validated; the x402 Adapter scenario itself is not yet
implemented and remains **Phase 3 (reference Adapters)** work (see
`docs/PRD.md` §31).

Reference scenario: x402 Research Agent (PRD §24.3).

`intent.json` in this directory is a standalone fixture matching the PRD
§9.2 example and `atf.agent-commerce.payment` v1.0 Profile. It uses CAIP-2,
CAIP-19 and CAIP-10 identifiers and exists so `atf-cli`'s
`validate-intent`/`evaluate` commands have something to run against before
the rest of this scenario (Adapter, full policy pack, Simulator) exists. It
does not model x402 proof or delivery evidence and is not itself the full
reference scenario.
