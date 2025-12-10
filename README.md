# GammaHedge Coverage Protocol

EVM-based delta-neutral coverage protocol with senior/junior capital structure and prediction market hedging.

## Overview

GammaHedge provides parametric insurance coverage for binary events (e.g., "BTC below $60k") while maintaining delta-neutral positioning through prediction market hedging. The protocol features a two-tier capital structure with automatic loss allocation between junior and senior pools.

## Architecture

### Core Components

- **CoveragePool** - ERC4626 vault for junior LP capital, sells coverage and manages hedges
- **ReinsuranceVault** - Senior capital pool that covers losses above configurable retention threshold  
- **CoverageToken** - ERC1155 tokens representing coverage positions for specific events
- **HedgeEngine** - Manages YES/NO token positions across multiple prediction market venues
- **PolymarketAdapter** - Venue adapter for Polymarket/Gnosis Conditional Tokens Framework

### Key Mechanics

**Delta-Neutral Hedging:**
- For each coverage unit sold, protocol buys `h * K` YES tokens where `h` = hedge ratio, `K` = strike
- Premium = hedge cost + reserves + protocol fee: `π = K·p·h + K·r + K·f`

**Senior/Junior Structure:**
- Junior pool (LPs) bears first X% of losses (`poolRetentionWad`)
- Senior pool (reinsurance) covers losses above X% up to per-event limit
- Trigger: `losses > preEventAssets * poolRetentionWad`

## Security Features

✅ **Comprehensive security hardening implemented:**
- ReentrancyGuard on all external calls
- Integer overflow protection via SafeMath
- Role-based access controls (MINTER_ROLE, BURNER_ROLE, etc.)
- Multi-oracle consensus with confidence scoring
- Governance delays on parameter changes
- Emergency pause functionality
- Input validation and slippage protection

## Deployment Status

**Contracts:** ✅ Implemented with security fixes  
**Testing:** 🔄 In progress  
**Audits:** ⏳ Pending  
**Frontend:** ⏳ Planned  

## Risk Parameters

- `h` (hedge ratio): Fraction of liability hedged via prediction markets (0.5-1.0)
- `r` (reserve ratio): Fraction allocated to per-product reserves (0-0.1) 
- `f` (fee ratio): Protocol revenue fraction (0-0.05)
- `X` (pool retention): LP drawdown before reinsurance kicks in (0-1)

## Development

```bash
# Install dependencies
npm install

# Compile contracts
npx hardhat compile

# Run tests
npx hardhat test

# Deploy to testnet
npx hardhat run scripts/deploy.js --network sepolia
```

## License

MIT