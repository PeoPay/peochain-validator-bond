# ADR 002: Consensus Performance Tracking Methodology

## Status
- Proposed
- Date: 2025-05-12
- Deciders: Daniil Krizhanovskyi, Dan Otieno

## Context
Accurate and fair performance tracking of validators is crucial for the network's health and reward distribution. The system needs to measure validator performance based on objective, consensus-related metrics without introducing subjective elements.

## Decision
Implement a performance tracking system that:
- Focuses solely on consensus-related metrics (block proposals, attestations, etc.)
- Uses cryptographically verifiable data points
- Implements a rolling window for performance calculation
- Provides real-time performance monitoring with historical data retention

## Consequences
### Positive
- Objective and transparent performance metrics
- Verifiable calculations
- Fair reward distribution
- Clear slashing conditions

### Negative
- Limited ability to measure qualitative aspects
- Higher storage requirements for historical data
- Increased computational overhead for real-time tracking

### Neutral
- Regular recalibration of performance thresholds may be needed
- Validators need to maintain performance monitoring tools

## Alternatives Considered
1. Reputation-based scoring system
2. Peer-review performance evaluation
3. Simple uptime-based tracking

## Notes and References
- Related documents: Performance Monitoring Service Specification
- Future implications: Integration with cross-chain validation metrics
