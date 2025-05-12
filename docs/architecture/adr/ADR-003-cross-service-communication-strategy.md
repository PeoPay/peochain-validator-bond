# ADR 003: Cross-Service Communication Strategy

## Status
- Proposed
- Date: 2025-05-12
- Deciders: Daniil Krizhanovskyi, Dan Otieno

## Context
The validator bond marketplace consists of multiple microservices that need to communicate efficiently while maintaining consistency, reliability, and security. The communication strategy must support both synchronous and asynchronous patterns.

## Decision
Implement a hybrid communication strategy:
- gRPC for synchronous service-to-service communication
- Apache Kafka for event-driven asynchronous communication
- GraphQL for frontend-to-backend queries
- Redis for distributed caching and temporary state

## Consequences
### Positive
- High performance with binary protocols
- Strong typing and contract-first development
- Excellent scalability for async operations
- Flexible query capabilities for frontend

### Negative
- Increased system complexity
- Multiple protocols to maintain
- Higher learning curve for developers
- More complex testing requirements

### Neutral
- Need for comprehensive service discovery
- Protocol version management overhead
- Different optimization strategies for each protocol

## Alternatives Considered
1. Pure REST architecture
2. WebSocket-based real-time communication
3. Pure event-driven architecture

## Notes and References
- Related documents: System Architecture Specification
- Future implications: Service mesh integration, cross-datacenter communication
