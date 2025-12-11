// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

// Oracle interfaces
interface IUMAOracle {
    function hasPrice(bytes32 identifier, uint256 time) external view returns (bool);
    function getPrice(bytes32 identifier, uint256 time) external view returns (int256);
}

interface IChainlinkOracle {
    function latestRoundData() external view returns (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    );
}

interface IRealityETH {
    function resultFor(bytes32 questionId) external view returns (bytes32);
    function getFinalizeTS(bytes32 questionId) external view returns (uint32);
}

/**
 * @title OracleAdapter
 * @notice Multi-oracle consensus mechanism with dispute resolution
 * @dev Aggregates multiple oracle sources to prevent single point of failure
 */
contract OracleAdapter is AccessControl, ReentrancyGuard, Pausable {
    using SafeMath for uint256;

    // Roles
    bytes32 public constant ORACLE_MANAGER_ROLE = keccak256("ORACLE_MANAGER_ROLE");
    bytes32 public constant DISPUTE_RESOLVER_ROLE = keccak256("DISPUTE_RESOLVER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    // Constants
    uint256 public constant WAD = 1e18;
    uint256 public constant MIN_CONSENSUS_THRESHOLD = 2; // Minimum oracles needed
    uint256 public constant MAX_ORACLES_PER_EVENT = 5;
    uint256 public constant DISPUTE_PERIOD = 24 hours;
    uint256 public constant PRICE_STALENESS_THRESHOLD = 3600; // 1 hour

    // Oracle configuration
    struct Oracle {
        address contractAddress;
        OracleType oracleType;
        uint256 weight;           // Voting weight (1-100)
        bool active;
        string name;
        uint256 lastUpdate;
    }

    enum OracleType {
        UMA,
        CHAINLINK, 
        REALITY_ETH,
        CUSTOM
    }

    // Event outcome tracking
    struct EventOutcome {
        bool resolved;
        bool outcome;             // Final consensus outcome
        uint256 confidence;       // Confidence score (0-1e18)
        uint256 resolvedAt;       // Resolution timestamp
        uint256 disputeEndTime;   // When dispute period ends
        bool disputed;            // Whether outcome is disputed
        uint256 consensusWeight;  // Total weight of agreeing oracles
        mapping(uint256 => bool) oracleVotes; // oracleId => outcome vote
        mapping(uint256 => bool) oracleReported; // oracleId => has reported
    }

    // State
    mapping(bytes32 => Oracle[]) public eventOracles; // eventId => Oracle[]
    mapping(bytes32 => EventOutcome) public eventOutcomes;
    mapping(bytes32 => bool) public supportedEvents;
    
    // Global oracle registry
    Oracle[] public globalOracles;
    mapping(address => uint256) public oracleIndex; // oracle address => index in globalOracles

    // Circuit breaker
    uint256 public maxDailyResolutions = 100;
    uint256 public dailyResolutionCount;
    uint256 public lastResetDay;

    // Events
    event OracleRegistered(uint256 indexed oracleId, address contractAddress, OracleType oracleType);
    event EventOracleConfigured(bytes32 indexed eventId, uint256[] oracleIds, uint256[] weights);
    event OracleReported(bytes32 indexed eventId, uint256 indexed oracleId, bool outcome, uint256 timestamp);
    event ConsensusReached(bytes32 indexed eventId, bool outcome, uint256 confidence);
    event DisputeRaised(bytes32 indexed eventId, uint256 indexed oracleId, string reason);
    event DisputeResolved(bytes32 indexed eventId, bool finalOutcome);
    event CircuitBreakerTriggered(uint256 resolutionCount, uint256 maxAllowed);

    // Errors
    error EventNotSupported();
    error EventAlreadyResolved();
    error InsufficientOracles();
    error OracleNotActive();
    error ConsensusNotReached();
    error DisputePeriodNotEnded();
    error CircuitBreakerActive();
    error InvalidOracleConfiguration();

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ORACLE_MANAGER_ROLE, msg.sender);
        _grantRole(DISPUTE_RESOLVER_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);
    }

    // ========== Oracle Management ==========

    function registerOracle(
        address contractAddress,
        OracleType oracleType,
        uint256 weight,
        string memory name
    ) external onlyRole(ORACLE_MANAGER_ROLE) {
        require(contractAddress != address(0), "Invalid address");
        require(weight > 0 && weight <= 100, "Invalid weight");

        uint256 oracleId = globalOracles.length;
        globalOracles.push(Oracle({
            contractAddress: contractAddress,
            oracleType: oracleType,
            weight: weight,
            active: true,
            name: name,
            lastUpdate: 0
        }));

        oracleIndex[contractAddress] = oracleId;

        emit OracleRegistered(oracleId, contractAddress, oracleType);
    }

    function configureEventOracles(
        bytes32 eventId,
        uint256[] memory oracleIds,
        uint256[] memory weights
    ) external onlyRole(ORACLE_MANAGER_ROLE) {
        require(oracleIds.length >= MIN_CONSENSUS_THRESHOLD, "Not enough oracles");
        require(oracleIds.length <= MAX_ORACLES_PER_EVENT, "Too many oracles");
        require(oracleIds.length == weights.length, "Array length mismatch");

        // Clear existing configuration
        delete eventOracles[eventId];

        uint256 totalWeight = 0;
        for (uint256 i = 0; i < oracleIds.length; i++) {
            require(oracleIds[i] < globalOracles.length, "Invalid oracle ID");
            require(globalOracles[oracleIds[i]].active, "Oracle not active");
            require(weights[i] > 0 && weights[i] <= 100, "Invalid weight");

            Oracle memory oracle = globalOracles[oracleIds[i]];
            oracle.weight = weights[i]; // Override with event-specific weight
            
            eventOracles[eventId].push(oracle);
            totalWeight = totalWeight.add(weights[i]);
        }

        require(totalWeight >= 51, "Insufficient total weight"); // Majority threshold
        supportedEvents[eventId] = true;

        emit EventOracleConfigured(eventId, oracleIds, weights);
    }

    // ========== Oracle Reporting ==========

    function reportOutcome(
        bytes32 eventId,
        bool outcome,
        bytes calldata proof
    ) external nonReentrant whenNotPaused {
        if (!supportedEvents[eventId]) revert EventNotSupported();
        
        EventOutcome storage eventOutcome = eventOutcomes[eventId];
        if (eventOutcome.resolved) revert EventAlreadyResolved();

        // Check circuit breaker
        _checkCircuitBreaker();

        // Find oracle in event configuration
        uint256 oracleId = _findOracleId(eventId, msg.sender);
        if (oracleId == type(uint256).max) revert OracleNotActive();

        // Prevent double reporting
        require(!eventOutcome.oracleReported[oracleId], "Oracle already reported");

        // Validate oracle-specific proof
        bool validProof = _validateOracleProof(eventId, oracleId, outcome, proof);
        require(validProof, "Invalid oracle proof");

        // Record vote
        eventOutcome.oracleVotes[oracleId] = outcome;
        eventOutcome.oracleReported[oracleId] = true;

        Oracle[] memory oracles = eventOracles[eventId];
        globalOracles[oracleId].lastUpdate = block.timestamp;

        emit OracleReported(eventId, oracleId, outcome, block.timestamp);

        // Check for consensus
        _checkConsensus(eventId);
    }

    function _findOracleId(bytes32 eventId, address oracleAddress) internal view returns (uint256) {
        Oracle[] memory oracles = eventOracles[eventId];
        for (uint256 i = 0; i < oracles.length; i++) {
            if (oracles[i].contractAddress == oracleAddress && oracles[i].active) {
                return i;
            }
        }
        return type(uint256).max; // Not found
    }

    function _validateOracleProof(
        bytes32 eventId,
        uint256 oracleId,
        bool outcome,
        bytes calldata proof
    ) internal view returns (bool) {
        Oracle[] memory oracles = eventOracles[eventId];
        Oracle memory oracle = oracles[oracleId];

        if (oracle.oracleType == OracleType.UMA) {
            return _validateUMAProof(eventId, oracle.contractAddress, outcome, proof);
        } else if (oracle.oracleType == OracleType.CHAINLINK) {
            return _validateChainlinkProof(eventId, oracle.contractAddress, outcome, proof);
        } else if (oracle.oracleType == OracleType.REALITY_ETH) {
            return _validateRealityETHProof(eventId, oracle.contractAddress, outcome, proof);
        }
        
        return true; // Custom oracles default to valid
    }

    function _validateUMAProof(
        bytes32 eventId,
        address oracleAddress,
        bool outcome,
        bytes calldata proof
    ) internal view returns (bool) {
        // Decode UMA proof
        (bytes32 identifier, uint256 timestamp) = abi.decode(proof, (bytes32, uint256));
        
        IUMAOracle uma = IUMAOracle(oracleAddress);
        if (!uma.hasPrice(identifier, timestamp)) return false;
        
        int256 price = uma.getPrice(identifier, timestamp);
        bool umaOutcome = price > 0;
        
        return umaOutcome == outcome;
    }

    function _validateChainlinkProof(
        bytes32 eventId,
        address oracleAddress,
        bool outcome,
        bytes calldata proof
    ) internal view returns (bool) {
        IChainlinkOracle chainlink = IChainlinkOracle(oracleAddress);
        (, int256 answer, , uint256 updatedAt,) = chainlink.latestRoundData();
        
        // Check staleness
        if (block.timestamp > updatedAt + PRICE_STALENESS_THRESHOLD) return false;
        
        // Decode threshold from proof
        int256 threshold = abi.decode(proof, (int256));
        bool chainlinkOutcome = answer < threshold; // e.g., BTC < 60k
        
        return chainlinkOutcome == outcome;
    }

    function _validateRealityETHProof(
        bytes32 eventId,
        address oracleAddress,
        bool outcome,
        bytes calldata proof
    ) internal view returns (bool) {
        bytes32 questionId = abi.decode(proof, (bytes32));
        
        IRealityETH reality = IRealityETH(oracleAddress);
        uint32 finalizeTS = reality.getFinalizeTS(questionId);
        
        if (finalizeTS == 0 || finalizeTS > block.timestamp) return false;
        
        bytes32 result = reality.resultFor(questionId);
        bool realityOutcome = uint256(result) > 0;
        
        return realityOutcome == outcome;
    }

    // ========== Consensus Logic ==========

    function _checkConsensus(bytes32 eventId) internal {
        EventOutcome storage eventOutcome = eventOutcomes[eventId];
        Oracle[] memory oracles = eventOracles[eventId];

        uint256 yesWeight = 0;
        uint256 noWeight = 0;
        uint256 totalReported = 0;
        uint256 totalWeight = 0;

        for (uint256 i = 0; i < oracles.length; i++) {
            totalWeight = totalWeight.add(oracles[i].weight);
            
            if (eventOutcome.oracleReported[i]) {
                totalReported++;
                if (eventOutcome.oracleVotes[i]) {
                    yesWeight = yesWeight.add(oracles[i].weight);
                } else {
                    noWeight = noWeight.add(oracles[i].weight);
                }
            }
        }

        // Need majority of oracles to report
        if (totalReported < oracles.length.mul(51).div(100)) return;

        // Determine consensus
        bool consensusOutcome;
        uint256 consensusWeight;
        
        if (yesWeight > noWeight) {
            consensusOutcome = true;
            consensusWeight = yesWeight;
        } else {
            consensusOutcome = false;
            consensusWeight = noWeight;
        }

        // Need majority weight for consensus
        if (consensusWeight.mul(100) < totalWeight.mul(51)) return;

        // Calculate confidence score
        uint256 confidence = consensusWeight.mul(WAD).div(totalWeight);

        // Finalize outcome
        eventOutcome.resolved = true;
        eventOutcome.outcome = consensusOutcome;
        eventOutcome.confidence = confidence;
        eventOutcome.resolvedAt = block.timestamp;
        eventOutcome.disputeEndTime = block.timestamp.add(DISPUTE_PERIOD);
        eventOutcome.consensusWeight = consensusWeight;

        _incrementDailyResolutions();

        emit ConsensusReached(eventId, consensusOutcome, confidence);
    }

    // ========== Dispute Resolution ==========

    function raiseDispute(
        bytes32 eventId,
        string memory reason
    ) external onlyRole(DISPUTE_RESOLVER_ROLE) {
        EventOutcome storage eventOutcome = eventOutcomes[eventId];
        require(eventOutcome.resolved, "Event not resolved");
        require(block.timestamp <= eventOutcome.disputeEndTime, "Dispute period ended");
        require(!eventOutcome.disputed, "Already disputed");

        eventOutcome.disputed = true;
        eventOutcome.disputeEndTime = block.timestamp.add(DISPUTE_PERIOD); // Extend period

        emit DisputeRaised(eventId, 0, reason);
    }

    function resolveDispute(
        bytes32 eventId,
        bool finalOutcome
    ) external onlyRole(DISPUTE_RESOLVER_ROLE) {
        EventOutcome storage eventOutcome = eventOutcomes[eventId];
        require(eventOutcome.disputed, "No active dispute");

        eventOutcome.outcome = finalOutcome;
        eventOutcome.disputed = false;
        eventOutcome.disputeEndTime = block.timestamp;

        emit DisputeResolved(eventId, finalOutcome);
    }

    // ========== Circuit Breaker ==========

    function _checkCircuitBreaker() internal view {
        if (dailyResolutionCount >= maxDailyResolutions) {
            revert CircuitBreakerActive();
        }
    }

    function _incrementDailyResolutions() internal {
        uint256 currentDay = block.timestamp / 1 days;
        if (currentDay > lastResetDay) {
            dailyResolutionCount = 1;
            lastResetDay = currentDay;
        } else {
            dailyResolutionCount++;
        }

        if (dailyResolutionCount >= maxDailyResolutions) {
            emit CircuitBreakerTriggered(dailyResolutionCount, maxDailyResolutions);
        }
    }

    function setMaxDailyResolutions(uint256 _maxDailyResolutions) external onlyRole(EMERGENCY_ROLE) {
        maxDailyResolutions = _maxDailyResolutions;
    }

    // ========== View Functions ==========

    function getEventOutcome(bytes32 eventId) external view returns (bool resolved, bool outcomeYes) {
        EventOutcome storage eventOutcome = eventOutcomes[eventId];
        
        if (!eventOutcome.resolved) return (false, false);
        if (eventOutcome.disputed) return (false, false);
        if (block.timestamp < eventOutcome.disputeEndTime) return (false, false);

        return (true, eventOutcome.outcome);
    }

    function isOracleValid(bytes32 eventId) external view returns (bool) {
        return supportedEvents[eventId] && eventOracles[eventId].length >= MIN_CONSENSUS_THRESHOLD;
    }

    function getConfidenceLevel(bytes32 eventId) external view returns (uint256) {
        EventOutcome storage eventOutcome = eventOutcomes[eventId];
        if (!eventOutcome.resolved || eventOutcome.disputed) return 0;
        return eventOutcome.confidence;
    }

    function getEventOracles(bytes32 eventId) external view returns (Oracle[] memory) {
        return eventOracles[eventId];
    }

    function getConsensusStatus(bytes32 eventId) external view returns (
        bool resolved,
        bool disputed,
        uint256 yesWeight,
        uint256 noWeight,
        uint256 totalWeight,
        uint256 reportedCount
    ) {
        EventOutcome storage eventOutcome = eventOutcomes[eventId];
        Oracle[] memory oracles = eventOracles[eventId];

        resolved = eventOutcome.resolved;
        disputed = eventOutcome.disputed;

        for (uint256 i = 0; i < oracles.length; i++) {
            totalWeight = totalWeight.add(oracles[i].weight);
            
            if (eventOutcome.oracleReported[i]) {
                reportedCount++;
                if (eventOutcome.oracleVotes[i]) {
                    yesWeight = yesWeight.add(oracles[i].weight);
                } else {
                    noWeight = noWeight.add(oracles[i].weight);
                }
            }
        }
    }

    // ========== Emergency Functions ==========

    function pause() external onlyRole(EMERGENCY_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(EMERGENCY_ROLE) {
        _unpause();
    }

    function emergencyResolveEvent(
        bytes32 eventId,
        bool outcome
    ) external onlyRole(EMERGENCY_ROLE) {
        EventOutcome storage eventOutcome = eventOutcomes[eventId];
        eventOutcome.resolved = true;
        eventOutcome.outcome = outcome;
        eventOutcome.confidence = WAD; // 100% confidence for emergency resolution
        eventOutcome.resolvedAt = block.timestamp;
        eventOutcome.disputeEndTime = block.timestamp;
        eventOutcome.disputed = false;
    }
}