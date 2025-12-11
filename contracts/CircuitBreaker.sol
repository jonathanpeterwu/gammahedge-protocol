// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

/**
 * @title CircuitBreaker
 * @notice Automated risk management system with multiple circuit breakers
 * @dev Monitors protocol metrics and automatically triggers emergency stops
 */
contract CircuitBreaker is AccessControl, ReentrancyGuard {
    using SafeMath for uint256;

    // Roles
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    bytes32 public constant RISK_MANAGER_ROLE = keccak256("RISK_MANAGER_ROLE");
    bytes32 public constant PROTOCOL_ROLE = keccak256("PROTOCOL_ROLE");

    // Constants
    uint256 public constant WAD = 1e18;
    uint256 public constant MAX_LOSS_THRESHOLD = 0.5e18; // 50% max loss
    uint256 public constant MIN_COOLDOWN_PERIOD = 1 hours;
    uint256 public constant MAX_COOLDOWN_PERIOD = 7 days;

    // Circuit breaker types
    enum BreakerType {
        POOL_LOSS_RATIO,          // Pool loss exceeds threshold
        DAILY_LOSS_ABSOLUTE,      // Daily losses exceed absolute amount
        ORACLE_FAILURE,           // Oracle consensus failures
        HEDGE_SLIPPAGE,           // Excessive hedge execution slippage
        VOLUME_SPIKE,             // Unusual volume patterns
        CORRELATION_BREAKDOWN,    // Hedge correlation breakdown
        LIQUIDITY_CRISIS          // Market liquidity below threshold
    }

    enum BreakerState {
        ACTIVE,
        TRIGGERED,
        COOLING_DOWN,
        DISABLED
    }

    // Circuit breaker configuration
    struct CircuitBreakerConfig {
        BreakerType breakerType;
        uint256 threshold;        // Threshold value (different units per type)
        uint256 windowPeriod;     // Time window for measurement
        uint256 cooldownPeriod;   // Cooldown after trigger
        bool enabled;
        string description;
    }

    // Breaker state tracking
    struct BreakerState {
        BreakerState state;
        uint256 triggeredAt;
        uint256 coolingDownUntil;
        uint256 triggerCount;
        uint256 lastMeasurement;
        bool emergencyStop;       // Forces protocol pause
    }

    // State variables
    mapping(uint256 => CircuitBreakerConfig) public breakerConfigs;
    mapping(uint256 => BreakerState) public breakerStates;
    uint256 public breakerCount;

    // Measurement windows
    struct MeasurementWindow {
        uint256[] values;
        uint256[] timestamps;
        uint256 head;
        uint256 size;
        uint256 maxSize;
    }

    mapping(uint256 => MeasurementWindow) public measurementWindows;

    // Protocol contracts for monitoring
    address public coveragePool;
    address public reinsuranceVault;
    address public hedgeEngine;
    address public oracleAdapter;

    // Emergency state
    bool public globalEmergencyStop;
    uint256 public emergencyStopTime;
    address public emergencyContact;

    // Risk metrics
    struct RiskMetrics {
        uint256 poolLossRatio;          // Current pool loss ratio
        uint256 dailyLossAbsolute;      // Losses in current day
        uint256 oracleFailureRate;      // Oracle failure rate
        uint256 avgHedgeSlippage;       // Average hedge slippage
        uint256 volumeMultiplier;       // Volume vs baseline
        uint256 hedgeCorrelation;       // Hedge effectiveness
        uint256 marketLiquidity;        // Available market liquidity
        uint256 lastUpdate;
    }

    RiskMetrics public currentMetrics;

    // Events
    event CircuitBreakerConfigured(uint256 indexed breakerId, BreakerType breakerType, uint256 threshold);
    event CircuitBreakerTriggered(uint256 indexed breakerId, uint256 measurement, uint256 threshold, string reason);
    event CircuitBreakerReset(uint256 indexed breakerId);
    event GlobalEmergencyStop(address indexed trigger, string reason);
    event EmergencyStopLifted(address indexed lifter);
    event RiskMetricsUpdated(uint256 poolLossRatio, uint256 dailyLoss, uint256 timestamp);

    // Errors
    error CircuitBreakerTriggered(uint256 breakerId, string reason);
    error GlobalEmergencyActive();
    error InsufficientPermissions();
    error InvalidConfiguration();
    error BreakerNotTriggered();

    modifier whenNotEmergencyStopped() {
        if (globalEmergencyStop) revert GlobalEmergencyActive();
        _;
    }

    modifier onlyProtocol() {
        if (!hasRole(PROTOCOL_ROLE, msg.sender)) revert InsufficientPermissions();
        _;
    }

    constructor(
        address _coveragePool,
        address _reinsuranceVault, 
        address _hedgeEngine,
        address _oracleAdapter
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(EMERGENCY_ROLE, msg.sender);
        _grantRole(RISK_MANAGER_ROLE, msg.sender);

        coveragePool = _coveragePool;
        reinsuranceVault = _reinsuranceVault;
        hedgeEngine = _hedgeEngine;
        oracleAdapter = _oracleAdapter;

        _initializeDefaultBreakers();
    }

    // ========== Circuit Breaker Configuration ==========

    function configureCircuitBreaker(
        BreakerType breakerType,
        uint256 threshold,
        uint256 windowPeriod,
        uint256 cooldownPeriod,
        bool enabled,
        string memory description
    ) external onlyRole(RISK_MANAGER_ROLE) {
        if (threshold == 0 || windowPeriod == 0) revert InvalidConfiguration();
        if (cooldownPeriod < MIN_COOLDOWN_PERIOD || cooldownPeriod > MAX_COOLDOWN_PERIOD) revert InvalidConfiguration();

        uint256 breakerId = breakerCount++;
        
        breakerConfigs[breakerId] = CircuitBreakerConfig({
            breakerType: breakerType,
            threshold: threshold,
            windowPeriod: windowPeriod,
            cooldownPeriod: cooldownPeriod,
            enabled: enabled,
            description: description
        });

        breakerStates[breakerId] = BreakerState({
            state: enabled ? BreakerState.ACTIVE : BreakerState.DISABLED,
            triggeredAt: 0,
            coolingDownUntil: 0,
            triggerCount: 0,
            lastMeasurement: 0,
            emergencyStop: _shouldTriggerEmergencyStop(breakerType)
        });

        _initializeMeasurementWindow(breakerId, windowPeriod);

        emit CircuitBreakerConfigured(breakerId, breakerType, threshold);
    }

    function _shouldTriggerEmergencyStop(BreakerType breakerType) internal pure returns (bool) {
        return breakerType == BreakerType.POOL_LOSS_RATIO || 
               breakerType == BreakerType.LIQUIDITY_CRISIS ||
               breakerType == BreakerType.ORACLE_FAILURE;
    }

    function _initializeMeasurementWindow(uint256 breakerId, uint256 windowPeriod) internal {
        uint256 maxSize = windowPeriod.div(300); // 5 minute intervals
        if (maxSize < 10) maxSize = 10;
        if (maxSize > 288) maxSize = 288; // Max 24 hours of 5-min intervals

        measurementWindows[breakerId].maxSize = maxSize;
        measurementWindows[breakerId].values = new uint256[](maxSize);
        measurementWindows[breakerId].timestamps = new uint256[](maxSize);
    }

    // ========== Risk Monitoring ==========

    function updateRiskMetrics(
        uint256 poolLossRatio,
        uint256 dailyLossAbsolute,
        uint256 oracleFailureRate,
        uint256 avgHedgeSlippage,
        uint256 volumeMultiplier,
        uint256 hedgeCorrelation,
        uint256 marketLiquidity
    ) external onlyProtocol nonReentrant {
        currentMetrics = RiskMetrics({
            poolLossRatio: poolLossRatio,
            dailyLossAbsolute: dailyLossAbsolute,
            oracleFailureRate: oracleFailureRate,
            avgHedgeSlippage: avgHedgeSlippage,
            volumeMultiplier: volumeMultiplier,
            hedgeCorrelation: hedgeCorrelation,
            marketLiquidity: marketLiquidity,
            lastUpdate: block.timestamp
        });

        // Check all active circuit breakers
        _checkAllCircuitBreakers();

        emit RiskMetricsUpdated(poolLossRatio, dailyLossAbsolute, block.timestamp);
    }

    function _checkAllCircuitBreakers() internal {
        for (uint256 i = 0; i < breakerCount; i++) {
            if (breakerStates[i].state == BreakerState.ACTIVE) {
                _checkCircuitBreaker(i);
            } else if (breakerStates[i].state == BreakerState.COOLING_DOWN) {
                _checkCooldownExpiry(i);
            }
        }
    }

    function _checkCircuitBreaker(uint256 breakerId) internal {
        CircuitBreakerConfig memory config = breakerConfigs[breakerId];
        if (!config.enabled) return;

        uint256 measurement = _getMeasurementForBreaker(config.breakerType);
        _addMeasurement(breakerId, measurement);

        uint256 aggregatedValue = _calculateWindowAggregation(breakerId, config.breakerType);
        
        if (_shouldTrigger(config.breakerType, aggregatedValue, config.threshold)) {
            _triggerCircuitBreaker(breakerId, aggregatedValue, config.threshold);
        }
    }

    function _getMeasurementForBreaker(BreakerType breakerType) internal view returns (uint256) {
        if (breakerType == BreakerType.POOL_LOSS_RATIO) {
            return currentMetrics.poolLossRatio;
        } else if (breakerType == BreakerType.DAILY_LOSS_ABSOLUTE) {
            return currentMetrics.dailyLossAbsolute;
        } else if (breakerType == BreakerType.ORACLE_FAILURE) {
            return currentMetrics.oracleFailureRate;
        } else if (breakerType == BreakerType.HEDGE_SLIPPAGE) {
            return currentMetrics.avgHedgeSlippage;
        } else if (breakerType == BreakerType.VOLUME_SPIKE) {
            return currentMetrics.volumeMultiplier;
        } else if (breakerType == BreakerType.CORRELATION_BREAKDOWN) {
            return WAD.sub(currentMetrics.hedgeCorrelation); // Invert for "breakdown"
        } else if (breakerType == BreakerType.LIQUIDITY_CRISIS) {
            return WAD.sub(currentMetrics.marketLiquidity.mul(WAD).div(1000000e6)); // Normalize to WAD
        }
        return 0;
    }

    function _shouldTrigger(
        BreakerType breakerType,
        uint256 measurement,
        uint256 threshold
    ) internal pure returns (bool) {
        // Most breakers trigger when measurement > threshold
        // LIQUIDITY_CRISIS triggers when measurement < threshold (inverted above)
        return measurement > threshold;
    }

    function _calculateWindowAggregation(
        uint256 breakerId,
        BreakerType breakerType
    ) internal view returns (uint256) {
        MeasurementWindow storage window = measurementWindows[breakerId];
        
        if (window.size == 0) return 0;

        if (breakerType == BreakerType.DAILY_LOSS_ABSOLUTE ||
            breakerType == BreakerType.VOLUME_SPIKE) {
            // Sum for absolute measurements
            return _calculateWindowSum(breakerId);
        } else {
            // Average for ratio measurements
            return _calculateWindowAverage(breakerId);
        }
    }

    function _calculateWindowSum(uint256 breakerId) internal view returns (uint256) {
        MeasurementWindow storage window = measurementWindows[breakerId];
        uint256 sum = 0;
        
        for (uint256 i = 0; i < window.size; i++) {
            sum = sum.add(window.values[i]);
        }
        
        return sum;
    }

    function _calculateWindowAverage(uint256 breakerId) internal view returns (uint256) {
        MeasurementWindow storage window = measurementWindows[breakerId];
        if (window.size == 0) return 0;
        
        uint256 sum = _calculateWindowSum(breakerId);
        return sum.div(window.size);
    }

    function _addMeasurement(uint256 breakerId, uint256 value) internal {
        MeasurementWindow storage window = measurementWindows[breakerId];
        
        window.values[window.head] = value;
        window.timestamps[window.head] = block.timestamp;
        
        window.head = (window.head + 1) % window.maxSize;
        
        if (window.size < window.maxSize) {
            window.size++;
        }
    }

    // ========== Circuit Breaker Triggering ==========

    function _triggerCircuitBreaker(
        uint256 breakerId,
        uint256 measurement,
        uint256 threshold
    ) internal {
        BreakerState storage state = breakerStates[breakerId];
        CircuitBreakerConfig memory config = breakerConfigs[breakerId];

        state.state = BreakerState.TRIGGERED;
        state.triggeredAt = block.timestamp;
        state.coolingDownUntil = block.timestamp.add(config.cooldownPeriod);
        state.triggerCount++;
        state.lastMeasurement = measurement;

        string memory reason = string(abi.encodePacked(
            config.description,
            ": ",
            _uint2str(measurement),
            " > ",
            _uint2str(threshold)
        ));

        emit CircuitBreakerTriggered(breakerId, measurement, threshold, reason);

        // Trigger emergency stop if configured
        if (state.emergencyStop && !globalEmergencyStop) {
            _triggerGlobalEmergencyStop(reason);
        }
    }

    function _triggerGlobalEmergencyStop(string memory reason) internal {
        globalEmergencyStop = true;
        emergencyStopTime = block.timestamp;

        emit GlobalEmergencyStop(msg.sender, reason);
    }

    function _checkCooldownExpiry(uint256 breakerId) internal {
        BreakerState storage state = breakerStates[breakerId];
        
        if (block.timestamp >= state.coolingDownUntil) {
            state.state = BreakerState.ACTIVE;
            emit CircuitBreakerReset(breakerId);
        }
    }

    // ========== Emergency Management ==========

    function manualTriggerEmergencyStop(string memory reason) external onlyRole(EMERGENCY_ROLE) {
        _triggerGlobalEmergencyStop(reason);
    }

    function liftEmergencyStop() external onlyRole(EMERGENCY_ROLE) {
        require(globalEmergencyStop, "No emergency stop active");
        
        globalEmergencyStop = false;
        emergencyStopTime = 0;

        emit EmergencyStopLifted(msg.sender);
    }

    function resetCircuitBreaker(uint256 breakerId) external onlyRole(RISK_MANAGER_ROLE) {
        BreakerState storage state = breakerStates[breakerId];
        if (state.state != BreakerState.TRIGGERED) revert BreakerNotTriggered();

        state.state = BreakerState.ACTIVE;
        state.coolingDownUntil = 0;

        emit CircuitBreakerReset(breakerId);
    }

    // ========== Default Configurations ==========

    function _initializeDefaultBreakers() internal {
        // Pool loss ratio breaker - 20% loss triggers emergency
        _configureDefaultBreaker(
            BreakerType.POOL_LOSS_RATIO,
            0.2e18, // 20%
            1 hours,
            4 hours,
            "Pool loss ratio exceeded"
        );

        // Daily loss absolute - $100K daily loss
        _configureDefaultBreaker(
            BreakerType.DAILY_LOSS_ABSOLUTE,
            100000e6, // $100K USDC
            24 hours,
            2 hours,
            "Daily loss limit exceeded"
        );

        // Oracle failure rate - 30% failure rate
        _configureDefaultBreaker(
            BreakerType.ORACLE_FAILURE,
            0.3e18, // 30%
            2 hours,
            1 hours,
            "Oracle failure rate too high"
        );

        // Hedge slippage - 5% average slippage
        _configureDefaultBreaker(
            BreakerType.HEDGE_SLIPPAGE,
            0.05e18, // 5%
            30 minutes,
            30 minutes,
            "Hedge execution slippage too high"
        );

        // Volume spike - 10x normal volume
        _configureDefaultBreaker(
            BreakerType.VOLUME_SPIKE,
            10e18, // 10x
            15 minutes,
            15 minutes,
            "Unusual volume spike detected"
        );

        // Correlation breakdown - 50% correlation loss
        _configureDefaultBreaker(
            BreakerType.CORRELATION_BREAKDOWN,
            0.5e18, // 50%
            1 hours,
            2 hours,
            "Hedge correlation breakdown"
        );

        // Liquidity crisis - 80% liquidity drop
        _configureDefaultBreaker(
            BreakerType.LIQUIDITY_CRISIS,
            0.8e18, // 80%
            5 minutes,
            30 minutes,
            "Market liquidity crisis"
        );
    }

    function _configureDefaultBreaker(
        BreakerType breakerType,
        uint256 threshold,
        uint256 windowPeriod,
        uint256 cooldownPeriod,
        string memory description
    ) internal {
        uint256 breakerId = breakerCount++;
        
        breakerConfigs[breakerId] = CircuitBreakerConfig({
            breakerType: breakerType,
            threshold: threshold,
            windowPeriod: windowPeriod,
            cooldownPeriod: cooldownPeriod,
            enabled: true,
            description: description
        });

        breakerStates[breakerId] = BreakerState({
            state: BreakerState.ACTIVE,
            triggeredAt: 0,
            coolingDownUntil: 0,
            triggerCount: 0,
            lastMeasurement: 0,
            emergencyStop: _shouldTriggerEmergencyStop(breakerType)
        });

        _initializeMeasurementWindow(breakerId, windowPeriod);
    }

    // ========== View Functions ==========

    function checkBreaker(uint256 breakerId) external view whenNotEmergencyStopped {
        BreakerState memory state = breakerStates[breakerId];
        if (state.state == BreakerState.TRIGGERED) {
            revert CircuitBreakerTriggered(breakerId, breakerConfigs[breakerId].description);
        }
    }

    function getAllBreakerStates() external view returns (
        uint256[] memory breakerIds,
        BreakerState[] memory states,
        string[] memory descriptions
    ) {
        breakerIds = new uint256[](breakerCount);
        states = new BreakerState[](breakerCount);
        descriptions = new string[](breakerCount);

        for (uint256 i = 0; i < breakerCount; i++) {
            breakerIds[i] = i;
            states[i] = breakerStates[i].state;
            descriptions[i] = breakerConfigs[i].description;
        }
    }

    // ========== Utility Functions ==========

    function _uint2str(uint256 _i) internal pure returns (string memory) {
        if (_i == 0) return "0";
        
        uint256 j = _i;
        uint256 length;
        while (j != 0) {
            length++;
            j /= 10;
        }
        
        bytes memory bstr = new bytes(length);
        uint256 k = length;
        while (_i != 0) {
            k = k - 1;
            uint8 temp = (48 + uint8(_i - _i / 10 * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        
        return string(bstr);
    }
}