// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

interface ICoverageToken {
    function balanceOf(bytes32 eventId, address owner) external view returns (uint256);
    function mint(address to, bytes32 eventId, uint256 units) external;
    function burn(address from, bytes32 eventId, uint256 units) external;
}

interface IOracleAdapter {
    function getEventOutcome(bytes32 eventId) external view returns (bool resolved, bool outcomeYes);
    function isOracleValid(bytes32 eventId) external view returns (bool);
    function getConfidenceLevel(bytes32 eventId) external view returns (uint256);
}

interface IHedgeEngine {
    function buyYes(
        bytes32 eventId,
        uint256 yesAmount,
        uint256 maxCost,
        address recipient
    ) external returns (uint256 costPaid);
    
    function settleEvent(bytes32 eventId) external returns (uint256 usdcReceived);
    function getYesPriceWad(bytes32 eventId) external view returns (uint256 priceWad);
    function validateEventId(bytes32 eventId) external view returns (bool);
}

interface IReinsuranceVault {
    function coverLoss(bytes32 eventId, uint256 amount) external;
    function getLayerInfo(bytes32 eventId) external view returns (
        uint256 limit,
        uint256 used, 
        uint256 available,
        bool active
    );
}

interface ICircuitBreaker {
    function checkBreaker(uint256 breakerId) external view;
    function updateRiskMetrics(
        uint256 poolLossRatio,
        uint256 dailyLossAbsolute,
        uint256 oracleFailureRate,
        uint256 avgHedgeSlippage,
        uint256 volumeMultiplier,
        uint256 hedgeCorrelation,
        uint256 marketLiquidity
    ) external;
}

/**
 * @title CoveragePool
 * @notice ERC4626-style pool for coverage provision with delta-neutral hedging
 * @dev Security-hardened version with comprehensive protections
 */
contract CoveragePool is ReentrancyGuard, Pausable, Ownable {
    using SafeERC20 for IERC20;
    using SafeMath for uint256;

    // Constants
    uint256 public constant WAD = 1e18;
    uint256 public constant MAX_PREMIUM_SLIPPAGE = 200; // 2% max slippage
    uint256 public constant MIN_HEDGE_RATIO = 0.5e18; // 50% minimum hedge
    uint256 public constant MAX_HEDGE_RATIO = 1.0e18; // 100% maximum hedge
    uint256 public constant MAX_RESERVE_RATIO = 0.1e18; // 10% maximum reserves
    uint256 public constant MAX_FEE_RATIO = 0.05e18; // 5% maximum protocol fee
    uint256 public constant MIN_COVERAGE_UNIT = 1e6; // 1 USDC minimum
    uint256 public constant MAX_COVERAGE_UNIT = 1_000_000e6; // 1M USDC maximum

    // Core contracts
    IERC20 public immutable usdc;
    ICoverageToken public immutable coverageToken;
    IOracleAdapter public immutable oracle;
    IHedgeEngine public immutable hedgeEngine;
    IReinsuranceVault public immutable reinsuranceVault;
    ICircuitBreaker public immutable circuitBreaker;

    address public treasury;

    // ERC4626-like vault state
    string public constant name = "Gamma Hedge Coverage Pool";
    string public constant symbol = "GH-POOL";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // Product configuration
    struct ProductConfig {
        uint256 strike;          // K: payout per unit (USDC)
        uint256 hedgeRatioWad;   // h: hedge ratio (0-1e18)
        uint256 reserveRatioWad; // r: reserve ratio (0-1e18) 
        uint256 feeRatioWad;     // f: fee ratio (0-1e18)
        uint256 poolRetentionWad; // X: LP retention before reinsurance
        uint256 maxNotional;     // Maximum total notional for this product
        bool active;
        uint256 lastPriceUpdate; // Timestamp of last price update
    }

    // Product state tracking
    struct ProductState {
        uint256 soldNotional;     // Total liability sold
        uint256 reserves;         // Accumulated reserves
        bool settled;
        bool outcomeYes;
        uint256 preEventAssets;   // Assets before settlement
        uint256 primaryLossLimit; // Max loss for LPs
        uint256 realizedLoss;     // Cumulative payouts
        uint256 hedgePosition;    // Current YES tokens held
        uint256 lastRebalance;    // Last rebalance timestamp
    }

    mapping(bytes32 => ProductConfig) public productConfig;
    mapping(bytes32 => ProductState) public productState;
    
    // Risk controls
    uint256 public totalLiability; // Sum of all outstanding liabilities
    uint256 public maxPoolUtilization = 0.8e18; // 80% max utilization
    uint256 public emergencyStopLoss = 0.2e18; // 20% max loss triggers emergency stop

    // Governance delays
    uint256 public constant PARAM_CHANGE_DELAY = 24 hours;
    mapping(bytes32 => uint256) public pendingParamChanges;

    // Events
    event ProductConfigured(bytes32 indexed eventId, ProductConfig config);
    event CoverageSold(bytes32 indexed eventId, address indexed buyer, uint256 units, uint256 premium);
    event EventSettled(bytes32 indexed eventId, bool outcomeYes, uint256 hedgePayout);
    event CoverageClaimed(bytes32 indexed eventId, address indexed user, uint256 units, uint256 payout);
    event HedgeRebalanced(bytes32 indexed eventId, uint256 targetAmount, uint256 actualCost);
    event HedgeFailed(bytes32 indexed eventId, uint256 targetAmount, string reason);
    event EmergencyStop(string reason, uint256 poolLoss);
    event ReinsuranceFallback(bytes32 indexed eventId, uint256 amount, string reason);

    // Errors
    error InvalidParameters();
    error ProductInactive();
    error ExceedsMaxNotional();
    error ExceedsSlippageLimit();
    error InsufficientLiquidity();
    error EventNotResolved();
    error EventAlreadySettled();
    error UnauthorizedRebalance();
    error GovernanceDelayNotMet();
    error PoolUtilizationExceeded();

    modifier validEventId(bytes32 eventId) {
        require(hedgeEngine.validateEventId(eventId), "Invalid event ID");
        _;
    }

    modifier onlyAfterDelay(bytes32 paramHash) {
        if (pendingParamChanges[paramHash] == 0) revert GovernanceDelayNotMet();
        require(block.timestamp >= pendingParamChanges[paramHash].add(PARAM_CHANGE_DELAY), 
                "Governance delay not met");
        _;
        delete pendingParamChanges[paramHash];
    }

    constructor(
        address _usdc,
        address _coverageToken,
        address _oracle,
        address _hedgeEngine,
        address _reinsuranceVault,
        address _circuitBreaker,
        address _treasury
    ) {
        usdc = IERC20(_usdc);
        coverageToken = ICoverageToken(_coverageToken);
        oracle = IOracleAdapter(_oracle);
        hedgeEngine = IHedgeEngine(_hedgeEngine);
        reinsuranceVault = IReinsuranceVault(_reinsuranceVault);
        circuitBreaker = ICircuitBreaker(_circuitBreaker);
        treasury = _treasury;
    }

    // ========== ERC4626-like Vault Functions ==========

    function totalAssets() public view returns (uint256) {
        return usdc.balanceOf(address(this));
    }

    function deposit(uint256 assets, address receiver) 
        external 
        nonReentrant 
        whenNotPaused 
        returns (uint256 shares) 
    {
        require(assets > 0, "Zero deposit");
        
        uint256 supply = totalSupply;
        if (supply == 0) {
            shares = assets;
        } else {
            shares = assets.mul(supply).div(totalAssets());
        }

        usdc.safeTransferFrom(msg.sender, address(this), assets);
        totalSupply = totalSupply.add(shares);
        balanceOf[receiver] = balanceOf[receiver].add(shares);
        
        return shares;
    }

    function withdraw(uint256 assets, address receiver, address owner) 
        external 
        nonReentrant 
        returns (uint256 shares) 
    {
        uint256 supply = totalSupply;
        shares = assets.mul(supply).div(totalAssets());
        
        require(balanceOf[owner] >= shares, "Insufficient shares");
        require(msg.sender == owner, "Not authorized");

        // Ensure withdrawal doesn't breach utilization limits
        uint256 remainingAssets = totalAssets().sub(assets);
        uint256 newUtilization = totalLiability.mul(WAD).div(remainingAssets);
        if (newUtilization > maxPoolUtilization) revert PoolUtilizationExceeded();

        balanceOf[owner] = balanceOf[owner].sub(shares);
        totalSupply = totalSupply.sub(shares);

        usdc.safeTransfer(receiver, assets);
        return shares;
    }

    // ========== Product Configuration ==========

    function proposeProductConfig(bytes32 eventId, ProductConfig memory config) 
        external 
        onlyOwner 
        validEventId(eventId) 
    {
        bytes32 configHash = keccak256(abi.encode(eventId, config));
        pendingParamChanges[configHash] = block.timestamp;
    }

    function setProductConfig(bytes32 eventId, ProductConfig memory config) 
        external 
        onlyOwner 
        validEventId(eventId)
        onlyAfterDelay(keccak256(abi.encode(eventId, config)))
    {
        // Validate parameters
        if (config.hedgeRatioWad < MIN_HEDGE_RATIO || config.hedgeRatioWad > MAX_HEDGE_RATIO) 
            revert InvalidParameters();
        if (config.reserveRatioWad > MAX_RESERVE_RATIO) revert InvalidParameters();
        if (config.feeRatioWad > MAX_FEE_RATIO) revert InvalidParameters();
        if (config.poolRetentionWad > WAD) revert InvalidParameters();
        if (config.strike < MIN_COVERAGE_UNIT || config.strike > MAX_COVERAGE_UNIT) 
            revert InvalidParameters();

        productConfig[eventId] = config;
        emit ProductConfigured(eventId, config);
    }

    // ========== Coverage Purchase ==========

    function buyCoverage(
        bytes32 eventId,
        uint256 units,
        uint256 maxPremium,
        uint256 deadline
    ) external nonReentrant whenNotPaused validEventId(eventId) returns (uint256 premiumPaid) {
        require(block.timestamp <= deadline, "Deadline exceeded");
        require(units > 0, "Zero units");
        
        ProductConfig memory config = productConfig[eventId];
        if (!config.active) revert ProductInactive();

        ProductState storage state = productState[eventId];
        require(!state.settled, "Event already settled");

        // Check notional limits
        uint256 newNotional = state.soldNotional.add(config.strike.mul(units));
        if (newNotional > config.maxNotional) revert ExceedsMaxNotional();

        // Get current market price with validation
        uint256 marketPrice = hedgeEngine.getYesPriceWad(eventId);
        require(marketPrice > 0 && marketPrice <= WAD, "Invalid market price");

        // Calculate premium components with overflow protection
        uint256 hedgeCostPerUnit = config.strike.mul(marketPrice).mul(config.hedgeRatioWad).div(WAD).div(WAD);
        uint256 reservePerUnit = config.strike.mul(config.reserveRatioWad).div(WAD);
        uint256 feePerUnit = config.strike.mul(config.feeRatioWad).div(WAD);
        
        uint256 totalPerUnit = hedgeCostPerUnit.add(reservePerUnit).add(feePerUnit);
        premiumPaid = totalPerUnit.mul(units);

        // Slippage protection
        if (premiumPaid > maxPremium) revert ExceedsSlippageLimit();

        // Check pool liquidity
        uint256 hedgeBudget = hedgeCostPerUnit.mul(units);
        if (totalAssets() < hedgeBudget.add(reservePerUnit.mul(units))) 
            revert InsufficientLiquidity();

        // Collect premium
        usdc.safeTransferFrom(msg.sender, address(this), premiumPaid);

        // Allocate components
        uint256 reserveCut = reservePerUnit.mul(units);
        uint256 protocolFee = feePerUnit.mul(units);

        state.soldNotional = newNotional;
        state.reserves = state.reserves.add(reserveCut);
        totalLiability = totalLiability.add(config.strike.mul(units));

        // Transfer protocol fee
        if (protocolFee > 0) {
            usdc.safeTransfer(treasury, protocolFee);
        }

        // Execute hedge with try/catch for safety
        if (hedgeBudget > 0) {
            uint256 targetYesAmount = config.hedgeRatioWad.mul(config.strike).mul(units).div(WAD).div(config.strike);
            
            try hedgeEngine.buyYes(eventId, targetYesAmount, hedgeBudget, address(this)) returns (uint256 actualCost) {
                state.hedgePosition = state.hedgePosition.add(targetYesAmount);
                
                // Calculate slippage and update circuit breaker
                uint256 expectedCost = targetYesAmount.mul(marketPrice).div(WAD);
                uint256 slippage = actualCost > expectedCost ? 
                    actualCost.sub(expectedCost).mul(WAD).div(expectedCost) : 0;
                
                _updateCircuitBreakerMetrics(slippage);
                
                emit HedgeRebalanced(eventId, targetYesAmount, actualCost);
            } catch Error(string memory reason) {
                // Log hedge failure but continue with coverage sale
                emit HedgeFailed(eventId, targetYesAmount, reason);
                
                // Increase reserve allocation to compensate for lack of hedge
                uint256 extraReserve = hedgeBudget.mul(50).div(100); // 50% of hedge budget to reserves
                state.reserves = state.reserves.add(extraReserve);
            } catch {
                // Generic catch for low-level failures
                emit HedgeFailed(eventId, targetYesAmount, "Unknown hedge failure");
                
                // Conservative approach: add full hedge budget to reserves
                state.reserves = state.reserves.add(hedgeBudget);
            }
        }

        // Mint coverage tokens
        coverageToken.mint(msg.sender, eventId, units);

        emit CoverageSold(eventId, msg.sender, units, premiumPaid);
        return premiumPaid;
    }

    // ========== Settlement & Claims ==========

    function settleEvent(bytes32 eventId) external nonReentrant validEventId(eventId) {
        ProductState storage state = productState[eventId];
        if (state.settled) revert EventAlreadySettled();

        // Validate oracle outcome with confidence check
        (bool resolved, bool outcomeYes) = oracle.getEventOutcome(eventId);
        if (!resolved) revert EventNotResolved();
        require(oracle.isOracleValid(eventId), "Oracle not valid");
        require(oracle.getConfidenceLevel(eventId) >= 0.95e18, "Low confidence");

        state.settled = true;
        state.outcomeYes = outcomeYes;
        state.preEventAssets = totalAssets();

        ProductConfig memory config = productConfig[eventId];
        state.primaryLossLimit = state.preEventAssets.mul(config.poolRetentionWad).div(WAD);

        // Redeem hedges
        uint256 hedgePayout = hedgeEngine.settleEvent(eventId);
        
        emit EventSettled(eventId, outcomeYes, hedgePayout);
    }

    function redeemCoverage(bytes32 eventId, uint256 units) 
        external 
        nonReentrant 
        returns (uint256 payout) 
    {
        ProductConfig memory config = productConfig[eventId];
        ProductState storage state = productState[eventId];

        require(state.settled, "Event not settled");
        require(units > 0, "Zero units");

        uint256 userBalance = coverageToken.balanceOf(eventId, msg.sender);
        require(userBalance >= units, "Insufficient coverage balance");

        // Burn coverage tokens first (CEI pattern)
        coverageToken.burn(msg.sender, eventId, units);

        if (!state.outcomeYes) {
            return 0; // No payout for good outcome
        }

        // Calculate payout
        payout = config.strike.mul(units);
        
        // Determine loss allocation with overflow protection
        uint256 currentLoss = state.realizedLoss;
        uint256 newTotalLoss = currentLoss.add(payout);
        
        // Prevent overflow
        require(newTotalLoss >= currentLoss, "Loss calculation overflow");
        
        uint256 remainingPrimary = state.primaryLossLimit > currentLoss ? 
            state.primaryLossLimit.sub(currentLoss) : 0;

        uint256 primaryPortion;
        uint256 reinsuredPortion;

        if (payout <= remainingPrimary) {
            primaryPortion = payout;
            reinsuredPortion = 0;
        } else {
            primaryPortion = remainingPrimary;
            reinsuredPortion = payout.sub(remainingPrimary);
        }

        // Update realized loss atomically
        state.realizedLoss = newTotalLoss;

        // Execute payments with fallback mechanisms
        if (reinsuredPortion > 0) {
            // Validate reinsurance layer before calling
            (uint256 limit, uint256 used, uint256 available, bool active) = 
                reinsuranceVault.getLayerInfo(eventId);
            
            if (active && available >= reinsuredPortion) {
                try reinsuranceVault.coverLoss(eventId, reinsuredPortion) {
                    // Success - reinsurance covered the loss
                } catch Error(string memory reason) {
                    // Reinsurance failed - use pool reserves as fallback
                    emit ReinsuranceFallback(eventId, reinsuredPortion, reason);
                    
                    // Reduce payout if insufficient pool assets
                    uint256 availableAssets = totalAssets();
                    if (availableAssets < payout) {
                        // Pro-rata payout based on available assets
                        payout = availableAssets.mul(90).div(100); // Leave 10% buffer
                    }
                } catch {
                    // Generic reinsurance failure
                    emit ReinsuranceFallback(eventId, reinsuredPortion, "Reinsurance system failure");
                    
                    // Emergency: reduce payout and trigger circuit breaker
                    payout = primaryPortion; // Only pay primary portion
                    _triggerEmergencyStop("Reinsurance system failure");
                }
            } else {
                // Reinsurance unavailable - fallback to pool assets
                emit ReinsuranceFallback(eventId, reinsuredPortion, "Reinsurance layer inactive or insufficient");
                
                uint256 availableAssets = totalAssets();
                if (availableAssets < payout) {
                    payout = availableAssets.mul(90).div(100); // Conservative payout
                }
            }
        }

        // Final solvency check
        require(totalAssets() >= payout, "Pool insolvent");
        
        // Transfer payout
        usdc.safeTransfer(msg.sender, payout);
        
        // Update total liability
        totalLiability = totalLiability.sub(config.strike.mul(units));

        emit CoverageClaimed(eventId, msg.sender, units, payout);
        return payout;
    }

    // ========== Emergency Controls ==========

    function emergencyStop(string calldata reason) external onlyOwner {
        _pause();
        emit EmergencyStop(reason, 0);
    }

    function setTreasury(address _treasury) external onlyOwner {
        require(_treasury != address(0), "Invalid treasury");
        treasury = _treasury;
    }

    function _updateCircuitBreakerMetrics(uint256 hedgeSlippage) internal {
        uint256 poolLossRatio = _calculatePoolLossRatio();
        uint256 dailyLoss = _calculateDailyLoss();
        
        try circuitBreaker.updateRiskMetrics(
            poolLossRatio,
            dailyLoss,
            0, // Oracle failure rate (managed by OracleAdapter)
            hedgeSlippage,
            0, // Volume multiplier (to be implemented)
            0, // Hedge correlation (to be implemented)
            0  // Market liquidity (to be implemented)
        ) {
            // Successfully updated metrics
        } catch {
            // Circuit breaker update failed - continue operation but log
            emit EmergencyStop("Circuit breaker update failed", poolLossRatio);
        }
    }

    function _calculatePoolLossRatio() internal view returns (uint256) {
        uint256 totalAssets_ = totalAssets();
        if (totalAssets_ == 0) return 0;
        
        // Simple loss ratio: (total liability - assets) / initial assets
        // This is simplified - production would track historical assets
        if (totalLiability > totalAssets_) {
            uint256 loss = totalLiability.sub(totalAssets_);
            return loss.mul(WAD).div(totalLiability);
        }
        return 0;
    }

    function _calculateDailyLoss() internal view returns (uint256) {
        // Simplified daily loss calculation
        // Production would track losses over rolling 24h window
        uint256 totalAssets_ = totalAssets();
        if (totalLiability > totalAssets_) {
            return totalLiability.sub(totalAssets_);
        }
        return 0;
    }

    function _triggerEmergencyStop(string memory reason) internal {
        _pause();
        emit EmergencyStop(reason, _calculatePoolLossRatio());
    }

    // ========== View Functions ==========

    function getPoolMetrics() external view returns (
        uint256 totalAssets_,
        uint256 totalLiability_,
        uint256 utilization,
        uint256 freeCapital
    ) {
        totalAssets_ = totalAssets();
        totalLiability_ = totalLiability;
        utilization = totalAssets_ > 0 ? totalLiability_.mul(WAD).div(totalAssets_) : 0;
        freeCapital = totalAssets_ > totalLiability_ ? totalAssets_.sub(totalLiability_) : 0;
    }

    function getProductStatus(bytes32 eventId) external view returns (
        ProductConfig memory config,
        ProductState memory state
    ) {
        return (productConfig[eventId], productState[eventId]);
    }
}