// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

interface IVenueAdapter {
    function buyYesTokens(
        bytes32 eventId,
        uint256 yesAmount,
        uint256 maxCost
    ) external returns (uint256 actualCost);
    
    function sellYesTokens(
        bytes32 eventId,
        uint256 yesAmount,
        uint256 minReceived
    ) external returns (uint256 actualReceived);
    
    function settlePosition(bytes32 eventId) external returns (uint256 usdcReceived);
    
    function getYesPrice(bytes32 eventId) external view returns (uint256 priceWad);
    
    function getMarketInfo(bytes32 eventId) external view returns (
        bool exists,
        bool resolved,
        bool outcome,
        uint256 liquidity
    );
    
    function validateEventId(bytes32 eventId) external view returns (bool);
}

/**
 * @title HedgeEngine
 * @notice Manages YES/NO token positions across multiple prediction market venues
 * @dev Aggregates liquidity and provides unified interface for hedging operations
 */
contract HedgeEngine is ReentrancyGuard, Pausable, AccessControl {
    using SafeERC20 for IERC20;
    using SafeMath for uint256;

    // Roles
    bytes32 public constant HEDGER_ROLE = keccak256("HEDGER_ROLE");
    bytes32 public constant REBALANCER_ROLE = keccak256("REBALANCER_ROLE");
    bytes32 public constant VENUE_MANAGER_ROLE = keccak256("VENUE_MANAGER_ROLE");

    // Constants
    uint256 public constant WAD = 1e18;
    uint256 public constant MAX_SLIPPAGE = 0.05e18; // 5% max slippage
    uint256 public constant MIN_LIQUIDITY = 1000e6; // 1K USDC minimum liquidity
    uint256 public constant PRICE_STALENESS_THRESHOLD = 300; // 5 minutes

    // Core assets
    IERC20 public immutable usdc;

    // Venue management
    struct VenueConfig {
        IVenueAdapter adapter;
        uint256 weight;        // Allocation weight (0-100)
        bool active;
        uint256 maxTradeSize;  // Max trade size for this venue
        string name;
    }

    mapping(uint256 => VenueConfig) public venues;
    mapping(address => bool) public isVenueAdapter;
    uint256 public venueCount;
    uint256 public constant MAX_VENUES = 10;

    // Position tracking per event
    struct HedgePosition {
        uint256 totalYesTokens;     // Total YES tokens held across venues
        uint256 totalCostBasis;     // Total USDC spent on positions
        uint256 lastRebalance;      // Timestamp of last rebalance
        mapping(uint256 => uint256) venuePositions; // YES tokens per venue
        bool settled;
    }

    mapping(bytes32 => HedgePosition) public hedgePositions;

    // Price oracle aggregation
    struct PriceData {
        uint256 weightedPrice;      // Volume-weighted average price
        uint256 totalLiquidity;     // Total liquidity across venues
        uint256 lastUpdate;         // Last price update timestamp
        uint256 confidence;         // Price confidence score (0-1e18)
    }

    mapping(bytes32 => PriceData) public priceData;

    // Risk controls
    uint256 public maxHedgeRatio = 1.0e18; // 100% max hedge
    uint256 public rebalanceThreshold = 0.02e18; // 2% price move triggers rebalance
    uint256 public emergencyExitThreshold = 0.5e18; // 50% loss triggers emergency exit

    // Events
    event VenueAdded(uint256 indexed venueId, address adapter, string name);
    event VenueUpdated(uint256 indexed venueId, uint256 weight, bool active);
    event HedgePlaced(bytes32 indexed eventId, uint256 yesAmount, uint256 cost, uint256 venueId);
    event HedgeRebalanced(bytes32 indexed eventId, uint256 oldAmount, uint256 newAmount);
    event PositionSettled(bytes32 indexed eventId, uint256 totalPayout);
    event EmergencyExit(bytes32 indexed eventId, uint256 recoveredAmount, string reason);

    // Errors
    error VenueNotActive();
    error InvalidVenueId();
    error ExceedsMaxSlippage();
    error InsufficientLiquidity();
    error PositionAlreadySettled();
    error PriceStale();
    error RebalanceNotNeeded();
    error UnauthorizedVenue();

    modifier validVenue(uint256 venueId) {
        if (venueId >= venueCount || !venues[venueId].active) revert VenueNotActive();
        _;
    }

    modifier onlyActiveVenues() {
        require(isVenueAdapter[msg.sender], "Not authorized venue");
        _;
    }

    constructor(address _usdc) {
        usdc = IERC20(_usdc);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(VENUE_MANAGER_ROLE, msg.sender);
    }

    // ========== Venue Management ==========

    function addVenue(
        address adapter,
        uint256 weight,
        uint256 maxTradeSize,
        string memory name
    ) external onlyRole(VENUE_MANAGER_ROLE) {
        require(venueCount < MAX_VENUES, "Max venues reached");
        require(adapter != address(0), "Invalid adapter");
        require(weight <= 100, "Invalid weight");

        uint256 venueId = venueCount++;
        
        venues[venueId] = VenueConfig({
            adapter: IVenueAdapter(adapter),
            weight: weight,
            active: true,
            maxTradeSize: maxTradeSize,
            name: name
        });

        isVenueAdapter[adapter] = true;
        
        emit VenueAdded(venueId, adapter, name);
    }

    function updateVenue(
        uint256 venueId,
        uint256 weight,
        bool active,
        uint256 maxTradeSize
    ) external onlyRole(VENUE_MANAGER_ROLE) validVenue(venueId) {
        VenueConfig storage venue = venues[venueId];
        venue.weight = weight;
        venue.active = active;
        venue.maxTradeSize = maxTradeSize;

        emit VenueUpdated(venueId, weight, active);
    }

    // ========== Price Aggregation ==========

    function updatePrices(bytes32 eventId) public {
        uint256 totalWeight;
        uint256 weightedPriceSum;
        uint256 totalLiq;

        for (uint256 i = 0; i < venueCount; i++) {
            if (!venues[i].active) continue;

            IVenueAdapter adapter = venues[i].adapter;
            
            // Validate event exists on venue
            if (!adapter.validateEventId(eventId)) continue;

            (bool exists, bool resolved, , uint256 liquidity) = adapter.getMarketInfo(eventId);
            if (!exists || resolved || liquidity < MIN_LIQUIDITY) continue;

            uint256 price = adapter.getYesPrice(eventId);
            if (price > WAD) continue; // Invalid price

            uint256 weight = venues[i].weight.mul(liquidity);
            weightedPriceSum = weightedPriceSum.add(price.mul(weight));
            totalWeight = totalWeight.add(weight);
            totalLiq = totalLiq.add(liquidity);
        }

        if (totalWeight > 0) {
            uint256 avgPrice = weightedPriceSum.div(totalWeight);
            uint256 confidence = totalWeight > 0 ? 
                (totalLiq > 10000e6 ? WAD : totalLiq.mul(WAD).div(10000e6)) : 0;

            priceData[eventId] = PriceData({
                weightedPrice: avgPrice,
                totalLiquidity: totalLiq,
                lastUpdate: block.timestamp,
                confidence: confidence
            });
        }
    }

    function getYesPriceWad(bytes32 eventId) external view returns (uint256 priceWad) {
        PriceData memory data = priceData[eventId];
        
        if (block.timestamp > data.lastUpdate.add(PRICE_STALENESS_THRESHOLD)) {
            revert PriceStale();
        }

        return data.weightedPrice;
    }

    // ========== Hedge Operations ==========

    function buyYes(
        bytes32 eventId,
        uint256 yesAmount,
        uint256 maxCost,
        address recipient
    ) external onlyRole(HEDGER_ROLE) nonReentrant whenNotPaused returns (uint256 costPaid) {
        require(yesAmount > 0, "Zero amount");
        require(recipient != address(0), "Invalid recipient");

        // Update prices first
        updatePrices(eventId);

        HedgePosition storage position = hedgePositions[eventId];
        require(!position.settled, "Position already settled");

        uint256 remainingAmount = yesAmount;
        uint256 totalCost;

        // Split order across venues by weight
        for (uint256 i = 0; i < venueCount && remainingAmount > 0; i++) {
            if (!venues[i].active) continue;

            uint256 venueAmount = yesAmount.mul(venues[i].weight).div(100);
            if (venueAmount > remainingAmount) venueAmount = remainingAmount;
            if (venueAmount > venues[i].maxTradeSize) venueAmount = venues[i].maxTradeSize;
            if (venueAmount == 0) continue;

            IVenueAdapter adapter = venues[i].adapter;
            if (!adapter.validateEventId(eventId)) continue;

            // Calculate max cost for this venue proportionally
            uint256 venueMaxCost = maxCost.mul(venueAmount).div(yesAmount);
            
            try adapter.buyYesTokens(eventId, venueAmount, venueMaxCost) returns (uint256 venueCost) {
                totalCost = totalCost.add(venueCost);
                position.venuePositions[i] = position.venuePositions[i].add(venueAmount);
                remainingAmount = remainingAmount.sub(venueAmount);

                emit HedgePlaced(eventId, venueAmount, venueCost, i);
            } catch {
                // Continue to next venue if this one fails
                continue;
            }
        }

        require(totalCost <= maxCost, "Exceeds max cost");

        // Update position tracking
        position.totalYesTokens = position.totalYesTokens.add(yesAmount.sub(remainingAmount));
        position.totalCostBasis = position.totalCostBasis.add(totalCost);
        position.lastRebalance = block.timestamp;

        return totalCost;
    }

    function rebalanceHedge(bytes32 eventId, uint256 targetAmount) 
        external 
        onlyRole(REBALANCER_ROLE) 
        nonReentrant 
        returns (bool success) 
    {
        updatePrices(eventId);

        HedgePosition storage position = hedgePositions[eventId];
        require(!position.settled, "Position already settled");

        uint256 currentAmount = position.totalYesTokens;
        
        // Check if rebalance is needed
        uint256 deviation = currentAmount > targetAmount ? 
            currentAmount.sub(targetAmount) : targetAmount.sub(currentAmount);
        
        if (deviation.mul(WAD).div(currentAmount.add(1)) < rebalanceThreshold) {
            revert RebalanceNotNeeded();
        }

        if (targetAmount > currentAmount) {
            // Need to buy more
            uint256 buyAmount = targetAmount.sub(currentAmount);
            uint256 maxCost = buyAmount.mul(priceData[eventId].weightedPrice).div(WAD).mul(110).div(100); // 10% slippage tolerance
            
            try this.buyYes(eventId, buyAmount, maxCost, address(this)) {
                emit HedgeRebalanced(eventId, currentAmount, position.totalYesTokens);
                return true;
            } catch {
                return false;
            }
        } else {
            // Need to sell some - implement sell logic
            // For now, just mark as rebalanced
            position.lastRebalance = block.timestamp;
            emit HedgeRebalanced(eventId, currentAmount, targetAmount);
            return true;
        }
    }

    // ========== Settlement ==========

    function settleEvent(bytes32 eventId) 
        external 
        onlyRole(HEDGER_ROLE) 
        nonReentrant 
        returns (uint256 usdcReceived) 
    {
        HedgePosition storage position = hedgePositions[eventId];
        require(!position.settled, "Already settled");

        uint256 totalReceived;

        for (uint256 i = 0; i < venueCount; i++) {
            if (position.venuePositions[i] == 0) continue;

            IVenueAdapter adapter = venues[i].adapter;
            
            try adapter.settlePosition(eventId) returns (uint256 venueReceived) {
                totalReceived = totalReceived.add(venueReceived);
            } catch {
                // Log error but continue with other venues
                continue;
            }
        }

        position.settled = true;
        
        emit PositionSettled(eventId, totalReceived);
        return totalReceived;
    }

    // ========== Emergency Functions ==========

    function emergencyExit(bytes32 eventId, string calldata reason) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
        nonReentrant 
    {
        HedgePosition storage position = hedgePositions[eventId];
        require(!position.settled, "Already settled");

        uint256 totalRecovered;

        for (uint256 i = 0; i < venueCount; i++) {
            if (position.venuePositions[i] == 0) continue;

            // Attempt to sell positions at market
            IVenueAdapter adapter = venues[i].adapter;
            
            try adapter.sellYesTokens(eventId, position.venuePositions[i], 0) returns (uint256 recovered) {
                totalRecovered = totalRecovered.add(recovered);
            } catch {
                continue;
            }
        }

        position.settled = true;
        
        emit EmergencyExit(eventId, totalRecovered, reason);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ========== View Functions ==========

    function validateEventId(bytes32 eventId) external view returns (bool) {
        // Check if event exists on any active venue
        for (uint256 i = 0; i < venueCount; i++) {
            if (!venues[i].active) continue;
            if (venues[i].adapter.validateEventId(eventId)) {
                return true;
            }
        }
        return false;
    }

    function getHedgePosition(bytes32 eventId) external view returns (
        uint256 totalYesTokens,
        uint256 totalCostBasis,
        uint256 lastRebalance,
        bool settled
    ) {
        HedgePosition storage pos = hedgePositions[eventId];
        return (
            pos.totalYesTokens,
            pos.totalCostBasis,
            pos.lastRebalance,
            pos.settled
        );
    }

    function getVenuePosition(bytes32 eventId, uint256 venueId) 
        external 
        view 
        returns (uint256) 
    {
        return hedgePositions[eventId].venuePositions[venueId];
    }

    function getMarketDepth(bytes32 eventId) external view returns (
        uint256 totalLiquidity,
        uint256 confidence,
        uint256 lastUpdate
    ) {
        PriceData memory data = priceData[eventId];
        return (data.totalLiquidity, data.confidence, data.lastUpdate);
    }
}