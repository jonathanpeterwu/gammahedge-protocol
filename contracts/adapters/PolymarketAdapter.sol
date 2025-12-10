// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

// Simplified interfaces for Gnosis CTF / Polymarket integration
interface IConditionalTokens {
    function balanceOf(address account, uint256 id) external view returns (uint256);
    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external;
    function redeemPositions(IERC20 collateralToken, bytes32 parentCollectionId, bytes32 conditionId, uint256[] calldata indexSets) external;
}

interface IFixedProductMarketMaker {
    function buy(uint256 investmentAmount, uint256 outcomeIndex, uint256 minOutcomeTokensToBuy) external;
    function sell(uint256 returnAmount, uint256 outcomeIndex, uint256 maxOutcomeTokensToSell) external;
    function calcBuyAmount(uint256 investmentAmount, uint256 outcomeIndex) external view returns (uint256);
    function calcSellAmount(uint256 returnAmount, uint256 outcomeIndex) external view returns (uint256);
}

/**
 * @title PolymarketAdapter
 * @notice Venue adapter for Polymarket/Gnosis Conditional Tokens Framework
 * @dev Handles YES/NO token trading through FPMM contracts
 */
contract PolymarketAdapter is ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;
    using SafeMath for uint256;

    // Constants
    uint256 public constant WAD = 1e18;
    uint256 public constant YES_INDEX = 1; // YES tokens typically at index 1
    uint256 public constant NO_INDEX = 0;  // NO tokens typically at index 0

    // Core contracts
    IERC20 public immutable usdc;
    IConditionalTokens public immutable conditionalTokens;
    
    // Event tracking
    struct MarketInfo {
        IFixedProductMarketMaker fpmm;   // Market maker contract
        uint256 yesTokenId;              // YES token ID in CTF
        uint256 noTokenId;               // NO token ID in CTF
        bytes32 conditionId;             // CTF condition ID
        bool resolved;                   // Market resolution status
        bool outcome;                    // Final outcome (true = YES won)
        uint256 liquidity;               // Current market liquidity
        uint256 lastPriceUpdate;         // Last price update timestamp
    }

    mapping(bytes32 => MarketInfo) public markets;
    mapping(bytes32 => bool) public supportedEvents;

    // Price caching
    struct PriceInfo {
        uint256 yesPrice;      // YES token price (0-1e18)
        uint256 noPrice;       // NO token price (0-1e18) 
        uint256 timestamp;     // Last update time
        uint256 liquidity;     // Market liquidity at time of update
    }

    mapping(bytes32 => PriceInfo) public priceCache;
    uint256 public constant PRICE_CACHE_DURATION = 60; // 1 minute cache

    // Events
    event MarketRegistered(bytes32 indexed eventId, address fpmm, uint256 yesTokenId, uint256 noTokenId);
    event TokensPurchased(bytes32 indexed eventId, uint256 amount, uint256 cost, bool isYes);
    event TokensSold(bytes32 indexed eventId, uint256 amount, uint256 received, bool isYes);
    event PositionRedeemed(bytes32 indexed eventId, uint256 amount);

    constructor(
        address _usdc,
        address _conditionalTokens
    ) {
        usdc = IERC20(_usdc);
        conditionalTokens = IConditionalTokens(_conditionalTokens);
    }

    // ========== Market Registration ==========

    function registerMarket(
        bytes32 eventId,
        address fpmm,
        uint256 yesTokenId,
        uint256 noTokenId,
        bytes32 conditionId
    ) external onlyOwner {
        require(fpmm != address(0), "Invalid FPMM");
        require(!supportedEvents[eventId], "Event already registered");

        markets[eventId] = MarketInfo({
            fpmm: IFixedProductMarketMaker(fpmm),
            yesTokenId: yesTokenId,
            noTokenId: noTokenId,
            conditionId: conditionId,
            resolved: false,
            outcome: false,
            liquidity: 0,
            lastPriceUpdate: 0
        });

        supportedEvents[eventId] = true;

        emit MarketRegistered(eventId, fpmm, yesTokenId, noTokenId);
    }

    function updateMarketResolution(bytes32 eventId, bool outcome) external onlyOwner {
        require(supportedEvents[eventId], "Event not supported");
        
        MarketInfo storage market = markets[eventId];
        market.resolved = true;
        market.outcome = outcome;
    }

    // ========== Price Updates ==========

    function updatePrice(bytes32 eventId) public {
        require(supportedEvents[eventId], "Event not supported");
        
        MarketInfo storage market = markets[eventId];
        if (market.resolved) return;

        // Cache prices for gas efficiency
        PriceInfo storage cache = priceCache[eventId];
        if (block.timestamp < cache.timestamp + PRICE_CACHE_DURATION) {
            return; // Use cached price
        }

        IFixedProductMarketMaker fpmm = market.fpmm;
        
        // Calculate YES price by simulating a 1 USDC buy
        uint256 testAmount = 1e6; // 1 USDC
        try fpmm.calcBuyAmount(testAmount, YES_INDEX) returns (uint256 yesTokens) {
            uint256 yesPrice = yesTokens.mul(WAD).div(testAmount);
            if (yesPrice > WAD) yesPrice = WAD; // Cap at 100%
            
            cache.yesPrice = yesPrice;
            cache.noPrice = WAD.sub(yesPrice); // NO price = 1 - YES price
            cache.timestamp = block.timestamp;
            
            // Estimate liquidity (simplified)
            cache.liquidity = estimateLiquidity(fpmm);
        } catch {
            // Price update failed, keep old values
        }
    }

    function estimateLiquidity(IFixedProductMarketMaker fpmm) internal view returns (uint256) {
        // Simplified liquidity estimation
        // In production, this would query the FPMM's pool balance
        return usdc.balanceOf(address(fpmm));
    }

    // ========== Trading Functions ==========

    function buyYesTokens(
        bytes32 eventId,
        uint256 yesAmount,
        uint256 maxCost
    ) external nonReentrant returns (uint256 actualCost) {
        require(supportedEvents[eventId], "Event not supported");
        
        MarketInfo memory market = markets[eventId];
        require(!market.resolved, "Market resolved");

        updatePrice(eventId);
        
        // Calculate required USDC investment
        IFixedProductMarketMaker fpmm = market.fpmm;
        uint256 requiredInvestment;
        
        try fpmm.calcSellAmount(yesAmount, YES_INDEX) returns (uint256 investment) {
            requiredInvestment = investment;
        } catch {
            revert("Price calculation failed");
        }

        require(requiredInvestment <= maxCost, "Exceeds max cost");

        // Transfer USDC from caller
        usdc.safeTransferFrom(msg.sender, address(this), requiredInvestment);
        
        // Approve FPMM to spend USDC
        usdc.safeApprove(address(fpmm), requiredInvestment);
        
        // Execute buy
        uint256 balanceBefore = conditionalTokens.balanceOf(address(this), market.yesTokenId);
        fpmm.buy(requiredInvestment, YES_INDEX, yesAmount);
        uint256 balanceAfter = conditionalTokens.balanceOf(address(this), market.yesTokenId);
        
        uint256 actualTokens = balanceAfter.sub(balanceBefore);
        require(actualTokens >= yesAmount, "Insufficient tokens received");

        emit TokensPurchased(eventId, actualTokens, requiredInvestment, true);
        return requiredInvestment;
    }

    function sellYesTokens(
        bytes32 eventId,
        uint256 yesAmount,
        uint256 minReceived
    ) external nonReentrant returns (uint256 actualReceived) {
        require(supportedEvents[eventId], "Event not supported");
        
        MarketInfo memory market = markets[eventId];
        require(!market.resolved, "Market resolved");

        uint256 balance = conditionalTokens.balanceOf(address(this), market.yesTokenId);
        require(balance >= yesAmount, "Insufficient balance");

        updatePrice(eventId);

        IFixedProductMarketMaker fpmm = market.fpmm;
        uint256 expectedReturn;
        
        try fpmm.calcBuyAmount(yesAmount, YES_INDEX) returns (uint256 returnAmount) {
            expectedReturn = returnAmount;
        } catch {
            revert("Price calculation failed");
        }

        require(expectedReturn >= minReceived, "Below minimum received");

        // Approve FPMM to take tokens
        conditionalTokens.safeTransferFrom(
            address(this), 
            address(fpmm), 
            market.yesTokenId, 
            yesAmount, 
            ""
        );
        
        uint256 usdcBefore = usdc.balanceOf(address(this));
        fpmm.sell(expectedReturn, YES_INDEX, yesAmount);
        uint256 usdcAfter = usdc.balanceOf(address(this));
        
        actualReceived = usdcAfter.sub(usdcBefore);

        emit TokensSold(eventId, yesAmount, actualReceived, true);
        return actualReceived;
    }

    function settlePosition(bytes32 eventId) external nonReentrant returns (uint256 usdcReceived) {
        require(supportedEvents[eventId], "Event not supported");
        
        MarketInfo memory market = markets[eventId];
        require(market.resolved, "Market not resolved");

        uint256 yesBalance = conditionalTokens.balanceOf(address(this), market.yesTokenId);
        uint256 noBalance = conditionalTokens.balanceOf(address(this), market.noTokenId);
        
        if (yesBalance == 0 && noBalance == 0) return 0;

        // Redeem winning tokens
        uint256[] memory indexSets = new uint256[](2);
        indexSets[0] = 1 << NO_INDEX;  // NO outcome
        indexSets[1] = 1 << YES_INDEX; // YES outcome

        uint256 usdcBefore = usdc.balanceOf(address(this));
        
        conditionalTokens.redeemPositions(
            usdc,
            bytes32(0), // parentCollectionId
            market.conditionId,
            indexSets
        );
        
        uint256 usdcAfter = usdc.balanceOf(address(this));
        usdcReceived = usdcAfter.sub(usdcBefore);

        emit PositionRedeemed(eventId, usdcReceived);
        return usdcReceived;
    }

    // ========== View Functions ==========

    function validateEventId(bytes32 eventId) external view returns (bool) {
        return supportedEvents[eventId];
    }

    function getYesPrice(bytes32 eventId) external view returns (uint256 priceWad) {
        if (!supportedEvents[eventId]) return 0;
        
        PriceInfo memory cache = priceCache[eventId];
        
        // Return cached price if recent enough
        if (block.timestamp < cache.timestamp + PRICE_CACHE_DURATION) {
            return cache.yesPrice;
        }
        
        // Fallback to 50% if no cached price
        return 0.5e18;
    }

    function getMarketInfo(bytes32 eventId) external view returns (
        bool exists,
        bool resolved,
        bool outcome,
        uint256 liquidity
    ) {
        if (!supportedEvents[eventId]) {
            return (false, false, false, 0);
        }

        MarketInfo memory market = markets[eventId];
        PriceInfo memory cache = priceCache[eventId];
        
        return (
            true,
            market.resolved,
            market.outcome,
            cache.liquidity
        );
    }

    function getTokenBalance(bytes32 eventId) external view returns (
        uint256 yesBalance,
        uint256 noBalance
    ) {
        if (!supportedEvents[eventId]) return (0, 0);
        
        MarketInfo memory market = markets[eventId];
        
        yesBalance = conditionalTokens.balanceOf(address(this), market.yesTokenId);
        noBalance = conditionalTokens.balanceOf(address(this), market.noTokenId);
    }

    // ========== Emergency Functions ==========

    function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
        IERC20(token).safeTransfer(owner(), amount);
    }

    function emergencyWithdrawCTF(uint256 tokenId, uint256 amount) external onlyOwner {
        conditionalTokens.safeTransferFrom(address(this), owner(), tokenId, amount, "");
    }
}