// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

/**
 * @title ReinsuranceVault
 * @notice Senior capital pool that covers losses above poolRetentionWad threshold
 * @dev Security-hardened version with comprehensive protections
 */
contract ReinsuranceVault is ReentrancyGuard, Pausable, Ownable {
    using SafeERC20 for IERC20;
    using SafeMath for uint256;

    // Constants
    uint256 public constant WAD = 1e18;
    uint256 public constant MAX_LAYER_LIMIT = 100_000_000 * 1e6; // 100M USDC max per layer
    uint256 public constant MIN_CAPITALIZATION = 1_000 * 1e6; // 1K USDC min
    uint256 public constant MAX_LAYERS_PER_EVENT = 10; // Prevent unbounded gas

    // Core contracts
    IERC20 public immutable usdc;
    address public immutable coveragePool;
    
    // ERC4626-like vault state
    string public constant name = "Gamma Hedge Reinsurance Vault";
    string public constant symbol = "GH-RE";
    uint8 public constant decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    // Layer configuration per event
    struct Layer {
        uint256 limit;     // Max USDC this vault pays for this event
        uint256 used;      // Already paid amount
        bool active;       // Layer is active
        uint256 createdAt; // Timestamp for governance delays
    }

    // Global risk controls
    uint256 public totalExposure; // Sum of all active layer limits
    uint256 public maxTotalExposure; // Global exposure cap
    uint256 public emergencyWithdrawDelay = 24 hours;
    
    mapping(bytes32 => Layer) public layers;
    mapping(bytes32 => uint256) public layerCount; // Track layers per event
    
    // Governance controls
    uint256 public constant GOVERNANCE_DELAY = 6 hours;
    mapping(bytes32 => uint256) public pendingLayerChanges; // keccak256(eventId, limit) => timestamp

    // Events
    event LayerConfigured(bytes32 indexed eventId, uint256 limit, bool active, uint256 timestamp);
    event LossCovered(bytes32 indexed eventId, uint256 amount, uint256 remainingLimit);
    event EmergencyWithdraw(address indexed user, uint256 assets, uint256 shares);
    event ExposureLimitUpdated(uint256 oldLimit, uint256 newLimit);

    // Errors
    error OnlyCoveragePool();
    error LayerInactive();
    error ExceedsLayerLimit();
    error ExceedsGlobalExposure();
    error GovernanceDelayNotMet();
    error InvalidLayerParameters();
    error InsufficientCapitalization();
    error ExceedsMaxLayers();

    modifier onlyCoveragePool() {
        if (msg.sender != coveragePool) revert OnlyCoveragePool();
        _;
    }

    constructor(
        address _usdc,
        address _coveragePool,
        uint256 _maxTotalExposure
    ) {
        usdc = IERC20(_usdc);
        coveragePool = _coveragePool;
        maxTotalExposure = _maxTotalExposure;
    }

    // ========== ERC4626-like Vault Functions ==========

    function asset() external view returns (address) {
        return address(usdc);
    }

    function totalAssets() public view returns (uint256) {
        return usdc.balanceOf(address(this));
    }

    function deposit(uint256 assets, address receiver) 
        external 
        nonReentrant 
        whenNotPaused 
        returns (uint256 shares) 
    {
        require(assets >= MIN_CAPITALIZATION, "Below min capitalization");
        
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
        require(msg.sender == owner, "Not authorized"); // Simplified - add allowance if needed

        // Check if withdrawal would leave vault undercapitalized for active layers
        uint256 remainingAssets = totalAssets().sub(assets);
        require(remainingAssets >= totalExposure.div(10), "Would undercapitalize"); // 10% buffer

        balanceOf[owner] = balanceOf[owner].sub(shares);
        totalSupply = totalSupply.sub(shares);

        usdc.safeTransfer(receiver, assets);
        return shares;
    }

    function emergencyWithdraw(uint256 shares, address receiver, address owner) 
        external 
        nonReentrant 
        returns (uint256 assets) 
    {
        require(balanceOf[owner] >= shares, "Insufficient shares");
        require(msg.sender == owner, "Not authorized");
        
        // Emergency withdrawals bypass some checks but have delay
        require(block.timestamp >= pendingLayerChanges[keccak256("emergency")] + emergencyWithdrawDelay, 
                "Emergency delay not met");

        uint256 supply = totalSupply;
        assets = shares.mul(totalAssets()).div(supply);

        balanceOf[owner] = balanceOf[owner].sub(shares);
        totalSupply = totalSupply.sub(shares);

        usdc.safeTransfer(receiver, assets);
        
        emit EmergencyWithdraw(owner, assets, shares);
        return assets;
    }

    // ========== Layer Management ==========

    function proposeLayerChange(bytes32 eventId, uint256 limit, bool active) external onlyOwner {
        bytes32 changeHash = keccak256(abi.encodePacked(eventId, limit, active));
        pendingLayerChanges[changeHash] = block.timestamp;
    }

    function setLayer(bytes32 eventId, uint256 limit, bool active) external onlyOwner {
        bytes32 changeHash = keccak256(abi.encodePacked(eventId, limit, active));
        
        if (pendingLayerChanges[changeHash] == 0) revert GovernanceDelayNotMet();
        require(block.timestamp >= pendingLayerChanges[changeHash] + GOVERNANCE_DELAY, 
                "Governance delay not met");

        if (limit > MAX_LAYER_LIMIT) revert InvalidLayerParameters();
        if (layerCount[eventId] >= MAX_LAYERS_PER_EVENT) revert ExceedsMaxLayers();

        Layer storage layer = layers[eventId];
        
        // Cannot reduce limit below already used amount
        if (limit < layer.used) revert InvalidLayerParameters();

        // Update global exposure tracking
        uint256 oldLimit = layer.active ? layer.limit : 0;
        uint256 newLimit = active ? limit : 0;
        
        uint256 newTotalExposure = totalExposure.sub(oldLimit).add(newLimit);
        if (newTotalExposure > maxTotalExposure) revert ExceedsGlobalExposure();

        // Update layer
        layer.limit = limit;
        layer.active = active;
        layer.createdAt = block.timestamp;
        
        totalExposure = newTotalExposure;

        if (active && layerCount[eventId] == 0) {
            layerCount[eventId] = 1;
        } else if (!active && layerCount[eventId] > 0) {
            layerCount[eventId] = layerCount[eventId] - 1;
        }

        delete pendingLayerChanges[changeHash];
        
        emit LayerConfigured(eventId, limit, active, block.timestamp);
    }

    // ========== Loss Coverage ==========

    function coverLoss(bytes32 eventId, uint256 amount) 
        external 
        onlyCoveragePool 
        nonReentrant 
        whenNotPaused 
    {
        if (amount == 0) return;

        Layer storage layer = layers[eventId];
        if (!layer.active) revert LayerInactive();

        uint256 availableLimit = layer.limit.sub(layer.used);
        if (amount > availableLimit) revert ExceedsLayerLimit();

        // Check vault has sufficient funds
        require(usdc.balanceOf(address(this)) >= amount, "Insufficient vault funds");

        // Update layer usage atomically
        layer.used = layer.used.add(amount);
        
        // Transfer to coverage pool
        usdc.safeTransfer(coveragePool, amount);

        emit LossCovered(eventId, amount, availableLimit.sub(amount));
    }

    // ========== Administrative ==========

    function setMaxTotalExposure(uint256 _maxTotalExposure) external onlyOwner {
        require(_maxTotalExposure >= totalExposure, "Below current exposure");
        
        uint256 oldLimit = maxTotalExposure;
        maxTotalExposure = _maxTotalExposure;
        
        emit ExposureLimitUpdated(oldLimit, _maxTotalExposure);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    function setEmergencyWithdrawDelay(uint256 delay) external onlyOwner {
        require(delay <= 7 days, "Delay too long");
        emergencyWithdrawDelay = delay;
    }

    // ========== View Functions ==========

    function getLayerInfo(bytes32 eventId) external view returns (
        uint256 limit,
        uint256 used,
        uint256 available,
        bool active
    ) {
        Layer memory layer = layers[eventId];
        return (
            layer.limit,
            layer.used,
            layer.limit > layer.used ? layer.limit - layer.used : 0,
            layer.active
        );
    }

    function getVaultMetrics() external view returns (
        uint256 totalAssets_,
        uint256 totalSupply_,
        uint256 totalExposure_,
        uint256 utilizationRatio,
        uint256 freeCapital
    ) {
        totalAssets_ = totalAssets();
        totalSupply_ = totalSupply;
        totalExposure_ = totalExposure;
        utilizationRatio = totalAssets_ > 0 ? totalExposure_.mul(WAD).div(totalAssets_) : 0;
        freeCapital = totalAssets_ > totalExposure ? totalAssets_ - totalExposure : 0;
    }
}