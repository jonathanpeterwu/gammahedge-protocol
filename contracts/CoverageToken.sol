// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Burnable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

/**
 * @title CoverageToken  
 * @notice ERC1155 token representing coverage positions for specific events
 * @dev Each eventId maps to a unique token ID with proper access controls
 */
contract CoverageToken is ERC1155, ERC1155Burnable, AccessControl, ReentrancyGuard, Pausable {
    using SafeMath for uint256;

    // Roles
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // Contract info
    string public name = "GammaHedge Coverage Token";
    string public symbol = "GH-COV";

    // Event metadata
    struct EventMetadata {
        string description;     // Human readable event description
        uint256 strike;        // Coverage payout amount (K)
        uint256 expiry;        // Event resolution deadline
        bool exists;           // Track if event is registered
        bool settled;          // Track if event is settled
        bool outcome;          // Event outcome (true = bad event occurred)
    }

    // Token ID management
    mapping(bytes32 => uint256) public eventIdToTokenId;
    mapping(uint256 => bytes32) public tokenIdToEventId;
    mapping(bytes32 => EventMetadata) public eventMetadata;
    
    uint256 private _currentTokenId = 1;
    uint256 public constant MAX_EVENTS = 10000; // Prevent unbounded token IDs

    // Supply tracking per event
    mapping(bytes32 => uint256) public totalSupplyByEvent;
    mapping(bytes32 => mapping(address => uint256)) public balancesByEvent;

    // Events
    event EventRegistered(bytes32 indexed eventId, uint256 indexed tokenId, EventMetadata metadata);
    event EventSettled(bytes32 indexed eventId, bool outcome);
    event CoverageMinted(bytes32 indexed eventId, address indexed to, uint256 amount);
    event CoverageBurned(bytes32 indexed eventId, address indexed from, uint256 amount);

    // Errors
    error EventNotRegistered();
    error EventAlreadyRegistered();
    error EventAlreadySettled();
    error MaxEventsReached();
    error InvalidEventParameters();
    error UnauthorizedMinter();
    error UnauthorizedBurner();
    error InsufficientBalance();

    constructor(string memory uri) ERC1155(uri) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
    }

    // ========== Event Management ==========

    function registerEvent(
        bytes32 eventId,
        string memory description,
        uint256 strike,
        uint256 expiry
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (eventMetadata[eventId].exists) revert EventAlreadyRegistered();
        if (_currentTokenId > MAX_EVENTS) revert MaxEventsReached();
        if (strike == 0 || expiry <= block.timestamp) revert InvalidEventParameters();

        uint256 tokenId = _currentTokenId++;
        
        eventIdToTokenId[eventId] = tokenId;
        tokenIdToEventId[tokenId] = eventId;
        
        eventMetadata[eventId] = EventMetadata({
            description: description,
            strike: strike,
            expiry: expiry,
            exists: true,
            settled: false,
            outcome: false
        });

        emit EventRegistered(eventId, tokenId, eventMetadata[eventId]);
    }

    function settleEvent(bytes32 eventId, bool outcome) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
    {
        EventMetadata storage metadata = eventMetadata[eventId];
        if (!metadata.exists) revert EventNotRegistered();
        if (metadata.settled) revert EventAlreadySettled();

        metadata.settled = true;
        metadata.outcome = outcome;

        emit EventSettled(eventId, outcome);
    }

    // ========== Token Operations ==========

    function mint(address to, bytes32 eventId, uint256 amount) 
        external 
        onlyRole(MINTER_ROLE) 
        nonReentrant 
        whenNotPaused 
    {
        if (!eventMetadata[eventId].exists) revert EventNotRegistered();
        if (eventMetadata[eventId].settled) revert EventAlreadySettled();

        uint256 tokenId = eventIdToTokenId[eventId];
        
        _mint(to, tokenId, amount, "");
        
        totalSupplyByEvent[eventId] = totalSupplyByEvent[eventId].add(amount);
        balancesByEvent[eventId][to] = balancesByEvent[eventId][to].add(amount);

        emit CoverageMinted(eventId, to, amount);
    }

    function burn(address from, bytes32 eventId, uint256 amount) 
        external 
        onlyRole(BURNER_ROLE) 
        nonReentrant 
    {
        if (!eventMetadata[eventId].exists) revert EventNotRegistered();
        if (balancesByEvent[eventId][from] < amount) revert InsufficientBalance();

        uint256 tokenId = eventIdToTokenId[eventId];
        
        _burn(from, tokenId, amount);
        
        totalSupplyByEvent[eventId] = totalSupplyByEvent[eventId].sub(amount);
        balancesByEvent[eventId][from] = balancesByEvent[eventId][from].sub(amount);

        emit CoverageBurned(eventId, from, amount);
    }

    // ========== View Functions ==========

    function balanceOf(bytes32 eventId, address owner) external view returns (uint256) {
        return balancesByEvent[eventId][owner];
    }

    function exists(bytes32 eventId) external view returns (bool) {
        return eventMetadata[eventId].exists;
    }

    function getEventMetadata(bytes32 eventId) external view returns (EventMetadata memory) {
        if (!eventMetadata[eventId].exists) revert EventNotRegistered();
        return eventMetadata[eventId];
    }

    function getTokenIdForEvent(bytes32 eventId) external view returns (uint256) {
        if (!eventMetadata[eventId].exists) revert EventNotRegistered();
        return eventIdToTokenId[eventId];
    }

    function getEventForTokenId(uint256 tokenId) external view returns (bytes32) {
        bytes32 eventId = tokenIdToEventId[tokenId];
        if (!eventMetadata[eventId].exists) revert EventNotRegistered();
        return eventId;
    }

    function uri(uint256 tokenId) public view override returns (string memory) {
        bytes32 eventId = tokenIdToEventId[tokenId];
        if (!eventMetadata[eventId].exists) {
            return super.uri(tokenId);
        }

        // Return metadata URI for the specific event
        // In production, this would point to IPFS or a metadata service
        return string(abi.encodePacked(
            super.uri(tokenId),
            "?eventId=",
            Strings.toHexString(uint256(eventId))
        ));
    }

    // ========== Admin Functions ==========

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function setURI(string memory newuri) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setURI(newuri);
    }

    function grantMinterRole(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(MINTER_ROLE, account);
    }

    function revokeMinterRole(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(MINTER_ROLE, account);
    }

    function grantBurnerRole(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(BURNER_ROLE, account);
    }

    function revokeBurnerRole(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(BURNER_ROLE, account);
    }

    // ========== Overrides ==========

    function supportsInterface(bytes4 interfaceId) 
        public 
        view 
        override(ERC1155, AccessControl) 
        returns (bool) 
    {
        return super.supportsInterface(interfaceId);
    }

    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal override whenNotPaused {
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);

        // Update balancesByEvent mapping for transfers
        if (from != address(0) && to != address(0)) {
            for (uint256 i = 0; i < ids.length; i++) {
                bytes32 eventId = tokenIdToEventId[ids[i]];
                if (eventMetadata[eventId].exists) {
                    balancesByEvent[eventId][from] = balancesByEvent[eventId][from].sub(amounts[i]);
                    balancesByEvent[eventId][to] = balancesByEvent[eventId][to].add(amounts[i]);
                }
            }
        }
    }

    // ========== Emergency Functions ==========

    function emergencyWithdraw(address token, uint256 amount) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
    {
        // Only for recovering accidentally sent tokens, not USDC from operations
        require(token != address(0), "Invalid token");
        IERC20(token).transfer(msg.sender, amount);
    }
}