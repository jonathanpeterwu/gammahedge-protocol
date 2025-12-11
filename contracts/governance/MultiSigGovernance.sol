// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

/**
 * @title MultiSigGovernance
 * @notice Multi-signature governance contract with time delays and role-based permissions
 * @dev Replaces single admin with multi-sig consensus for critical protocol operations
 */
contract MultiSigGovernance is ReentrancyGuard {
    using SafeMath for uint256;

    // Transaction types
    enum TxType {
        ADMIN_ACTION,           // General admin operations
        PARAMETER_CHANGE,       // Protocol parameter modifications
        EMERGENCY_ACTION,       // Emergency response (shorter delays)
        TREASURY_ACTION,        // Treasury management
        UPGRADE_ACTION          // Contract upgrades
    }

    enum TxStatus {
        PENDING,
        EXECUTED,
        CANCELLED,
        EXPIRED
    }

    // Transaction structure
    struct Transaction {
        address target;
        uint256 value;
        bytes data;
        TxType txType;
        TxStatus status;
        uint256 timestamp;
        uint256 requiredSignatures;
        uint256 signatureCount;
        uint256 deadline;
        mapping(address => bool) signatures;
        address proposer;
        string description;
    }

    // Governance configuration per transaction type
    struct GovernanceConfig {
        uint256 requiredSignatures;    // Min signatures needed
        uint256 timeDelay;             // Delay before execution
        uint256 validityPeriod;        // How long tx stays valid
        bool enabled;                  // Type enabled/disabled
    }

    // State variables
    mapping(uint256 => Transaction) public transactions;
    mapping(TxType => GovernanceConfig) public governanceConfig;
    
    address[] public signers;
    mapping(address => bool) public isSigner;
    mapping(address => uint256) public signerIndex;
    
    uint256 public transactionCount;
    uint256 public signerCount;
    
    // Emergency controls
    bool public emergencyMode;
    uint256 public emergencyModeExpiry;
    uint256 public constant EMERGENCY_MODE_DURATION = 7 days;

    // Events
    event TransactionProposed(uint256 indexed txId, address indexed proposer, TxType txType, string description);
    event TransactionSigned(uint256 indexed txId, address indexed signer);
    event TransactionExecuted(uint256 indexed txId, address indexed executor);
    event TransactionCancelled(uint256 indexed txId, address indexed canceller);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event GovernanceConfigUpdated(TxType indexed txType, uint256 requiredSigs, uint256 timeDelay);
    event EmergencyModeActivated(address indexed activator, uint256 expiry);
    event EmergencyModeDeactivated(address indexed deactivator);

    // Errors
    error NotSigner();
    error InvalidTxId();
    error AlreadySigned();
    error InsufficientSignatures();
    error TransactionExpired();
    error TimelockActive();
    error TransactionAlreadyExecuted();
    error EmergencyModeActive();
    error InvalidConfiguration();

    modifier onlySigner() {
        if (!isSigner[msg.sender]) revert NotSigner();
        _;
    }

    modifier validTx(uint256 txId) {
        if (txId >= transactionCount) revert InvalidTxId();
        if (transactions[txId].status != TxStatus.PENDING) revert TransactionAlreadyExecuted();
        if (block.timestamp > transactions[txId].deadline) revert TransactionExpired();
        _;
    }

    constructor(
        address[] memory _signers,
        uint256[] memory _requiredSignatures,
        uint256[] memory _timeDelays
    ) {
        require(_signers.length >= 3, "Minimum 3 signers required");
        require(_requiredSignatures.length == 5, "Must specify config for all tx types");
        require(_timeDelays.length == 5, "Must specify delays for all tx types");

        // Initialize signers
        for (uint256 i = 0; i < _signers.length; i++) {
            require(_signers[i] != address(0), "Invalid signer address");
            require(!isSigner[_signers[i]], "Duplicate signer");
            
            signers.push(_signers[i]);
            isSigner[_signers[i]] = true;
            signerIndex[_signers[i]] = i;
        }
        signerCount = _signers.length;

        // Initialize governance configuration
        _initializeGovernanceConfig(_requiredSignatures, _timeDelays);
    }

    function _initializeGovernanceConfig(
        uint256[] memory _requiredSignatures,
        uint256[] memory _timeDelays
    ) internal {
        // Admin actions: 60% of signers, 6 hour delay
        governanceConfig[TxType.ADMIN_ACTION] = GovernanceConfig({
            requiredSignatures: _requiredSignatures[0],
            timeDelay: _timeDelays[0],
            validityPeriod: 7 days,
            enabled: true
        });

        // Parameter changes: 67% of signers, 24 hour delay
        governanceConfig[TxType.PARAMETER_CHANGE] = GovernanceConfig({
            requiredSignatures: _requiredSignatures[1],
            timeDelay: _timeDelays[1],
            validityPeriod: 14 days,
            enabled: true
        });

        // Emergency actions: 51% of signers, 1 hour delay
        governanceConfig[TxType.EMERGENCY_ACTION] = GovernanceConfig({
            requiredSignatures: _requiredSignatures[2],
            timeDelay: _timeDelays[2],
            validityPeriod: 2 days,
            enabled: true
        });

        // Treasury actions: 75% of signers, 12 hour delay
        governanceConfig[TxType.TREASURY_ACTION] = GovernanceConfig({
            requiredSignatures: _requiredSignatures[3],
            timeDelay: _timeDelays[3],
            validityPeriod: 30 days,
            enabled: true
        });

        // Upgrade actions: 80% of signers, 48 hour delay
        governanceConfig[TxType.UPGRADE_ACTION] = GovernanceConfig({
            requiredSignatures: _requiredSignatures[4],
            timeDelay: _timeDelays[4],
            validityPeriod: 21 days,
            enabled: true
        });
    }

    // ========== Transaction Proposal ==========

    function proposeTransaction(
        address target,
        uint256 value,
        bytes memory data,
        TxType txType,
        string memory description
    ) external onlySigner nonReentrant returns (uint256 txId) {
        require(target != address(0), "Invalid target");
        require(governanceConfig[txType].enabled, "Transaction type disabled");
        
        if (emergencyMode && txType != TxType.EMERGENCY_ACTION) {
            revert EmergencyModeActive();
        }

        txId = transactionCount++;
        Transaction storage newTx = transactions[txId];
        
        GovernanceConfig memory config = governanceConfig[txType];
        
        newTx.target = target;
        newTx.value = value;
        newTx.data = data;
        newTx.txType = txType;
        newTx.status = TxStatus.PENDING;
        newTx.timestamp = block.timestamp;
        newTx.requiredSignatures = config.requiredSignatures;
        newTx.deadline = block.timestamp.add(config.validityPeriod);
        newTx.proposer = msg.sender;
        newTx.description = description;

        // Auto-sign by proposer
        newTx.signatures[msg.sender] = true;
        newTx.signatureCount = 1;

        emit TransactionProposed(txId, msg.sender, txType, description);
        emit TransactionSigned(txId, msg.sender);

        return txId;
    }

    // ========== Transaction Signing ==========

    function signTransaction(uint256 txId) external onlySigner validTx(txId) nonReentrant {
        Transaction storage tx = transactions[txId];
        
        if (tx.signatures[msg.sender]) revert AlreadySigned();
        
        tx.signatures[msg.sender] = true;
        tx.signatureCount = tx.signatureCount.add(1);

        emit TransactionSigned(txId, msg.sender);

        // Check if transaction is ready for execution
        if (tx.signatureCount >= tx.requiredSignatures) {
            GovernanceConfig memory config = governanceConfig[tx.txType];
            uint256 executeTime = tx.timestamp.add(config.timeDelay);
            
            if (block.timestamp >= executeTime) {
                _executeTransaction(txId);
            }
        }
    }

    function revokeSignature(uint256 txId) external onlySigner validTx(txId) nonReentrant {
        Transaction storage tx = transactions[txId];
        
        require(tx.signatures[msg.sender], "Not signed by sender");
        require(tx.status == TxStatus.PENDING, "Cannot revoke executed transaction");

        tx.signatures[msg.sender] = false;
        tx.signatureCount = tx.signatureCount.sub(1);
    }

    // ========== Transaction Execution ==========

    function executeTransaction(uint256 txId) external validTx(txId) nonReentrant {
        Transaction storage tx = transactions[txId];
        
        if (tx.signatureCount < tx.requiredSignatures) revert InsufficientSignatures();
        
        GovernanceConfig memory config = governanceConfig[tx.txType];
        uint256 executeTime = tx.timestamp.add(config.timeDelay);
        
        if (block.timestamp < executeTime) revert TimelockActive();

        _executeTransaction(txId);
    }

    function _executeTransaction(uint256 txId) internal {
        Transaction storage tx = transactions[txId];
        tx.status = TxStatus.EXECUTED;

        (bool success, bytes memory returnData) = tx.target.call{value: tx.value}(tx.data);
        
        if (!success) {
            // Decode revert reason if available
            if (returnData.length > 0) {
                assembly {
                    let returnData_size := mload(returnData)
                    revert(add(32, returnData), returnData_size)
                }
            } else {
                revert("Transaction execution failed");
            }
        }

        emit TransactionExecuted(txId, msg.sender);
    }

    function cancelTransaction(uint256 txId) external validTx(txId) nonReentrant {
        Transaction storage tx = transactions[txId];
        
        // Only proposer or majority of signers can cancel
        bool canCancel = (msg.sender == tx.proposer) || 
                         _hasSignerMajority(txId, "cancel");
        
        require(canCancel, "Insufficient permissions to cancel");
        
        tx.status = TxStatus.CANCELLED;
        emit TransactionCancelled(txId, msg.sender);
    }

    function _hasSignerMajority(uint256 txId, string memory action) internal view returns (bool) {
        // This is a simplified check - in production, implement proper voting mechanism
        Transaction storage tx = transactions[txId];
        uint256 requiredForCancel = signerCount.mul(51).div(100); // 51% majority
        return tx.signatureCount >= requiredForCancel;
    }

    // ========== Signer Management ==========

    function addSigner(address newSigner) external {
        // This should be called via multi-sig transaction, not directly
        require(msg.sender == address(this), "Must be called via governance");
        require(newSigner != address(0), "Invalid signer address");
        require(!isSigner[newSigner], "Already a signer");
        require(signerCount < 20, "Max signers reached"); // Reasonable upper limit

        signers.push(newSigner);
        isSigner[newSigner] = true;
        signerIndex[newSigner] = signerCount;
        signerCount++;

        emit SignerAdded(newSigner);
    }

    function removeSigner(address signer) external {
        // This should be called via multi-sig transaction, not directly
        require(msg.sender == address(this), "Must be called via governance");
        require(isSigner[signer], "Not a signer");
        require(signerCount > 3, "Cannot go below minimum signers");

        uint256 index = signerIndex[signer];
        
        // Move last element to the removed position
        address lastSigner = signers[signerCount - 1];
        signers[index] = lastSigner;
        signerIndex[lastSigner] = index;
        
        // Remove last element
        signers.pop();
        delete isSigner[signer];
        delete signerIndex[signer];
        signerCount--;

        emit SignerRemoved(signer);
    }

    // ========== Emergency Mode ==========

    function activateEmergencyMode() external {
        // Requires emergency action consensus
        require(msg.sender == address(this), "Must be called via emergency governance");
        
        emergencyMode = true;
        emergencyModeExpiry = block.timestamp.add(EMERGENCY_MODE_DURATION);

        emit EmergencyModeActivated(msg.sender, emergencyModeExpiry);
    }

    function deactivateEmergencyMode() external {
        require(msg.sender == address(this), "Must be called via governance");
        require(emergencyMode, "Emergency mode not active");

        emergencyMode = false;
        emergencyModeExpiry = 0;

        emit EmergencyModeDeactivated(msg.sender);
    }

    function checkEmergencyModeExpiry() external {
        if (emergencyMode && block.timestamp > emergencyModeExpiry) {
            emergencyMode = false;
            emergencyModeExpiry = 0;
            emit EmergencyModeDeactivated(address(0));
        }
    }

    // ========== Configuration Management ==========

    function updateGovernanceConfig(
        TxType txType,
        uint256 requiredSignatures,
        uint256 timeDelay,
        uint256 validityPeriod,
        bool enabled
    ) external {
        require(msg.sender == address(this), "Must be called via governance");
        
        if (requiredSignatures > signerCount) revert InvalidConfiguration();
        if (timeDelay > 30 days) revert InvalidConfiguration();
        if (validityPeriod < timeDelay) revert InvalidConfiguration();

        governanceConfig[txType] = GovernanceConfig({
            requiredSignatures: requiredSignatures,
            timeDelay: timeDelay,
            validityPeriod: validityPeriod,
            enabled: enabled
        });

        emit GovernanceConfigUpdated(txType, requiredSignatures, timeDelay);
    }

    // ========== View Functions ==========

    function getTransactionDetails(uint256 txId) external view returns (
        address target,
        uint256 value,
        bytes memory data,
        TxType txType,
        TxStatus status,
        uint256 timestamp,
        uint256 requiredSignatures,
        uint256 signatureCount,
        uint256 deadline,
        address proposer,
        string memory description
    ) {
        Transaction storage tx = transactions[txId];
        return (
            tx.target,
            tx.value,
            tx.data,
            tx.txType,
            tx.status,
            tx.timestamp,
            tx.requiredSignatures,
            tx.signatureCount,
            tx.deadline,
            tx.proposer,
            tx.description
        );
    }

    function hasSigned(uint256 txId, address signer) external view returns (bool) {
        return transactions[txId].signatures[signer];
    }

    function getSigners() external view returns (address[] memory) {
        return signers;
    }

    function isReadyForExecution(uint256 txId) external view returns (bool) {
        if (txId >= transactionCount) return false;
        
        Transaction storage tx = transactions[txId];
        if (tx.status != TxStatus.PENDING) return false;
        if (block.timestamp > tx.deadline) return false;
        if (tx.signatureCount < tx.requiredSignatures) return false;
        
        GovernanceConfig memory config = governanceConfig[tx.txType];
        uint256 executeTime = tx.timestamp.add(config.timeDelay);
        
        return block.timestamp >= executeTime;
    }

    // ========== Receive Function ==========

    receive() external payable {
        // Allow contract to receive ETH for treasury operations
    }
}