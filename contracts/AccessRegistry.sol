// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {LowLevelCall} from "@openzeppelin/contracts/utils/LowLevelCall.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/// @title AccessRegistry
/// @notice Time-limited, plan-based access rights that are paid for in ETH.
///         An off-chain service asks `hasAccess(user, planId)` to decide whether to serve a request.
/// @dev Educational example. Not audited and not deployed anywhere.
///
///      Roles
///      - `DEFAULT_ADMIN_ROLE` (one account, two-step transfer with a delay, see
///        OpenZeppelin `AccessControlDefaultAdminRules`): creates plans, changes plan price and
///        active flag, pauses purchases, withdraws revenue, manages operators.
///      - `OPERATOR_ROLE`: grants and revokes access without payment.
///
///      Payment rules
///      - `purchase` accepts `msg.value >= price`. The overpayment is refunded to the buyer in the
///        same transaction (the only push payment in the contract). If the refund fails, the whole
///        purchase reverts. A buyer that cannot receive ETH must pay the exact price.
///      - Revenue is only accounted, never forwarded. The admin pulls it with `withdrawTo`.
///      - The contract has no `receive` or `fallback`, so plain transfers revert. ETH can still be
///        forced into any contract (for example by a self-destructing contract); such ETH is not
///        accounted and cannot be withdrawn.
///
///      Time rules
///      - Access is valid while `expiry > block.timestamp`. At `expiry == block.timestamp` it is over.
///      - A purchase or grant adds the duration to `max(now, currentExpiry)`, so renewing early
///        does not waste the remaining time.
///      - Changing a plan price never changes time that was already bought.
///
///      Capacity rules
///      - `maxHolders == 0` means unlimited. For capped plans, a holder occupies one slot from the
///        first purchase or grant until `revoke` or `releaseExpired`. Expiry alone does not free a
///        slot because nothing runs on-chain when time passes. Anyone can call `releaseExpired` with
///        a bounded list of users to free the slots of expired holders.
///      - Operator grants count against the cap like purchases.
contract AccessRegistry is AccessControlDefaultAdminRules, Pausable, ReentrancyGuard {
    /// @notice Role allowed to grant and revoke access without payment.
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Upper bound for a plan duration and for a single grant (about 10 years).
    uint64 public constant MAX_DURATION = 3650 days;
    /// @notice Upper bound for the length of a grant or revoke reason, in bytes.
    uint256 public constant MAX_REASON_LENGTH = 140;
    /// @notice Upper bound for the number of users in one `releaseExpired` call.
    uint256 public constant MAX_RELEASE_BATCH = 50;

    struct Plan {
        uint256 price; // wei, applies to future purchases only
        uint64 duration; // seconds added per purchase; 0 means the plan does not exist
        uint32 maxHolders; // 0 = unlimited
        uint32 activeHolders; // slots in use, tracked only when maxHolders != 0
        bool active; // purchases allowed
    }

    mapping(uint256 planId => Plan) private _plans;
    mapping(uint256 planId => mapping(address user => uint64)) private _expiry;
    mapping(uint256 planId => mapping(address user => bool)) private _holdsSlot;

    /// @notice ETH received for plans and not yet withdrawn.
    uint256 public accruedRevenue;
    /// @notice Lifetime sum of plan prices paid (excludes refunded overpayments).
    uint256 public totalReceived;
    /// @notice Lifetime sum of withdrawn revenue.
    uint256 public totalWithdrawn;
    /// @notice Lifetime sum of refunded overpayments.
    uint256 public totalRefunded;

    event PlanCreated(uint256 indexed planId, uint256 price, uint64 duration, uint32 maxHolders);
    event PlanActiveChanged(uint256 indexed planId, bool active);
    event PlanPriceChanged(uint256 indexed planId, uint256 oldPrice, uint256 newPrice);
    event Purchased(uint256 indexed planId, address indexed buyer, uint256 price, uint64 newExpiry);
    event Refunded(address indexed buyer, uint256 amount);
    event AccessGranted(
        uint256 indexed planId,
        address indexed user,
        address indexed operator,
        uint64 duration,
        uint64 newExpiry,
        string reason
    );
    event AccessRevoked(
        uint256 indexed planId,
        address indexed user,
        address indexed operator,
        uint64 previousExpiry,
        string reason
    );
    event SlotReleased(uint256 indexed planId, address indexed user);
    event Withdrawn(address indexed to, uint256 amount, address indexed admin);

    error InvalidAddress();
    error InvalidPrice();
    error InvalidDuration(uint64 duration);
    error PlanNotFound(uint256 planId);
    error PlanAlreadyExists(uint256 planId);
    error PlanInactive(uint256 planId);
    error PlanFull(uint256 planId, uint32 maxHolders);
    error InsufficientPayment(uint256 sent, uint256 required);
    error RefundFailed(address buyer, uint256 amount);
    error ReasonTooLong(uint256 length, uint256 maxLength);
    error NothingToRevoke(address user, uint256 planId);
    error BatchTooLarge(uint256 length, uint256 maxLength);
    error ZeroAmount();
    error InsufficientRevenue(uint256 requested, uint256 available);
    error WithdrawFailed(address to, uint256 amount);

    /// @param initialDelay Delay in seconds before a default admin transfer can be accepted.
    /// @param initialAdmin The first default admin. Must not be the zero address.
    constructor(
        uint48 initialDelay,
        address initialAdmin
    ) AccessControlDefaultAdminRules(initialDelay, initialAdmin) {}

    // ------------------------------------------------------------------
    // Admin: plans
    // ------------------------------------------------------------------

    /// @notice Define a new plan. Plan ids are chosen by the admin and cannot be reused.
    function createPlan(
        uint256 planId,
        uint256 price,
        uint64 duration,
        uint32 maxHolders
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_plans[planId].duration != 0) revert PlanAlreadyExists(planId);
        if (price == 0) revert InvalidPrice();
        _checkDuration(duration);

        _plans[planId] = Plan({
            price: price,
            duration: duration,
            maxHolders: maxHolders,
            activeHolders: 0,
            active: true
        });
        emit PlanCreated(planId, price, duration, maxHolders);
    }

    /// @notice Allow or stop new purchases of a plan. Existing access is not affected.
    function setPlanActive(uint256 planId, bool active) external onlyRole(DEFAULT_ADMIN_ROLE) {
        Plan storage plan = _plan(planId);
        plan.active = active;
        emit PlanActiveChanged(planId, active);
    }

    /// @notice Change the price of future purchases. Access that was already bought is unchanged.
    function setPlanPrice(uint256 planId, uint256 newPrice) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newPrice == 0) revert InvalidPrice();
        Plan storage plan = _plan(planId);
        uint256 oldPrice = plan.price;
        plan.price = newPrice;
        emit PlanPriceChanged(planId, oldPrice, newPrice);
    }

    // ------------------------------------------------------------------
    // Admin: pause and revenue
    // ------------------------------------------------------------------

    /// @notice Stop `purchase`. Grants, revokes, releases and withdrawals keep working.
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Send `amount` of accrued revenue to `to`.
    /// @dev Accounting is updated before the external call. `nonReentrant` additionally blocks
    ///      the receiver from calling `purchase` or `withdrawTo` while the call is in flight.
    function withdrawTo(address payable to, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert ZeroAmount();
        uint256 available = accruedRevenue;
        if (amount > available) revert InsufficientRevenue(amount, available);

        accruedRevenue = available - amount;
        totalWithdrawn += amount;
        emit Withdrawn(to, amount, msg.sender);

        if (!LowLevelCall.callNoReturn(to, amount, "")) revert WithdrawFailed(to, amount);
    }

    // ------------------------------------------------------------------
    // Users
    // ------------------------------------------------------------------

    /// @notice Buy or extend access to `planId` for the caller.
    ///         Sending more than the price refunds the difference to the caller.
    function purchase(uint256 planId) external payable whenNotPaused nonReentrant {
        Plan storage plan = _plan(planId);
        if (!plan.active) revert PlanInactive(planId);

        uint256 price = plan.price;
        if (msg.value < price) revert InsufficientPayment(msg.value, price);

        uint64 newExpiry = _extend(planId, plan, msg.sender, plan.duration);

        accruedRevenue += price;
        totalReceived += price;
        emit Purchased(planId, msg.sender, price, newExpiry);

        uint256 refund = msg.value - price;
        if (refund != 0) {
            totalRefunded += refund;
            emit Refunded(msg.sender, refund);
            if (!LowLevelCall.callNoReturn(msg.sender, refund, "")) revert RefundFailed(msg.sender, refund);
        }
    }

    /// @notice Free the capacity slots held by users whose access has ended.
    ///         Anyone can call this. Users that still have access or hold no slot are skipped.
    /// @return released Number of slots freed.
    function releaseExpired(uint256 planId, address[] calldata users) external returns (uint256 released) {
        Plan storage plan = _plan(planId);
        if (users.length > MAX_RELEASE_BATCH) revert BatchTooLarge(users.length, MAX_RELEASE_BATCH);

        for (uint256 i = 0; i < users.length; ++i) {
            address user = users[i];
            if (_holdsSlot[planId][user] && _expiry[planId][user] <= block.timestamp) {
                _holdsSlot[planId][user] = false;
                plan.activeHolders -= 1;
                ++released;
                emit SlotReleased(planId, user);
            }
        }
    }

    // ------------------------------------------------------------------
    // Operators
    // ------------------------------------------------------------------

    /// @notice Give `user` `duration` seconds of access without payment (added like a purchase).
    function grant(
        address user,
        uint256 planId,
        uint64 duration,
        string calldata reason
    ) external onlyRole(OPERATOR_ROLE) {
        if (user == address(0)) revert InvalidAddress();
        _checkDuration(duration);
        _checkReason(reason);
        Plan storage plan = _plan(planId);

        uint64 newExpiry = _extend(planId, plan, user, duration);
        emit AccessGranted(planId, user, msg.sender, duration, newExpiry, reason);
    }

    /// @notice End the access of `user` immediately and free their slot. No refund is made.
    function revoke(address user, uint256 planId, string calldata reason) external onlyRole(OPERATOR_ROLE) {
        _checkReason(reason);
        Plan storage plan = _plan(planId);

        uint64 previousExpiry = _expiry[planId][user];
        if (previousExpiry == 0) revert NothingToRevoke(user, planId);

        delete _expiry[planId][user];
        if (_holdsSlot[planId][user]) {
            _holdsSlot[planId][user] = false;
            plan.activeHolders -= 1;
        }
        emit AccessRevoked(planId, user, msg.sender, previousExpiry, reason);
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------

    /// @notice True while the user's access to `planId` has not ended. Unknown plans return false.
    function hasAccess(address user, uint256 planId) external view returns (bool) {
        return _expiry[planId][user] > block.timestamp;
    }

    /// @notice Unix time at which the user's access ends; 0 if none was ever recorded or it was revoked.
    function expiryOf(address user, uint256 planId) external view returns (uint64) {
        return _expiry[planId][user];
    }

    /// @notice True if the user currently occupies a capacity slot of a capped plan.
    function holdsSlot(address user, uint256 planId) external view returns (bool) {
        return _holdsSlot[planId][user];
    }

    function getPlan(uint256 planId) external view returns (Plan memory) {
        return _plan(planId);
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    function _plan(uint256 planId) private view returns (Plan storage plan) {
        plan = _plans[planId];
        if (plan.duration == 0) revert PlanNotFound(planId);
    }

    function _checkDuration(uint64 duration) private pure {
        if (duration == 0 || duration > MAX_DURATION) revert InvalidDuration(duration);
    }

    function _checkReason(string calldata reason) private pure {
        uint256 length = bytes(reason).length;
        if (length > MAX_REASON_LENGTH) revert ReasonTooLong(length, MAX_REASON_LENGTH);
    }

    /// @dev Adds `duration` to max(now, current expiry) and takes a capacity slot if needed.
    function _extend(
        uint256 planId,
        Plan storage plan,
        address user,
        uint64 duration
    ) private returns (uint64 newExpiry) {
        uint64 start = SafeCast.toUint64(block.timestamp);
        uint64 current = _expiry[planId][user];
        if (current > start) start = current;
        newExpiry = start + duration;

        uint32 cap = plan.maxHolders;
        if (cap != 0 && !_holdsSlot[planId][user]) {
            if (plan.activeHolders >= cap) revert PlanFull(planId, cap);
            _holdsSlot[planId][user] = true;
            plan.activeHolders += 1;
        }
        _expiry[planId][user] = newExpiry;
    }
}
