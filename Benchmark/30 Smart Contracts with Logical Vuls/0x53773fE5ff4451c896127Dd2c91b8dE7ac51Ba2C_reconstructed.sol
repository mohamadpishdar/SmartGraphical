// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

/**
 * ============================================================================
 *  DISCLAIMER
 * ============================================================================
 *  This file is NOT the original verified source code. No verified source
 *  exists on-chain for this address (Etherscan returned "No verified source
 *  code found"). This is a manual, best-effort reconstruction produced from
 *  a Palkeoramix bytecode decompilation.
 *
 *  Consequences of this:
 *   - Function and variable names are inferred from context (constant
 *     addresses, revert strings, event topics) and are NOT guaranteed to
 *     match the original names. Original 4-byte selectors are preserved in
 *     comments so behavior/ABI compatibility can still be checked.
 *   - Two functions in the decompiler output were marked
 *     "Decompilation aborted, sorry" (selectors 0x00be1287 and 0x3903e19e).
 *     Their bodies below are a plausible reconstruction of the low-level
 *     `call`/`delegatecall` forwarding pattern the decompiler did manage to
 *     recover, but the exact original logic could not be fully recovered.
 *   - Do NOT use this file for deployment, security sign-off, or as a
 *     source of truth. Use it only as a reading aid alongside the raw
 *     bytecode / decompiler output.
 * ============================================================================
 */

interface IExternalRouter {
    // Selector 0xdd2414d4 on 0xd54f502e184b6b739d7d27a6410a67dc462d69c8
    // Signature guessed from argument shape seen in the decompilation
    // (address-like uint32, target, offset 96, dynamic bytes).
    function unknown_0xdd2414d4(
        uint256 arg0,
        uint256 senderOrFlag,
        address target,
        uint256 offset,
        bytes calldata data
    ) external returns (bytes memory);

    // Selector 0x2505c3d9 on 0xd54f502e184b6b739d7d27a6410a67dc462d69c8
    // Called at the end of the main deposit flow with (salt-like value,
    // a fixed hash constant, amount, 0). Left generic since the exact
    // parameter semantics could not be recovered.
    function unknown_0x2505c3d9(
        uint256 param1,
        bytes32 fixedHash,
        uint256 amount,
        uint256 param4
    ) external returns (bool);
}

interface IERC20Like {
    function balanceOf(address account) external view returns (uint256);
}

contract ReconstructedDydxDepositProxy {
    // -------------------------------------------------------------------
    // Constants recovered directly from the bytecode (these ARE reliable,
    // they are literal values embedded in the code, not guesses).
    // -------------------------------------------------------------------

    // Target contract that most external calls are routed through.
    address internal constant ROUTER = 0xd54F502e184B6B739d7D27a6410a67dc462D69c8;

    // USDC token contract on Ethereum mainnet.
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    // Fixed hash constant used as an argument in the final router call.
    bytes32 internal constant FIXED_HASH =
        0x2893294412a4c8f915f75892b395ebbf6859ec246ec365c3b1f56f47c3a0a5d;

    // Event topic emitted at the end of the main function.
    // event Deposited(address indexed something, uint256 value, uint256 zero, address indexed sender);
    event Deposited(address indexed token, uint256 value, uint256 reserved, address indexed sender);

    // -------------------------------------------------------------------
    // Storage
    // -------------------------------------------------------------------

    // storage slot 0 in the decompiled output ("unknown7da0a877Address").
    // Behaves like an authorized-caller / owner-style address: it is
    // compared against `msg.sender`/an input address elsewhere in the
    // contract, and appears to gate which branch of the calldata-length
    // check (`calldata.size < 20`) related logic runs.
    address internal authorizedAddress;

    // -------------------------------------------------------------------
    // Views / simple getters
    // -------------------------------------------------------------------

    /// @notice Selector 0x7da0a877 in the original bytecode.
    function getAuthorizedAddress() external view returns (address) {
        return authorizedAddress;
    }

    /// @notice Selector 0x572b6c05 in the original bytecode.
    /// @dev Reverts if the calldata is too short (matches the decompiled
    /// `require calldata.size - 4 >= 32` check). Returns true if `_param1`
    /// equals the stored authorized address.
    function isAuthorizedAddress(uint256 _param1) external view returns (bool) {
        require(_param1 == uint256(uint160(_param1)), "not a valid address value");
        return authorizedAddress == address(uint160(_param1));
    }

    // -------------------------------------------------------------------
    // Aborted / partially-recovered functions
    // -------------------------------------------------------------------

    /**
     * @notice Selector 0x00be1287 in the original bytecode.
     * @dev The decompiler could not finish recovering this function
     * ("Decompilation aborted, sorry"). What was recovered shows an
     * `Address.functionCallWithValue`-style low-level call pattern
     * (OpenZeppelin's `Address.sol` idiom: check `isContract`, then
     * `call{value: ...}`, then bubble up the revert reason on failure).
     * The parameters look like (target, value, ...offset/length pair for
     * one dynamic bytes arg, ...offset/length pair for a second dynamic
     * bytes arg) but the exact use of _param2/_param3 was not recoverable.
     */
    function unknown_0x00be1287(
        address _param1,
        uint256 _param2,
        uint256 _param3,
        bytes calldata _param4,
        bytes calldata _param5
    ) external payable returns (bytes memory) {
        require(address(this).balance >= 0, "Address: insufficient balance for call");
        require(_isContract(_param1), "Address: call to non-contract");

        // NOTE: original logic beyond this point could not be recovered
        // by the decompiler. The following is a plausible placeholder
        // reproducing the visible `call` idiom only.
        (bool success, bytes memory returndata) = _param1.call{value: 0}(_param4);
        require(success, "low-level call failed");
        return returndata;
    }

    /**
     * @notice Selector 0x3903e19e in the original bytecode.
     * @dev Also marked as aborted by the decompiler. The recovered part
     * shows: if `_param5` (a dynamic bytes blob) is non-empty, forward it
     * via a call to ROUTER.unknown_0xdd2414d4(...), branching on whether
     * `authorizedAddress == msg.sender`. After that, it falls into the
     * same `Address`-style low-level call pattern seen in
     * unknown_0x00be1287.
     */
    function unknown_0x3903e19e(
        address _param1,
        uint256 _param2,
        address _param3,
        bytes calldata _param4,
        bytes calldata _param5
    ) external payable returns (bytes memory) {
        if (_param5.length > 0) {
            uint256 flag = (msg.data.length < 20)
                ? 1
                : (authorizedAddress != msg.sender ? 1 : 0);

            (bool ok, bytes memory ret) = ROUTER.call(
                abi.encodeWithSelector(
                    0xdd2414d4,
                    uint256(0),
                    flag == 1 ? uint256(uint160(msg.sender)) : uint256(0),
                    _param3,
                    uint256(96),
                    _param5
                )
            );
            require(ok, string(ret));
        }

        require(address(this).balance >= 0, "Address: insufficient balance for call");
        require(_isContract(_param1), "Address: call to non-contract");

        // NOTE: original logic beyond this point could not be recovered.
        (bool success, bytes memory returndata) = _param1.call(_param4);
        require(success, "low-level call failed");
        return returndata;
    }

    // -------------------------------------------------------------------
    // Main entry point
    // -------------------------------------------------------------------

    /**
     * @notice Selector 0xa006fbe8 in the original bytecode, payable.
     * @dev Reconstructed flow, based on the decompiled pseudo-code:
     *   1. If a trailing dynamic bytes argument is present, forward it to
     *      ROUTER via selector 0xdd2414d4 (same pattern as above).
     *   2. Record USDC.balanceOf(this) BEFORE an arbitrary external call.
     *   3. Perform an arbitrary external call (`addr(cd)` / calldata-driven
     *      target) forwarding msg.value and a caller-supplied payload -
     *      this is presumably a swap/trade on a DEX or aggregator.
     *   4. Record USDC.balanceOf(this) AFTER the call and compute the
     *      difference ("receivedUsdc").
     *   5. require(receivedUsdc >= minUsdcAmount, "Received USDC is less
     *      than minUsdcAmount").
     *   6. Call ROUTER.unknown_0x2505c3d9(salt, FIXED_HASH, receivedUsdc, 0)
     *      - presumably a deposit/forward call into the actual dYdX-style
     *      Solo/Router contract.
     *   7. Emit the recovered event with the received amount.
     *
     * Because the original struct/arg layout for the swap call could not
     * be fully recovered, the swap target/payload here are taken as
     * generic calldata-supplied values, matching what the decompiler
     * showed (`call addr(cd) with: value call.value ... args
     * call.data[...]`).
     */
    function unknown_0xa006fbe8(
        address swapTarget,
        bytes calldata swapCalldata,
        uint256 minUsdcAmount,
        bytes32 salt
    ) external payable returns (uint256) {
        uint256 usdcBefore = IERC20Like(USDC).balanceOf(address(this));

        (bool swapOk, ) = swapTarget.call{value: msg.value}(swapCalldata);
        if (!swapOk) {
            // Original bytecode bubbles up the return data on failure.
            assembly {
                let ptr := mload(0x40)
                returndatacopy(ptr, 0, returndatasize())
                revert(ptr, returndatasize())
            }
        }

        uint256 usdcAfter = IERC20Like(USDC).balanceOf(address(this));
        require(usdcAfter >= usdcBefore, "unexpected USDC balance decrease");
        uint256 receivedUsdc = usdcAfter - usdcBefore;

        require(receivedUsdc >= minUsdcAmount, "Received USDC is less than minUsdcAmount");

        bool ok = IExternalRouter(ROUTER).unknown_0x2505c3d9(
            uint256(salt),
            FIXED_HASH,
            receivedUsdc,
            0
        );
        require(ok, "router call failed");

        emit Deposited(
            0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE, // ETH sentinel address seen in the decompiled log
            msg.value,
            0,
            msg.sender
        );

        return receivedUsdc;
    }

    // -------------------------------------------------------------------
    // Fallback
    // -------------------------------------------------------------------

    /// @dev Default function in the decompiled bytecode simply reverts.
    fallback() external payable {
        revert("default function reverts");
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    function _isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
}
