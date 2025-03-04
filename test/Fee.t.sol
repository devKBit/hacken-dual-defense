// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../src/Fee.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Test, console} from "forge-std/Test.sol";

using SafeERC20 for IERC20;

contract UUPSProxy is ERC1967Proxy {
    constructor(address _implementation, bytes memory _data) ERC1967Proxy(_implementation, _data) {}
}

contract FeeTest is Test {
    UUPSProxy public feeProxy;
    Fee public fee;

    address owner;
    address admin;
    address protocolFeeCollector;
    address user;
    address user2;
    address referrer;
    uint256 userPk;
    uint256 user2Pk;
    uint256 referrerPk;

    function setUp() public {
        vm.chainId(8217);

        (owner,) = makeAddrAndKey("owner");
        (admin,) = makeAddrAndKey("admin");
        (protocolFeeCollector,) = makeAddrAndKey("protocolFeeCollector");
        (user, userPk) = makeAddrAndKey("user");
        (user2, user2Pk) = makeAddrAndKey("user2");
        (referrer, referrerPk) = makeAddrAndKey("referrer");

        vm.startPrank(owner);

        Fee feeImpl = new Fee();
        feeProxy = new UUPSProxy(address(feeImpl), "");
        fee = Fee(address(feeProxy));
        fee.initialize(owner);
        fee.setAdmin(admin);

        vm.stopPrank();
    }

    function setAddresses() public {
        vm.startPrank(owner);
        vm.mockCall(address(0x1), abi.encodeWithSelector(IERC20Metadata.decimals.selector), abi.encode(6));
        fee.setUsdtAddr(address(0x1));
        fee.setPerpDexAddr(address(0x2));
        vm.stopPrank();
    }

    function test_onlyOwnerForSetAddr() public {
        assertEq(address(fee.usdt()), address(0));
        assertEq(address(fee.perpDex()), address(0));

        vm.expectRevert();
        fee.setUsdtAddr(address(0x1));
        vm.expectRevert();
        fee.setPerpDexAddr(address(0x2));

        setAddresses();

        assertEq(address(fee.usdt()), address(1));
        assertEq(address(fee.perpDex()), address(2));
    }

    function test_onlyAdmin() public {
        vm.startPrank(owner);
        fee.setAdmin(admin);

        vm.expectRevert("Only admin can call this function");
        fee.registerReferrer(address(0x1), address(0x2), hex"1234");

        vm.expectRevert("Only admin can call this function");
        fee.setFeePercent(address(0x1), 1, 2, hex"1234");
        vm.stopPrank();

        vm.startPrank(admin);
        vm.expectRevert("Cannot refer yourself");
        fee.registerReferrer(address(0x1), address(0x1), hex"1234");
        vm.expectRevert("Fee percent must be less than denominator");
        fee.setFeePercent(address(0x1), 10_000_000_000, 2, hex"1234");
        vm.stopPrank();
    }

    function test_feeConstants() public view {
        assertEq(fee.getTotalFeePercent(), 70);
        assertEq(fee.getFeeDenominator(), 100_000);
    }

    function signMsg(uint256 pk, string memory message) internal pure returns (bytes memory) {
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", "11", message));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }

    function test_setFeePercent() public {
        string memory message =
            string(abi.encodePacked("Create referral code. Nonce: 0, Chain: 8217, Contract: ", Strings.toHexString(address(fee))));
        bytes32 ethSignedMessageHash =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(bytes(message).length), message));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(referrerPk, ethSignedMessageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // 1. Owner
        vm.expectRevert();
        fee.setFeePercent(referrer, 10, 20, signature);

        vm.startPrank(admin);
        // 2. FeePercent
        uint256 protocolFee = fee.getFeeDenominator() + 1;
        vm.expectRevert("Fee percent must be less than denominator");
        fee.setFeePercent(referrer, protocolFee, 20, signature);

        uint256 referrerFee = fee.getFeeDenominator() + 1;
        vm.expectRevert("Fee percent must be less than denominator");
        fee.setFeePercent(referrer, 20, referrerFee, signature);

        // 3. Check sig
        message = string(abi.encodePacked("Create referral code. Nonce: 999, Chain: 8217, Contract: ", Strings.toHexString(address(fee))));
        ethSignedMessageHash =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(bytes(message).length), message));
        (v, r, s) = vm.sign(referrerPk, ethSignedMessageHash);
        bytes memory wrongSignature = abi.encodePacked(r, s, v);
        vm.expectRevert("Invalid signed data");
        fee.setFeePercent(referrer, 20, 20, wrongSignature);

        // 4. Success
        vm.expectEmit(true, true, true, true);
        emit Fee.FeePercentSet(referrer, 20, 10);
        fee.setFeePercent(referrer, 20, 10, signature);
        assertEq(fee.protocolFeePercent(referrer), 20);
        assertEq(fee.referrerFeePercent(referrer), 10);

        vm.stopPrank();
    }

    function test_registerReferrer() public {
        string memory message =
            string(abi.encodePacked("Create referral code. Nonce: 0, Chain: 8217, Contract: ", Strings.toHexString(address(fee))));
        bytes32 ethSignedMessageHash =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(bytes(message).length), message));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(referrerPk, ethSignedMessageHash);
        bytes memory referrerSig = abi.encodePacked(r, s, v);

        string memory message2 =
            string(abi.encodePacked("Register referrer. Nonce: 0, Chain: 8217, Contract: ", Strings.toHexString(address(fee))));
        bytes32 ethSignedMessageHash2 =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(bytes(message2).length), message2));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(userPk, ethSignedMessageHash2);
        bytes memory signature = abi.encodePacked(r2, s2, v2);

        // 1. Admin
        vm.expectRevert("Only admin can call this function");
        fee.registerReferrer(referrer, user, signature);

        vm.startPrank(admin);

        // 2. refer self
        vm.expectRevert("Cannot refer yourself");
        fee.registerReferrer(user, user, signature);

        // 3. protocolFeePercent is 0
        vm.expectRevert("protocolFeePercent is 0");
        fee.registerReferrer(referrer, user, signature);

        // 4. Check sig
        fee.setFeePercent(referrer, 20, 10, referrerSig);
        vm.expectRevert("Invalid signed data");
        fee.registerReferrer(referrer, user, referrerSig);

        // 5. Success
        vm.expectEmit(true, true, true, true);
        emit Fee.ReferralRegistered(referrer, user);
        fee.registerReferrer(referrer, user, signature);
        assertEq(fee.referral(user), referrer);
        assertEq(fee.refereeCount(referrer), 1);

        // 6. Referrer already exists
        vm.expectRevert("Referrer already exists");
        fee.registerReferrer(referrer, user, signature);

        vm.stopPrank();
    }

    function setUpReferrerForUser() public {
        string memory message =
            string(abi.encodePacked("Create referral code. Nonce: 0, Chain: 8217, Contract: ", Strings.toHexString(address(fee))));
        bytes32 ethSignedMessageHash =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(bytes(message).length), message));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(referrerPk, ethSignedMessageHash);
        bytes memory referrerSig = abi.encodePacked(r, s, v);

        emit log_string(message);
        emit log_string(Strings.toString(bytes(message).length));

        vm.startPrank(admin);
        fee.setFeePercent(referrer, 90_000, 80_000, referrerSig);

        string memory message2 =
            string(abi.encodePacked("Register referrer. Nonce: 0, Chain: 8217, Contract: ", Strings.toHexString(address(fee))));
        bytes32 ethSignedMessageHash2 =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(bytes(message2).length), message2));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(userPk, ethSignedMessageHash2);
        bytes memory refereeSig = abi.encodePacked(r2, s2, v2);

        fee.registerReferrer(referrer, user, refereeSig);
        vm.stopPrank();
    }

    function setUpReferrerForUser2() public {
        string memory message =
            string(abi.encodePacked("Create referral code. Nonce: 1, Chain: 8217, Contract: ", Strings.toHexString(address(fee))));
        bytes32 ethSignedMessageHash =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(bytes(message).length), message));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPk, ethSignedMessageHash);
        bytes memory referrerSig = abi.encodePacked(r, s, v);

        vm.startPrank(admin);
        fee.setFeePercent(user, 90_000, 50_000, referrerSig);

        string memory message2 =
            string(abi.encodePacked("Register referrer. Nonce: 0, Chain: 8217, Contract: ", Strings.toHexString(address(fee))));
        bytes32 ethSignedMessageHash2 =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(bytes(message2).length), message2));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(user2Pk, ethSignedMessageHash2);
        bytes memory refereeSig = abi.encodePacked(r2, s2, v2);

        emit log_string(message2);
        emit log_string(Strings.toString(bytes(message2).length));
        emit log_bytes32(ethSignedMessageHash2);
        emit log_address(user2);

        fee.registerReferrer(user, user2, refereeSig);

        vm.stopPrank();
    }

    function test_payFee_no_referrer() public {
        vm.expectRevert("Only perpDex can call this function");
        fee.payFee(user, 100);

        vm.startPrank(address(fee.perpDex()));
        vm.mockCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transferFrom.selector), abi.encode());
        vm.expectCall(
            address(fee.usdt()), abi.encodeWithSelector(IERC20.transferFrom.selector, address(fee.perpDex()), address(fee), 100), 1
        );
        vm.expectEmit(true, true, true, true);
        emit Fee.FeePaid(user, address(0), 100, 100, 0, 0);
        fee.payFee(user, 100);
    }

    function test_payFee_with_referrer() public {
        setUpReferrerForUser();
        assertEq(fee.referral(user), referrer);

        vm.startPrank(address(fee.perpDex()));

        vm.mockCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transferFrom.selector), abi.encode());
        vm.expectCall(
            address(fee.usdt()), abi.encodeWithSelector(IERC20.transferFrom.selector, address(fee.perpDex()), address(fee), 100), 1
        );

        uint256 fee100 = 100;
        uint256 pFee = fee100 * fee.protocolFeePercent(referrer) / fee.getFeeDenominator();
        uint256 pFeeBalanceBefore = fee.protocolFeeBalance();

        uint256 feeForReferrerAndReferee = fee100 - pFee;
        uint256 referrerFee = feeForReferrerAndReferee * fee.referrerFeePercent(referrer) / fee.getFeeDenominator();
        uint256 feeBalanceAsReferrerBefore = fee.feeBalanceAsReferrer(referrer);

        uint256 refereeFee = feeForReferrerAndReferee - referrerFee;
        uint256 feeBalanceAsRefereeBefore = fee.feeBalanceAsReferee(user);

        vm.expectEmit(true, true, true, true);
        emit Fee.FeePaid(user, referrer, fee100, pFee, referrerFee, refereeFee);

        fee.payFee(user, 100);

        assertEq(fee.protocolFeeBalance(), pFeeBalanceBefore + pFee);
        assertEq(fee.feeBalanceAsReferrer(referrer), feeBalanceAsReferrerBefore + referrerFee);
        assertEq(fee.feeBalanceAsReferee(user), feeBalanceAsRefereeBefore + refereeFee);
    }

    function setUpPayFeeUser() public {
        vm.startPrank(address(fee.perpDex()));
        vm.mockCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transferFrom.selector), abi.encode());
        fee.payFee(user, 100);
        vm.stopPrank();
    }

    function setUpPayFeeUser2() public {
        vm.startPrank(address(fee.perpDex()));
        vm.mockCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transferFrom.selector), abi.encode());
        fee.payFee(user2, 100);
        vm.stopPrank();
    }

    function test_claimProtocolFee() public {
        setUpReferrerForUser();
        setUpPayFeeUser();
        assertEq(fee.protocolFeeBalance(), 90);
        assertEq(fee.feeBalanceAsReferrer(referrer), 8);
        assertEq(fee.feeBalanceAsReferee(user), 2);

        setUpPayFeeUser();
        assertEq(fee.protocolFeeBalance(), 180);
        assertEq(fee.feeBalanceAsReferrer(referrer), 16);
        assertEq(fee.feeBalanceAsReferee(user), 4);

        uint256 protocolFeeBalanceBefore = fee.protocolFeeBalance();
        vm.startPrank(owner);
        fee.setProtocolFeeCollector(protocolFeeCollector);
        vm.expectRevert("Only collector can call this function");
        fee.claimProtocolFee();
        vm.stopPrank();

        vm.startPrank(protocolFeeCollector);
        vm.mockCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());
        vm.expectCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transfer.selector, protocolFeeCollector, 180), 1);
        vm.expectEmit(true, true, true, true);
        emit Fee.ProtocolFeeClaimed(protocolFeeCollector, protocolFeeBalanceBefore);
        fee.claimProtocolFee();
        assertEq(fee.protocolFeeBalance(), 0);
    }

    function test_claimFee() public {
        setUpReferrerForUser();
        setUpReferrerForUser2();

        setUpPayFeeUser();
        assertEq(fee.feeBalanceAsReferrer(referrer), 8);
        assertEq(fee.feeBalanceAsReferrer(user), 0);
        assertEq(fee.feeBalanceAsReferrer(user2), 0);
        assertEq(fee.feeBalanceAsReferee(referrer), 0);
        assertEq(fee.feeBalanceAsReferee(user), 2);
        assertEq(fee.feeBalanceAsReferee(user2), 0);

        setUpPayFeeUser2();
        assertEq(fee.feeBalanceAsReferrer(referrer), 8);
        assertEq(fee.feeBalanceAsReferrer(user), 5);
        assertEq(fee.feeBalanceAsReferrer(user2), 0);
        assertEq(fee.feeBalanceAsReferee(referrer), 0);
        assertEq(fee.feeBalanceAsReferee(user), 2);
        assertEq(fee.feeBalanceAsReferee(user2), 5);

        vm.startPrank(owner);
        fee.setProtocolFeeCollector(protocolFeeCollector);
        vm.stopPrank();

        vm.startPrank(protocolFeeCollector);
        vm.mockCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());
        vm.expectCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transfer.selector, protocolFeeCollector, 180), 1);
        fee.claimProtocolFee();
        vm.stopPrank();

        vm.startPrank(user);
        assertEq(fee.claimedFeeBalanceAsReferrer(user), 0);
        assertEq(fee.claimedFeeBalanceAsReferee(user), 0);
        vm.mockCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());
        vm.expectCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transfer.selector, address(user), 5), 2); // For the last test as well
        vm.expectCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transfer.selector, address(user), 2), 1);
        fee.claimFee();
        assertEq(fee.claimedFeeBalanceAsReferrer(user), 5);
        assertEq(fee.feeBalanceAsReferrer(user), 0);
        assertEq(fee.claimedFeeBalanceAsReferee(user), 2);
        assertEq(fee.feeBalanceAsReferee(user), 0);
        vm.stopPrank();

        vm.startPrank(referrer);
        assertEq(fee.claimedFeeBalanceAsReferrer(referrer), 0);
        assertEq(fee.claimedFeeBalanceAsReferee(referrer), 0);
        vm.mockCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());
        vm.expectCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transfer.selector, address(referrer), 8), 1);
        vm.expectCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transfer.selector, address(referrer), 0), 1);
        fee.claimFee();
        assertEq(fee.claimedFeeBalanceAsReferrer(referrer), 8);
        assertEq(fee.feeBalanceAsReferrer(referrer), 0);
        assertEq(fee.claimedFeeBalanceAsReferee(referrer), 0);
        assertEq(fee.feeBalanceAsReferee(referrer), 0);
        vm.stopPrank();

        vm.startPrank(user2);
        assertEq(fee.claimedFeeBalanceAsReferrer(user2), 0);
        assertEq(fee.claimedFeeBalanceAsReferee(user2), 0);
        vm.mockCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());
        vm.expectCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transfer.selector, address(user2), 0), 1);
        vm.expectCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transfer.selector, address(user2), 5), 1);
        fee.claimFee();
        assertEq(fee.claimedFeeBalanceAsReferrer(user2), 0);
        assertEq(fee.feeBalanceAsReferrer(user2), 0);
        assertEq(fee.claimedFeeBalanceAsReferee(user2), 5);
        assertEq(fee.feeBalanceAsReferee(user2), 0);
        vm.stopPrank();

        setUpPayFeeUser2();
        assertEq(fee.feeBalanceAsReferrer(referrer), 0);
        assertEq(fee.feeBalanceAsReferrer(user), 5);
        assertEq(fee.feeBalanceAsReferrer(user2), 0);
        assertEq(fee.feeBalanceAsReferee(referrer), 0);
        assertEq(fee.feeBalanceAsReferee(user), 0);
        assertEq(fee.feeBalanceAsReferee(user2), 5);

        vm.startPrank(user);
        assertEq(fee.claimedFeeBalanceAsReferrer(user), 5);
        assertEq(fee.claimedFeeBalanceAsReferee(user), 2);
        vm.mockCall(address(fee.usdt()), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());
        fee.claimFee();
        assertEq(fee.claimedFeeBalanceAsReferrer(user), 10);
        assertEq(fee.feeBalanceAsReferrer(user), 0);
        assertEq(fee.claimedFeeBalanceAsReferee(user), 2);
        assertEq(fee.feeBalanceAsReferee(user), 0);
        vm.stopPrank();
    }
}
