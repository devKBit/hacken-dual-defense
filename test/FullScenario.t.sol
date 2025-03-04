// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../src/Fee.sol";
import "../src/LP.sol";
import "../src/PerpDex.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Test, console} from "forge-std/Test.sol";

using SafeERC20 for ERC20;

// @see: https://github.com/jordaniza/OZ-Upgradeable-Foundry/blob/main/script/DeployUUPS.s.sol
contract UUPSProxy is ERC1967Proxy {
    constructor(address _implementation, bytes memory _data) ERC1967Proxy(_implementation, _data) {}
}

contract FullScenario is Test {
    using ECDSA for bytes32;

    UUPSProxy public perpDexProxy;
    // Interface to interact with the proxy as PerpDex
    PerpDex public perpDex;

    UUPSProxy public feeProxy;
    Fee public feeContract;

    LP public lpContract;
    ERC20 public usdtContract;

    address owner;
    address admin;
    address liqAdmin;
    address limitAdmin;
    address singleOpenAdmin;
    address closeAdmin;

    address user;
    address lpProvider;

    uint256 ownerPk;
    uint256 adminPk;
    uint256 userPk;

    IBisonAIRouter bisonAIRouter;
    IBisonAISubmissionProxy bisonAISubmissionProxy;
    IPyth pyth;

    uint256 defaultTotalFeePercent = 70;
    uint256 defaultFeeDenominator = 100_000;

    uint256 openPositionForkId;

    uint256 tokenCount = 19;

    string KAIA_RPC_URL = vm.envString("KAIA_RPC_URL");

    function setUp() public {
        openPositionForkId = vm.createFork(KAIA_RPC_URL, 169_547_580);
    }

    function deployAndSet() public {
        usdtContract = ERC20(0x5C13E303a62Fc5DEdf5B52D66873f2E59fEdADC2);

        (owner, ownerPk) = makeAddrAndKey("owner");
        vm.startPrank(owner);

        PerpDex perpDexImpl = new PerpDex();
        perpDexProxy = new UUPSProxy(address(perpDexImpl), "");
        perpDex = PerpDex(address(perpDexProxy));
        perpDex.initialize(owner);
        perpDex.addInitialTokenTotalSizes(tokenCount);
        perpDex.changeMaxTokenTotalSizes();

        Fee feeImpl = new Fee();
        feeProxy = new UUPSProxy(address(feeImpl), "");
        feeContract = Fee(address(feeProxy));
        feeContract.initialize(owner);

        feeContract.setUsdtAddr(address(usdtContract));
        feeContract.setPerpDexAddr(address(perpDex));

        LP lpImpl = new LP();
        UUPSProxy lpProxy = new UUPSProxy(address(lpImpl), "");
        lpContract = LP(address(lpProxy));
        lpContract.initialize(owner, address(usdtContract), address(perpDex));

        bisonAIRouter = IBisonAIRouter(0x653078F0D3a230416A59aA6486466470Db0190A2);
        bisonAISubmissionProxy = IBisonAISubmissionProxy(0xcB56b163E545A3870CA04C6Ae2401f2405FB29a9);
        pyth = IPyth(0x2880aB155794e7179c9eE2e38200202908C17B43);

        perpDex.setupAddr(address(usdtContract), address(lpContract), address(feeContract));
        perpDex.setOracles(address(bisonAIRouter), address(bisonAISubmissionProxy), address(pyth));

        vm.stopPrank();

        adminSetUp();
        userSetUp();
    }

    function adminSetUp() public {
        (admin, adminPk) = makeAddrAndKey("admin");
        vm.startPrank(owner);
        perpDex.setAdmin(admin);

        liqAdmin = makeAddr("liqAdmin");
        limitAdmin = makeAddr("limitAdmin");
        singleOpenAdmin = makeAddr("singleOpenAdmin");
        closeAdmin = makeAddr("closeAdmin");

        address[] memory closeAdminsArray = new address[](1);
        closeAdminsArray[0] = closeAdmin;
        perpDex.setAdmins(PerpDexAuthLib.AdminType.Close, closeAdminsArray);

        address[] memory liqAdminsArray = new address[](1);
        liqAdminsArray[0] = liqAdmin;
        perpDex.setAdmins(PerpDexAuthLib.AdminType.Liquidation, liqAdminsArray);

        address[] memory limitAdminsArray = new address[](1);
        limitAdminsArray[0] = limitAdmin;
        perpDex.setAdmins(PerpDexAuthLib.AdminType.LimitOrder, limitAdminsArray);

        address[] memory singleOpenAdminsArray = new address[](1);
        singleOpenAdminsArray[0] = singleOpenAdmin;
        perpDex.setAdmins(PerpDexAuthLib.AdminType.SingleOpen, singleOpenAdminsArray);

        vm.stopPrank();
    }

    function userSetUp() public {
        (user, userPk) = makeAddrAndKey("user");
        (lpProvider,) = makeAddrAndKey("lpProvider");

        vm.prank(user);
        usdtContract.approve(address(perpDex), type(uint256).max);

        deal(address(usdtContract), user, 2_000_000);
        deal(address(usdtContract), lpProvider, 1_000_000);
    }

    function signMessage(uint256 privateKey, bytes32 message) internal pure returns (bytes memory signature) {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(message);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedMessageHash);
        signature = abi.encodePacked(r, s, v);
    }

    function test_fullScenario() public {
        vm.selectFork(openPositionForkId);
        vm.rollFork(169_547_579);
        deployAndSet();

        // Add liquidity
        vm.startPrank(owner);
        deal(address(usdtContract), owner, 2_000_000);
        usdtContract.approve(address(lpContract), type(uint256).max);
        lpContract.deposit(1_000_000, owner);
        vm.stopPrank();

        vm.startPrank(lpProvider);
        usdtContract.approve(address(lpContract), type(uint256).max);
        lpContract.deposit(1_000_000, lpProvider);
        lpContract.approve(address(lpContract), type(uint256).max);
        vm.stopPrank();

        // Open/close -> loss
        PerpDexLib.OraclePrices memory priceData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.BisonAI,
            feedHashes: new bytes32[](1),
            answers: new int256[](1),
            timestamps: new uint256[](1),
            proofs: new bytes[](1)
        });

        priceData.feedHashes[0] = 0xce3e90cc1f29fa40c7bf832c5d85d5dbb8f98b81538a3e03e5d4ba4c48229914;
        priceData.answers[0] = 39_265_655;
        priceData.timestamps[0] = 1_731_559_866_115;
        priceData.proofs[0] =
            hex"d0df061667ca107a7829806df0a23aaeea4f76964a87ffd98b376f43d6a5aea741408dc77d27931d897ec4806e67dcf5f718f52cb896afaae8aa3919b2ee7cba1ba38281052dd698d4ce37fb8175b0d9b60169df5316f470842c94b7fbb94b4e1d254c98201e1b8c91b7493aed732eb0e048835dc1ef2b6913e087caee1ce2046b1c";

        bytes memory message = abi.encodePacked(
            "Open position for Token: 4, Margin: 2000000, Leverage: 3, Long: 1, TP: 0, SL: 0, Price: 39265655, Nonce: 0, Chain: 8217, Contract: ",
            Strings.toHexString(address(perpDex))
        );
        bytes32 ethSignedMessageHash =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(bytes(message).length), message));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPk, ethSignedMessageHash);
        bytes memory userSignedData = abi.encodePacked(r, s, v);

        vm.prank(singleOpenAdmin);
        perpDex.openPosition(
            PerpDexLib.OpenPositionData({
                tokenType: PerpDexLib.TokenType.Doge,
                marginAmount: 2_000_000,
                leverage: 3,
                long: true,
                trader: user,
                priceData: priceData,
                tpPrice: 0,
                slPrice: 0,
                expectedPrice: uint256(priceData.answers[0]),
                userSignedData: userSignedData
            })
        );

        vm.roll(169_556_375);
        priceData.feedHashes[0] = 0xce3e90cc1f29fa40c7bf832c5d85d5dbb8f98b81538a3e03e5d4ba4c48229914;
        priceData.answers[0] = 38_901_393;
        priceData.timestamps[0] = 1_731_568_665_715;
        priceData.proofs[0] =
            hex"a2823695d2f42d5e7df7fbf6af5f8d748daa6fa6b02779caab5b67dca5a1628f1a15dd53479abf8a0d5be22a9bff8347d5348a3ee6a5b09e904f05d6da1d9cba1b";

        string memory message2 =
            string(abi.encodePacked("Close Position: 1, Nonce: 1, Chain: 8217, Contract: ", Strings.toHexString(address(perpDex))));
        emit log_string(message2);
        bytes32 ethSignedMessageHash2 =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(bytes(message2).length), message2));
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(userPk, ethSignedMessageHash2);
        bytes memory userSignedData2 = abi.encodePacked(r2, s2, v2);

        vm.prank(closeAdmin);
        perpDex.closePosition(1, priceData, userSignedData2);

        PerpDexLib.Position memory p = perpDex.getPosition(1);
        assertEq(p.traderAddr, user);
        assertEq(uint256(p.tokenType), uint256(PerpDexLib.TokenType.Doge));
        assertEq(p.margin, 1_995_800);
        assertEq(p.size, 5_987_400);
        assertEq(p.openFee, 4200);
        assertEq(p.closeFee, 4152);
        assertEq(p.initialPrice, 39_265_655);
        assertEq(p.isLong, true);
        assertEq(p.openPositionIndex, type(uint256).max);
        assertEq(p.finalPrice, 38_901_393);
        assertEq(uint256(p.positionStatus), uint256(PerpDexLib.PositionStatus.Closed));
        assertEq(p.pnl, -55_545);
        assertEq(p.liquidationPrice, 0); // deprecated
        assertEq(p.tpPrice, 0);
        assertEq(p.slPrice, 0);

        // Check user balance
        assertEq(int256(usdtContract.balanceOf(user)), 2_000_000 + p.pnl - int256(p.openFee + p.closeFee));

        // Check fee
        assertEq(usdtContract.balanceOf(address(feeContract)), p.openFee + p.closeFee);
        assertEq(feeContract.protocolFeeBalance(), p.openFee + p.closeFee);

        // Remove liquidity
        assertEq(lpContract.balanceOf(lpProvider), 1_000_000);
        assertEq(usdtContract.balanceOf(lpProvider), 0);
        assertEq(int256(usdtContract.balanceOf(address(lpContract))), 2_000_000 - p.pnl);

        vm.prank(lpProvider);
        lpContract.redeem(1_000_000, lpProvider, lpProvider);

        // Check lpProvider and LP
        assertEq(usdtContract.balanceOf(address(lpContract)), 1_027_773);
        assertEq(lpContract.balanceOf(lpProvider), 0);
        assertEq(usdtContract.balanceOf(lpProvider), 1_027_772);
    }
}
