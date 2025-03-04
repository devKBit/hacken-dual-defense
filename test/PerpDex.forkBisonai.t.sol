// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../src/Fee.sol";
import "../src/LP.sol";

/// @dev change KAIA-USDT to KLAY-USDT
import "./PerpDexBisonaiForkHelper.sol";
// import "../src/PerpDex.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Test, console} from "forge-std/Test.sol";

using SafeERC20 for ERC20;

// @see: https://github.com/jordaniza/OZ-Upgradeable-Foundry/blob/main/script/DeployUUPS.s.sol
contract UUPSProxy is ERC1967Proxy {
    constructor(address _implementation, bytes memory _data) ERC1967Proxy(_implementation, _data) {}
}

contract PerpDexForkBisonaiTest is Test {
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
    address tpslAdmin;

    address user;

    uint256 ownerPk;
    uint256 adminPk;
    uint256 userPk;

    IBisonAIRouter bisonAIRouter;
    IBisonAISubmissionProxy bisonAISubmissionProxy;
    IPyth pyth;

    uint256 defaultTotalFeePercent = 70;
    uint256 defaultFeeDenominator = 100_000;

    uint256 openPositionForkId;
    uint256 openPositionRevertForkId;
    uint256 closeForkId;
    uint256 limitOrderForkId;
    uint256 liquidationForkId;

    uint256 tokenCount = 19;
    uint256 initialLpBalance = 1_000_000_000_000_000;
    uint256 initialUserBalance = 1_000_000_000_000_000;

    /**
     * or Use foundry.toml
     * [rpc_endpoints]
     * kaia = "${KAIA_RPC_URL}"
     */
    string KAIA_RPC_URL = vm.envString("KAIA_RPC_URL");

    function setUp() public {
        openPositionRevertForkId = vm.createFork(KAIA_RPC_URL, 167_567_825);
        openPositionForkId = vm.createFork(KAIA_RPC_URL, 169_547_580);
        closeForkId = vm.createFork(KAIA_RPC_URL, 169_556_376);

        limitOrderForkId = vm.createFork(KAIA_RPC_URL, 169_474_582);
        liquidationForkId = vm.createFork(KAIA_RPC_URL, 169_828_869);
    }

    function deployAndSet() public {
        usdtContract = ERC20(0x5C13E303a62Fc5DEdf5B52D66873f2E59fEdADC2);

        (owner, ownerPk) = makeAddrAndKey("owner");
        vm.startPrank(owner);

        // perpDex = PerpDex(0x21b776374C4B9cC52dD053212a8dde9DD6da061c);
        PerpDex perpDexImpl = new PerpDex();
        perpDexProxy = new UUPSProxy(address(perpDexImpl), "");
        perpDex = PerpDex(address(perpDexProxy));
        perpDex.initialize(owner);
        perpDex.addInitialTokenTotalSizes(tokenCount);
        perpDex.changeMaxTokenTotalSizes();

        // feeContract = Fee(0x2994F8C9Df255e3926f73ae892E7464b4F76cd49);
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

        deal(address(usdtContract), address(lpContract), initialLpBalance);

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

        address[] memory tpslAdminsArray = new address[](1);
        tpslAdminsArray[0] = tpslAdmin;
        perpDex.setAdmins(PerpDexAuthLib.AdminType.Tpsl, tpslAdminsArray);

        vm.stopPrank();
    }

    function userSetUp() public {
        (user, userPk) = makeAddrAndKey("user");

        vm.prank(user);
        usdtContract.approve(address(perpDex), type(uint256).max);

        deal(address(usdtContract), user, initialUserBalance);
    }

    function getSignedMessage(uint256 pk, bytes memory message) internal pure returns (bytes memory) {
        bytes32 ethSignedMessageHash =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(message.length), message));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }

    // @see https://kaiascan.io/tx/0x8b5e0b936a5ea94c87ec17b0a6d3d0c9db55cfca7e75d18e4fe95eaa45da3300
    // block number 167_580_064
    function test_bisonai_submitSingleWithoutSupersedValidation_latestRoundData() public {
        vm.selectFork(openPositionForkId);
        vm.rollFork(169_547_579);
        deployAndSet();
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

        (uint256 roundId,,) = bisonAIRouter.latestRoundData(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Doge));

        bisonAISubmissionProxy.submitSingleWithoutSupersedValidation(
            priceData.feedHashes[0], priceData.answers[0], priceData.timestamps[0], priceData.proofs[0]
        );
        (uint256 roundIdAfter, int256 answer, uint256 updatedAt) =
            bisonAIRouter.latestRoundData(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Doge));

        assertEq(roundIdAfter, roundId + 1, "roundId");
        assertEq(answer, priceData.answers[0], "answer");
        assertGe(updatedAt * 1000, priceData.timestamps[0], "timestamp");
        assertEq(updatedAt, block.timestamp, "timestamp");
    }

    function test_bisonai_submitSingleWithoutSupersedValidation_SupersedingCase() public {
        vm.selectFork(openPositionForkId);
        vm.rollFork(169_547_580);
        deployAndSet();
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

        (uint256 roundId,,) = bisonAIRouter.latestRoundData(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Doge));

        bisonAISubmissionProxy.submitSingleWithoutSupersedValidation(
            priceData.feedHashes[0], priceData.answers[0], priceData.timestamps[0], priceData.proofs[0]
        );
        (uint256 roundIdAfter, int256 answer, uint256 updatedAt) =
            bisonAIRouter.latestRoundData(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Doge));

        assertEq(roundIdAfter, roundId, "roundId");
        assertEq(answer, priceData.answers[0], "answer");
        assertGe(updatedAt * 1000, priceData.timestamps[0], "timestamp");
        assertEq(updatedAt, block.timestamp, "timestamp");
    }

    // @see https://kaiascan.io/tx/0x8b5e0b936a5ea94c87ec17b0a6d3d0c9db55cfca7e75d18e4fe95eaa45da3300
    // block number 167_580_064
    function test_openPosition_bisonai() public {
        vm.selectFork(openPositionForkId);
        vm.rollFork(169_547_579);
        deployAndSet();
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

        bytes memory userSignedData = getSignedMessage(
            userPk,
            abi.encodePacked(
                "Open position for Token: 4, Margin: 2000000, Leverage: 3, Long: 1, TP: 0, SL: 0, Price: 39265655, Nonce: 0, Chain: 8217, Contract: ",
                Strings.toHexString(address(perpDex))
            )
        );

        vm.startPrank(singleOpenAdmin);
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
        vm.stopPrank();

        PerpDexLib.Position memory p = perpDex.getPosition(1);
        assertEq(p.initialPrice, 39_265_655);
        assertEq(uint256(p.positionStatus), 1);
    }

    function test_openPosition_bisonai_given_old_price_but_oracle_already_has_a_newer_price() public {
        // If oracle has a newer price, it should use that price
        vm.selectFork(closeForkId);
        vm.rollFork(169_556_376);
        deployAndSet();
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

        bytes memory userSignedData = getSignedMessage(
            userPk,
            abi.encodePacked(
                "Open position for Token: 4, Margin: 2000000, Leverage: 3, Long: 1, TP: 0, SL: 0, Price: 39265655, Nonce: 0, Chain: 8217, Contract: ",
                Strings.toHexString(address(perpDex))
            )
        );

        vm.startPrank(singleOpenAdmin);
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
        vm.stopPrank();

        PerpDexLib.Position memory p = perpDex.getPosition(1);
        assert(p.initialPrice != 39_265_655);
        assertEq(uint256(p.positionStatus), 1);
    }

    // @see https://kaiascan.io/tx/0x8b5e0b936a5ea94c87ec17b0a6d3d0c9db55cfca7e75d18e4fe95eaa45da3300
    // block number vm.rollFork(167_580_063);
    function test_openPosition_bisonai_revert_etc_cases() public {
        vm.selectFork(openPositionForkId);
        vm.rollFork(169_547_579);
        deployAndSet();
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

        bytes memory userSignedData = getSignedMessage(
            userPk,
            abi.encodePacked(
                "Open position for Token: 4, Margin: 2000000, Leverage: 3, Long: 1, TP: 0, SL: 0, Price: 39265655, Nonce: 0, Chain: 8217, Contract: ",
                Strings.toHexString(address(perpDex))
            )
        );

        vm.startPrank(singleOpenAdmin);
        // 🔥 wrong proof
        priceData.proofs[0] =
            hex"9653cf3a0b2d868f0e939dc8bc54b5c33a8bf7aba896a194c16674ca7b9c86eb40e4664d1827d77c69c4926709ed90d79aff24b8de9900091fb6ca332ca44b391b6d208ccd348560ca4143a895819c1adfd58e67550b7b7912db1014650e81e3e13032a8de317c5195a80da46db95ea570ee8de5cc7296b91b9c8fb9cb2b2026bf1c";
        vm.expectRevert(abi.encodeWithSignature("IndexesNotAscending()"));
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

        // 🔥 no feedhash
        priceData.proofs[0] =
            hex"d0df061667ca107a7829806df0a23aaeea4f76964a87ffd98b376f43d6a5aea741408dc77d27931d897ec4806e67dcf5f718f52cb896afaae8aa3919b2ee7cba1ba38281052dd698d4ce37fb8175b0d9b60169df5316f470842c94b7fbb94b4e1d254c98201e1b8c91b7493aed732eb0e048835dc1ef2b6913e087caee1ce2046b1c";
        priceData.feedHashes = new bytes32[](1);
        vm.expectRevert(abi.encodeWithSignature("FeedHashNotFound()"));
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

        // 🔥 wrong feedhash => different tokenType
        priceData.feedHashes[0] = keccak256(abi.encodePacked(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType(1))));
        vm.expectRevert(abi.encodeWithSignature("IndexesNotAscending()"));
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

        // 🔥 old updatedAt => Passes and uses previous round's data if it is not too old
        (, int256 answer, uint256 updatedAt) = bisonAIRouter.latestRoundData(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType(4)));
        priceData.timestamps[0] = (updatedAt - 10);
        // original priceData.timestamps[0] = 1731559866
        emit log_uint(updatedAt); // 1731559856
        emit log_uint(block.timestamp); // 1731559868
        // vm.expectRevert(abi.encodeWithSignature("AnswerTooOld()"));
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
        PerpDexLib.Position memory pos = perpDex.getPosition(perpDex.nextPositionId() - 1);

        assertEq(pos.initialPrice, uint256(answer));
        assertEq(uint256(pos.positionStatus), 1);
    }

    // 167_580_639 price standard
    function test_closePosition_bisonai() public {
        vm.selectFork(openPositionForkId);
        vm.rollFork(169_547_579);
        deployAndSet();

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

        bytes memory userSignedData = getSignedMessage(
            userPk,
            abi.encodePacked(
                "Open position for Token: 4, Margin: 2000000, Leverage: 3, Long: 1, TP: 0, SL: 0, Price: 39265655, Nonce: 0, Chain: 8217, Contract: ",
                Strings.toHexString(address(perpDex))
            )
        );

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

        vm.warp(block.timestamp + 169_556_375 - block.number);
        vm.roll(169_556_375);
        priceData.feedHashes[0] = 0xce3e90cc1f29fa40c7bf832c5d85d5dbb8f98b81538a3e03e5d4ba4c48229914;
        priceData.answers[0] = 38_901_393;
        priceData.timestamps[0] = 1_731_568_665_715;
        priceData.proofs[0] =
            hex"a2823695d2f42d5e7df7fbf6af5f8d748daa6fa6b02779caab5b67dca5a1628f1a15dd53479abf8a0d5be22a9bff8347d5348a3ee6a5b09e904f05d6da1d9cba1b";

        bytes memory userSignedData2 = getSignedMessage(
            userPk, abi.encodePacked("Close Position: 1, Nonce: 1, Chain: 8217, Contract: ", Strings.toHexString(address(perpDex)))
        );

        vm.prank(closeAdmin);
        perpDex.closePosition(1, priceData, userSignedData2);

        PerpDexLib.Position memory p = perpDex.getPosition(1);
        assertEq(p.finalPrice, 38_901_393);
        assertEq(uint256(p.positionStatus), 2);
        assertEq(p.openFee, 2_000_000 * 3 * 70 / 100_000);

        assertEq(p.closeFee, (p.size * p.finalPrice / p.initialPrice) * 70 / 100_000); // loss

        int256 expectingFundingFee = int256(p.size * 1e20 * (169_556_375 - 169_547_579) * 875 / (1e20 * 1e7 * 3600));
        uint256 loss = p.size - p.size * p.finalPrice / p.initialPrice;
        uint256 closeFee = (p.size * p.finalPrice / p.initialPrice) * 70 / 100_000;
        assertEq(p.closeFee, closeFee); // loss

        assertEq(p.fundingFee, expectingFundingFee);
        assertEq(p.pnl, -int256(loss));

        assertEq(usdtContract.balanceOf(address(lpContract)), initialLpBalance + uint256(loss));
        assertEq(usdtContract.balanceOf(address(feeContract)), p.closeFee + p.openFee);
        assertEq(
            usdtContract.balanceOf(address(user)),
            initialUserBalance - p.margin - p.openFee + (p.margin - uint256(p.fundingFee) - closeFee - loss)
        );
    }

    function getLimitOrderValidPriceData() public pure returns (PerpDexLib.OraclePrices memory) {
        PerpDexLib.OraclePrices memory priceData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.BisonAI,
            feedHashes: new bytes32[](13),
            answers: new int256[](13),
            timestamps: new uint256[](13),
            proofs: new bytes[](13)
        });

        priceData.feedHashes[0] = 0xa92bcb5bc51aa5535ed0cc3f522992dd9a6fb2e8dd6dcf484705d93eb3cd167a;
        priceData.answers[0] = int256(0x07f76931fca6);
        priceData.timestamps[0] = uint256(0x019324a7477e);
        priceData.proofs[0] =
            hex"46109133c17cf2e99cc5f4989f36f51a6e817098caae17f4463949063debc7567c5f2c8d1f6d1d483f70f40b79e55efae51cd93072503b398f08567300753a901b170577423248367783d3697ae113ac3e72e56862472f77961f17dc5daa0dc572050dc8be568dde55182f2a0661283ba096506151954fa698e9e0ef713fc5f0a41c";
        priceData.feedHashes[1] = 0x44056fd001da2ea02617117909aa18a3931efd8820d1a75ea95516958e5f96d5;
        priceData.answers[1] = int256(0xb72a27);
        priceData.timestamps[1] = uint256(0x019324a747e4);
        priceData.proofs[1] =
            hex"42083fa2afcae6ae1a15513aa5c1b89696866c4e2ae582b685ac38735fe82e09547da52d300d793ba8faf19d9630778764435d71274dc0ea40ebbcb7819fe33f1b3ea875080b8b9dc77c2c17762a0f0592a495a1555f51b5c6c3953a612e16def91cd84ff40e0a59ac3c2a27756fda637c7fbee5f6ffc0270742c79d27c787d5401b";
        priceData.feedHashes[2] = 0xd17438ade2a57a233f67cf57bd903b44a3c13b2c40497a93bf935a62cbe94b17;
        priceData.answers[2] = int256(0x04739630);
        priceData.timestamps[2] = uint256(0x019324a747fb);
        priceData.proofs[2] =
            hex"207a95682dfd1803b6ad0223e40dcd6818bfc063f01bf6823c92dbc6b12142392bfa3a2be182d89ba51baa94c17033936b74a05a7eb106abb5e7563604a52f7d1b47ba74a6e0fd074c929585585cf0dfc14eb08536c58eb781932532d1345466e866797fa0cef36a10d0d6585bec67a7cdda7411ca79ccc48f4c8b116eb77aa0781c";
        priceData.feedHashes[3] = 0x7020b52841bb268cbc78137a54d4bf1f5305eed1039fb5d003ba95b8ededc46c;
        priceData.answers[3] = int256(0x49ceca8f38);
        priceData.timestamps[3] = uint256(0x019324a747bc);
        priceData.proofs[3] =
            hex"7b29cb7442d9648dc02fb728f00d771b21fd0d73116abfc2419a117d29d8300e143bb047daa8cec19901e83268bb55c336e1d434a20aa5d17e6eb4c451e03c251bebb0f8e2378ddebef2afb50d185948febd09fbb9d86c530a64e54fea268294b808dca475696afd444999de8f77cf972d301f8aa031388baa6e6f5b07a5d046c11b";

        priceData.feedHashes[4] = 0xce3e90cc1f29fa40c7bf832c5d85d5dbb8f98b81538a3e03e5d4ba4c48229914;
        priceData.answers[4] = int256(0x024963e8);
        priceData.timestamps[4] = uint256(0x019324a747b3);
        priceData.proofs[4] =
            hex"1c168eae36c3529cc3391baf5047c8e1dd75171c3c6a8d005a83609255d2132e509d62ba80221a7450a0427b6375eea05329d51aa2f31e6d851380958e1053191cc376fff2e4c87b3b7fa0511bbaf9b9d705a5620aed741cf0a2141ac5d09a08a62230d8bfdb821b5a5d5d9f1a5ed37631cf115d9758332e5dd828575628a7589a1c";
        priceData.feedHashes[5] = 0x455314fa66a1287be93e6f2d43ee572d47b716b7c69361df3409a28f3c1b7546;
        priceData.answers[5] = int256(0x051a);
        priceData.timestamps[5] = uint256(0x019324a74785);
        priceData.proofs[5] =
            hex"672e6c837b6a3963252d7a01f4ab32cf11850613f972801c7f88900c8b982e082eb262dbc399099689bd8da9a9afd388ccd4ca5f8e92a5676435271983c9279a1cc1c384c3d83e83db65dc4632b96321315e0cf5b9de33fb872fd9705bdbc6b60e759d2e55810a789846989345ce121cfb0c7a3872670fbc5a5a5aaa418af01e421b";

        priceData.feedHashes[6] = 0x02c0a62d9ad950cd79feeae43830a378279a187e9dbc92e826e19ca6efde183f;
        priceData.answers[6] = int256(0x04d010ca7e);
        priceData.timestamps[6] = uint256(0x019324a747cf);
        priceData.proofs[6] =
            hex"19077da1fb4a41fbdac1aff6a6bd6037cfe68a8c7efe02fe6a393c1a515bf5b431823d2a77e939408cd79b886c7b956b68301f95c1d9fc077ade4742615db8051cf91d39e789fb02d6fb107304dde9b4ef733f1b9975fb4add9e44a29b59cbd28d10e7597f8bcc1c7984e5645d8081b0f596fbb2be0c85763663065a590688e0181b";
        priceData.feedHashes[7] = 0xb7d399d01faafdf72706e94b58187f12f2cb26600753022f64d8bf43fab774b1;
        priceData.answers[7] = int256(0x04005d32);
        priceData.timestamps[7] = uint256(0x019324a7489e);
        priceData.proofs[7] =
            hex"fd1d5262b8a8888de186f324580e57df9773d326c67ea61ed4fcfdc50cafbf407cb3c5537aa44f1ad9d1f544f6e66fbdd7a9ab4cb3a77ce0fbb54406f44b81e21bee5b3cabbaf2969d8004ee55dafbf5b6764cd7c5ae6897eccc19bb26c9ec248b0973c1e048812bcb23255497a1050e28b449c4df5bd9e1ea0d90e820e918a7f71b";
        priceData.feedHashes[8] = 0x430a06ad154743a8d72ec533360245f8f4c08a195b600968780852a079bf16fb;
        priceData.answers[8] = int256(0x47164393);
        priceData.timestamps[8] = uint256(0x019324a747d5);
        priceData.proofs[8] =
            hex"34eaeb6efedd308aa074a67910c4b544a2632374f0bd2f6ae56f80f74c5411a70a3a4076ab565fbd5c79ea9d0e509084ca9adfb59c61b7cc001b0e0fb422f4e31ce53a63d6329e1fc4705fc4404cd1df3281cd01c585573860bd51c323063235dd7ff94da6513b59ef79177b326e16f0436b6665347722159ba81868659adbc6aa1c";
        priceData.feedHashes[9] = 0x646f04eca6f4604590b84aae60a51b37086dfc6a46feca6c5416ab7a3c0e23c9;
        priceData.answers[9] = int256(0x11f53c11);
        priceData.timestamps[9] = uint256(0x019324a7473e);
        priceData.proofs[9] =
            hex"a44fd9639d495567e54edc87c6946b952ad5ad4bba078f6e12c0980173ae3a3c1865153aa2f0cc7b86d44aa5c28bbcdea8d5842f682c56470f5c977b274a834a1c2c1ea9e62ccd0ae47a57704195adb9d077beb764fbf98f2b1d78b359ba50b1eb1f54ea5be220a305b9eac86f89234b2cfa7cdbd150e5f958ef5dcec043c65da61c";
        priceData.feedHashes[10] = 0xb4b7bb0e1aecd0b5851b8c48fb171337317c1a9c45e755de3909e93958765e81;
        priceData.answers[10] = int256(0x0985);
        priceData.timestamps[10] = uint256(0x019324a747ca);
        priceData.proofs[10] =
            hex"89685b1f1242818306d8aa4b16f11e21a84f30eb5b303cc9f81200975e60ada9501d50404975d7771686ea6456153e9ec863f0e7bd2b68c0bb454643cc2bf0411b151da3e780a600f6d4a5eb3ef583ea7b84f4d82e7a8c808dbc60d11c4f38d84c55a705262494c0c5fbdee7f494b16b3e47bcdb9eb4e6d74a66e1edd2c126cab71b";
        priceData.feedHashes[11] = 0x069dee7ca2e950642ea45600b1f3ca3eb7bc30291426a82b65838576379666d3;
        priceData.answers[11] = int256(0x02a3e360);
        priceData.timestamps[11] = uint256(0x019324a74783);
        priceData.proofs[11] =
            hex"bd0366d3edb7405e646981ea92dac40289dae9a574b345d32be54addf6a4634b4d7943d1b8be05be3a500df5486485d1cb86e736b214edc424c112d6dec5e3b51cbf07c3357a44b688eb3ed27e9d106019a7f9412b4a6810c30ccbbbb232c98a6e7f9cbe97a10d0d05c6e0426d7862ad1a8072dc27bcbe070037514bdecbc0d5ce1c";
        priceData.feedHashes[12] = 0x5f741f7995dc7d3a3a89dd2daccc6c019033c69204605aabf2739c3aa5ec8a62;
        priceData.answers[12] = int256(0x0335136f);
        priceData.timestamps[12] = uint256(0x019324a74787);
        priceData.proofs[12] =
            hex"d601e6392c722c18c7573c47e997466eca7e7f389d704909f0b793aa583292ef578eccac08463913dd190e8006df35c5ef4f62b8777a5b6d510c5287cb3d31451bec89fd3cd5fb54d6f6dc412b65cf7c7ce79d1fd27968f977591ef61f12dfb22f2faf18d1d25bcdee42d5d7f0dbf2d4e14bc3c554dab128ab1de7c1230ddd8bbd1c";

        return priceData;
    }

    // block number 169474582
    function test_submitAndGetBisonAIRoundId_bisonai() public {
        vm.selectFork(limitOrderForkId);
        vm.rollFork(169_474_573);
        deployAndSet();
        vm.startPrank(limitAdmin);

        uint64[] memory roundIds = new uint64[](13);
        for (uint256 i = 0; i < 13; i++) {
            (uint256 roundId,,) = bisonAIRouter.latestRoundData(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType(i)));
            roundIds[i] = uint64(roundId);
        }

        PerpDexLib.OraclePrices memory priceData = getLimitOrderValidPriceData();

        emit log_named_uint("block number", block.number);

        vm.expectEmit(true, true, true, true);
        emit PerpDex.SubmittedRoundId(PerpDexLib.TokenType.Btc, roundIds[0] + 1);
        emit PerpDex.SubmittedRoundId(PerpDexLib.TokenType.Klay, roundIds[1] + 1);
        emit PerpDex.SubmittedRoundId(PerpDexLib.TokenType.Wemix, roundIds[2] + 1);
        emit PerpDex.SubmittedRoundId(PerpDexLib.TokenType.Eth, roundIds[3] + 1);
        emit PerpDex.SubmittedRoundId(PerpDexLib.TokenType.Doge, roundIds[4] + 1);
        emit PerpDex.SubmittedRoundId(PerpDexLib.TokenType.Pepe, roundIds[5] + 1);
        emit PerpDex.SubmittedRoundId(PerpDexLib.TokenType.Sol, roundIds[6] + 1);
        emit PerpDex.SubmittedRoundId(PerpDexLib.TokenType.Xrp, roundIds[7] + 1);
        emit PerpDex.SubmittedRoundId(PerpDexLib.TokenType.Apt, roundIds[8] + 1);
        emit PerpDex.SubmittedRoundId(PerpDexLib.TokenType.Sui, roundIds[9] + 1);
        emit PerpDex.SubmittedRoundId(PerpDexLib.TokenType.Shib, roundIds[10] + 1);
        emit PerpDex.SubmittedRoundId(PerpDexLib.TokenType.Sei, roundIds[11] + 1);
        emit PerpDex.SubmittedRoundId(PerpDexLib.TokenType.Ada, roundIds[12] + 1);
        perpDex.submitAndGetBisonAIRoundId(priceData);
    }

    function test_submitAndGetBisonAIRoundId_bisonai_revert_switch_order() public {
        vm.selectFork(limitOrderForkId);
        vm.rollFork(169_474_573);
        deployAndSet();
        vm.startPrank(limitAdmin);

        PerpDexLib.OraclePrices memory priceData = getLimitOrderValidPriceData();

        // 🔥 switch only answer
        priceData.answers[4] = int256(0x051a);
        priceData.answers[5] = int256(0x024963e8);
        vm.expectRevert(abi.encodeWithSignature("IndexesNotAscending()"));
        perpDex.submitAndGetBisonAIRoundId(priceData);
    }

    // @see https://kaiascan.io/tx/0xed13f3fbac2299d63067bcde006cfcd0e1ab255c231cf09ec678c2d61213ab41?tabId=inputData&page=1
    // block numebr 169474582
    function test_executeLimitOrders_ok() public {
        vm.selectFork(limitOrderForkId);
        vm.rollFork(169_474_573); // positionId 2118 limit opened
        deployAndSet();

        uint256 nextPositionId = perpDex.nextPositionId();
        emit log_named_uint("nextPositionId", nextPositionId);

        bytes memory signature = getSignedMessage(
            userPk,
            abi.encodePacked(
                "Open Limit Order for Token: 1, Margin: 1995800, Leverage: 3, Long: 1, Wanted Price: 12010000, TP: 0, SL: 0, Nonce: 0, Chain: 8217, Contract: ",
                Strings.toHexString(address(perpDex))
            )
        );

        PerpDexLib.OpenLimitOrderData memory o = PerpDexLib.OpenLimitOrderData({
            tokenType: PerpDexLib.TokenType.Klay,
            marginAmount: 1_995_800,
            leverage: 3,
            long: true,
            trader: user,
            wantedPrice: 12_010_000,
            tpPrice: 0,
            slPrice: 0,
            userSignedData: signature
        });
        vm.prank(singleOpenAdmin);
        perpDex.openLimitOrder(o);

        uint64[] memory roundIds = new uint64[](13);
        roundIds[0] = uint64(0x0e1db0);
        roundIds[1] = uint64(0x0e18cd);
        roundIds[2] = uint64(0x0dfd1a);
        roundIds[3] = uint64(0x0e053e);
        roundIds[4] = uint64(0x0e01cf);
        roundIds[5] = uint64(0x0c82bc);
        roundIds[6] = uint64(0x0dd5a0);
        roundIds[7] = uint64(0x0dd6c2);
        roundIds[8] = uint64(0xb879);
        roundIds[9] = uint64(0xb8d8);
        roundIds[10] = uint64(0x0dce2e);
        roundIds[11] = uint64(0xb6a2);
        roundIds[12] = uint64(0x0dd3a7);

        uint256[] memory ordersToExecute = new uint256[](1);
        ordersToExecute[0] = nextPositionId;
        PerpDexLib.OraclePrices memory priceData = getLimitOrderValidPriceData();

        vm.warp(block.timestamp + 1);
        vm.roll(169_474_574);
        vm.startPrank(limitAdmin);
        perpDex.submitAndGetBisonAIRoundId(priceData); // at 169474574

        vm.warp(block.timestamp + 8);
        vm.roll(169_474_582);
        vm.deal(limitAdmin, 100_000);

        perpDex.executeLimitOrders(ordersToExecute, roundIds, priceData);
        vm.stopPrank();

        PerpDexLib.Position memory p = perpDex.getPosition(nextPositionId);
        emit log_named_uint("limitOrderPrice", p.limitOrderPrice);
        emit log_named_uint("tokenType", uint256(priceData.answers[uint64(p.tokenType)]));
        emit log_named_uint("positionStatus", uint256(p.positionStatus));
        emit log_named_uint("limitOpenTime", p.statusTime.limitOpenTime);
        emit log_named_uint("openTime", p.statusTime.openTime);
        assertEq(p.initialPrice, uint256(priceData.answers[uint64(p.tokenType)]));
        assertEq(uint256(p.positionStatus), 1);
    }

    function test_executeLimitOrders_revert() public {
        vm.selectFork(limitOrderForkId);
        vm.rollFork(169_474_581);
        deployAndSet();

        vm.startPrank(limitAdmin);
        uint64[] memory roundIds = new uint64[](13);
        roundIds[0] = uint64(0x0e1db0);
        roundIds[1] = uint64(0x0e18cd);
        roundIds[2] = uint64(0x0dfd1a);
        roundIds[3] = uint64(0x0e053e);
        roundIds[4] = uint64(0x0e01cf);
        roundIds[5] = uint64(0x0c82bc);
        roundIds[6] = uint64(0x0dd5a0);
        roundIds[7] = uint64(0x0dd6c2);
        roundIds[8] = uint64(0xb879);
        roundIds[9] = uint64(0xb8d8);
        roundIds[10] = uint64(0x0dce2e);
        roundIds[11] = uint64(0xb6a2);
        roundIds[12] = uint64(0x0dd3a7);

        uint256[] memory ordersToExecute = new uint256[](1);
        ordersToExecute[0] = 2118;
        PerpDexLib.OraclePrices memory priceData = getLimitOrderValidPriceData();

        // switch roundId order
        roundIds[2] = uint64(0x0e053e);
        roundIds[3] = uint64(0x0dfd1a);
        vm.expectRevert(abi.encodeWithSignature("NoDataPresent()"));
        perpDex.executeLimitOrders(ordersToExecute, roundIds, priceData);
        roundIds[2] = uint64(0x0dfd1a);
        roundIds[3] = uint64(0x0e053e);

        // use wrong roundId => Doesn't revert
        roundIds[3] = uint64(0x0dd3a7);
        // vm.expectRevert("Price is not correct (BisonAI)");
        perpDex.executeLimitOrders(ordersToExecute, roundIds, priceData);
        roundIds[3] = uint64(0x0e053e);

        // switch priceData
        // 🔥 switch order => no problem
        priceData.feedHashes[5] = 0xce3e90cc1f29fa40c7bf832c5d85d5dbb8f98b81538a3e03e5d4ba4c48229914;
        priceData.answers[5] = int256(0x024963e8);
        priceData.timestamps[5] = uint256(0x019324a747b3);
        priceData.proofs[5] =
            hex"1c168eae36c3529cc3391baf5047c8e1dd75171c3c6a8d005a83609255d2132e509d62ba80221a7450a0427b6375eea05329d51aa2f31e6d851380958e1053191cc376fff2e4c87b3b7fa0511bbaf9b9d705a5620aed741cf0a2141ac5d09a08a62230d8bfdb821b5a5d5d9f1a5ed37631cf115d9758332e5dd828575628a7589a1c";
        priceData.feedHashes[4] = 0x455314fa66a1287be93e6f2d43ee572d47b716b7c69361df3409a28f3c1b7546;
        priceData.answers[4] = int256(0x051a);
        priceData.timestamps[4] = uint256(0x019324a74785);
        priceData.proofs[4] =
            hex"672e6c837b6a3963252d7a01f4ab32cf11850613f972801c7f88900c8b982e082eb262dbc399099689bd8da9a9afd388ccd4ca5f8e92a5676435271983c9279a1cc1c384c3d83e83db65dc4632b96321315e0cf5b9de33fb872fd9705bdbc6b60e759d2e55810a789846989345ce121cfb0c7a3872670fbc5a5a5aaa418af01e421b";
        // vm.expectRevert(abi.encodeWithSignature("NoDataPresent()"));
        vm.expectRevert("Feed hash is not correct (BisonAI)");
        perpDex.executeLimitOrders(ordersToExecute, roundIds, priceData);
    }

    function getLiquidateValidPriceData() public pure returns (PerpDexLib.OraclePrices memory) {
        PerpDexLib.OraclePrices memory priceData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.BisonAI,
            feedHashes: new bytes32[](13),
            answers: new int256[](13),
            timestamps: new uint256[](13),
            proofs: new bytes[](13)
        });

        priceData.feedHashes[0] = 0xa92bcb5bc51aa5535ed0cc3f522992dd9a6fb2e8dd6dcf484705d93eb3cd167a;
        priceData.answers[0] = int256(0x0843a1bbb7f1);
        priceData.timestamps[0] = uint256(0x019339cb184b);
        priceData.proofs[0] =
            hex"8f3d9d5e49c8bd3ead00fa1c639643e5f5216c4608c7af9148b8c2d542fea9b858a37f84b118448a43bdcfdfb751fdfa35ca7ac6b675473f939cfc2acbc8178f1b";
        priceData.feedHashes[1] = 0x44056fd001da2ea02617117909aa18a3931efd8820d1a75ea95516958e5f96d5;
        priceData.answers[1] = int256(0xce7045);
        priceData.timestamps[1] = uint256(0x019339cb177e);
        priceData.proofs[1] =
            hex"bf5eb630e7a7ebe1c6184d5009270387551176a1e4460b9b901c2327eb196d1b27e1b6a9ad741ec90b98daecd832b8732b630dc52cc371c79fd2225c2674a0421ba00fe1760a36d07028dd8b8e96224f3301a8c6495e6741bed8f0435bf0bd56c73e6de7458eb93f32db1d5139f0f100257c1538e6f2dd906b59954b4dfa4c43231c";
        priceData.feedHashes[2] = 0xd17438ade2a57a233f67cf57bd903b44a3c13b2c40497a93bf935a62cbe94b17;
        priceData.answers[2] = int256(0x05b3f23a);
        priceData.timestamps[2] = uint256(0x019339cb181d);
        priceData.proofs[2] =
            hex"77ee4e3f91a1e76f034b98592650fa27c2d44f20bc039492c6e155d775952a2d4187262395d9bec797e69910a4b78f9a1a0193f60bb01aa5e8389b488d00024a1c";
        priceData.feedHashes[3] = 0x7020b52841bb268cbc78137a54d4bf1f5305eed1039fb5d003ba95b8ededc46c;
        priceData.answers[3] = int256(0x48c3f83004);
        priceData.timestamps[3] = uint256(0x019339cb187f);
        priceData.proofs[3] =
            hex"cea1a9ec20d0137838ed84f0d4c9653a5d1a4bdf413525fc83ef424c06312b440ed5a3c4f8a53ca609362aacf0e4dfad71e151e409533d249c677f2a4a2ae1761b691cbe9ba13ccb6cf22a27b46a03d4977f7a719a13abc4c5815e862458733f637d1329a18d9262815f6acf3723ce990d3459619a8dd6aaed0fdcc31f1ca832131b";
        priceData.feedHashes[4] = 0xce3e90cc1f29fa40c7bf832c5d85d5dbb8f98b81538a3e03e5d4ba4c48229914;
        priceData.answers[4] = int256(0x0227a99d);
        priceData.timestamps[4] = uint256(0x019339cb17a4);
        priceData.proofs[4] =
            hex"31117dc136ad799d8bb27ed80cecdd72f32c409770b4ccb674cc1c6178a601b645e748bfdb2916fc7e516cdaebb7a84bb505ec50d80b55254f013c73c7087b141b7ccdbf9865b7172906e5fa102dc42c1fddafcd30da52380333499409d9421dbc26ebfa96efc8c6c42e8466fc125a2483ace34e118a132261edcbf947e275aab41b";
        priceData.feedHashes[5] = 0x455314fa66a1287be93e6f2d43ee572d47b716b7c69361df3409a28f3c1b7546;
        priceData.answers[5] = int256(0x082c);
        priceData.timestamps[5] = uint256(0x019339cb183e);
        priceData.proofs[5] =
            hex"93bf2015b4c7ec40b43099755117369f0596f0d6be676f4c5f41c4c0d10ee1f635b7d165d7643e15b8c60f6f89493a1fa0b5daca5c15c827091c7e73c6911d891c7d01ad447426ee6fb5ecf406b8882c63210e4bb92443fb1229319f7195e16a89561987b1564306b4270cba90fbb95b457cb74c5f157de25a1c1f52bad40f17db1b";
        priceData.feedHashes[6] = 0x02c0a62d9ad950cd79feeae43830a378279a187e9dbc92e826e19ca6efde183f;
        priceData.answers[6] = int256(0x0594c01ab7);
        priceData.timestamps[6] = uint256(0x019339cb18ac);
        priceData.proofs[6] =
            hex"194f28369669ac71eff6bcc7a3b456cd438750242465a33ce9a3729ddd3371f40ebc55d52b33c402b1042381b45891d63acb6f46dac9b17663e9893593e09d331c3f7e6dbea7a2d977edcc12fe926cf12b7e13f21092568e8d91c2445a674e62681197306305bb9c8bbbe268732be8b58840bb94247251959b52c85858b0d468f41c";
        priceData.feedHashes[7] = 0xb7d399d01faafdf72706e94b58187f12f2cb26600753022f64d8bf43fab774b1;
        priceData.answers[7] = int256(0x06475cea);
        priceData.timestamps[7] = uint256(0x019339cb1779);
        priceData.proofs[7] =
            hex"5886db2e5c542a18591305c5ca4f90142f8665c765e093d3d919ddfc4ab04c8f2ebc0ab4f392e5f20609c16761dc2aaebb1e07998105731048ca7668ae8cd9341b158dd4b2870ed7c9daa2bd1adf424dfdb8b44367a5e36d2626536d62d24bc47111709ea7f24a7f3b4c9685836c31ecdff2a4bc63fe3f7b087c7f6532f404eb9c1c";
        priceData.feedHashes[8] = 0x430a06ad154743a8d72ec533360245f8f4c08a195b600968780852a079bf16fb;
        priceData.answers[8] = int256(0x4aa56fd5);
        priceData.timestamps[8] = uint256(0x019339cb17ff);
        priceData.proofs[8] =
            hex"f7dc5f1b3deff104ea9be391767289d7a1797bd93c33bff69e54a90d60903c3602ed52389e7ce09d9f02c91c9275e359e9e57890bc8ee07e9cd96891379e0b901c";
        priceData.feedHashes[9] = 0x646f04eca6f4604590b84aae60a51b37086dfc6a46feca6c5416ab7a3c0e23c9;
        priceData.answers[9] = int256(0x164d48fc);
        priceData.timestamps[9] = uint256(0x019339cb1773);
        priceData.proofs[9] =
            hex"6d5f0adafe3edfd91544d5a3db73497f9e2e22e082cc558d43bb8c83303fa57e41c3c360cb271d0bef4e0f93adbd7e13b4361dfd3f583bf3c2e97459a38d2e021bef733bd90987426627ef10659e989a5a2865ea86c235f7351c92598ed8eba8af23788dcac84b5c100fb5e360958e6dcd97d42b9e0a5b821cdee90192819768fb1c";
        priceData.feedHashes[10] = 0xb4b7bb0e1aecd0b5851b8c48fb171337317c1a9c45e755de3909e93958765e81;
        priceData.answers[10] = int256(0x0996);
        priceData.timestamps[10] = uint256(0x019339cb189e);
        priceData.proofs[10] =
            hex"5f4a77cf7cbfb32707a297e7caa8fa2d6cb0b44a5e9542e7f1f2f65d2276519e24091c4185f7dc5add0cfd5755d8ea9f4782202bb8441a0fb2a4e37c099ba01d1cac1fe26f21e0e1e74c9afcdd0dc162960b7f7e958bb223ef6326ada550f2cd710c21afd6bf117eaaaa5ea345f6b539cfb24cf51dcd049eb597f17fc27bbac59f1c";
        priceData.feedHashes[11] = 0x069dee7ca2e950642ea45600b1f3ca3eb7bc30291426a82b65838576379666d3;
        priceData.answers[11] = int256(0x0316f4c2);
        priceData.timestamps[11] = uint256(0x019339cb1727);
        priceData.proofs[11] =
            hex"30fbf160a00009595fff45f5e91c7775d39a94e93b23ddd296c7fb9d721c42fe43e9fa3e56944836e5931ce1b87a39d0c3f7816bceaba20cc244c0f29a551e8b1c7b8ebe204671681da3d8adc5c2e77f8232a4af37fac8a9316f1c9c2afb3bbb7c79413718c14ec986283fe75d2631497c7e9099e1bc67580ed6b01acd2d09eb8d1b";
        priceData.feedHashes[12] = 0x5f741f7995dc7d3a3a89dd2daccc6c019033c69204605aabf2739c3aa5ec8a62;
        priceData.answers[12] = int256(0x04445023);
        priceData.timestamps[12] = uint256(0x019339cb1852);
        priceData.proofs[12] =
            hex"ff8323846eb56c560fe50ce26680997f6498fcd6fde2f97576215b222e06ebe16ea0afd9c1ea6a8a0faeefc5f880cd0c00b1a7ed330e827b8f9a7857156a46e71b3b124fe691c0b5c30e157d9e6a46769d82299c6b41abe0432c25fd268ad2bec7743d320a469167930080a8778b6099fc94e3a567f32e5c72be105d82e8db5de41c";

        return priceData;
    }

    // block numebr 169_828_869
    // positionId 2219
    function test_liquidatePositions_ok() public {
        vm.selectFork(liquidationForkId);
        vm.rollFork(169_811_776); // 2219 opened 169811777
        uint256 time1 = block.timestamp;
        deployAndSet();

        PerpDexLib.OraclePrices memory priceData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.BisonAI,
            feedHashes: new bytes32[](1),
            answers: new int256[](1),
            timestamps: new uint256[](1),
            proofs: new bytes[](1)
        });

        priceData.feedHashes[0] = 0x455314fa66a1287be93e6f2d43ee572d47b716b7c69361df3409a28f3c1b7546;
        priceData.answers[0] = int256(0x0840);
        priceData.timestamps[0] = uint256(0x019338c61866);
        priceData.proofs[0] =
            hex"c9787af91537241c84cd9ffa7ac8e69fbcfdd9d525937a93fbbb8b24328d27843c0a1130548e8806fca4a80acac2d12beb259627f9630f5f9449de8f6517e5591c77c27d0738618223b7e72c4434ccfcc640f36317c00bd6474607ed602d8bb9eb1210524b60dd82a41d4c63601dfa4e9a28feba2142c9443270523c08487d6af11b";

        bytes memory userSignedData = getSignedMessage(
            userPk,
            abi.encodePacked(
                "Open position for Token: 5, Margin: 7598100, Leverage: 100, Long: 1, TP: 0, SL: 0, Price: 2112, Nonce: 0, Chain: 8217, Contract: ",
                Strings.toHexString(address(perpDex))
            )
        );

        vm.startPrank(singleOpenAdmin);
        perpDex.openPosition(
            PerpDexLib.OpenPositionData({
                tokenType: PerpDexLib.TokenType.Pepe,
                marginAmount: 7_598_100,
                leverage: 100,
                long: true,
                trader: user,
                priceData: priceData,
                tpPrice: 0,
                slPrice: 0,
                expectedPrice: 2112,
                userSignedData: userSignedData
            })
        );
        vm.stopPrank();

        PerpDexLib.Position memory p = perpDex.getPosition(1);
        assertEq(p.initialPrice, 2112);
        assertEq(p.liquidationPrice, 0); // deprecated

        PerpDexLib.OraclePrices memory priceData2 = getLiquidateValidPriceData();
        vm.makePersistent(user);
        vm.makePersistent(address(perpDex));
        vm.makePersistent(address(lpContract));
        vm.makePersistent(address(usdtContract));
        vm.startPrank(liqAdmin);
        vm.rollFork(169_828_864); // submitted at 169828865
        perpDex.submitAndGetBisonAIRoundId(priceData2);

        uint64[] memory roundIds = new uint64[](13);
        roundIds[0] = uint64(0x0e7974);
        roundIds[1] = uint64(0x0e7465);
        roundIds[2] = uint64(0x0e5895);
        roundIds[3] = uint64(0x0e60c9);
        roundIds[4] = uint64(0x0e5d66);
        roundIds[5] = uint64(0x0cde4b);
        roundIds[6] = uint64(0x0e3122);
        roundIds[7] = uint64(0x0e3243);
        roundIds[8] = uint64(0xcf01);
        roundIds[9] = uint64(0xcf6f);
        roundIds[10] = uint64(0x0e29aa);
        roundIds[11] = uint64(0xcd32);
        roundIds[12] = uint64(0x0e2f22);

        uint256[] memory candidates = new uint256[](1);
        candidates[0] = 1;
        vm.warp(block.timestamp + 5);
        uint256 time2 = block.timestamp;
        vm.roll(169_828_869);
        perpDex.liquidatePositions(candidates, roundIds, priceData2);
        vm.stopPrank();

        PerpDexLib.Position memory p2 = perpDex.getPosition(1);
        assertEq(uint256(p2.positionStatus), uint256(PerpDexLib.PositionStatus.Liquidated));
        assertEq(p2.finalPrice, 2092);

        int256 expectingFundingFee = int256(p2.size * 1e20 * (time2 - time1) * 875 / (1e20 * 1e7 * 3600));
        int256 marginAfterFundingFee = int256(p2.margin) - expectingFundingFee;

        int256 pnl = int256((p2.size * p2.finalPrice) / p2.initialPrice) - int256(p2.size);
        uint256 loss = Math.min(uint256(marginAfterFundingFee), uint256(-pnl));
        int256 closeFee = int256((p2.size - loss) * 70 / 100_000);
        emit log_int(expectingFundingFee);
        emit log_int(marginAfterFundingFee);
        emit log_int(closeFee);

        assertEq(p2.fundingFee, expectingFundingFee);
        assertEq(p2.pnl, -(marginAfterFundingFee - closeFee));
        assertEq(p2.closeFee, uint256(closeFee));
        assertEq(usdtContract.balanceOf(address(lpContract)), initialLpBalance + uint256(marginAfterFundingFee - closeFee));
        assertEq(usdtContract.balanceOf(address(feeContract)), p2.closeFee + p2.openFee);
        assertEq(usdtContract.balanceOf(address(user)), initialUserBalance - p2.margin - p2.openFee);
    }

    function test_liquidatePositions_revert() public {
        vm.selectFork(liquidationForkId);
        vm.rollFork(169_828_868);
        deployAndSet();

        vm.startPrank(liqAdmin);
        uint64[] memory roundIds = new uint64[](13);
        roundIds[0] = uint64(0x0e7974);
        roundIds[1] = uint64(0x0e7465);
        roundIds[2] = uint64(0x0e5895);
        roundIds[3] = uint64(0x0e60c9);
        roundIds[4] = uint64(0x0e5d66);
        roundIds[5] = uint64(0x0cde4b);
        roundIds[6] = uint64(0x0e3122);
        roundIds[7] = uint64(0x0e3243);
        roundIds[8] = uint64(0xcf01);
        roundIds[9] = uint64(0xcf6f);
        roundIds[10] = uint64(0x0e29aa);
        roundIds[11] = uint64(0xcd32);
        roundIds[12] = uint64(0x0e2f22);

        uint256[] memory candidates = new uint256[](1);
        candidates[0] = 2219;
        PerpDexLib.OraclePrices memory priceData = getLiquidateValidPriceData();

        // switch roundId order
        roundIds[2] = uint64(0x0e60c9);
        roundIds[3] = uint64(0x0e5895);
        vm.expectRevert(abi.encodeWithSignature("NoDataPresent()"));
        perpDex.liquidatePositions(candidates, roundIds, priceData);
        roundIds[2] = uint64(0x0e5895);
        roundIds[3] = uint64(0x0e60c9);

        // use wrong roundId => Doesn't revert
        roundIds[3] = uint64(0x0e2f22);
        // vm.expectRevert("Price is not correct (BisonAI)");
        perpDex.liquidatePositions(candidates, roundIds, priceData);
        roundIds[3] = uint64(0x0e60c9);

        // switch priceData order
        priceData.feedHashes[5] = 0xce3e90cc1f29fa40c7bf832c5d85d5dbb8f98b81538a3e03e5d4ba4c48229914;
        priceData.answers[5] = 14_332_811;
        priceData.timestamps[5] = 1_729_585_846_411;
        priceData.proofs[5] =
            hex"266465dfe9806c3927e931aa550dbd839aff79f526a53ce2a877c0013ef3721f195b4d6d21cfa3b80111bc90af7085354041695465add31fd5595375ca9c62661ccbd7e03cf9e0161c9e1b8fa4c3e0b08d8e8a9909e14369b55f0e7c360008cdda025fd4f170af54984e0051217e123f48b1a61abc54565f2a322c8c21f9e60b1d1b";
        priceData.feedHashes[4] = 0x455314fa66a1287be93e6f2d43ee572d47b716b7c69361df3409a28f3c1b7546;
        priceData.answers[4] = 1016;
        priceData.timestamps[4] = 1_729_585_846_587;
        priceData.proofs[4] =
            hex"5a7f363b3b057975f004be74aa0ed37b594c20631e8ef5a120f7fe81015b0f9632698dbba5682ee3768403ba607f8dbf1b36b3b986f7b9d1b29ac5441092034d1bca8cf6409b9f91cbf4909e27b9c8c82c2a5cd894b8fda8431bc47fd5e58f6bf5657d37317b04a17a314e08bcc41cf0307ac1def7c83c0abe810f8724039c1f111b";
        // vm.expectRevert(abi.encodeWithSignature("NoDataPresent()"));
        vm.expectRevert("Feed hash is not correct (BisonAI)");
        perpDex.liquidatePositions(candidates, roundIds, priceData);
    }

    function getTpslValidPriceData() public pure returns (PerpDexLib.OraclePrices memory) {
        PerpDexLib.OraclePrices memory priceData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.BisonAI,
            feedHashes: new bytes32[](18),
            answers: new int256[](18),
            timestamps: new uint256[](18),
            proofs: new bytes[](18)
        });

        priceData.feedHashes[0] = 0xa92bcb5bc51aa5535ed0cc3f522992dd9a6fb2e8dd6dcf484705d93eb3cd167a;
        priceData.feedHashes[1] = 0x44056fd001da2ea02617117909aa18a3931efd8820d1a75ea95516958e5f96d5;
        priceData.feedHashes[2] = 0xd17438ade2a57a233f67cf57bd903b44a3c13b2c40497a93bf935a62cbe94b17;
        priceData.feedHashes[3] = 0x7020b52841bb268cbc78137a54d4bf1f5305eed1039fb5d003ba95b8ededc46c;
        priceData.feedHashes[4] = 0xce3e90cc1f29fa40c7bf832c5d85d5dbb8f98b81538a3e03e5d4ba4c48229914;
        priceData.feedHashes[5] = 0x455314fa66a1287be93e6f2d43ee572d47b716b7c69361df3409a28f3c1b7546;
        priceData.feedHashes[6] = 0x02c0a62d9ad950cd79feeae43830a378279a187e9dbc92e826e19ca6efde183f;
        priceData.feedHashes[7] = 0xb7d399d01faafdf72706e94b58187f12f2cb26600753022f64d8bf43fab774b1;
        priceData.feedHashes[8] = 0x430a06ad154743a8d72ec533360245f8f4c08a195b600968780852a079bf16fb;
        priceData.feedHashes[9] = 0x646f04eca6f4604590b84aae60a51b37086dfc6a46feca6c5416ab7a3c0e23c9;
        priceData.feedHashes[10] = 0xb4b7bb0e1aecd0b5851b8c48fb171337317c1a9c45e755de3909e93958765e81;
        priceData.feedHashes[11] = 0x069dee7ca2e950642ea45600b1f3ca3eb7bc30291426a82b65838576379666d3;
        priceData.feedHashes[12] = 0x5f741f7995dc7d3a3a89dd2daccc6c019033c69204605aabf2739c3aa5ec8a62;
        priceData.feedHashes[13] = 0xbd6a76f3fffa56516b9b0527c18e302c728e3729ebf97cce43f45467376a3464;
        priceData.feedHashes[14] = 0x916b18d15243bbee40f4c78c0aa4cafbccdcecac1bd0f81f241f36b49e3e645a;
        priceData.feedHashes[15] = 0x134e1d85f944c3f41a0d9b6ab4b87a800a90932ec955191218979d3523708f70;
        priceData.feedHashes[16] = 0x677f622ac9ddb0c4720292ba0ce6cc4dd1c07576b7f5448b3f7eef7a1a44c143;
        priceData.feedHashes[17] = 0x3b98925e7d5d865e2e8b845f091aab239943cee7604960a43ca551e03aaf2326;

        priceData.answers[0] = 9_458_724_881_641;
        priceData.answers[1] = 20_610_836;
        priceData.answers[2] = 79_789_530;
        priceData.answers[3] = 338_529_344_451;
        priceData.answers[4] = 32_250_623;
        priceData.answers[5] = 1844;
        priceData.answers[6] = 19_464_702_556;
        priceData.answers[7] = 216_762_762;
        priceData.answers[8] = 906_318_432;
        priceData.answers[9] = 419_109_096;
        priceData.answers[10] = 2198;
        priceData.answers[11] = 42_135_427;
        priceData.answers[12] = 89_897_431;
        priceData.answers[13] = 48_036_906;
        priceData.answers[14] = 70_908_798_809;
        priceData.answers[15] = 700_886_532;
        priceData.answers[16] = 10_060_985_628;
        priceData.answers[17] = 3_685_017_126;

        priceData.timestamps[0] = 1_735_482_263_079;
        priceData.timestamps[1] = 1_735_482_262_876;
        priceData.timestamps[2] = 1_735_482_262_913;
        priceData.timestamps[3] = 1_735_482_263_003;
        priceData.timestamps[4] = 1_735_482_263_105;
        priceData.timestamps[5] = 1_735_482_263_191;
        priceData.timestamps[6] = 1_735_482_263_094;
        priceData.timestamps[7] = 1_735_482_262_875;
        priceData.timestamps[8] = 1_735_482_262_882;
        priceData.timestamps[9] = 1_735_482_263_079;
        priceData.timestamps[10] = 1_735_482_262_991;
        priceData.timestamps[11] = 1_735_482_263_179;
        priceData.timestamps[12] = 1_735_482_263_182;
        priceData.timestamps[13] = 1_735_482_262_838;
        priceData.timestamps[14] = 1_735_482_263_076;
        priceData.timestamps[15] = 1_735_482_262_933;
        priceData.timestamps[16] = 1_735_482_262_896;
        priceData.timestamps[17] = 1_735_482_262_881;

        priceData.proofs[0] =
            hex"302ce910a56e9d1fd375ef44bd28e5947d59b64ce38cdd41580dcaf90450b9d214154e23ed4acd2c89e1e94166f4d5c661f2912e0659752ac15ef291a024f5ce1ca7c57442c9e5f0ab54c821c53c87650d12cbc722f49d70f449c568beb707549645811162b7bc507664db05d600518f6e3a866086195237192877d4db79758e221b";
        priceData.proofs[1] =
            hex"1dc90ed6a58eb8d440783958959ae8df1845609ecb7b62520d55834c32616f90415a8cbf6676ba91f69eeea22f965034550a4ee9330e03fde5d991cd4971e4571b843dc166455594103e3ecbd1e4a5a2d494deb127dbb2cb6ce868c4b8b2be7ab642bc34cc29e139b79595cf8b3016af64de74c1b44796f664b7be1caef3d23ce61b";
        priceData.proofs[2] =
            hex"45d3df471775c5158fbc5a395444db2fcf265b685c38d898a1852a0d200606273c26bcbaf01ae44760a15cc8d6cdb7ebf28dbb52dabc25820b5c3641c081ea201b830b2f4f7f8135ad0659072d79896dbcf576edc244d91cb0610939fa7102ba744c5b43ce6cc3f94b5d999f9ee86853aaa59735876ae7ecd87ccc669baa2fe0c11b";
        priceData.proofs[3] =
            hex"9fd92b53f4c87a5aa821c46e067b8c5fea436ef9590d28017d8916368692b85e0b5d5df468d90b4a1c46eedab362f8467aa0cc00481651cea3747ff09272a2eb1c356a695943538a4c5b311f5031c6a1a39381c80778ab2cf4d374f7cd6f2bb27a41e4f242d142fa6bd7e6ae8447ed13257b4aa0ef59f55c673e791b9c894c038f1c";
        priceData.proofs[4] =
            hex"605a4a06dc1f574a620f5f9ad8865c13ac8152c767339e48b8b6d72b0221ab431a5b47d3e7a7c60cdacd9b25b133ba25fa6171263344e5f7571bea971128567e1cd2ff2539aa9d09ed2e3c59ff9c21f4d67956200ebd6922ebc6f8f592b8ccdd9776a961253e75d99a320740f93ceb2243bb32365957db7d096d92c60e60d658801b";
        priceData.proofs[5] =
            hex"e67438bf4d1fbe7129c7cce533cc4894dc94943cbb4c30205dc1b0259b623ba41d79aa5c044ca98d27e07d24a535aa33cadccac7411c227cfb985727e7d8b4b51be033623c63bf4e7377de463c74f6f53dc34bf52292bbb9f83c21734c519a90d53f0222d615cf5e304e8126243d45b6509cb1fe0cdaa9a9fcc49d8946ad81c6231c";
        priceData.proofs[6] =
            hex"7d29e556f71f2abd7b64985ca978d3d289e1575a70fb4520b771df89702ff4b519decd4437879251308005351a58c7a91367f33ceaf7626d3fb5ccda00ea1e461bfb8af61fbed7cb277a8a1fd20034bd767ee3e2b27eaede22fabccdf98ad359085761fc6c47d6c14b9c65d7764105fb2396d7ac80b1951f04d1442d2f0552e7cb1b";
        priceData.proofs[7] =
            hex"f3fa6d310dc88736a6ed133f406146ebb3c92b77a6925fa1161d5d11721064d94f73c3de97080a7796c4842d5277c4a5a0f9f7db73dc5f879bc1fde4fc83395b1b523fe32c8e04d3986861a1b10140a473d1797404f1c23021822e4933fbe78dc43470717d53e6cbcd1581d4f22b681a1d28758247fe9ca1eb003d2099d21e6b141c";
        priceData.proofs[8] =
            hex"ab52b0a423f5e6b166dccee5c26d93ed3f16da4ee12d4b53aefeb7eb7f7b1f1836464e2c04f99726d90f217f0909fe2c9698d1329b5cde0185ab26e9be0faf6e1ccfc2842817ab6adee8052d4a3d4a8caa15be858fa906b13f16e08456f2a1a4e82799ad270e3ece5fa064e8ee1a16d8dc5fa57f2cb5475797279d38226d4a361c1c";
        priceData.proofs[9] =
            hex"c8321705278f4ea71c32738c0cd71e56202efeff33e8db4f13ed8d126ae9427f1ea3b99b328df30fd9bf9c06f0dadea360ea21a5142298b807492121f166c3891bbc6424754e3b302d658d358cdca32214d131b55477067c3c32c500c878b973c628ee1f1ae4ee9398fa61545cd67c838f29f7557dd733119a62c23c20021a83f31b";
        priceData.proofs[10] =
            hex"67a38c3a6cf82a4ba29d97e44d36dbc0cbaa2b3f3b6a8a0dfb38c786025871af501676e3a04a5e8fda3fb22b755165c07c8f8fdef3ba6a248de4e2c4c3a36c281bb2d4700a89362ca522ce0b6dad02df98ac3b2f6736f4806386e455f2210f958d623b10802e4fca91209bfdc300522c2140aecb6aea49a165035fa4275f18e79c1c";
        priceData.proofs[11] =
            hex"dafdb2c214f9f41b2ed7e2851d2bbdf17794b953a5fe1716c889c99ff791da3b25033d3eb3b7f661b489d327c02bc4208808a858c4799b7748c0b5cdaadda9f51b8e4a04602cf8dbf2d85425126ebd8ee9cfe6dd7668766ae99a4ab5253b85ddd87a966f48e471cc3a35039e17ec52af561f566e38aa6e41baa48cabc10c250c051c";
        priceData.proofs[12] =
            hex"fe7ab9d3c1322acdc4a1d1cf3730d83db3084c6ae383f2bb3e2e51a4737cca7570c4ee3f72227a4361c2fb0d87d6b57cf140137e4780aa82c0bfea135aa096a51cdeeb9ffd3f39acdb3be074a8d1f1bcc892940f78ca518e90272a44ccbd07fec4329fd2d1455cf45cf16a7638e38fb3cfb02cf30a29c98012f22deb77b3e184fb1c";
        priceData.proofs[13] =
            hex"295809bae0c2be3536e9b17a41556c51d47987ed1d4c2d05ed548689a967bc410e72a92b14a39043be1dae76fac99026558e89ad6ab92f80c2f4b7d12084ed9c1cf46519fd83d095c419dafff8c662b881be0c608bebf994b5d1194b42ee18160c7da0293363700857ce88d3f8acd7709659146227b64f5918cebf0c84b6fd034f1b";
        priceData.proofs[14] =
            hex"9917e8584fc3c3461bfe0bd499075818c57168c676b0af288a47b5061555bf104c2c1b65b367ed12a1abfb3cc3a753df788fc3af141e4900f55b6038e98b06bf1c6cf5fd0226db35923db8e8ea9a805d11589ae9c1004501c4156c63466aade5cb1abb2e620e54dc7c0d458cb72680ba29edd52166601cc493a8dc2a810665962e1b";
        priceData.proofs[15] =
            hex"a61ca6217125dd5c462be1733a7df8e670a7561128e91b68c68f850f71f6f73e7698d356fd326461c83c9eba60bffba0690fa7d903652e335244a84c954fb8611b16ca1fcd6e1b2f52703ffbd5bbff9322b8606f90167e58736d2202eac86552df41268047ead14d36d9faae042e55ddb3592dcfd5df879679e8d0e8ffcf302e161b";
        priceData.proofs[16] =
            hex"2d679049b8b00ae31edc44d695b9069d039032bdb8f0e47011ef05b6cf9120ff327c5831bb2ddd07f3fa04433bcd9ee4d69f2dd13730470fc06057b569473f071bd060e3a641a98a1361be7e58ac787a406863f5db869d64d66aac73a560bb7ad17fe5942170ffa4ef7644707cdfe923826ae897d161d684c689a73aca3d821e501b";
        priceData.proofs[17] =
            hex"c3e365d8fc8aad682cbf3b985ce5e4b25bff82eec9a7201a084b2edb884f41a97007b475ec03a9b9ed58e0ba844972f60ee662ebcc959f9e20c0ee35c76c970c1c0e5fe89b717b09847d0f28cdc527e702058ccda5ab084c0d6f6011db88d0bbea11fc69e87c36713938b24c1c9c5e792a05a3676d025c9b2b27247582930f6d9c1b";

        return priceData;
    }

    /**
     * positionId: 3750
     * blockNumber:
     *     open 173437647
     *     close 173465574
     */
    function test_tpslClosePositions_sl() public {
        vm.selectFork(liquidationForkId);
        vm.rollFork(173_437_647);
        uint256 time1 = block.timestamp;
        deployAndSet();

        PerpDexLib.OraclePrices memory priceData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.BisonAI,
            feedHashes: new bytes32[](1),
            answers: new int256[](1),
            timestamps: new uint256[](1),
            proofs: new bytes[](1)
        });

        priceData.feedHashes[0] = 0xa92bcb5bc51aa5535ed0cc3f522992dd9a6fb2e8dd6dcf484705d93eb3cd167a;
        priceData.answers[0] = 9_515_132_295_859;
        priceData.timestamps[0] = 1_735_454_339_451;
        priceData.proofs[0] =
            hex"42704e2345f238f492cd49ea8dcc7a3b876cfc3a506c358cbe675f06a03e9ec14623c24d2315e75a5fd31448dc17fd33eba3d4287712597b764fd6d59425907b1b5224472fc9f8cbdc861d8b3418fe892b628056366a274f3b0d32ea5cfbb7b35a28aec40677281c9ddf6d76b974e3d4a16ca8b12ba1680d67cf5a455b555985a71c";

        bytes memory userSignedData = getSignedMessage(
            userPk,
            abi.encodePacked(
                "Open position for Token: 0, Margin: 1000000000, Leverage: 35, Long: 1, TP: 0, SL: 9460000000000, Price: 9515132286411, Nonce: 0, Chain: 8217, Contract: ",
                Strings.toHexString(address(perpDex))
            )
        );

        vm.startPrank(singleOpenAdmin);
        perpDex.openPosition(
            PerpDexLib.OpenPositionData({
                tokenType: PerpDexLib.TokenType.Btc,
                marginAmount: 1_000_000_000,
                leverage: 35,
                long: true,
                trader: user,
                priceData: priceData,
                tpPrice: 0,
                slPrice: 9_460_000_000_000,
                expectedPrice: 9_515_132_286_411,
                userSignedData: userSignedData
            })
        );
        vm.stopPrank();

        PerpDexLib.Position memory p = perpDex.getPosition(1);
        assertEq(p.initialPrice, 9_515_132_295_859);
        assertEq(p.slPrice, 9_460_000_000_000);

        vm.makePersistent(user);
        vm.makePersistent(address(perpDex));
        vm.makePersistent(address(lpContract));
        vm.makePersistent(address(usdtContract));
        vm.rollFork(173_465_568); // submitted at 173465569
        vm.prank(limitAdmin);
        PerpDexLib.OraclePrices memory priceData2 = getTpslValidPriceData();
        perpDex.submitAndGetBisonAIRoundId(priceData2);

        uint64[] memory roundIds = new uint64[](18);
        roundIds[0] = 1_189_178;
        roundIds[1] = 1_188_304;
        roundIds[2] = 1_180_270;
        roundIds[3] = 1_182_676;
        roundIds[4] = 1_181_705;
        roundIds[5] = 1_083_462;
        roundIds[6] = 1_170_210;
        roundIds[7] = 1_170_569;
        roundIds[8] = 112_534;
        roundIds[9] = 112_676;
        roundIds[10] = 1_168_313;
        roundIds[11] = 112_097;
        roundIds[12] = 1_169_659;
        roundIds[13] = 151_947;
        roundIds[14] = 1_168_941;
        roundIds[15] = 1_168_054;
        roundIds[16] = 1_169_330;
        roundIds[17] = 1_169_081;

        uint256[] memory candidates = new uint256[](1);
        candidates[0] = 1;
        vm.warp(block.timestamp + 5);
        vm.roll(173_465_574);
        uint256 time2 = block.timestamp;
        vm.prank(tpslAdmin);
        perpDex.tpslClosePositions(candidates, roundIds, priceData2);

        PerpDexLib.Position memory p2 = perpDex.getPosition(1);
        assertEq(uint256(p2.positionStatus), uint256(PerpDexLib.PositionStatus.Closed));
        assertEq(p2.finalPrice, 9_458_724_881_641);

        // loss
        // payAndRecordFee(position, closeFee, false, c.feeContract);
        // PerpDexPricesLib.safeTransferAndCheckBalance(position.traderAddr, uint256(marginAfterFundingFee) - closeFee - loss, c.usdt);
        // takeAndRecordLoss(position, uint256(-pnl), c.lp, c.usdt);
        int256 expectingFundingFee = int256(p2.size * 1e20 * (time2 - time1) * 875 / (1e20 * 1e7 * 3600));
        uint256 loss = p2.size - p2.size * p2.finalPrice / p2.initialPrice;
        uint256 closeFee = (p2.size * p2.finalPrice / p2.initialPrice) * 70 / 100_000;
        assertEq(p2.closeFee, closeFee); // loss

        assertEq(p2.fundingFee, expectingFundingFee);
        assertEq(p2.pnl, -int256(loss));
        assertEq(p2.closeFee, uint256(closeFee));

        assertEq(usdtContract.balanceOf(address(lpContract)), initialLpBalance + uint256(loss));
        assertEq(usdtContract.balanceOf(address(feeContract)), p2.closeFee + p2.openFee);
        assertEq(
            usdtContract.balanceOf(address(user)),
            initialUserBalance - p2.margin - p2.openFee + (p2.margin - uint256(p2.fundingFee) - closeFee - loss)
        );
    }
}
