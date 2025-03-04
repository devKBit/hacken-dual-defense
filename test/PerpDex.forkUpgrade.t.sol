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

contract PerpDexForkUpgradeTest is Test {
    using ECDSA for bytes32;

    UUPSProxy public feeProxy;
    Fee public feeContract;
    LP public lpContract;
    ERC20 public usdtContract;

    address owner = 0xe9770c38A3B2B151501974977305F81412e77Ab9;
    address admin;
    address liqAdmin = 0xFB2557bA121bAD996FF173890E041a6A9B21d41a;
    address limitAdmin;
    address singleOpenAdmin = 0x282D5A44a33a195548BC51113c54f0dABD23143e;
    address closeAdmin = 0x33BD4Cf1f7B1774a19341C6CE33c017B74fD4428;
    address tpslAdmin;

    address user = 0xb14BD75315C8fd0EB70DfE93D61517a4A06db996;
    PerpDex perpDexProxy;

    uint256 ownerPk;
    uint256 adminPk;

    IBisonAIRouter bisonAIRouter;
    IBisonAISubmissionProxy bisonAISubmissionProxy;
    IPyth pyth;

    uint256 forkId;
    uint256 forkId2;

    uint256 defaultTotalFeePercent = 70;
    uint256 defaultFeeDenominator = 100_000;
    uint256 defaultMarginFeePercent = 100;

    /**
     * or Use foundry.toml
     * [rpc_endpoints]
     * kaia = "${KAIA_RPC_URL}"
     */
    string KAIA_RPC_URL = vm.envString("KAIA_RPC_URL");

    function setUp() public {
        forkId = vm.createFork(KAIA_RPC_URL, 168_168_196);
        forkId2 = vm.createFork(KAIA_RPC_URL, 172_314_664); // target positionId 3390, blockNumber 172314654
        perpDexProxy = PerpDex(0x21b776374C4B9cC52dD053212a8dde9DD6da061c);
        lpContract = LP(0xfFD3928Be7FA924Aa9c19b7CD4c107e9F276d9e8);
        usdtContract = ERC20(0x5C13E303a62Fc5DEdf5B52D66873f2E59fEdADC2);

        feeContract = Fee(0x2994F8C9Df255e3926f73ae892E7464b4F76cd49);
        lpContract = LP(0xfFD3928Be7FA924Aa9c19b7CD4c107e9F276d9e8);

        bisonAIRouter = IBisonAIRouter(0x653078F0D3a230416A59aA6486466470Db0190A2);
        bisonAISubmissionProxy = IBisonAISubmissionProxy(0x3a251c738e19806A546815eb6065e139A8D65B4b);
        pyth = IPyth(0x2880aB155794e7179c9eE2e38200202908C17B43);
    }

    function migrateAddrs() public {
        address[] memory tempAdmin = new address[](1);
        tempAdmin[0] = closeAdmin;
        perpDexProxy.setAdmins(PerpDexAuthLib.AdminType.Close, tempAdmin);
        tempAdmin[0] = liqAdmin;
        perpDexProxy.setAdmins(PerpDexAuthLib.AdminType.Liquidation, tempAdmin);
        tempAdmin[0] = limitAdmin;
        perpDexProxy.setAdmins(PerpDexAuthLib.AdminType.LimitOrder, tempAdmin);
        tempAdmin[0] = singleOpenAdmin;
        perpDexProxy.setAdmins(PerpDexAuthLib.AdminType.SingleOpen, tempAdmin);
        tempAdmin[0] = tpslAdmin;
        perpDexProxy.setAdmins(PerpDexAuthLib.AdminType.Tpsl, tempAdmin);

        perpDexProxy.setupAddr(address(usdtContract), address(lpContract), address(feeContract));
    }

    function mockFee(uint256 totalFeePercent, uint256 feeDenominator, uint256 marginFeePercent) public {
        vm.mockCall(address(feeContract), abi.encodeWithSelector(IFee.payFee.selector), abi.encode());
        vm.mockCall(address(feeContract), abi.encodeWithSelector(IFee.getTotalFeePercent.selector), abi.encode(totalFeePercent));
        vm.mockCall(address(feeContract), abi.encodeWithSelector(IFee.getFeeDenominator.selector), abi.encode(feeDenominator));
        vm.mockCall(address(feeContract), abi.encodeWithSelector(IFee.getMarginFeePercent.selector), abi.encode(marginFeePercent));
    }

    function mockCurrentPrice(uint256 currentPrice) public {
        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.submitAndGetLatestPrice.selector), abi.encode(currentPrice)
        );
    }

    function mockGetPreviousPriceAndTime(uint256[6] memory _prices, uint256[6] memory _updatedAts) public {
        uint256[] memory prices = new uint256[](6);
        prices[0] = _prices[0];
        prices[1] = _prices[1];
        prices[2] = _prices[2];
        prices[3] = _prices[3];
        prices[4] = _prices[4];
        prices[5] = _prices[5];

        uint256[] memory updatedAts = new uint256[](6);
        updatedAts[0] = _updatedAts[0];
        updatedAts[1] = _updatedAts[1];
        updatedAts[2] = _updatedAts[2];
        updatedAts[3] = _updatedAts[3];
        updatedAts[4] = _updatedAts[4];
        updatedAts[5] = _updatedAts[5];
        vm.mockCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector),
            abi.encode(prices, updatedAts)
        );
    }

    function getOraclePricesDefault(uint256 count)
        public
        pure
        returns (PerpDexLib.OraclePrices memory bisonAIData, PerpDexLib.OraclePrices memory pythData)
    {
        bisonAIData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.BisonAI,
            feedHashes: new bytes32[](count),
            answers: new int256[](count),
            timestamps: new uint256[](count),
            proofs: new bytes[](count)
        });

        pythData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.Pyth,
            feedHashes: new bytes32[](count),
            answers: new int256[](count),
            timestamps: new uint256[](count),
            proofs: new bytes[](count)
        });
    }

    function closePositionDefault(uint256 positionId, uint256 closingPrice) public {
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(1);
        mockCurrentPrice(closingPrice);

        vm.mockCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), abi.encode());
        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferFromAndCheckBalance.selector), abi.encode()
        );
        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());

        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);
        vm.prank(closeAdmin);
        perpDexProxy.closePosition(positionId, bisonAIData, hex"1234");
    }

    function test_upgrade() public {
        vm.selectFork(forkId);
        vm.startPrank(owner);

        PerpDex newPerpDexImpl = new PerpDex();
        perpDexProxy.upgradeToAndCall(address(newPerpDexImpl), bytes(""));

        newPerpDexImpl = new PerpDex();
        perpDexProxy.upgradeToAndCall(address(newPerpDexImpl), bytes(""));
    }

    function test_upgrade_storage() public {
        vm.selectFork(forkId);
        vm.startPrank(owner);
        PerpDex newPerpDexImpl = new PerpDex();

        perpDexProxy.upgradeToAndCall(address(newPerpDexImpl), bytes(""));

        uint256 nextPositionId = perpDexProxy.nextPositionId();
        uint256 traderNonce = perpDexProxy.traderNonce(user);
        uint256[] memory limitOrderIds = perpDexProxy.getLimitOrderIds();
        uint256[] memory positionIdsForTrader = perpDexProxy.getPositionIdsForTrader(user);
        (uint256 lastUpdatedTime, int256 lastAppliedRate, int256 accFeePerSize) =
            perpDexProxy.fundingFeeTokenStates(PerpDexLib.TokenType.Btc);

        emit log_uint(nextPositionId);
        emit log_uint(traderNonce);
        emit log_array(limitOrderIds);
        emit log_array(positionIdsForTrader);

        vm.assertEq(nextPositionId, 1075);
        vm.assertEq(traderNonce, 69);
        vm.assertEq(limitOrderIds, new uint256[](0));
        vm.assertEq(positionIdsForTrader[0], 0);
        vm.assertEq(positionIdsForTrader[9], 13);
        vm.assertEq(positionIdsForTrader[63], 1049);
        vm.assertEq(positionIdsForTrader.length, 64);

        vm.assertEq(lastUpdatedTime, 0);
        vm.assertEq(lastAppliedRate, 0);
        vm.assertEq(accFeePerSize, 0);

        vm.stopPrank();
    }

    // TODO: block number is compatible with tokenCount 10, so add enum TokenType APT, SUI to get ok result
    function test_upgrade_storage_open() public {
        vm.selectFork(forkId);
        vm.startPrank(owner);
        PerpDex newPerpDexImpl = new PerpDex();

        perpDexProxy.upgradeToAndCall(address(newPerpDexImpl), bytes(""));
        migrateAddrs();

        uint256[] memory openPositionIds = perpDexProxy.getOpenPositionIds();
        uint256 sampleOpenPositionId1 = openPositionIds[openPositionIds.length - 1];
        uint256 sampleOpenPositionId2 = openPositionIds[0];

        assertEq(sampleOpenPositionId1, 1074);
        assertEq(sampleOpenPositionId2, 1049);

        PerpDexLib.Position memory p1 = perpDexProxy.getPosition(sampleOpenPositionId1);
        PerpDexLib.Position memory p2 = perpDexProxy.getPosition(sampleOpenPositionId2);

        assertEq(p1.positionId, 1074, "positionId");
        assertEq(p1.traderAddr, 0x035A25FB3f7B446a5D9895B44e5EA0f1D4c5b132, "traderAddr");
        assertEq(uint256(p1.tokenType), 9, "tokenType");
        assertEq(p1.margin, 93_000_000, "margin");
        assertEq(p1.size, 9_300_000_000, "size");
        assertEq(p1.openFee, 7_000_000, "fee");

        assertEq(p1.initialPrice, 187_890_482, "initialPrice");
        assertEq(p1.isLong, false, "isLong");
        assertEq(p1.openPositionIndex, 41, "openPositionIndex");
        assertEq(p1.finalPrice, 0, "finalPrice");
        assertEq(uint256(p1.positionStatus), 1, "positionStatus");
        assertEq(p1.limitOrderPrice, 0, "limitOrderPrice");
        assertEq(
            p1.limitOrderIndex,
            115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457_584_007_913_129_639_935,
            "limitOrderIndex"
        );
        assertEq(p1.statusTime.requestOpenTime, 0, "requestOpenTime");
        assertEq(p1.statusTime.openTime, 1_730_176_961, "openTime");
        assertEq(p1.statusTime.closeTime, 0, "closeTime");
        assertEq(p1.statusTime.limitOpenTime, 0, "limitOpenTime");
        assertEq(p1.statusTime.limitCloseTime, 0, "limitCloseTime");
        assertEq(p1.statusTime.liquidatedTime, 0, "liquidatedTime");
        assertEq(p1.pnl, 0, "pnl");
        assertEq(p1.liquidationPrice, 189_636_642, "liquidationPrice p1"); // already opened before upgrade

        assertEq(p1.tpPrice, 0, "tpPrice");
        assertEq(p1.slPrice, 0, "slPrice");
        assertEq(p1.marginUpdatedTime, 0, "marginUpdatedTime");
        assertEq(p1.accFundingFeePerSize, 0, "accFundingFeePerSize");
        assertEq(p1.fundingFee, 0, "fundingFee");
        assertEq(p1.closeFee, 0, "closeFee");

        assertEq(p2.positionId, 1049, "positionId");
        assertEq(p2.traderAddr, 0xb14BD75315C8fd0EB70DfE93D61517a4A06db996, "traderAddr");
        assertEq(uint256(p2.tokenType), 9, "tokenType");
        assertEq(p2.margin, 1_995_800, "margin");
        assertEq(p2.size, 5_987_400, "size");
        assertEq(p2.openFee, 4200, "fee");
        assertEq(p2.initialPrice, 189_059_108, "initialPrice");
        assertEq(p2.isLong, true, "isLong");
        assertEq(p2.openPositionIndex, 0, "openPositionIndex");
        assertEq(p2.finalPrice, 0, "finalPrice");
        assertEq(uint256(p2.positionStatus), 1, "positionStatus");
        assertEq(p2.limitOrderPrice, 0, "limitOrderPrice");
        assertEq(
            p2.limitOrderIndex,
            115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457_584_007_913_129_639_935,
            "limitOrderIndex"
        );
        assertEq(p2.statusTime.requestOpenTime, 0, "requestOpenTime");
        assertEq(p2.statusTime.openTime, 1_730_168_220, "openTime");
        assertEq(p2.statusTime.closeTime, 0, "closeTime");
        assertEq(p2.statusTime.limitOpenTime, 0, "limitOpenTime");
        assertEq(p2.statusTime.limitCloseTime, 0, "limitCloseTime");
        assertEq(p2.statusTime.liquidatedTime, 0, "liquidatedTime");
        assertEq(p2.pnl, 0, "pnl");
        assertEq(p2.liquidationPrice, 126_127_694, "liquidationPrice p2"); // already opened before upgrade

        assertEq(p2.tpPrice, 0, "tpPrice");
        assertEq(p2.slPrice, 0, "slPrice");
        assertEq(p2.marginUpdatedTime, 0, "marginUpdatedTime");
        assertEq(p2.accFundingFeePerSize, 0, "accFundingFeePerSize");
        assertEq(p2.fundingFee, 0, "fundingFee");
        assertEq(p2.closeFee, 0, "closeFee");

        vm.stopPrank();

        PerpDexLib.OraclePrices memory bisonAIData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.BisonAI,
            feedHashes: new bytes32[](10),
            answers: new int256[](10),
            timestamps: new uint256[](10),
            proofs: new bytes[](10)
        });

        PerpDexLib.OpenPositionData memory data = PerpDexLib.OpenPositionData({
            tokenType: PerpDexLib.TokenType.Btc,
            marginAmount: 2_000_000,
            leverage: 3,
            long: true,
            trader: user,
            priceData: bisonAIData,
            tpPrice: 0,
            slPrice: 0,
            expectedPrice: 10_000_000,
            userSignedData: hex"1234"
        });

        vm.mockCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), abi.encode());
        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferFromAndCheckBalance.selector), abi.encode()
        );
        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.submitAndGetLatestPrice.selector), abi.encode(10_000_000)
        );

        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(
            block.timestamp, PerpDexLib.TokenType.Btc, 8_581_471_869_460_328, 0, 96_257_160_400, 935_987_400
        );

        vm.prank(singleOpenAdmin);
        perpDexProxy.openPosition(data);
        uint256 positionId = perpDexProxy.nextPositionId() - 1;
        PerpDexLib.Position memory p = perpDexProxy.getPosition(positionId);

        assertEq(p.positionId, 1075, "positionId");
        assertEq(uint256(p.tokenType), 0, "tokenType");
        assertEq(p.margin, 1_995_800, "margin");
        assertEq(p.size, 5_987_400, "size");
        assertEq(p.openFee, 4200, "fee");
        assertEq(p.initialPrice, 10_000_000, "initialPrice");
        assertEq(p.isLong, true, "isLong");
        assertEq(p.openPositionIndex, 42, "openPositionIndex");
        assertEq(p.finalPrice, 0, "finalPrice");
        assertEq(uint256(p.positionStatus), 1, "positionStatus");
        assertEq(p.finalPrice, 0, "finalPrice");
        assertEq(p.limitOrderPrice, 0, "limitOrderPrice"); // opened after upgrade
        assertEq(
            p.limitOrderIndex,
            115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457_584_007_913_129_639_935,
            "limitOrderIndex"
        );

        assertEq(p.statusTime.requestOpenTime, 0, "requestOpenTime");
        assertEq(p.statusTime.openTime, 1_730_176_961, "openTime");
        assertEq(p.statusTime.closeTime, 0, "closeTime");
        assertEq(p.statusTime.limitOpenTime, 0, "limitOpenTime");
        assertEq(p.statusTime.limitCloseTime, 0, "limitCloseTime");
        assertEq(p.statusTime.liquidatedTime, 0, "liquidatedTime");
        assertEq(uint256(p.pnl), 0, "pnl");
        assertEq(p.liquidationPrice, 0, "liquidationPrice p");

        assertEq(p.tpPrice, 0, "tpPrice");
        assertEq(p.slPrice, 0, "slPrice");
        assertEq(p.marginUpdatedTime, 0, "marginUpdatedTime");
        assertEq(p.accFundingFeePerSize, 0, "accFundingFeePerSize");
        assertEq(p.fundingFee, 0, "fundingFee");
        assertEq(p.closeFee, 0, "closeFee");
    }

    function test_upgrade_storage_open_new_and_merge() public {
        vm.selectFork(forkId);
        vm.startPrank(owner);
        PerpDex newPerpDexImpl = new PerpDex();
        perpDexProxy.upgradeToAndCall(address(newPerpDexImpl), bytes(""));

        migrateAddrs();
        vm.stopPrank();

        PerpDexLib.OraclePrices memory bisonAIData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.BisonAI,
            feedHashes: new bytes32[](10),
            answers: new int256[](10),
            timestamps: new uint256[](10),
            proofs: new bytes[](10)
        });

        PerpDexLib.OpenPositionData memory data = PerpDexLib.OpenPositionData({
            tokenType: PerpDexLib.TokenType.Btc,
            marginAmount: 2_000_000,
            leverage: 3,
            long: true,
            trader: user,
            priceData: bisonAIData,
            tpPrice: 0,
            slPrice: 0,
            expectedPrice: 10_000_000,
            userSignedData: hex"1234"
        });

        vm.mockCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), abi.encode());
        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferFromAndCheckBalance.selector), abi.encode()
        );
        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.submitAndGetLatestPrice.selector), abi.encode(10_000_000)
        );

        vm.prank(singleOpenAdmin);
        perpDexProxy.openPosition(data);
        uint256 positionId = perpDexProxy.nextPositionId() - 1;
        PerpDexLib.Position memory p = perpDexProxy.getPosition(positionId);
        // emit log_uint(p.test);

        assertEq(p.positionId, 1075, "positionId");
        assertEq(uint256(p.tokenType), 0, "tokenType");
        assertEq(p.margin, 1_995_800, "margin");
        assertEq(p.size, 5_987_400, "size");
        assertEq(p.openFee, 4200, "fee");
        assertEq(p.initialPrice, 10_000_000, "initialPrice");
        assertEq(p.isLong, true, "isLong");
        assertEq(p.openPositionIndex, 42, "openPositionIndex");
        assertEq(p.finalPrice, 0, "finalPrice");
        assertEq(uint256(p.positionStatus), 1, "positionStatus");
        assertEq(p.finalPrice, 0, "finalPrice");
        assertEq(p.limitOrderPrice, 0, "limitOrderPrice"); // opened after upgrade
        assertEq(
            p.limitOrderIndex,
            115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457_584_007_913_129_639_935,
            "limitOrderIndex"
        );

        assertEq(p.statusTime.requestOpenTime, 0, "requestOpenTime");
        assertEq(p.statusTime.openTime, 1_730_176_961, "openTime");
        assertEq(p.statusTime.closeTime, 0, "closeTime");
        assertEq(p.statusTime.limitOpenTime, 0, "limitOpenTime");
        assertEq(p.statusTime.limitCloseTime, 0, "limitCloseTime");
        assertEq(p.statusTime.liquidatedTime, 0, "liquidatedTime");
        assertEq(uint256(p.pnl), 0, "pnl");
        assertEq(p.liquidationPrice, 0, "liquidationPrice p");

        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.submitAndGetLatestPrice.selector), abi.encode(9_000_000)
        );
        vm.prank(singleOpenAdmin);
        PerpDexLib.OpenPositionData memory data2 = PerpDexLib.OpenPositionData({
            tokenType: PerpDexLib.TokenType.Btc,
            marginAmount: 2_000_000,
            leverage: 3,
            long: true,
            trader: user,
            priceData: bisonAIData,
            tpPrice: 0,
            slPrice: 0,
            expectedPrice: 9_000_000,
            userSignedData: hex"1234"
        });
        perpDexProxy.openPosition(data2);

        PerpDexLib.Position memory mergedP = perpDexProxy.getPosition(positionId);
        assertEq(mergedP.positionId, 1075, "positionId");
        assertEq(uint256(mergedP.tokenType), 0, "tokenType");
        assertEq(mergedP.margin, 3_991_600, "margin");
        assertEq(mergedP.size, 11_974_800, "size");
        assertEq(mergedP.openFee, 8400, "fee");
        assertEq(mergedP.initialPrice, 9_473_684, "initialPrice");
        assertEq(mergedP.isLong, true, "isLong");
        assertEq(mergedP.openPositionIndex, 42, "openPositionIndex");
        assertEq(mergedP.finalPrice, 0, "finalPrice");
        assertEq(uint256(mergedP.positionStatus), 1, "positionStatus");
        assertEq(mergedP.finalPrice, 0, "finalPrice");
        assertEq(mergedP.limitOrderPrice, 0, "limitOrderPrice");
        assertEq(
            mergedP.limitOrderIndex,
            115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457_584_007_913_129_639_935,
            "limitOrderIndex"
        );

        assertEq(mergedP.statusTime.requestOpenTime, 0, "requestOpenTime");
        assertEq(mergedP.statusTime.openTime, 1_730_176_961, "openTime");
        assertEq(mergedP.statusTime.closeTime, 0, "closeTime");
        assertEq(mergedP.statusTime.limitOpenTime, 0, "limitOpenTime");
        assertEq(mergedP.statusTime.limitCloseTime, 0, "limitCloseTime");
        assertEq(mergedP.statusTime.liquidatedTime, 0, "liquidatedTime");
        assertEq(uint256(mergedP.pnl), 0, "pnl");
        assertEq(mergedP.liquidationPrice, 0, "liquidationPrice mergedP");
    }

    // target positionId 3390, blockNumber 172314654
    function test_upgrade_storage_merge_to_already_opened() public {
        vm.selectFork(forkId2);
        vm.startPrank(owner);
        PerpDex newPerpDexImpl = new PerpDex();
        perpDexProxy.upgradeToAndCall(address(newPerpDexImpl), bytes(""));
        perpDexProxy.addInitialTokenTotalSizes(1);
        perpDexProxy.changeMaxTokenTotalSizes();
        migrateAddrs();
        vm.stopPrank();

        PerpDexLib.OraclePrices memory bisonAIData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.BisonAI,
            feedHashes: new bytes32[](1),
            answers: new int256[](1),
            timestamps: new uint256[](1),
            proofs: new bytes[](1)
        });

        PerpDexLib.OpenPositionData memory data = PerpDexLib.OpenPositionData({
            tokenType: PerpDexLib.TokenType.Klay,
            marginAmount: 2_000_000,
            leverage: 10,
            long: true,
            trader: user,
            priceData: bisonAIData,
            tpPrice: 0,
            slPrice: 0,
            expectedPrice: 30_000_000, // initialPrice 28_608_331
            userSignedData: hex"1234"
        });

        vm.mockCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), abi.encode());
        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferFromAndCheckBalance.selector), abi.encode()
        );
        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.submitAndGetLatestPrice.selector), abi.encode(30_000_000)
        );

        uint256 positionId = perpDexProxy.nextPositionId();
        uint256[] memory openPositionIds = perpDexProxy.getOpenPositionIds();
        vm.prank(singleOpenAdmin);
        perpDexProxy.openPosition(data);

        PerpDexLib.Position memory newP = perpDexProxy.getPosition(positionId);
        // emit log_uint(p.test);

        assertEq(newP.positionId, positionId, "positionId new");
        assertEq(uint256(newP.tokenType), 1, "tokenType new");
        assertEq(newP.margin, 1_986_000, "margin new");
        assertEq(newP.size, 19_860_000, "size new");
        assertEq(newP.openFee, 14_000, "fee new");
        assertEq(newP.initialPrice, 30_000_000, "initialPrice new");
        assertEq(newP.isLong, true, "isLong new");
        assertEq(newP.openPositionIndex, openPositionIds.length, "openPositionIndex new");
        assertEq(newP.finalPrice, 0, "finalPrice new");
        assertEq(uint256(newP.positionStatus), 8, "positionStatus new");
        assertEq(newP.finalPrice, 0, "finalPrice new");
        assertEq(newP.limitOrderPrice, 0, "limitOrderPrice new"); // opened after upgrade
        assertEq(
            newP.limitOrderIndex,
            115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457_584_007_913_129_639_935,
            "limitOrderIndex"
        );

        assertEq(newP.statusTime.requestOpenTime, 0, "requestOpenTime new");
        assertEq(newP.statusTime.openTime, block.timestamp, "openTime new");
        assertEq(newP.statusTime.closeTime, 0, "closeTime new");
        assertEq(newP.statusTime.limitOpenTime, 0, "limitOpenTime new");
        assertEq(newP.statusTime.limitCloseTime, 0, "limitCloseTime new");
        assertEq(newP.statusTime.liquidatedTime, 0, "liquidatedTime new");
        assertEq(uint256(newP.pnl), 0, "pnl new");
        assertEq(newP.liquidationPrice, 0, "liquidationPrice p new");

        assertEq(newP.tpPrice, 0, "tpPrice new");
        assertEq(newP.slPrice, 0, "slPrice new");
        assertEq(newP.marginUpdatedTime, 0, "marginUpdatedTime new");
        assertEq(newP.accFundingFeePerSize, 0, "accFundingFeePerSize new");
        assertEq(newP.fundingFee, 0, "fundingFee new");
        assertEq(newP.closeFee, 0, "closeFee new");

        PerpDexLib.Position memory oldP = perpDexProxy.getPosition(3390);

        assertEq(oldP.positionId, 3390, "positionId");
        assertEq(uint256(oldP.tokenType), 1, "tokenType");
        assertEq(oldP.margin, 1_995_800 + 1_986_000, "margin");
        assertEq(oldP.size, 5_987_400 + 19_860_000, "size");
        assertEq(oldP.openFee, 4200 + 14_000, "fee");

        uint256 numerator = 28_608_331 * 30_000_000 * (5_987_400 + 19_860_000);
        uint256 denominator = 30_000_000 * 5_987_400 + 28_608_331 * 19_860_000;
        assertEq(oldP.initialPrice, numerator / denominator, "initialPrice");
        assertEq(oldP.isLong, true, "isLong");
        assertEq(oldP.openPositionIndex, openPositionIds.length - 1, "openPositionIndex");
        assertEq(oldP.finalPrice, 0, "finalPrice");
        assertEq(uint256(oldP.positionStatus), 1, "positionStatus");
        assertEq(oldP.finalPrice, 0, "finalPrice");
        assertEq(oldP.limitOrderPrice, 0, "limitOrderPrice");
        assertEq(
            oldP.limitOrderIndex,
            115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457_584_007_913_129_639_935,
            "limitOrderIndex"
        );

        assertEq(oldP.statusTime.requestOpenTime, 0, "requestOpenTime");
        assertEq(oldP.statusTime.openTime, block.timestamp, "openTime");
        assertEq(oldP.statusTime.closeTime, 0, "closeTime");
        assertEq(oldP.statusTime.limitOpenTime, 0, "limitOpenTime");
        assertEq(oldP.statusTime.limitCloseTime, 0, "limitCloseTime");
        assertEq(oldP.statusTime.liquidatedTime, 0, "liquidatedTime");
        assertEq(uint256(oldP.pnl), 0, "pnl");
        assertEq(oldP.liquidationPrice, 19_085_580, "liquidationPrice p"); // opened before upgrade

        assertEq(oldP.tpPrice, 0, "tpPrice");
        assertEq(oldP.slPrice, 0, "slPrice");
        assertEq(oldP.marginUpdatedTime, 0, "marginUpdatedTime");
        assertEq(oldP.accFundingFeePerSize, 0, "accFundingFeePerSize");
        assertEq(oldP.fundingFee, 0, "fundingFee");
        assertEq(oldP.closeFee, 0, "closeFee");
    }

    function test_funding_fee_update_for_existing_position() public {
        vm.selectFork(forkId2);
        vm.startPrank(owner);
        PerpDex newPerpDexImpl = new PerpDex();
        perpDexProxy.upgradeToAndCall(address(newPerpDexImpl), bytes(""));

        perpDexProxy.addInitialTokenTotalSizes(1);
        perpDexProxy.changeMaxTokenTotalSizes();
        migrateAddrs();
        vm.stopPrank();

        (uint256 lastUpdatedTime, int256 lastAppliedRate, int256 accFeePerSize) =
            perpDexProxy.fundingFeeTokenStates(PerpDexLib.TokenType.Klay);

        assertEq(lastUpdatedTime, 0, "lastUpdatedTime");
        assertEq(lastAppliedRate, 0, "lastAppliedRate");
        assertEq(accFeePerSize, 0, "accFeePerSize");

        // 1️⃣ before updateFundingFeeState call
        vm.warp(block.timestamp + 3600);
        vm.roll(block.number + 3600);
        (lastUpdatedTime, lastAppliedRate, accFeePerSize) = perpDexProxy.fundingFeeTokenStates(PerpDexLib.TokenType.Klay);
        assertEq(lastUpdatedTime, 0, "lastUpdatedTime 2");
        assertEq(lastAppliedRate, 0, "lastAppliedRate 2");
        assertEq(accFeePerSize, 0, "accFeePerSize 2");

        // 2️⃣ after updateFundingFeeState call
        vm.prank(owner);
        perpDexProxy.updateFundingFeeStates();
        (lastUpdatedTime, lastAppliedRate, accFeePerSize) = perpDexProxy.fundingFeeTokenStates(PerpDexLib.TokenType.Klay);
        (,, uint256 long, uint256 short) = perpDexProxy.tokenTotalSizes(uint256(PerpDexLib.TokenType.Klay));
        int256 fundingRate = (1e20 / 1e7) * 875 * (int256(long) - int256(short)) / (int256(long) + int256(short));
        assertEq(lastUpdatedTime, block.timestamp, "lastUpdatedTime 3");
        assertEq(lastAppliedRate, fundingRate, "lastAppliedRate 3");
        assertEq(accFeePerSize, 0, "accFeePerSize 3");

        vm.warp(block.timestamp + 3600);
        vm.roll(block.number + 3600);
        closePositionDefault(3390, 28_608_331);
        PerpDexLib.Position memory p = perpDexProxy.getPosition(3390);

        assertEq(p.accFundingFeePerSize, 0);
        assertEq(p.fundingFee, fundingRate * int256(p.size) / 1e20);
    }

    function test_liquidatePositions_for_existing_position() public {
        vm.selectFork(forkId2);

        vm.startPrank(owner);
        PerpDex newPerpDexImpl = new PerpDex();
        perpDexProxy.upgradeToAndCall(address(newPerpDexImpl), bytes(""));

        perpDexProxy.addInitialTokenTotalSizes(1);
        perpDexProxy.changeMaxTokenTotalSizes();
        migrateAddrs();
        vm.stopPrank();

        vm.warp(block.timestamp + 3600);
        vm.roll(block.number + 3600);

        uint256 positionId = 3390;
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);
        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);
        uint256 closingPrice = 19_085_580; // original liquidationPrice

        vm.startPrank(liqAdmin);
        mockGetPreviousPriceAndTime(
            [closingPrice, closingPrice, closingPrice, closingPrice, closingPrice, closingPrice],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );

        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());
        vm.mockCall(address(lpContract), abi.encodeWithSelector(lpContract.giveProfit.selector), abi.encode());
        vm.mockCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.decreaseTotalPositionSize.selector), abi.encode());
        // vm.mockCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.cleanUpPosition.selector), abi.encode());

        uint256[] memory liquidatablePositions = new uint256[](1);
        liquidatablePositions[0] = positionId;
        uint64[] memory roundIds = new uint64[](1);

        perpDexProxy.liquidatePositions(liquidatablePositions, roundIds, bisonAIData);
        PerpDexLib.Position memory pAfter = perpDexProxy.getPosition(positionId);

        assertEq(uint256(pAfter.positionStatus), uint256(PerpDexLib.PositionStatus.Liquidated));
        assertEq(pAfter.initialPrice, 28_608_331); // from db
        assertEq(pAfter.finalPrice, closingPrice);
        assertEq(pAfter.statusTime.liquidatedTime, block.timestamp);

        vm.stopPrank();
    }
}
