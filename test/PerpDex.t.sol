// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./PerpDexTestBase.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {console} from "forge-std/Test.sol";

using SafeERC20 for IERC20;

contract PerpDexTest is PerpDexTestBase {
    function test_adminModifier() public {
        // Get all admin lists
        address[] memory liqAdmins = this.getAdminsByRole(PerpDexAuthLib.AdminType.Liquidation);
        address[] memory limitAdmins = this.getAdminsByRole(PerpDexAuthLib.AdminType.LimitOrder);
        address[] memory singleOpenAdmins = this.getAdminsByRole(PerpDexAuthLib.AdminType.SingleOpen);
        address[] memory closeAdmins = this.getAdminsByRole(PerpDexAuthLib.AdminType.Close);
        address[] memory tpslAdmins = this.getAdminsByRole(PerpDexAuthLib.AdminType.Tpsl);
        address nonAdmin = makeAddr("nonAdmin");

        // Test successful cases - each admin can access their designated function
        vm.prank(liqAdmins[0]);
        this.checkLiquidationAdminModifier();

        vm.prank(limitAdmins[0]);
        this.checkLimitOrderAdminModifier();

        vm.prank(singleOpenAdmins[0]);
        this.checkSingleOpenAdminModifier();

        vm.prank(closeAdmins[0]);
        this.checkCloseAdminModifier();

        vm.prank(tpslAdmins[0]);
        this.checkTpslAdminModifier();

        // Test LimitOrLiquidation modifier with both types of admins
        vm.prank(liqAdmins[0]);
        this.checkLimitOrLiquidationAdminModifier();

        vm.prank(limitAdmins[0]);
        this.checkLimitOrLiquidationAdminModifier();

        // Test that admins cannot access other admin functions
        vm.prank(liqAdmins[0]);
        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.checkLimitOrderAdminModifier();

        vm.prank(limitAdmins[0]);
        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.checkLiquidationAdminModifier();

        vm.prank(singleOpenAdmins[0]);
        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.checkCloseAdminModifier();

        vm.prank(closeAdmins[0]);
        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.checkSingleOpenAdminModifier();

        vm.prank(tpslAdmins[0]);
        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.checkLimitOrderAdminModifier();

        // Test that non-admin cannot access any admin functions
        vm.startPrank(nonAdmin);

        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.checkSingleOpenAdminModifier();

        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.checkCloseAdminModifier();

        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.checkLimitOrderAdminModifier();

        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.checkLiquidationAdminModifier();

        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.checkLimitOrLiquidationAdminModifier();

        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.checkTpslAdminModifier();
        vm.stopPrank();
    }

    function test_checkZeroAddress() public {
        vm.expectRevert(abi.encodeWithSelector(ZeroAddress.selector));
        checkZeroAddress(address(0));

        checkZeroAddress(address(1));
        emit log_string("success!!");
    }

    function test_addInitialTokenTotalSizes() public {
        vm.startPrank(owner());
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib._addInitialTokenTotalSizes.selector));
        this.addInitialTokenTotalSizes(tokenCount);
        vm.stopPrank();
    }

    function test_changeMaxTokenTotalSizes() public {
        vm.startPrank(owner());
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib._changeMaxTokenTotalSizes.selector));
        this.changeMaxTokenTotalSizes();
        vm.stopPrank();
    }

    function test_setAdmin() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, user));
        this.setAdmin(address(1000));

        vm.startPrank(owner());

        // Test cannot set zero address as admin
        vm.expectRevert(abi.encodeWithSelector(ZeroAddress.selector));
        this.setAdmin(address(0));

        // Test valid admin set
        address newAdmin = address(1000);
        this.setAdmin(newAdmin);
        assertEq(admin, newAdmin);

        vm.stopPrank();
    }

    function test_setAdmins() public {
        vm.startPrank(owner());

        address[] memory newAdmins = new address[](5);
        newAdmins[0] = address(1000);
        newAdmins[1] = address(1001);
        newAdmins[2] = address(1002);
        newAdmins[3] = address(1003);
        newAdmins[4] = address(1004);
        this.setAdmins(PerpDexAuthLib.AdminType.Liquidation, newAdmins);
        address[] memory admins = this.getAdminsByRole(PerpDexAuthLib.AdminType.Liquidation);
        for (uint256 i = 0; i < 5; i++) {
            assertEq(admins[i], newAdmins[i]);
        }

        this.setAdmins(PerpDexAuthLib.AdminType.LimitOrder, newAdmins);
        address[] memory admins2 = this.getAdminsByRole(PerpDexAuthLib.AdminType.LimitOrder);
        for (uint256 i = 0; i < 5; i++) {
            assertEq(admins2[i], newAdmins[i]);
        }

        this.setAdmins(PerpDexAuthLib.AdminType.SingleOpen, newAdmins);
        address[] memory admins3 = this.getAdminsByRole(PerpDexAuthLib.AdminType.SingleOpen);
        for (uint256 i = 0; i < 5; i++) {
            assertEq(admins3[i], newAdmins[i]);
        }

        this.setAdmins(PerpDexAuthLib.AdminType.Close, newAdmins);
        address[] memory admins4 = this.getAdminsByRole(PerpDexAuthLib.AdminType.Close);
        for (uint256 i = 0; i < 5; i++) {
            assertEq(admins4[i], newAdmins[i]);
        }

        this.setAdmins(PerpDexAuthLib.AdminType.Tpsl, newAdmins);
        address[] memory admins5 = this.getAdminsByRole(PerpDexAuthLib.AdminType.Tpsl);
        for (uint256 i = 0; i < 5; i++) {
            assertEq(admins5[i], newAdmins[i]);
        }

        vm.stopPrank();
    }

    function test_setOracles() public {
        vm.startPrank(owner());

        address bisonAIRouterAddr = address(1000);
        address bisonAISubmissionProxyAddr = address(1001);
        address pythAddr = address(1002);

        // Test setting valid oracle addresses
        this.setOracles(bisonAIRouterAddr, bisonAISubmissionProxyAddr, pythAddr);

        // Test zero address check for bisonAIRouter
        vm.expectRevert(abi.encodeWithSelector(ZeroAddress.selector));
        this.setOracles(address(0), bisonAISubmissionProxyAddr, pythAddr);

        // Test zero address check for bisonAISubmissionProxy
        vm.expectRevert(abi.encodeWithSelector(ZeroAddress.selector));
        this.setOracles(bisonAIRouterAddr, address(0), pythAddr);

        // Test zero address check for pyth
        vm.expectRevert(abi.encodeWithSelector(ZeroAddress.selector));
        this.setOracles(bisonAIRouterAddr, bisonAISubmissionProxyAddr, address(0));

        vm.stopPrank();
    }

    function test_setupAddr() public {
        vm.startPrank(owner());

        // Test zero address for USDT
        vm.expectRevert(abi.encodeWithSelector(ZeroAddress.selector));
        this.setupAddr(address(0), address(2), address(3)); // 🚀

        // Test zero address for LP token
        vm.expectRevert(abi.encodeWithSelector(ZeroAddress.selector));
        this.setupAddr(address(1), address(0), address(3)); // 🚀

        // Test zero address for fee contract
        vm.expectRevert(abi.encodeWithSelector(ZeroAddress.selector));
        this.setupAddr(address(1), address(2), address(0)); // 🚀

        // Test valid addresses
        address usdt = address(1);
        address lp = address(2);
        address feeContract = address(3);

        vm.mockCall(usdt, abi.encodeWithSelector(IERC20.approve.selector, feeContract, type(uint256).max), abi.encode(true));
        vm.mockCall(usdt, abi.encodeWithSelector(IERC20Metadata.decimals.selector), abi.encode(6));

        this.setupAddr(usdt, lp, feeContract); // 🚀

        assertEq(address(externalContracts.usdt), usdt);
        assertEq(address(externalContracts.lp), lp);
        assertEq(address(externalContracts.feeContract), feeContract);

        vm.stopPrank();
    }

    function test_getPosition() public {}
    function test_getOpenPositionsIds() public {}
    function test_getLimitOrderIds() public {}
    function test_getPositionIdsForTrader() public {}
    function test_checkUserSignedData() public {}

    function test_getTraderOpenPositionIds() public {
        uint256 positionId1 = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 1_000_000, 0, 0);
        uint256 positionId2 = openPositionDefault(user, PerpDexLib.TokenType.Xrp, 2_000_000, 10, false, 1_000_000, 0, 0);

        PerpDexLib.TraderOpenPositionId[] memory Ids = this.getTraderOpenPositionIds(user);
        PerpDexLib.TraderOpenPositionId[] memory expectingIds = new PerpDexLib.TraderOpenPositionId[](tokenCount);
        expectingIds[uint256(PerpDexLib.TokenType.Btc)].longPositionId = positionId1;
        expectingIds[uint256(PerpDexLib.TokenType.Xrp)].shortPositionId = positionId2;
        for (uint256 i = 0; i < tokenCount; i++) {
            assertEq(Ids[i].longPositionId, expectingIds[i].longPositionId);
            assertEq(Ids[i].shortPositionId, expectingIds[i].shortPositionId);
        }
    }

    function test_openLimitOrder() public {
        uint256 traderNonceBefore = traderNonce[user];
        uint256 nextPositionIdBefore = nextPositionId;

        OpenPositionInput memory input = getOpenPositionInput(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 0, 0);

        string memory message = createOpenLimitOrderMessage(
            uint256(input.inputTokenType),
            input.marginAmount,
            input.leverage,
            input.isLong,
            190_000_000, // wantedPrice
            input.tpPrice,
            input.slPrice,
            traderNonceBefore // nonce
        );
        bytes memory userSignedData = signMessage(message, userPk);

        PerpDexLib.OpenLimitOrderData memory o = PerpDexLib.OpenLimitOrderData({
            tokenType: input.inputTokenType,
            marginAmount: input.marginAmount,
            leverage: input.leverage,
            long: input.isLong,
            trader: input.traderAddr,
            wantedPrice: 190_000_000,
            tpPrice: input.tpPrice,
            slPrice: input.slPrice,
            userSignedData: userSignedData
        });

        vm.expectCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), 1);

        vm.mockCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib._openLimitOrder.selector), abi.encode());
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib._openLimitOrder.selector), 1);

        vm.prank(singleOpenAdmin);
        this.openLimitOrder(o); // 🚀

        assertEq(traderNonce[input.traderAddr], traderNonceBefore + 1, "traderNonce");
        assertEq(nextPositionId, nextPositionIdBefore + 1);
    }

    function test_closeLimitOrder() public {
        uint256 traderNonceBefore = traderNonce[user];
        uint256 orderId = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);

        string memory message = createCloseLimitOrderMessage(orderId, traderNonceBefore);
        bytes memory userSignedData = signMessage(message, userPk);

        vm.expectCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), 1);

        vm.mockCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib._closeLimitOrder.selector), abi.encode());
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib._closeLimitOrder.selector), 1);

        vm.prank(closeAdmin);
        this.closeLimitOrder(orderId, userSignedData); // 🚀
    }

    /// 👇 openPosition
    function test_openPosition_ok() public {
        uint256 traderNonceBefore = traderNonce[user];
        uint256 nextPositionIdBefore = nextPositionId;

        OpenPositionInput memory input = getOpenPositionInput(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_001, 199_999_999);
        string memory message = createOpenPositionMessage(
            uint256(input.inputTokenType), // tokenType (BTC)
            input.marginAmount, // margin
            input.leverage, // leverage
            input.isLong, // isLong
            input.tpPrice, // tpPrice
            input.slPrice, // slPrice
            200_000_000, // expectedPrice
            traderNonce[user] // nonce
        );
        bytes memory userSignedData = signMessage(message, userPk);

        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(1);
        PerpDexLib.OpenPositionData memory data = PerpDexLib.OpenPositionData({
            tokenType: input.inputTokenType,
            marginAmount: input.marginAmount,
            leverage: input.leverage,
            long: input.isLong,
            trader: input.traderAddr,
            priceData: bisonAIData,
            tpPrice: input.tpPrice,
            slPrice: input.slPrice,
            expectedPrice: 200_000_000,
            userSignedData: userSignedData
        });

        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferFromAndCheckBalance.selector), abi.encode()
        );
        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);
        mockCurrentPrice(200_000_000);

        vm.expectCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), 2);
        vm.expectCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferFromAndCheckBalance.selector), 2);
        vm.expectCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.submitAndGetLatestPrice.selector), 2);
        vm.expectCall(
            address(externalContracts.feeContract),
            abi.encodeWithSelector(externalContracts.feeContract.payFee.selector, data.trader, 14_000),
            2
        );
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.mergePosition.selector), 0);
        // vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.updateTraderOpenPositionId.selector), 2); // updateTraderOpenPositionId is internal now
        uint256 openFee = data.marginAmount * data.leverage * defaultTotalFeePercent / defaultFeeDenominator;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.PositionOpened(
            1,
            user,
            data.tokenType,
            data.marginAmount - openFee,
            (data.marginAmount - openFee) * data.leverage,
            200_000_000,
            data.long,
            data.tpPrice,
            data.slPrice
        );

        vm.startPrank(singleOpenAdmin);
        this.openPosition(data); // 🚀

        assertEq(traderNonce[user], traderNonceBefore + 1);
        assertEq(nextPositionId, nextPositionIdBefore + 1);

        PerpDexLib.Position memory p = PerpDexLib.Position({
            positionId: 1,
            traderAddr: user,
            tokenType: PerpDexLib.TokenType.Btc,
            margin: data.marginAmount - openFee,
            size: (data.marginAmount - openFee) * data.leverage,
            openFee: openFee,
            closeFee: 0,
            initialPrice: 200_000_000,
            isLong: true,
            openPositionIndex: 0,
            finalPrice: 0,
            positionStatus: PerpDexLib.PositionStatus.Open,
            limitOrderPrice: 0,
            limitOrderIndex: type(uint256).max,
            statusTime: PerpDexLib.StatusTime({
                requestOpenTime: 0,
                openTime: block.timestamp,
                closeTime: 0,
                limitOpenTime: 0,
                limitCloseTime: 0,
                liquidatedTime: 0
            }),
            pnl: 0,
            liquidationPrice: 0,
            tpPrice: 200_000_001,
            slPrice: 199_999_999,
            marginUpdatedTime: 0,
            accFundingFeePerSize: 0,
            fundingFee: 0,
            tpslUpdatedTime: block.timestamp
        });
        assertPosition(positions[1], p);

        assertEq(traderPositionIds[user].length, 1);
        assertEq(traderPositionIds[user][0], 1);
        assertEq(openPositionIds.length, 1);
        assertEq(openPositionIds[0], 1);
        assertEq(traderOpenPositionIds[user][uint16(p.tokenType)].longPositionId, 1);
        assertEq(traderOpenPositionIds[user][uint16(p.tokenType)].shortPositionId, 0);

        data.tokenType = PerpDexLib.TokenType.Eth;
        data.slPrice = 300;
        data.tpPrice = 2_000_000_000;
        message = createOpenPositionMessage(
            uint256(data.tokenType), // tokenType (ETH)
            data.marginAmount, // margin
            data.leverage, // leverage
            data.long, // isLong
            data.tpPrice, // slPrice
            data.slPrice, // tpPrice
            data.expectedPrice, // expectedPrice
            traderNonce[user] // nonce
        );
        userSignedData = signMessage(message, userPk);
        data.userSignedData = userSignedData;
        this.openPosition(data); // 🚀

        assertEq(traderNonce[user], 2);
        assertEq(nextPositionId, 3);

        PerpDexLib.Position memory p2 = PerpDexLib.Position({
            positionId: 2,
            traderAddr: user,
            tokenType: PerpDexLib.TokenType.Eth,
            margin: data.marginAmount - openFee,
            size: (data.marginAmount - openFee) * data.leverage,
            openFee: openFee,
            closeFee: 0,
            initialPrice: 200_000_000,
            isLong: true,
            openPositionIndex: 1,
            finalPrice: 0,
            positionStatus: PerpDexLib.PositionStatus.Open,
            limitOrderPrice: 0,
            limitOrderIndex: type(uint256).max,
            statusTime: PerpDexLib.StatusTime({
                requestOpenTime: 0,
                openTime: block.timestamp,
                closeTime: 0,
                limitOpenTime: 0,
                limitCloseTime: 0,
                liquidatedTime: 0
            }),
            pnl: 0,
            liquidationPrice: 0,
            tpPrice: 2_000_000_000,
            slPrice: 300,
            marginUpdatedTime: 0,
            accFundingFeePerSize: 0,
            fundingFee: 0,
            tpslUpdatedTime: block.timestamp
        });

        assertPosition(positions[2], p2);

        assertEq(traderPositionIds[user].length, 2);
        assertEq(traderPositionIds[user][0], 1);
        assertEq(traderPositionIds[user][1], 2);
        assertEq(openPositionIds.length, 2);
        assertEq(openPositionIds[0], 1);
        assertEq(openPositionIds[1], 2);
        assertEq(traderOpenPositionIds[user][uint16(p2.tokenType)].longPositionId, 2);
        assertEq(traderOpenPositionIds[user][uint16(p2.tokenType)].shortPositionId, 0);
    }

    function test_openPosition_revertCases_1() public {
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(1);
        PerpDexLib.OpenPositionData memory data = PerpDexLib.OpenPositionData({
            tokenType: PerpDexLib.TokenType.Btc,
            marginAmount: 2_000_000,
            leverage: 10,
            long: true,
            trader: user,
            priceData: bisonAIData,
            tpPrice: 0,
            slPrice: 0,
            expectedPrice: 100,
            userSignedData: hex"1234"
        });

        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.openPosition(data);

        vm.expectCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), 1);
        vm.startPrank(singleOpenAdmin);
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, 2));
        this.openPosition(data);
    }

    function test_openPosition_revertSlippage() public {
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(1);
        PerpDexLib.OpenPositionData memory data = PerpDexLib.OpenPositionData({
            tokenType: PerpDexLib.TokenType.Btc,
            marginAmount: 2_000_000,
            leverage: 10,
            long: true,
            trader: user,
            priceData: bisonAIData,
            tpPrice: 0,
            slPrice: 0,
            expectedPrice: 100,
            userSignedData: hex"1234"
        });

        vm.mockCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), abi.encode());
        vm.expectCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), 3);
        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferFromAndCheckBalance.selector), abi.encode()
        );

        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);
        mockCurrentPrice(98);

        vm.startPrank(singleOpenAdmin);
        vm.expectRevert("Slippage is more than 1%");
        this.openPosition(data);

        mockCurrentPrice(102);
        vm.expectRevert("Slippage is more than 1%");
        this.openPosition(data);

        mockCurrentPrice(101);
        this.openPosition(data);
    }

    function test_openPosition_checkUser() public {
        uint256 wrongNonce = 100;
        string memory message = createOpenPositionMessage(
            0, // tokenType (BTC)
            100, // margin
            3, // leverage
            true, // isLong
            0, // tpPrice
            0, // slPrice
            100, // expectedPrice
            wrongNonce
        );
        bytes memory userSignedData = signMessage(message, userPk);

        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(1);

        vm.expectCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), 1);

        vm.startPrank(singleOpenAdmin);
        vm.expectRevert("Invalid signed data");
        PerpDexLib.OpenPositionData memory data = PerpDexLib.OpenPositionData({
            tokenType: PerpDexLib.TokenType.Btc,
            marginAmount: 100,
            leverage: 3,
            long: true,
            trader: user,
            priceData: bisonAIData,
            tpPrice: 0,
            slPrice: 0,
            expectedPrice: 100,
            userSignedData: userSignedData
        });
        this.openPosition(data);
    }

    /// 👇 closePosition
    function test_closePosition_external() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 1_000_000, 0, 0);
        uint256 traderNonceBefore = traderNonce[user];

        string memory message = createClosePositionMessage(positionId, traderNonce[user]);
        uint256 wrongNonce = 100;
        string memory wrongMessage = createClosePositionMessage(positionId, wrongNonce);
        bytes memory wrongUserSignedData = signMessage(wrongMessage, userPk);

        vm.clearMockedCalls(); // clear checkUser mock

        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(1);
        uint256 closingPrice = 1_000_000;
        mockCurrentPrice(closingPrice);

        vm.prank(singleOpenAdmin);
        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.closePosition(positionId, bisonAIData, wrongUserSignedData);

        vm.expectCall(
            address(PerpDexAuthLib),
            abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector, message, bytes(message).length, wrongUserSignedData, user),
            1
        );

        vm.startPrank(closeAdmin);
        vm.expectRevert("Invalid signed data");
        this.closePosition(positionId, bisonAIData, wrongUserSignedData); // 🚀

        // ok case
        bytes memory userSignedData = signMessage(message, userPk);
        vm.expectCall(
            address(PerpDexAuthLib),
            abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector, message, bytes(message).length, userSignedData, user),
            1
        );

        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(
                PerpDexPricesLib.submitAndGetLatestPrice.selector,
                bisonAIData,
                PerpDexLib.TokenType.Btc,
                bisonAISubmissionProxy,
                bisonAIRouter,
                pyth
            ),
            1
        );

        vm.mockCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib._closePosition.selector), abi.encode());
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib._closePosition.selector), 1);
        this.closePosition(positionId, bisonAIData, userSignedData); // 🚀

        assertEq(traderNonce[user], traderNonceBefore + 1);
    }

    function test__closePosition_ok() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 1_000_000, 0, 0);
        PerpDexLib.Position memory p = positions[positionId];

        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);
        uint256 expectingFee = p.size * defaultTotalFeePercent / defaultFeeDenominator;

        uint256 closingPrice = 1_000_000; // Price unchanged => normal lossPartial case
        mockCurrentPrice(closingPrice);
        vm.expectCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector, p.traderAddr, expectingFee), 1);

        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector, p.traderAddr, p.margin - expectingFee),
            1
        );
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector, address(externalContracts.lp), 0),
            1
        );

        vm.expectEmit(true, true, true, true);
        emit PositionClosed(positionId, p.traderAddr, p.tokenType, p.margin, p.size, p.initialPrice, p.isLong, closingPrice, p.fundingFee);

        vm.prank(closeAdmin);
        PerpDexLib._closePosition(
            positions,
            positionId,
            fundingFeeTokenStates[p.tokenType],
            fundingFeeGlobalState,
            traderOpenPositionIds,
            tokenTotalSizes,
            openPositionIds,
            closingPrice,
            externalContracts
        ); // 🚀

        p.closeFee = expectingFee;
        p.positionStatus = PerpDexLib.PositionStatus.Closed;
        p.statusTime.closeTime = block.timestamp;
        p.finalPrice = closingPrice;
        p.openPositionIndex = type(uint256).max;
        assertPosition(positions[positionId], p);

        assertEq(fundingFeeTokenStates[p.tokenType].lastUpdatedTime, block.timestamp); // check if updateFundingFeeState is called
        assertEq(tokenTotalSizes[uint256(p.tokenType)].currentLong, 0); // check if decreaseTotalPositionSize is called

        (uint256 long, uint256 short) = this.getTraderOpenPositionId(p.traderAddr, uint16(p.tokenType)); // check if cleanUpPosition is called
        assertEq(long, 0);
        assertEq(short, 0);
    }

    function test__closePosition_profit() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 1_000_000, 0, 0);
        PerpDexLib.Position memory p = positions[positionId];

        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);

        uint256 closingPrice = 1_500_000; // Price increased
        mockCurrentPrice(closingPrice);

        uint256 profit = ((p.size * closingPrice) / p.initialPrice) - p.size;
        uint256 fee = (p.size + profit) * defaultTotalFeePercent / defaultFeeDenominator;
        vm.mockCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector), abi.encode());
        vm.expectCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector, p.traderAddr, fee), 1);

        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector, p.traderAddr, p.margin - fee),
            1
        );

        vm.mockCall(address(externalContracts.lp), abi.encodeWithSelector(ILP.giveProfit.selector), abi.encode());
        vm.expectCall(address(externalContracts.lp), abi.encodeWithSelector(ILP.giveProfit.selector, p.traderAddr, profit), 1);

        vm.expectEmit(true, true, true, true);
        emit PositionClosed(positionId, p.traderAddr, p.tokenType, p.margin, p.size, p.initialPrice, p.isLong, closingPrice, p.fundingFee);

        vm.prank(closeAdmin);
        PerpDexLib._closePosition(
            positions,
            positionId,
            fundingFeeTokenStates[p.tokenType],
            fundingFeeGlobalState,
            traderOpenPositionIds,
            tokenTotalSizes,
            openPositionIds,
            closingPrice,
            externalContracts
        ); // 🚀

        p.pnl = int256(profit);
        p.closeFee = fee;
        p.positionStatus = PerpDexLib.PositionStatus.Closed;
        p.statusTime.closeTime = block.timestamp;
        p.finalPrice = closingPrice;
        p.openPositionIndex = type(uint256).max;
        assertPosition(positions[positionId], p);

        assertEq(fundingFeeTokenStates[p.tokenType].lastUpdatedTime, block.timestamp); // check if updateFundingFeeState is called
        assertEq(tokenTotalSizes[uint256(p.tokenType)].currentLong, 0); // check if decreaseTotalPositionSize is called

        (uint256 long, uint256 short) = this.getTraderOpenPositionId(p.traderAddr, uint16(p.tokenType)); // check if cleanUpPosition is called
        assertEq(long, 0);
        assertEq(short, 0);
    }

    function test__closePosition_profit_maxProfit_1() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 3, true, 1_000_000, 0, 0);
        PerpDexLib.Position memory p = positions[positionId];

        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);

        uint256 closingPrice = 2_000_000; // 🔥 high price
        mockCurrentPrice(closingPrice);

        uint256 profit = p.size; // 🔥
        uint256 fee = (p.size + profit) * defaultTotalFeePercent / defaultFeeDenominator;
        vm.expectCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector, p.traderAddr, fee), 1);

        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector, p.traderAddr, p.margin - fee),
            1
        );

        vm.mockCall(address(externalContracts.lp), abi.encodeWithSelector(ILP.giveProfit.selector), abi.encode());
        vm.expectCall(address(externalContracts.lp), abi.encodeWithSelector(ILP.giveProfit.selector, p.traderAddr, profit), 1);

        vm.expectEmit(true, true, true, true);
        emit PositionClosed(positionId, p.traderAddr, p.tokenType, p.margin, p.size, p.initialPrice, p.isLong, closingPrice, p.fundingFee);

        vm.prank(closeAdmin);
        PerpDexLib._closePosition(
            positions,
            positionId,
            fundingFeeTokenStates[p.tokenType],
            fundingFeeGlobalState,
            traderOpenPositionIds,
            tokenTotalSizes,
            openPositionIds,
            closingPrice,
            externalContracts
        ); // 🚀

        p.pnl = int256(profit);
        p.closeFee = fee;
        p.positionStatus = PerpDexLib.PositionStatus.Closed;
        p.statusTime.closeTime = block.timestamp;
        p.finalPrice = closingPrice;
        p.openPositionIndex = type(uint256).max;
        assertPosition(positions[positionId], p);

        assertEq(fundingFeeTokenStates[p.tokenType].lastUpdatedTime, block.timestamp); // check if updateFundingFeeState is called
        assertEq(tokenTotalSizes[uint256(p.tokenType)].currentLong, 0); // check if decreaseTotalPositionSize is called

        (uint256 long, uint256 short) = this.getTraderOpenPositionId(p.traderAddr, uint16(p.tokenType)); // check if cleanUpPosition is called
        assertEq(long, 0);
        assertEq(short, 0);
    }

    function test__closePosition_profit_maxProfit_2() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 100, true, 1_000_000, 0, 0);
        PerpDexLib.Position memory p = positions[positionId];

        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);

        uint256 closingPrice = 120_000_000; // 🔥 high price
        mockCurrentPrice(closingPrice);

        uint256 profit = p.margin * 5; // 🔥
        uint256 fee = (p.size + profit) * defaultTotalFeePercent / defaultFeeDenominator;
        vm.mockCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector), abi.encode());
        vm.expectCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector, p.traderAddr, fee), 1);

        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector, p.traderAddr, p.margin - fee),
            1
        );

        vm.mockCall(address(externalContracts.lp), abi.encodeWithSelector(ILP.giveProfit.selector), abi.encode());
        vm.expectCall(address(externalContracts.lp), abi.encodeWithSelector(ILP.giveProfit.selector, p.traderAddr, profit), 1);

        vm.expectEmit(true, true, true, true);
        emit PositionClosed(positionId, p.traderAddr, p.tokenType, p.margin, p.size, p.initialPrice, p.isLong, closingPrice, p.fundingFee);

        vm.prank(closeAdmin);
        PerpDexLib._closePosition(
            positions,
            positionId,
            fundingFeeTokenStates[p.tokenType],
            fundingFeeGlobalState,
            traderOpenPositionIds,
            tokenTotalSizes,
            openPositionIds,
            closingPrice,
            externalContracts
        ); // 🚀

        p.pnl = int256(profit);
        p.closeFee = fee;
        p.positionStatus = PerpDexLib.PositionStatus.Closed;
        p.statusTime.closeTime = block.timestamp;
        p.finalPrice = closingPrice;
        p.openPositionIndex = type(uint256).max;
        assertPosition(positions[positionId], p);

        assertEq(fundingFeeTokenStates[p.tokenType].lastUpdatedTime, block.timestamp); // check if updateFundingFeeState is called
        assertEq(tokenTotalSizes[uint256(p.tokenType)].currentLong, 0); // check if decreaseTotalPositionSize is called

        (uint256 long, uint256 short) = this.getTraderOpenPositionId(p.traderAddr, uint16(p.tokenType)); // check if cleanUpPosition is called
        assertEq(long, 0);
        assertEq(short, 0);
    }

    function test__closePosition_liquidate() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 10_000_000_000_000_000, 0, 0);
        PerpDexLib.Position memory p = positions[positionId];

        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);

        uint256 closingPrice = 1; // 🔥 Price decreased below liquidation price
        int256 pnl = int256((p.size * closingPrice) / p.initialPrice) - int256(p.size);
        uint256 loss = Math.min(p.margin, uint256(-pnl));

        uint256 fee = (p.size - p.margin) * defaultTotalFeePercent / defaultFeeDenominator;
        mockCurrentPrice(closingPrice);
        vm.mockCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector), abi.encode());
        vm.expectCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector, p.traderAddr, fee), 1);

        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector, address(externalContracts.lp), p.margin - fee),
            1
        );

        vm.prank(closeAdmin);
        PerpDexLib._closePosition(
            positions,
            positionId,
            fundingFeeTokenStates[p.tokenType],
            fundingFeeGlobalState,
            traderOpenPositionIds,
            tokenTotalSizes,
            openPositionIds,
            closingPrice,
            externalContracts
        ); // 🚀

        p.pnl = -int256(loss - fee);
        p.closeFee = fee;
        p.positionStatus = PerpDexLib.PositionStatus.Liquidated;
        p.statusTime.liquidatedTime = block.timestamp;
        p.finalPrice = closingPrice;
        p.openPositionIndex = type(uint256).max;
        assertPosition(positions[positionId], p);

        assertEq(fundingFeeTokenStates[p.tokenType].lastUpdatedTime, block.timestamp); // check if updateFundingFeeState is called
        assertEq(tokenTotalSizes[uint256(p.tokenType)].currentLong, 0); // check if decreaseTotalPositionSize is called

        (uint256 long, uint256 short) = this.getTraderOpenPositionId(p.traderAddr, uint16(p.tokenType)); // check if cleanUpPosition is called
        assertEq(long, 0);
        assertEq(short, 0);
    }

    function test__closePosition_lossPartial() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 1_000_000, 0, 0);
        PerpDexLib.Position memory p = positions[positionId];

        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);

        uint256 closingPrice = 999_000; // 🔥 Price decreased little
        int256 pnl = int256((p.size * closingPrice) / p.initialPrice) - int256(p.size);
        uint256 loss = uint256(-pnl);
        uint256 fee = (p.size - loss) * defaultTotalFeePercent / defaultFeeDenominator;
        mockCurrentPrice(closingPrice);
        vm.mockCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector), abi.encode());
        vm.expectCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector, p.traderAddr, fee), 1);

        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector, p.traderAddr, p.margin - loss - fee),
            1
        );
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector, address(externalContracts.lp), loss),
            1
        );
        vm.expectEmit(true, true, true, true);
        emit PositionClosed(positionId, p.traderAddr, p.tokenType, p.margin, p.size, p.initialPrice, p.isLong, closingPrice, p.fundingFee);

        vm.prank(closeAdmin);
        PerpDexLib._closePosition(
            positions,
            positionId,
            fundingFeeTokenStates[p.tokenType],
            fundingFeeGlobalState,
            traderOpenPositionIds,
            tokenTotalSizes,
            openPositionIds,
            closingPrice,
            externalContracts
        ); // 🚀

        p.pnl = -int256(loss);
        p.closeFee = fee;
        p.positionStatus = PerpDexLib.PositionStatus.Closed;
        p.statusTime.closeTime = block.timestamp;
        p.finalPrice = closingPrice;
        p.openPositionIndex = type(uint256).max;
        assertPosition(positions[positionId], p);

        assertEq(fundingFeeTokenStates[p.tokenType].lastUpdatedTime, block.timestamp); // check if updateFundingFeeState is called
        assertEq(tokenTotalSizes[uint256(p.tokenType)].currentLong, 0); // check if decreaseTotalPositionSize is called

        (uint256 long, uint256 short) = this.getTraderOpenPositionId(p.traderAddr, uint16(p.tokenType)); // check if cleanUpPosition is called
        assertEq(long, 0);
        assertEq(short, 0);
    }

    function test__closePosition_revert_zeroPrice() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 1_000_000, 0, 0);

        vm.expectRevert("Price is 0");
        PerpDexLib._closePosition(
            positions,
            positionId,
            fundingFeeTokenStates[PerpDexLib.TokenType.Btc],
            fundingFeeGlobalState,
            traderOpenPositionIds,
            tokenTotalSizes,
            openPositionIds,
            0,
            externalContracts
        );
    }

    function test__closePosition_revert_invalidPositionStatus() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 1_000_000, 0, 0);

        positions[positionId].positionStatus = PerpDexLib.PositionStatus.Initial;
        vm.expectRevert(abi.encodeWithSelector(InvalidPositionStatus.selector));
        PerpDexLib._closePosition(
            positions,
            positionId,
            fundingFeeTokenStates[PerpDexLib.TokenType.Btc],
            fundingFeeGlobalState,
            traderOpenPositionIds,
            tokenTotalSizes,
            openPositionIds,
            1_000_000,
            externalContracts
        );

        positions[positionId].positionStatus = PerpDexLib.PositionStatus.Closed;
        vm.expectRevert(abi.encodeWithSelector(InvalidPositionStatus.selector));
        PerpDexLib._closePosition(
            positions,
            positionId,
            fundingFeeTokenStates[PerpDexLib.TokenType.Btc],
            fundingFeeGlobalState,
            traderOpenPositionIds,
            tokenTotalSizes,
            openPositionIds,
            1_000_000,
            externalContracts
        );
    }

    function test__executeLimitOrder_ok() public {
        vm.warp(100);
        uint256 orderId = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        vm.warp(110); // order.statusTime.limitOpenTime < updatedAt
        PerpDexLib.Position memory order = positions[orderId];
        uint256 limitOrderIdLengthBefore = limitOrderIds.length;

        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.updateFundingFeeState.selector), 1);
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkPositionSizeAndIncrease.selector), 1);
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.findPositionToMerge.selector), 1);
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.updateTraderOpenPositionId.selector), 1);
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.mergePosition.selector), 0);
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.cleanUpLimitOrder.selector), 1);
        vm.expectCall(
            address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector, order.traderAddr, order.openFee), 1
        );

        vm.expectEmit(true, true, true, true);
        emit PerpDex.PositionOpened(
            orderId, order.traderAddr, order.tokenType, order.margin, order.size, 199_000_000, order.isLong, order.tpPrice, order.slPrice
        );
        vm.expectEmit(true, true, true, true);
        emit PerpDex.LimitOrderExecuted(orderId, order.traderAddr);

        vm.prank(limitAdmin);
        PerpDexBotLib._executeLimitOrder(
            positions,
            orderId,
            fundingFeeTokenStates,
            traderOpenPositionIds,
            fundingFeeGlobalState,
            tokenTotalSizes,
            openPositionIds,
            externalContracts,
            199_000_000,
            limitOrderIds
        ); // 🚀

        order.initialPrice = 199_000_000;
        order.openPositionIndex = openPositionIds.length - 1;
        order.positionStatus = PerpDexLib.PositionStatus.Open;
        order.statusTime.openTime = block.timestamp;

        order.accFundingFeePerSize = 0; // TODO add test case for accFundingFeePerSize update
        order.limitOrderIndex = type(uint256).max;

        assertPosition(positions[orderId], order);

        assertEq(openPositionIds[openPositionIds.length - 1], orderId); // check openPositionForLimitOrder called
        assertEq(limitOrderIds.length, limitOrderIdLengthBefore - 1); // check cleanupLimitOrder called
    }

    function test_executeLimitOrders_external_ok() public {
        vm.warp(100);
        uint256 positionId = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        vm.warp(110); // order.statusTime.limitOpenTime < updatedAt
        PerpDexLib.Position memory position = positions[positionId];
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);
        uint256[] memory ordersToExecute = new uint256[](1);
        ordersToExecute[0] = positionId;
        uint64[] memory roundIds = new uint64[](3);

        mockGetPreviousPriceAndTime(
            [uint256(199_000_000), uint256(100_000_000), uint256(0), uint256(50_000_000), uint256(50_000_000), uint256(50_000_000)],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector, roundIds, bisonAIData, bisonAIRouter, pyth),
            1
        );

        vm.mockCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector), abi.encode(true));
        vm.expectCall(
            address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector, position, 199_000_000), 1
        );

        vm.expectCall(address(PerpDexBotLib), abi.encodeWithSelector(PerpDexBotLib._executeLimitOrder.selector), 1);

        vm.prank(limitAdmin);
        this.executeLimitOrders(ordersToExecute, roundIds, bisonAIData); // 🚀
    }

    function test_executeLimitOrders_multi_ok() public {
        vm.warp(100);
        uint256 positionId1 = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        uint256 positionId2 = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        uint256 positionId3 = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        vm.warp(110); // order.statusTime.limitOpenTime < updatedAt
        PerpDexLib.Position memory position1 = this.getPosition(positionId1);
        PerpDexLib.Position memory position2 = this.getPosition(positionId2);
        PerpDexLib.Position memory position3 = this.getPosition(positionId3);

        uint256[] memory ordersToExecute = new uint256[](3);
        ordersToExecute[0] = positionId1;
        ordersToExecute[1] = positionId2;
        ordersToExecute[2] = positionId3;
        uint64[] memory roundIds = new uint64[](3);

        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);

        vm.expectEmit(true, true, true, true);
        emit PerpDex.LimitOrderExecuted(positionId1, position1.traderAddr);
        vm.expectEmit(true, true, true, true);
        emit PerpDex.LimitOrderExecuted(positionId2, position2.traderAddr);
        vm.expectEmit(true, true, true, true);
        emit PerpDex.LimitOrderExecuted(positionId3, position3.traderAddr);

        mockGetPreviousPriceAndTime(
            [uint256(200_000_000), uint256(100_000_000), uint256(0), uint256(50_000_000), uint256(50_000_000), uint256(50_000_000)],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector, roundIds, bisonAIData, bisonAIRouter, pyth),
            1
        );

        vm.mockCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector), abi.encode(true));
        vm.expectCall(
            address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector, position1, 200_000_000), 1
        );
        vm.expectCall(
            address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector, position2, 200_000_000), 1
        );

        position3.limitOrderIndex = 0; // 🔥 limitOrderIndex swaps with position1 when position1 is executed and cleanUpLimitOrder is called
        vm.expectCall(
            address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector, position3, 200_000_000), 1
        );

        vm.expectCall(address(PerpDexBotLib), abi.encodeWithSelector(PerpDexBotLib._executeLimitOrder.selector), 3);

        vm.prank(limitAdmin);
        this.executeLimitOrders(ordersToExecute, roundIds, bisonAIData); // 🚀
    }

    function test_executeLimitOrders_multi_skipOne() public {
        vm.warp(100);
        uint256 positionId1 = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        uint256 positionId2 = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        uint256 positionId3 = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        vm.warp(110); // order.statusTime.limitOpenTime < updatedAt
        PerpDexLib.Position memory position1 = this.getPosition(positionId1);
        PerpDexLib.Position memory position2 = this.getPosition(positionId2);
        PerpDexLib.Position memory position3 = this.getPosition(positionId3);

        uint256[] memory ordersToExecute = new uint256[](3);
        ordersToExecute[0] = positionId1;
        ordersToExecute[1] = positionId2;
        ordersToExecute[2] = positionId3;

        uint64[] memory roundIds = new uint64[](3);

        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);

        vm.expectEmit(true, true, true, true);
        emit PerpDex.LimitOrderExecuted(positionId1, position1.traderAddr);
        // 🔥
        // vm.expectEmit(true, true, true, true);
        // emit PerpDex.LimitOrderExecuted(positionId2, position2.traderAddr);
        vm.expectEmit(true, true, true, true);
        emit PerpDex.LimitOrderExecuted(positionId3, position3.traderAddr);

        mockGetPreviousPriceAndTime(
            [uint256(200_000_000), uint256(100_000_000), uint256(0), uint256(50_000_000), uint256(50_000_000), uint256(50_000_000)],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector, roundIds, bisonAIData, bisonAIRouter, pyth),
            1
        );

        vm.mockCall(
            address(PerpDexLib),
            abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector, position1, 200_000_000),
            abi.encode(true)
        );
        vm.mockCall(
            address(PerpDexLib),
            abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector, position2, 200_000_000),
            abi.encode(false) // 🔥
        );
        vm.mockCall(
            address(PerpDexLib),
            abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector, position3, 200_000_000),
            abi.encode(true)
        );

        vm.expectCall(
            address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector, position1, 200_000_000), 1
        );
        vm.expectCall(
            address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector, position2, 200_000_000), 1
        );
        position3.limitOrderIndex = 0; // 🔥 limitOrderIndex swaps with position1 when position1 is executed and cleanUpLimitOrder is called
        vm.expectCall(
            address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector, position3, 200_000_000), 1
        );

        vm.expectCall(address(PerpDexBotLib), abi.encodeWithSelector(PerpDexBotLib._executeLimitOrder.selector), 2);

        vm.prank(limitAdmin);
        this.executeLimitOrders(ordersToExecute, roundIds, bisonAIData); // 🚀
    }

    function test_executeLimitOrders_updatedAt() public {
        vm.warp(100);
        uint256 positionId1 = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        uint256 positionId2 = createLimitOrderDefault(PerpDexLib.TokenType.Klay, 2_000_000, 10, true, 200_000_000, 0, 0);
        uint256 positionId3 = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        PerpDexLib.Position memory position1 = this.getPosition(positionId1);
        PerpDexLib.Position memory position2 = this.getPosition(positionId2);
        PerpDexLib.Position memory position3 = this.getPosition(positionId3);

        uint256[] memory ordersToExecute = new uint256[](3);
        ordersToExecute[0] = positionId1;
        ordersToExecute[1] = positionId2;
        ordersToExecute[2] = positionId3;

        uint64[] memory roundIds = new uint64[](3);

        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);

        vm.expectEmit(true, true, true, true);
        emit PerpDex.LimitOrderExecuted(positionId1, position1.traderAddr);
        // 🔥
        // vm.expectEmit(true, true, true, true);
        // emit PerpDex.LimitOrderExecuted(positionId2, position2.traderAddr);
        vm.expectEmit(true, true, true, true);
        emit PerpDex.LimitOrderExecuted(positionId3, position3.traderAddr);

        mockGetPreviousPriceAndTime(
            [uint256(200_000_000), uint256(100_000_000), uint256(0), uint256(50_000_000), uint256(50_000_000), uint256(50_000_000)],
            [block.timestamp + 1, block.timestamp, block.timestamp + 1, block.timestamp + 1, block.timestamp + 1, block.timestamp + 1] // 🔥 klay price is behind updatedAt
        );
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector, roundIds, bisonAIData, bisonAIRouter, pyth),
            1
        );

        vm.mockCall(
            address(PerpDexLib),
            abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector, position1, 200_000_000),
            abi.encode(true)
        );
        vm.mockCall(
            address(PerpDexLib),
            abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector, position3, 200_000_000),
            abi.encode(true)
        );

        vm.expectCall(
            address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector, position1, 200_000_000), 1
        );
        vm.expectCall(
            address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector, position2, 200_000_000), 0
        );

        position3.limitOrderIndex = 0; // 🔥 limitOrderIndex swaps with position1 when position1 is executed and cleanUpLimitOrder is called
        vm.expectCall(
            address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector, position3, 200_000_000), 1
        );

        vm.expectCall(address(PerpDexBotLib), abi.encodeWithSelector(PerpDexBotLib._executeLimitOrder.selector), 2);

        vm.prank(limitAdmin);
        this.executeLimitOrders(ordersToExecute, roundIds, bisonAIData);
    }

    function test_executeLimitOrders_noRequestedPositions() public {
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);

        vm.expectCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector), 0);
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector), 0);
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.cleanUpLimitOrder.selector), 0);
        vm.expectCall(address(PerpDexBotLib), abi.encodeWithSelector(PerpDexBotLib._executeLimitOrder.selector), 0);

        vm.prank(limitAdmin);
        uint256[] memory ordersToExecute = new uint256[](0);
        uint64[] memory roundIds = new uint64[](0);
        this.executeLimitOrders(ordersToExecute, roundIds, bisonAIData); // 🚀
    }

    function test_executeLimitOrders_revert_invalidAdmin() public {
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);

        vm.prank(makeAddr("invalidAdmin"));
        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        uint256[] memory ordersToExecute = new uint256[](3);
        uint64[] memory roundIds = new uint64[](3);
        this.executeLimitOrders(ordersToExecute, roundIds, bisonAIData); // 🚀
    }

    function test_executeLimitOrders_revert_invalidPriceData() public {
        vm.warp(100);
        uint256 positionId = createLimitOrderDefault(PerpDexLib.TokenType.Trump, 2_000_000, 10, true, 200_000_000, 0, 0); // 🔥
        vm.warp(110); // order.statusTime.limitOpenTime < updatedAt

        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);
        uint256[] memory ordersToExecute = new uint256[](1);
        ordersToExecute[0] = positionId;
        uint64[] memory roundIds = new uint64[](3);

        // 🔥 no Trump price available
        mockGetPreviousPriceAndTime(
            [uint256(199_000_000), uint256(100_000_000), uint256(0), uint256(50_000_000), uint256(50_000_000), uint256(50_000_000)],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector, roundIds, bisonAIData, bisonAIRouter, pyth),
            1
        );

        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector), 0);
        vm.expectCall(address(PerpDexBotLib), abi.encodeWithSelector(PerpDexBotLib._executeLimitOrder.selector), 0);
        vm.expectRevert(abi.encodeWithSelector(InvalidPriceData.selector));
        vm.prank(limitAdmin);
        this.executeLimitOrders(ordersToExecute, roundIds, bisonAIData); // 🚀
    }

    function test__liquidatePosition_ok() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        vm.warp(12); //  1 (openTime) + 11 (liquidationSafePadding);
        PerpDexLib.Position memory position = positions[positionId];

        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);
        uint256 fee = (position.size - position.margin) * defaultTotalFeePercent / defaultFeeDenominator;
        uint256 closingPrice = 100;

        // int256 expectingFundingFee = PerpDexLib.calculateFundingFee(positions[positionId], fundingFeeTokenStates[position.tokenType]);
        // can calculate manually, but it is handled in PerpDex.fundingFee.t.sol
        int256 expectingFundingFee = 5;

        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());

        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(
                PerpDexPricesLib.safeTransferAndCheckBalance.selector,
                address(externalContracts.lp),
                position.margin - fee - uint256(expectingFundingFee)
            ),
            1
        );

        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.updateFundingFeeState.selector), 1);
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.calculateFundingFee.selector), 1);
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.calculatePnlAndCloseFee.selector), 1);

        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkAndLiquidatePosition.selector), 1);
        vm.expectCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector, position.traderAddr, fee), 1);
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.decreaseTotalPositionSize.selector), 1);
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.cleanUpPosition.selector), 1);

        vm.expectEmit(true, true, true, true);
        emit PerpDex.PositionLiquidated(
            position.positionId,
            position.traderAddr,
            position.tokenType,
            position.margin,
            position.size,
            position.initialPrice,
            position.isLong,
            closingPrice,
            expectingFundingFee
        );

        vm.prank(liqAdmin);
        PerpDexBotLib._liquidatePosition(
            positions,
            positionId,
            fundingFeeTokenStates,
            traderOpenPositionIds,
            fundingFeeGlobalState,
            tokenTotalSizes,
            openPositionIds,
            externalContracts,
            closingPrice
        ); // 🚀

        position.pnl = -int256(position.margin - fee - uint256(expectingFundingFee));
        position.closeFee = fee;
        position.finalPrice = closingPrice;
        position.fundingFee = expectingFundingFee;
        position.positionStatus = PerpDexLib.PositionStatus.Liquidated;
        position.statusTime.liquidatedTime = block.timestamp;
        position.openPositionIndex = type(uint256).max;
        assertPosition(positions[positionId], position);

        assertEq(fundingFeeTokenStates[position.tokenType].lastUpdatedTime, block.timestamp); // check if updateFundingFeeState is called
        assertEq(tokenTotalSizes[uint256(position.tokenType)].currentLong, 0); // check if decreaseTotalPositionSize is called

        assertEq(openPositionIds.length, 0); // check if cleanUpPosition is called
        (uint256 long, uint256 short) = this.getTraderOpenPositionId(position.traderAddr, uint16(position.tokenType)); // check if clearTraderOpenPositionId is called
        assertEq(long, 0);
        assertEq(short, 0);
    }

    function test_liquidatePositions_external_ok() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        vm.warp(12); //  1 (openTime) + 11 (liquidationSafePadding);

        uint256[] memory liquidatablePositions = new uint256[](1);
        liquidatablePositions[0] = positionId;
        uint64[] memory roundIds = new uint64[](1);

        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);
        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);
        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());
        uint256 closingPrice = 100;
        mockGetPreviousPriceAndTime(
            [closingPrice, closingPrice, closingPrice, closingPrice, closingPrice, closingPrice],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector, roundIds, bisonAIData, bisonAIRouter, pyth),
            1
        );

        vm.expectCall(address(PerpDexBotLib), abi.encodeWithSelector(PerpDexBotLib._liquidatePosition.selector), 1);

        vm.prank(liqAdmin);
        this.liquidatePositions(liquidatablePositions, roundIds, bisonAIData); // 🚀
    }

    function test_liquidatePositions_updatedAt_skip() public {
        uint256 openTime = 100;
        uint256 liquidationSafePadding = 11;

        vm.warp(openTime);
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        uint256 updatedAt = openTime + liquidationSafePadding;
        vm.warp(updatedAt);
        PerpDexLib.Position memory position = positions[positionId];

        uint256[] memory liquidatablePositions = new uint256[](1);
        liquidatablePositions[0] = positionId;
        uint64[] memory roundIds = new uint64[](1);

        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);
        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);
        uint256 closingPrice = 100;
        mockGetPreviousPriceAndTime(
            [closingPrice, closingPrice, closingPrice, closingPrice, closingPrice, closingPrice],
            [openTime - 1, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector, roundIds, bisonAIData, bisonAIRouter, pyth),
            1
        );

        vm.expectCall(address(PerpDexBotLib), abi.encodeWithSelector(PerpDexBotLib._liquidatePosition.selector), 0);

        vm.prank(liqAdmin);
        this.liquidatePositions(liquidatablePositions, roundIds, bisonAIData); // 🚀

        assertPosition(positions[positionId], position); // nothing changed
    }

    function test_liquidatePositions_notOpen() public {
        uint256 openTime = 100;
        uint256 liquidationSafePadding = 11;

        vm.warp(openTime);
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        uint256 updatedAt = openTime + liquidationSafePadding;
        vm.warp(updatedAt);

        positions[positionId].positionStatus = PerpDexLib.PositionStatus.Closed; // 🔥 status is not open
        PerpDexLib.Position memory position = positions[positionId];

        uint256[] memory liquidatablePositions = new uint256[](1);
        liquidatablePositions[0] = positionId;
        uint64[] memory roundIds = new uint64[](1);

        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(1);
        uint256 closingPrice = 1_000_000;
        mockCurrentPrice(closingPrice);

        closingPrice = 100;
        mockGetPreviousPriceAndTime(
            [closingPrice, closingPrice, closingPrice, closingPrice, closingPrice, closingPrice],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector, roundIds, bisonAIData, bisonAIRouter, pyth),
            1
        );

        vm.expectCall(address(PerpDexBotLib), abi.encodeWithSelector(PerpDexBotLib._liquidatePosition.selector), 0);

        vm.prank(liqAdmin);
        this.liquidatePositions(liquidatablePositions, roundIds, bisonAIData); // 🚀

        assertPosition(positions[positionId], position); // nothing changed
    }

    function test_liquidatePositions_multiple_all() public {
        uint256 openTime = 100;
        uint256 liquidationSafePadding = 11;
        uint256 closingPrice = 100;

        uint256[] memory liquidatablePositions = new uint256[](3);
        vm.warp(openTime);
        openPositionDefault(user, PerpDexLib.TokenType.Btc, 1_000_000, 3, true, 100_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Eth, 2_000_000, 4, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Klay, 3_000_000, 5, true, 300_000_000, 0, 0);
        liquidatablePositions[0] = 1;
        liquidatablePositions[1] = 2;
        liquidatablePositions[2] = 3;
        uint256 updatedAt = openTime + liquidationSafePadding;
        vm.warp(updatedAt);

        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);
        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);
        mockGetPreviousPriceAndTime(
            [closingPrice, closingPrice, closingPrice, closingPrice, closingPrice, closingPrice],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );
        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());

        uint64[] memory roundIds = new uint64[](3);
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector, roundIds, bisonAIData, bisonAIRouter, pyth),
            1
        );

        vm.expectCall(address(PerpDexBotLib), abi.encodeWithSelector(PerpDexBotLib._liquidatePosition.selector), 3);

        int256[] memory fundingFees = new int256[](4);
        fundingFees[1] = 0;
        fundingFees[2] = 2;
        fundingFees[3] = 3;

        for (uint64 i = 1; i < 4; i++) {
            PerpDexLib.Position storage position = positions[i];
            vm.expectEmit(true, true, true, true);
            emit PerpDex.PositionLiquidated(
                position.positionId,
                position.traderAddr,
                position.tokenType,
                position.margin,
                position.size,
                position.initialPrice,
                position.isLong,
                closingPrice,
                fundingFees[i]
            );

            uint256 fee = (position.size - position.margin) * defaultTotalFeePercent / defaultFeeDenominator;
            vm.expectCall(
                address(PerpDexPricesLib),
                abi.encodeWithSelector(
                    PerpDexPricesLib.safeTransferAndCheckBalance.selector,
                    address(externalContracts.lp),
                    position.margin - fee - uint256(fundingFees[i])
                ),
                1
            );
            vm.expectCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector, position.traderAddr, fee), 1);
        }

        vm.prank(liqAdmin);
        this.liquidatePositions(liquidatablePositions, roundIds, bisonAIData); // 🚀
    }

    function test_liquidatePositions_multiple_skipOne() public {
        uint256 openTime = 100;
        uint256 closingPrice = 100;

        uint256[] memory liquidatablePositions = new uint256[](3);
        vm.warp(openTime);
        openPositionDefault(user, PerpDexLib.TokenType.Btc, 1_000_000, 3, true, 100_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Eth, 2_000_000, 4, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Klay, 3_000_000, 5, true, 300_000_000, 0, 0);
        liquidatablePositions[0] = 1;
        liquidatablePositions[1] = 2;
        liquidatablePositions[2] = 3;

        uint256 updatedAt = openTime + 11;
        vm.warp(updatedAt);

        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);
        uint64[] memory roundIds = new uint64[](3);
        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);
        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());
        mockGetPreviousPriceAndTime(
            [
                uint256(100_000_000), // 🔥 not liquidatable
                uint256(closingPrice),
                uint256(closingPrice),
                uint256(closingPrice),
                uint256(closingPrice),
                uint256(closingPrice)
            ],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector, roundIds, bisonAIData, bisonAIRouter, pyth),
            1
        );

        vm.expectCall(address(PerpDexBotLib), abi.encodeWithSelector(PerpDexBotLib._liquidatePosition.selector), 3);
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.decreaseTotalPositionSize.selector), 2); // 🔥
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.cleanUpPosition.selector), 2); // 🔥

        for (uint64 i = 1; i < 4; i++) {
            bool isLiquidatable = i == 1 ? false : true;
            PerpDexLib.Position storage position = positions[i];
            if (isLiquidatable) {
                vm.expectEmit(true, true, true, true);
                emit PerpDex.PositionLiquidated(
                    position.positionId,
                    position.traderAddr,
                    position.tokenType,
                    position.margin,
                    position.size,
                    position.initialPrice,
                    position.isLong,
                    closingPrice,
                    int256(position.size * 1e20 * 875 * 11) / 3600 / 1e7 / 1e20
                );
            }
        }

        vm.prank(liqAdmin);
        this.liquidatePositions(liquidatablePositions, roundIds, bisonAIData); // 🚀

        assertEq(uint256(positions[1].positionStatus), uint256(PerpDexLib.PositionStatus.Open)); // 🔥
        assertEq(uint256(positions[2].positionStatus), uint256(PerpDexLib.PositionStatus.Liquidated));
        assertEq(uint256(positions[3].positionStatus), uint256(PerpDexLib.PositionStatus.Liquidated));
    }

    function test_liquidatePositions_revert_InvalidPriceData() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Trump, 2_000_000, 10, true, 200_000_000, 0, 0); // 🔥
        vm.warp(12); //  1 (openTime) + 11 (liquidationSafePadding);

        uint256[] memory liquidatablePositions = new uint256[](1);
        liquidatablePositions[0] = positionId;
        uint64[] memory roundIds = new uint64[](1);

        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);
        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);
        uint256 closingPrice = 100;
        // 🔥 no Trump price available
        mockGetPreviousPriceAndTime(
            [closingPrice, closingPrice, closingPrice, closingPrice, closingPrice, closingPrice],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector, roundIds, bisonAIData, bisonAIRouter, pyth),
            1
        );

        vm.expectCall(address(PerpDexBotLib), abi.encodeWithSelector(PerpDexBotLib._liquidatePosition.selector), 0);
        vm.expectRevert(abi.encodeWithSelector(InvalidPriceData.selector));

        vm.prank(liqAdmin);
        this.liquidatePositions(liquidatablePositions, roundIds, bisonAIData); // 🚀
    }

    function test_rollbackPosition() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 1_000_000, 0, 0);
        PerpDexLib.Position memory position = positions[positionId];

        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.decreaseTotalPositionSize.selector), 1);
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.cleanUpPosition.selector), 1);
        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector, position.traderAddr, position.margin),
            1
        );

        vm.expectEmit(true, true, true, true);
        emit PositionRolledBack(
            position.positionId,
            position.traderAddr,
            position.tokenType,
            position.margin,
            position.size,
            position.initialPrice,
            position.isLong,
            position.closeFee
        );
        vm.prank(owner());
        this.rollbackPosition(positionId); // 🚀

        position.statusTime.closeTime = block.timestamp;
        position.positionStatus = PerpDexLib.PositionStatus.RolledBack;
        position.finalPrice = position.initialPrice;
        position.openPositionIndex = type(uint256).max;
        assertPosition(positions[positionId], position);

        assertEq(fundingFeeTokenStates[position.tokenType].lastUpdatedTime, block.timestamp); // check if updateFundingFeeState is called
        assertEq(tokenTotalSizes[uint256(position.tokenType)].currentLong, 0); // check if decreaseTotalPositionSize is called

        assertEq(openPositionIds.length, 0); // check if cleanUpPosition is called

        (uint256 long, uint256 short) = this.getTraderOpenPositionId(position.traderAddr, uint16(position.tokenType));
        assertEq(long, 0);
        assertEq(short, 0);
    }

    function test_rollbackPosition_revert() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 1_000_000, 0, 0);

        address invalidOwner = makeAddr("invalidOwner");
        vm.prank(invalidOwner);
        vm.expectRevert(abi.encodeWithSelector(OwnableUpgradeable.OwnableUnauthorizedAccount.selector, address(invalidOwner)));
        this.rollbackPosition(positionId); // 🚀

        positions[positionId].positionStatus = PerpDexLib.PositionStatus.Closed;
        vm.expectRevert(abi.encodeWithSelector(InvalidPositionStatus.selector));
        vm.prank(owner());
        this.rollbackPosition(positionId); // 🚀
    }

    function test_submitAndGetBisonAIRoundId_external() public {
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(1);

        vm.prank(singleOpenAdmin);
        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.submitAndGetBisonAIRoundId(bisonAIData); // 🚀

        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.submitAndGetBisonAIRoundId.selector), abi.encode());
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.submitAndGetBisonAIRoundId.selector, bisonAIData, bisonAISubmissionProxy, bisonAIRouter),
            1
        );
        vm.prank(limitAdmin);
        this.submitAndGetBisonAIRoundId(bisonAIData); // 🚀
    }

    function test_executeLimitOrders_unOpenedLimitOrder() public {
        // SW-3503
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(1);

        uint256[] memory ordersToExecute = new uint256[](1);
        ordersToExecute[0] = 100;
        uint64[] memory roundIds = new uint64[](1);

        mockGetPreviousPriceAndTime(
            [uint256(200_000_000), uint256(100_000_000), uint256(0), uint256(50_000_000), uint256(50_000_000), uint256(50_000_000)],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );
        vm.mockCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector), abi.encode());
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.checkExecutionForLimitOrder.selector), 0);

        vm.prank(limitAdmin);
        this.executeLimitOrders(ordersToExecute, roundIds, bisonAIData);
    }

    function test_closePosition_unOpenedPosition() public {
        // SW-3503
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(1);
        vm.mockCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), abi.encode());
        vm.expectCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), 1);
        mockCurrentPrice(1000);

        vm.expectRevert(abi.encodeWithSelector(InvalidPositionStatus.selector));
        vm.prank(closeAdmin);
        this.closePosition(100, bisonAIData, hex"1234");
    }

    function test_mergePosition_twice_long() public {
        assertEq(openPositionIds.length, 0);

        uint256 positionId1 = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 100, 101, 0); // 🚀
        assertEq(openPositionIds.length, 1);

        PerpDexLib.Position memory positionOriginal = positions[positionId1];

        vm.warp(100);
        uint256 positionId2 = openPositionDefaultWithMerge(PerpDexLib.TokenType.Btc, 3_000_000, 10, true, 150, 0, 99); // 🚀
        assertEq(openPositionIds.length, 1);

        PerpDexLib.Position memory positionOld = positions[positionId1];
        PerpDexLib.Position memory positionNew = positions[positionId2];

        positionOriginal.margin += 3_000_000 - 30_000_000 * 0.0007;
        positionOriginal.size += (3_000_000 - 30_000_000 * 0.0007) * 10;
        positionOriginal.openFee += 30_000_000 * 0.0007;
        positionOriginal.initialPrice = 125;
        positionOriginal.statusTime.openTime = block.timestamp;
        positionOriginal.slPrice = 99;
        positionOriginal.tpslUpdatedTime = block.timestamp;
        positionOriginal.accFundingFeePerSize = 240_625_000_000_000; // calculating numbers are handled in PerpDex.fundingFee.t.sol
        positionOriginal.fundingFee = 47;
        assertPosition(positionOld, positionOriginal);

        assertEq(uint256(positionNew.positionStatus), uint256(PerpDexLib.PositionStatus.Merged));
        assertEq(positionNew.statusTime.openTime, block.timestamp);
        assertEq(positionNew.initialPrice, 150);

        vm.warp(200);
        openPositionDefaultWithMerge(PerpDexLib.TokenType.Btc, 4_000_000, 10, true, 150, 151, 0); // 🚀
        assertEq(openPositionIds.length, 1);
        assertEq(traderPositionIds[user].length, 3);

        positionOld = positions[positionId1];

        positionOriginal.margin += 4_000_000 - 40_000_000 * 0.0007;
        positionOriginal.size += (4_000_000 - 40_000_000 * 0.0007) * 10;
        positionOriginal.openFee += 40_000_000 * 0.0007;
        positionOriginal.initialPrice = 135;
        positionOriginal.statusTime.openTime = block.timestamp;
        positionOriginal.tpPrice = 151;
        positionOriginal.tpslUpdatedTime = block.timestamp;
        positionOriginal.accFundingFeePerSize = 483_680_555_555_555; // calculating numbers are handled in PerpDex.fundingFee.t.sol
        positionOriginal.fundingFee = 167;
        assertPosition(positionOld, positionOriginal);

        (uint256 long, uint256 short) = this.getTraderOpenPositionId(positionOriginal.traderAddr, uint16(positionOriginal.tokenType));
        assertEq(long, positionId1);
        assertEq(short, 0);
    }

    function test_mergePosition_twice_short() public {
        assertEq(openPositionIds.length, 0);

        uint256 positionId1 = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, false, 100, 0, 0); // 🚀
        assertEq(openPositionIds.length, 1);

        PerpDexLib.Position memory positionOriginal = positions[positionId1];

        vm.warp(100);

        uint256 positionId2 = openPositionDefaultWithMerge(PerpDexLib.TokenType.Btc, 3_000_000, 5, false, 105, 0, 0); // 🚀
        assertEq(openPositionIds.length, 1);

        PerpDexLib.Position memory positionOld = positions[positionId1];
        PerpDexLib.Position memory positionNew = positions[positionId2];

        positionOriginal.margin += 3_000_000 - 15_000_000 * 0.0007;
        positionOriginal.size += (3_000_000 - 15_000_000 * 0.0007) * 5;
        positionOriginal.openFee += 15_000_000 * 0.0007;
        // oldPosition.initialPrice = oldPosition.initialPrice * currentPrice * (oldPosition.size + newPosition.size) / (currentPrice * oldPosition.size + oldPosition.initialPrice * newPosition.size);
        // 100 * 105 * (20 + 15) / 105 * 20 + 100 * 15
        positionOriginal.initialPrice = 102;
        positionOriginal.statusTime.openTime = block.timestamp;
        positionOriginal.tpslUpdatedTime = block.timestamp;
        positionOriginal.accFundingFeePerSize = -240_625_000_000_000; // calculating numbers are handled in PerpDex.fundingFee.t.sol
        positionOriginal.fundingFee = 47;
        assertPosition(positionOld, positionOriginal);

        assertEq(uint256(positionNew.positionStatus), uint256(PerpDexLib.PositionStatus.Merged));
        assertEq(positionNew.statusTime.openTime, block.timestamp);
        assertEq(positionNew.initialPrice, 105);

        (uint256 long, uint256 short) = this.getTraderOpenPositionId(positionOriginal.traderAddr, uint16(positionOriginal.tokenType));
        assertEq(long, 0);
        assertEq(short, positionId1);
    }

    function test_mergePosition_limitOrder() public {
        uint256 positionId1 = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 3, true, 100, 101, 0);
        uint256 positionId2 = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 4_000_000, 3, true, 90, 80, 2);
        uint256 positionId3 = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 6_000_000, 3, true, 90, 0, 1);
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);

        vm.warp(100);
        mockGetPreviousPriceAndTime(
            [uint256(100), uint256(100_000_000), uint256(0), uint256(50_000_000), uint256(50_000_000), uint256(50_000_000)],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );

        uint256[] memory ordersToExecute = new uint256[](1);
        ordersToExecute[0] = positionId1;
        uint64[] memory roundIds = new uint64[](3);

        vm.startPrank(limitAdmin);
        this.executeLimitOrders(ordersToExecute, roundIds, bisonAIData); // 🚀 open positionId 1

        assertEq(limitOrderIds.length, 2);
        assertEq(openPositionIds.length, 1);

        PerpDexLib.Position memory positionOriginal = positions[positionId1];
        assertEq(positionOriginal.margin, 2_000_000 - 6_000_000 * 0.0007);

        (uint256 long, uint256 short) = this.getTraderOpenPositionId(positionOriginal.traderAddr, uint16(positionOriginal.tokenType));
        assertEq(long, positionId1);
        assertEq(short, 0);

        uint256[] memory ordersToExecute2 = new uint256[](2);
        ordersToExecute2[0] = positionId2;
        ordersToExecute2[1] = positionId3;

        vm.warp(200);
        mockGetPreviousPriceAndTime(
            [uint256(90), uint256(100_000_000), uint256(0), uint256(50_000_000), uint256(50_000_000), uint256(50_000_000)],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );

        this.executeLimitOrders(ordersToExecute2, roundIds, bisonAIData); // 🚀 open positionId 2 and 3 at the same time

        assertEq(limitOrderIds.length, 0);
        assertEq(openPositionIds.length, 1);

        PerpDexLib.Position memory positionOld = positions[positionId1];
        positionOriginal.margin += 4_000_000 - 12_000_000 * 0.0007 + 6_000_000 - 18_000_000 * 0.0007;
        positionOriginal.size += (4_000_000 - 12_000_000 * 0.0007 + 6_000_000 - 18_000_000 * 0.0007) * 3;
        positionOriginal.openFee += 12_000_000 * 0.0007 + 18_000_000 * 0.0007;

        // oldPosition.initialPrice = oldPosition.initialPrice * currentPrice * (oldPosition.size + newPosition.size) / (currentPrice * oldPosition.size + oldPosition.initialPrice * newPosition.size);
        // 93 * 90 * (4 + 6) / 6 * 93 + 90 * 4
        positionOriginal.initialPrice = 91;
        positionOriginal.statusTime.openTime = block.timestamp;
        positionOriginal.tpPrice = 80;
        positionOriginal.slPrice = 1;
        positionOriginal.tpslUpdatedTime = block.timestamp;
        positionOriginal.accFundingFeePerSize = 0;
        positionOriginal.fundingFee = 57;
        assertPosition(positionOld, positionOriginal);
    }

    function test_setTpslPrice_external() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 1_000_000, 0, 0);
        PerpDexLib.Position memory positionBefore = positions[positionId];

        string memory message = string(
            abi.encodePacked(
                "Set TPSL: 1, TpPrice: 1200000, SlPrice: 900000, Nonce: 1, Chain: 8217, Contract: ", Strings.toHexString(address(this))
            )
        );
        uint256 tpPrice = 1_200_000;
        uint256 slPrice = 900_000;

        vm.expectCall(
            address(PerpDexAuthLib),
            abi.encodeWithSelector(PerpDexAuthLib.getSetTpslMsg.selector, positionId, tpPrice, slPrice, traderNonce[user], address(this)),
            1
        );

        vm.mockCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), abi.encode());
        vm.expectCall(
            address(PerpDexAuthLib),
            abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector, message, bytes(message).length, hex"1234", user),
            1
        );

        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib._setTpslPrice.selector), 1);

        vm.warp(100);
        vm.prank(tpslAdmin);
        this.setTpslPrice(positionId, 1_200_000, 900_000, hex"1234"); // 🚀

        assertEq(traderNonce[user], 2);

        positionBefore.tpPrice = 1_200_000;
        positionBefore.slPrice = 900_000;
        positionBefore.tpslUpdatedTime = block.timestamp;
        assertPosition(positions[positionId], positionBefore);
    }

    function test_setTpslPrice_external_revert() public {
        vm.prank(singleOpenAdmin);
        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.setTpslPrice(1, 1_200_000, 900_000, hex"1234"); // 🚀

        vm.prank(tpslAdmin);
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, 2));
        this.setTpslPrice(1, 1_200_000, 900_000, hex"1234"); // 🚀
    }

    function test_tpslClosePositions_ok() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Pepe, 2_000_000, 10, true, 1026, 1200, 800);
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);
        PerpDexLib.Position memory p = positions[positionId];

        uint256[] memory positionsToClose = new uint256[](1);
        positionsToClose[0] = positionId;
        uint64[] memory roundIds = new uint64[](8);

        vm.warp(block.timestamp + 100);
        mockGetPreviousPriceAndTime(
            [uint256(200_000_000), uint256(100_000_000), uint256(0), uint256(50_000_000), uint256(100_000), uint256(1200)],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector, roundIds, bisonAIData, bisonAIRouter, pyth),
            1
        );

        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);
        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());
        vm.expectCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), 1);

        int256 profit = int256(p.size) * 1200 / 1026 - int256(p.size);
        uint256 closeFee = (p.size + uint256(profit)) * defaultTotalFeePercent / defaultFeeDenominator;
        vm.expectCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector, p.traderAddr, closeFee), 1);

        vm.mockCall(address(externalContracts.lp), abi.encodeWithSelector(ILP.giveProfit.selector), abi.encode());
        vm.expectCall(address(externalContracts.lp), abi.encodeWithSelector(ILP.giveProfit.selector, p.traderAddr, profit), 1);

        vm.expectEmit(true, true, true, true);
        emit PerpDex.PositionClosed(p.positionId, p.traderAddr, p.tokenType, p.margin, p.size, p.initialPrice, p.isLong, 1200, 48);

        vm.prank(tpslAdmin);
        this.tpslClosePositions(positionsToClose, roundIds, bisonAIData); // 🚀

        p.closeFee = closeFee;
        p.finalPrice = 1200;
        p.pnl = profit;
        p.statusTime.closeTime = block.timestamp;
        p.openPositionIndex = type(uint256).max;
        p.positionStatus = PerpDexLib.PositionStatus.Closed;
        p.fundingFee = 48;
        p.accFundingFeePerSize = 0;
        assertPosition(positions[positionId], p);

        (uint256 long, uint256 short) = this.getTraderOpenPositionId(user, uint16(p.tokenType));
        assertEq(long, 0);
        assertEq(short, 0);

        // Add assertions for funding fee state
        PerpDexLib.FundingFeeTokenState storage f = fundingFeeTokenStates[PerpDexLib.TokenType.Pepe];
        assertEq(f.lastUpdatedTime, block.timestamp, "Funding fee state not updated");
    }

    function test_tpslClosePositions_multiple() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Pepe, 2_000_000, 10, true, 1026, 1200, 800);
        uint256 positionId2 = openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 6_000_000, 6_000_001, 5_999_999); // 🔥 skip
        uint256 positionId3 = openPositionDefault(user, PerpDexLib.TokenType.Klay, 2_000_000, 10, false, 1_000_000, 1_200_000, 9_000_000);

        uint256[] memory positionsToClose = new uint256[](3);
        positionsToClose[0] = positionId;
        positionsToClose[1] = positionId2;
        positionsToClose[2] = positionId3;
        uint64[] memory roundIds = new uint64[](8);

        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);

        vm.warp(block.timestamp + 100);
        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);
        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());
        vm.mockCall(address(externalContracts.lp), abi.encodeWithSelector(ILP.giveProfit.selector), abi.encode());
        mockGetPreviousPriceAndTime(
            [uint256(6_000_000), uint256(9_000_000), uint256(0), uint256(50_000_000), uint256(100_000), uint256(1200)], // 🔥 skip BTC
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector, roundIds, bisonAIData, bisonAIRouter, pyth),
            1
        );

        vm.expectCall(address(PerpDexBotLib), abi.encodeWithSelector(PerpDexBotLib._tpslClosePosition.selector), 3);
        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib._closePosition.selector), 2); // 🔥 skip BTC

        vm.prank(tpslAdmin);
        this.tpslClosePositions(positionsToClose, roundIds, bisonAIData); // 🚀
    }

    function test_tpslClosePositions_revert_notAdmin() public {
        uint256[] memory positionsToClose = new uint256[](3);
        uint64[] memory roundIds = new uint64[](8);
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);
        vm.prank(closeAdmin);
        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.tpslClosePositions(positionsToClose, roundIds, bisonAIData); // 🚀
    }

    function test_tpslClosePositions_skip_empty() public {
        uint256[] memory positionsToClose = new uint256[](3);
        uint64[] memory roundIds = new uint64[](8);
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);
        positionsToClose = new uint256[](0);
        vm.expectCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector), 0); // 🔥 early return
        vm.prank(tpslAdmin);
        this.tpslClosePositions(positionsToClose, roundIds, bisonAIData); // 🚀
    }

    function test_tpslClosePositions_skip_notOpen() public {
        uint256[] memory positionsToClose = new uint256[](3);
        uint64[] memory roundIds = new uint64[](8);
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);

        positionsToClose = new uint256[](1);
        positionsToClose[0] = 100; // 🔥 position is not open
        mockGetPreviousPriceAndTime(
            [uint256(6_000_000), uint256(9_000_000), uint256(0), uint256(50_000_000), uint256(100_000), uint256(1200)],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );
        vm.expectCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.getPreviousPriceAndTime.selector), 1);
        vm.expectCall(address(PerpDexBotLib), abi.encodeWithSelector(PerpDexBotLib._tpslClosePosition.selector), 0);
        vm.prank(tpslAdmin);
        this.tpslClosePositions(positionsToClose, roundIds, bisonAIData);
    }

    // revert when price data is not enough for tokenType
    function test_priceData_is_not_enough_for_tokenType() public {
        vm.warp(100);
        uint256 orderId = createLimitOrderDefault(PerpDexLib.TokenType.Sol, 2_000_000, 10, true, 200_000_000, 0, 0);
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Sol, 2_000_000, 10, true, 200_000_000, 0, 0);
        vm.warp(110); // order.statusTime.limitOpenTime < updatedAt
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(6);

        mockGetPreviousPriceAndTime(
            [uint256(200_000_000), uint256(100_000_000), uint256(0), uint256(50_000_000), uint256(50_000_000), uint256(50_000_000)],
            [block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp, block.timestamp]
        );

        uint256[] memory ordersToExecute = new uint256[](1);
        ordersToExecute[0] = orderId;
        uint64[] memory roundIds = new uint64[](6);

        vm.prank(limitAdmin);
        vm.expectRevert(abi.encodeWithSelector(InvalidPriceData.selector));
        this.executeLimitOrders(ordersToExecute, roundIds, bisonAIData);

        uint256[] memory candidates = new uint256[](1);
        candidates[0] = positionId;
        vm.prank(liqAdmin);
        vm.expectRevert(abi.encodeWithSelector(InvalidPriceData.selector));
        this.liquidatePositions(candidates, roundIds, bisonAIData);

        vm.prank(tpslAdmin);
        vm.expectRevert(abi.encodeWithSelector(InvalidPriceData.selector));
        this.tpslClosePositions(candidates, roundIds, bisonAIData);
    }

    function test_claimProtocolFundingFee() public {
        // Setup initial state
        fundingFeeGlobalState.protocolClaimable = 1000;
        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.balanceOf.selector, address(this)), abi.encode(2000));
        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());

        vm.expectCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), 1);

        // Test successful claim by admin
        vm.prank(admin);
        this.claimProtocolFundingFee();

        // Test revert when non-admin tries to claim
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.claimProtocolFundingFee();

        // Test revert when protocolClaimable is 0
        fundingFeeGlobalState.protocolClaimable = 0;
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(InvalidProtocolClaimable.selector));
        this.claimProtocolFundingFee();

        // Test revert when contract balance is insufficient
        fundingFeeGlobalState.protocolClaimable = 3000;
        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.balanceOf.selector, address(this)), abi.encode(2000));
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(InvalidProtocolClaimable.selector));
        this.claimProtocolFundingFee();
    }

    function test_depositFundingFeeGlobalStateBalance() public {
        uint256 initialBalance = fundingFeeGlobalState.bufferBalance;
        uint256 depositAmount = 1000;

        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferFromAndCheckBalance.selector), abi.encode()
        );

        // Test successful deposit by admin
        vm.prank(admin);
        this.depositFundingFeeGlobalStateBalance(depositAmount);
        assertEq(fundingFeeGlobalState.bufferBalance, initialBalance + depositAmount, "Buffer balance should increase by deposit amount");

        // Test revert when non-admin tries to deposit
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(InvalidAdmin.selector));
        this.depositFundingFeeGlobalStateBalance(depositAmount);
    }

    function test_updateFundingFeeStates() public {
        vm.warp(100_000);
        // Setup mock calls for each token type
        for (uint256 i = 0; i < tokenCount; i++) {
            fundingFeeTokenStates[PerpDexLib.TokenType(i)].lastUpdatedTime = block.timestamp - 3600; // 1 hour ago
            fundingFeeTokenStates[PerpDexLib.TokenType(i)].lastAppliedRate = 100;
            fundingFeeTokenStates[PerpDexLib.TokenType(i)].accFeePerSize = 1000;

            tokenTotalSizes[i].currentLong = 5000;
            tokenTotalSizes[i].currentShort = 3000;
        }

        // Test revert when non-owner tries to update
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(OwnableUnauthorizedAccount.selector, user));
        this.updateFundingFeeStates();

        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.updateFundingFeeState.selector), tokenCount);
        // Test successful update by owner
        vm.prank(owner());
        this.updateFundingFeeStates();

        // Verify states were updated for each token
        for (uint256 i = 0; i < tokenCount; i++) {
            assertEq(
                fundingFeeTokenStates[PerpDexLib.TokenType(i)].lastUpdatedTime,
                block.timestamp,
                "Last updated time should be current block timestamp"
            );
        }
    }
}
