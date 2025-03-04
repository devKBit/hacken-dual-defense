// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./PerpDexTestBase.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Test, console} from "forge-std/Test.sol";

contract PerpDexLibTest is PerpDexTestBase {
    address[] admins;
    bytes mockSignedData;
    PerpDexLib.TokenTotalSize[] tokenTotalSizesControl;

    function setUp() public override {
        super.setUp();
        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);
    }

    function test_addInitialTokenTotalSizes() public {
        delete tokenTotalSizes;
        PerpDexLib._addInitialTokenTotalSizes(tokenTotalSizes, tokenCount);

        assertEq(tokenTotalSizes.length, tokenCount, "TokenTotalSizes length should equal tokenCount");
        for (uint256 i = 0; i < tokenCount; i++) {
            assertEq(tokenTotalSizes[i].maxLong, 0, "maxLong should be 0");
            assertEq(tokenTotalSizes[i].maxShort, 0, "maxShort should be 0");
            assertEq(tokenTotalSizes[i].currentLong, 0, "currentLong should be 0");
            assertEq(tokenTotalSizes[i].currentShort, 0, "currentShort should be 0");
        }
    }

    function setTokenTotalSizesControl() public {
        for (uint256 i = 0; i < tokenCount; i++) {
            tokenTotalSizesControl.push(PerpDexLib.TokenTotalSize({maxLong: 0, maxShort: 0, currentLong: 0, currentShort: 0}));
        }

        tokenTotalSizesControl[0].maxLong = 300_000_000_000;
        tokenTotalSizesControl[0].maxShort = 300_000_000_000;

        tokenTotalSizesControl[1].maxLong = 75_000_000_000;
        tokenTotalSizesControl[1].maxShort = 75_000_000_000;

        tokenTotalSizesControl[2].maxLong = 0;
        tokenTotalSizesControl[2].maxShort = 0;

        tokenTotalSizesControl[3].maxLong = 300_000_000_000;
        tokenTotalSizesControl[3].maxShort = 300_000_000_000;

        tokenTotalSizesControl[4].maxLong = 120_000_000_000;
        tokenTotalSizesControl[4].maxShort = 120_000_000_000;

        tokenTotalSizesControl[5].maxLong = 120_000_000_000;
        tokenTotalSizesControl[5].maxShort = 120_000_000_000;

        tokenTotalSizesControl[6].maxLong = 250_000_000_000;
        tokenTotalSizesControl[6].maxShort = 250_000_000_000;

        tokenTotalSizesControl[7].maxLong = 200_000_000_000;
        tokenTotalSizesControl[7].maxShort = 200_000_000_000;

        tokenTotalSizesControl[8].maxLong = 200_000_000_000;
        tokenTotalSizesControl[8].maxShort = 200_000_000_000;

        tokenTotalSizesControl[9].maxLong = 200_000_000_000;
        tokenTotalSizesControl[9].maxShort = 200_000_000_000;

        tokenTotalSizesControl[10].maxLong = 120_000_000_000;
        tokenTotalSizesControl[10].maxShort = 120_000_000_000;

        tokenTotalSizesControl[11].maxLong = 150_000_000_000;
        tokenTotalSizesControl[11].maxShort = 150_000_000_000;

        tokenTotalSizesControl[12].maxLong = 250_000_000_000;
        tokenTotalSizesControl[12].maxShort = 250_000_000_000;

        tokenTotalSizesControl[13].maxLong = 200_000_000_000;
        tokenTotalSizesControl[13].maxShort = 200_000_000_000;

        tokenTotalSizesControl[14].maxLong = 250_000_000_000;
        tokenTotalSizesControl[14].maxShort = 250_000_000_000;

        tokenTotalSizesControl[15].maxLong = 200_000_000_000;
        tokenTotalSizesControl[15].maxShort = 200_000_000_000;

        tokenTotalSizesControl[16].maxLong = 250_000_000_000;
        tokenTotalSizesControl[16].maxShort = 250_000_000_000;

        tokenTotalSizesControl[17].maxLong = 250_000_000_000;
        tokenTotalSizesControl[17].maxShort = 250_000_000_000;

        tokenTotalSizesControl[18].maxLong = 100_000_000_000;
        tokenTotalSizesControl[18].maxShort = 100_000_000_000;
    }

    function test_changeMaxTokenTotalSizes() public {
        delete tokenTotalSizes;
        PerpDexLib._addInitialTokenTotalSizes(tokenTotalSizes, tokenCount);
        PerpDexLib._changeMaxTokenTotalSizes(tokenTotalSizes);

        setTokenTotalSizesControl();
        for (uint256 i = 0; i < tokenCount; i++) {
            assertEq(
                tokenTotalSizes[i].maxLong,
                tokenTotalSizesControl[i].maxLong,
                string.concat("maxLong incorrect for token ", Strings.toString(i))
            );
            assertEq(
                tokenTotalSizes[i].maxShort,
                tokenTotalSizesControl[i].maxShort,
                string.concat("maxShort incorrect for token ", Strings.toString(i))
            );
        }

        // check currentLong and currentShort maintained
        tokenTotalSizes[0].currentLong = 100_000_000_000;
        tokenTotalSizes[0].currentShort = 500_000;
        PerpDexLib._changeMaxTokenTotalSizes(tokenTotalSizes);
        assertEq(tokenTotalSizes[0].currentLong, 100_000_000_000, "currentLong");
        assertEq(tokenTotalSizes[0].currentShort, 500_000, "currentShort");

        uint256 tokenTypeLength = uint256(type(PerpDexLib.TokenType).max) + 1;
        assertEq(tokenTotalSizes.length, tokenTypeLength, "TokenTotalSizes length should equal tokenCount");
    }

    function test_checkExecutionForLimitOrder() public {
        uint256 longPositionId = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 3, true, 50_000, 101, 0);
        uint256 shortPositionId = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 3, false, 50_000, 101, 0);

        PerpDexLib.Position memory longPosition = positions[longPositionId];
        PerpDexLib.Position memory shortPosition = positions[shortPositionId];

        // Test long position
        assertFalse(PerpDexLib.checkExecutionForLimitOrder(longPosition, 51_000));
        assertTrue(PerpDexLib.checkExecutionForLimitOrder(longPosition, 50_000));
        assertTrue(PerpDexLib.checkExecutionForLimitOrder(longPosition, 49_000));

        // Test short position
        assertFalse(PerpDexLib.checkExecutionForLimitOrder(shortPosition, 49_000));
        assertFalse(PerpDexLib.checkExecutionForLimitOrder(shortPosition, 48_000));
        assertTrue(PerpDexLib.checkExecutionForLimitOrder(shortPosition, 50_000));

        // Test revert
        vm.expectRevert("Price is 0");
        PerpDexLib.checkExecutionForLimitOrder(longPosition, 0);

        vm.expectRevert("Price is 0");
        PerpDexLib.checkExecutionForLimitOrder(shortPosition, 0);
    }

    function test_calculateOpenFee() public {
        uint256 marginAmount = 1_000_000;
        uint256 leverage = 10;

        uint256 totalFeePercent = 99;
        uint256 feeDenominator = 100_000;
        mockFee(totalFeePercent, feeDenominator, 0);

        uint256 expectingFee = marginAmount * leverage * totalFeePercent / feeDenominator;

        vm.expectCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.getTotalFeePercent.selector), 1);
        vm.expectCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.getFeeDenominator.selector), 1);
        uint256 fee = PerpDexLib.calculateOpenFee(marginAmount, leverage, externalContracts.feeContract);
        assertEq(fee, expectingFee);
        assertLt(fee, marginAmount);
    }

    function test_checkPositionSizeAndIncrease_long_true() public {
        delete tokenTotalSizes;
        PerpDexLib._addInitialTokenTotalSizes(tokenTotalSizes, tokenCount);
        PerpDexLib._changeMaxTokenTotalSizes(tokenTotalSizes);
        PerpDexLib.TokenType tokenType = PerpDexLib.TokenType.Btc;
        PerpDexLib.TokenTotalSize[] memory totalSize = tokenTotalSizes;
        uint256 size = 100_000;
        bool result = PerpDexLib.checkPositionSizeAndIncrease(tokenTotalSizes, tokenType, true, size);
        PerpDexLib.TokenTotalSize[] memory totalSizeAfter = tokenTotalSizes;

        assertEq(totalSizeAfter[uint256(tokenType)].currentLong, totalSize[uint256(tokenType)].currentLong + size);
        assertEq(totalSizeAfter[uint256(tokenType)].currentShort, totalSize[uint256(tokenType)].currentShort);
        assertEq(totalSizeAfter[uint256(tokenType)].maxLong, totalSize[uint256(tokenType)].maxLong);
        assertEq(totalSizeAfter[uint256(tokenType)].maxShort, totalSize[uint256(tokenType)].maxShort);
        assertEq(result, true);

        for (uint256 i = 0; i < tokenCount; i++) {
            if (i == uint256(tokenType)) {
                continue;
            }
            assertEq(totalSizeAfter[i].currentLong, totalSize[i].currentLong);
            assertEq(totalSizeAfter[i].currentShort, totalSize[i].currentShort);
            assertEq(totalSizeAfter[i].maxLong, totalSize[i].maxLong);
            assertEq(totalSizeAfter[i].maxShort, totalSize[i].maxShort);
        }
    }

    function test_checkPositionSizeAndIncrease_short_true() public {
        delete tokenTotalSizes;
        PerpDexLib._addInitialTokenTotalSizes(tokenTotalSizes, tokenCount);
        PerpDexLib._changeMaxTokenTotalSizes(tokenTotalSizes);
        PerpDexLib.TokenType tokenType = PerpDexLib.TokenType.Btc;
        PerpDexLib.TokenTotalSize[] memory totalSize = tokenTotalSizes;
        uint256 size = 100_000;
        bool result = PerpDexLib.checkPositionSizeAndIncrease(tokenTotalSizes, tokenType, false, size);
        PerpDexLib.TokenTotalSize[] memory totalSizeAfter = tokenTotalSizes;
        assertEq(totalSizeAfter[uint256(tokenType)].currentLong, totalSize[uint256(tokenType)].currentLong);
        assertEq(totalSizeAfter[uint256(tokenType)].currentShort, totalSize[uint256(tokenType)].currentShort + size);
        assertEq(result, true);

        for (uint256 i = 0; i < tokenCount; i++) {
            if (i == uint256(tokenType)) {
                continue;
            }
            assertEq(totalSizeAfter[i].currentLong, totalSize[i].currentLong);
            assertEq(totalSizeAfter[i].currentShort, totalSize[i].currentShort);
        }
    }

    function test_checkPositionSizeAndIncrease_long_false() public {
        delete tokenTotalSizes;
        PerpDexLib._addInitialTokenTotalSizes(tokenTotalSizes, tokenCount);
        PerpDexLib._changeMaxTokenTotalSizes(tokenTotalSizes);
        PerpDexLib.TokenType tokenType = PerpDexLib.TokenType.Btc;
        PerpDexLib.TokenTotalSize[] memory totalSize = tokenTotalSizes;

        bool result = PerpDexLib.checkPositionSizeAndIncrease(tokenTotalSizes, tokenType, true, 1_000_000_000_000_000);
        PerpDexLib.TokenTotalSize[] memory totalSizeAfter = tokenTotalSizes;
        assertEq(totalSizeAfter[uint256(tokenType)].currentLong, totalSize[uint256(tokenType)].currentLong);
        assertEq(totalSizeAfter[uint256(tokenType)].currentShort, totalSize[uint256(tokenType)].currentShort);
        assertEq(result, false);

        for (uint256 i = 0; i < tokenCount; i++) {
            if (i == uint256(tokenType)) {
                continue;
            }
            assertEq(totalSizeAfter[i].currentLong, totalSize[i].currentLong);
            assertEq(totalSizeAfter[i].currentShort, totalSize[i].currentShort);
        }
    }

    function test_checkPositionSizeAndIncrease_short_false() public {
        delete tokenTotalSizes;
        PerpDexLib._addInitialTokenTotalSizes(tokenTotalSizes, tokenCount);
        PerpDexLib._changeMaxTokenTotalSizes(tokenTotalSizes);
        PerpDexLib.TokenType tokenType = PerpDexLib.TokenType.Btc;
        PerpDexLib.TokenTotalSize[] memory totalSize = tokenTotalSizes;

        bool result = PerpDexLib.checkPositionSizeAndIncrease(tokenTotalSizes, tokenType, false, 1_000_000_000_000_000);
        PerpDexLib.TokenTotalSize[] memory totalSizeAfter = tokenTotalSizes;
        assertEq(totalSizeAfter[uint256(tokenType)].currentLong, totalSize[uint256(tokenType)].currentLong);
        assertEq(totalSizeAfter[uint256(tokenType)].currentShort, totalSize[uint256(tokenType)].currentShort);
        assertEq(result, false);

        for (uint256 i = 0; i < tokenCount; i++) {
            if (i == uint256(tokenType)) {
                continue;
            }
            assertEq(totalSizeAfter[i].currentLong, totalSize[i].currentLong);
            assertEq(totalSizeAfter[i].currentShort, totalSize[i].currentShort);
        }
    }

    function test_decreaseTotalPositionSize_revert() public {
        PerpDexLib.TokenType tokenType = PerpDexLib.TokenType.Btc;
        bool isLong = true;
        uint256 size = 100_000;

        vm.expectRevert(); // panic: arithmetic underflow or overflow (0x11)
        PerpDexLib.decreaseTotalPositionSize(tokenTotalSizes, tokenType, isLong, size);
    }

    function test_decreaseTotalPositionSize_long() public {
        PerpDexLib.TokenType tokenType = PerpDexLib.TokenType.Btc;
        bool isLong = true;
        uint256 size = 100_000;

        tokenTotalSizes[uint256(tokenType)].currentLong += 1_000_000_000;

        PerpDexLib.TokenTotalSize[] memory totalSize = tokenTotalSizes;
        PerpDexLib.decreaseTotalPositionSize(tokenTotalSizes, tokenType, isLong, size);

        assertEq(tokenTotalSizes[uint256(tokenType)].currentLong, totalSize[uint256(tokenType)].currentLong - size); // 🔥 only currentLong is decreased
        assertEq(tokenTotalSizes[uint256(tokenType)].currentShort, totalSize[uint256(tokenType)].currentShort);
        assertEq(tokenTotalSizes[uint256(tokenType)].maxLong, totalSize[uint256(tokenType)].maxLong);
        assertEq(tokenTotalSizes[uint256(tokenType)].maxShort, totalSize[uint256(tokenType)].maxShort);

        for (uint256 i = 0; i < tokenCount; i++) {
            if (i == uint256(tokenType)) {
                continue;
            }
            assertEq(tokenTotalSizes[i].currentLong, totalSize[i].currentLong);
            assertEq(tokenTotalSizes[i].currentShort, totalSize[i].currentShort);
            assertEq(tokenTotalSizes[i].maxLong, totalSize[i].maxLong);
            assertEq(tokenTotalSizes[i].maxShort, totalSize[i].maxShort);
        }
    }

    function test_decreaseTotalPositionSize_short() public {
        delete tokenTotalSizes;
        PerpDexLib._addInitialTokenTotalSizes(tokenTotalSizes, tokenCount);
        PerpDexLib._changeMaxTokenTotalSizes(tokenTotalSizes);

        PerpDexLib.TokenType tokenType = PerpDexLib.TokenType.Btc;
        bool isLong = false;
        uint256 size = 100_000;

        tokenTotalSizes[uint256(tokenType)].currentShort += 1_000_000_000; // opened short position

        PerpDexLib.TokenTotalSize[] memory totalSize = tokenTotalSizes;
        PerpDexLib.decreaseTotalPositionSize(tokenTotalSizes, tokenType, isLong, size);

        assertEq(tokenTotalSizes[uint256(tokenType)].currentShort, totalSize[uint256(tokenType)].currentShort - size);
        assertEq(tokenTotalSizes[uint256(tokenType)].currentLong, totalSize[uint256(tokenType)].currentLong);
        assertEq(tokenTotalSizes[uint256(tokenType)].maxLong, totalSize[uint256(tokenType)].maxLong);
        assertEq(tokenTotalSizes[uint256(tokenType)].maxShort, totalSize[uint256(tokenType)].maxShort);

        for (uint256 i = 0; i < tokenCount; i++) {
            if (i == uint256(tokenType)) {
                continue;
            }
            assertEq(tokenTotalSizes[i].currentLong, totalSize[i].currentLong);
            assertEq(tokenTotalSizes[i].currentShort, totalSize[i].currentShort);
            assertEq(tokenTotalSizes[i].maxLong, totalSize[i].maxLong);
            assertEq(tokenTotalSizes[i].maxShort, totalSize[i].maxShort);
        }
    }

    function test_cleanUpLimitOrder() public {
        uint256 orderCount = 5;

        for (uint256 i = 0; i < orderCount; i++) {
            createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        }

        uint256 cleanUpOrderId = 2;
        PerpDexLib.Position memory _order = positions[cleanUpOrderId];
        PerpDexLib.cleanUpLimitOrder(positions, limitOrderIds, cleanUpOrderId); // 🚀

        assertEq(limitOrderIds.length, orderCount - 1);

        for (uint256 i = 0; i < limitOrderIds.length; i++) {
            assertNotEq(limitOrderIds[i], cleanUpOrderId);
        }

        PerpDexLib.Position memory closedOrder = positions[cleanUpOrderId];
        assertEq(closedOrder.limitOrderIndex, type(uint256).max);
        assertNotEq(closedOrder.limitOrderIndex, _order.limitOrderIndex);
    }

    function test_cleanUpLimitOrder_revert() public {
        uint256 orderCount = 5;
        resetPositions(orderCount);
        delete limitOrderIds;

        for (uint256 i = 0; i < 5; i++) {
            createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        }

        uint256 cleanUpOrderId = 5;

        limitOrderIds.pop(); // remove positionId 5
        vm.expectRevert("Invalid limit order index");
        PerpDexLib.cleanUpLimitOrder(positions, limitOrderIds, cleanUpOrderId);

        delete limitOrderIds;
        vm.expectRevert("No limit orders");
        PerpDexLib.cleanUpLimitOrder(positions, limitOrderIds, cleanUpOrderId);
    }

    function test_updateAndClearTraderOpenPositionId() public {
        PerpDexLib.updateTraderOpenPositionId(true, 1, traderOpenPositionIds[msg.sender][uint16(PerpDexLib.TokenType.Btc)]);
        PerpDexLib.updateTraderOpenPositionId(false, 2, traderOpenPositionIds[msg.sender][uint16(PerpDexLib.TokenType.Btc)]);

        assertEq(traderOpenPositionIds[msg.sender][uint16(PerpDexLib.TokenType.Btc)].longPositionId, 1);
        assertEq(traderOpenPositionIds[msg.sender][uint16(PerpDexLib.TokenType.Btc)].shortPositionId, 2);

        vm.expectRevert("Long position already exists");
        PerpDexLib.updateTraderOpenPositionId(true, 1, traderOpenPositionIds[msg.sender][uint16(PerpDexLib.TokenType.Btc)]);
        vm.expectRevert("Short position already exists");
        PerpDexLib.updateTraderOpenPositionId(false, 2, traderOpenPositionIds[msg.sender][uint16(PerpDexLib.TokenType.Btc)]);

        PerpDexLib.clearTraderOpenPositionId(true, traderOpenPositionIds[msg.sender][uint16(PerpDexLib.TokenType.Btc)]);
        assertEq(traderOpenPositionIds[msg.sender][uint16(PerpDexLib.TokenType.Btc)].longPositionId, 0);
        PerpDexLib.clearTraderOpenPositionId(false, traderOpenPositionIds[msg.sender][uint16(PerpDexLib.TokenType.Btc)]);
        assertEq(traderOpenPositionIds[msg.sender][uint16(PerpDexLib.TokenType.Btc)].shortPositionId, 0);
    }

    function test_cleanUpPosition_close() public {
        openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Klay, 2_000_000, 10, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Eth, 2_000_000, 10, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Pepe, 2_000_000, 10, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Trump, 2_000_000, 10, true, 200_000_000, 0, 0);

        uint256 cleanUpPositionId = 2;
        uint256 closingPrice = 100;
        PerpDexLib.Position memory position = positions[cleanUpPositionId];
        PerpDexLib.cleanUpPosition(
            positions,
            openPositionIds,
            cleanUpPositionId,
            closingPrice,
            PerpDexLib.PositionStatus.Closed,
            traderOpenPositionIds[position.traderAddr][uint16(position.tokenType)]
        ); // 🚀

        assertEq(openPositionIds.length, 4);
        for (int256 i = 0; i < int256(openPositionIds.length); i++) {
            assertNotEq(openPositionIds[uint256(i)], cleanUpPositionId);
        }

        position.statusTime.closeTime = block.timestamp;
        position.positionStatus = PerpDexLib.PositionStatus.Closed;
        position.finalPrice = closingPrice;
        position.openPositionIndex = type(uint256).max;
        assertPosition(positions[cleanUpPositionId], position);
    }

    function test_cleanUpPosition_liquidate() public {
        openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Klay, 2_000_000, 10, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Eth, 2_000_000, 10, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Pepe, 2_000_000, 10, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Trump, 2_000_000, 10, true, 200_000_000, 0, 0);

        uint256 cleanUpPositionId = 2;
        uint256 closingPrice = 100;
        PerpDexLib.Position memory position = positions[cleanUpPositionId];
        PerpDexLib.cleanUpPosition(
            positions,
            openPositionIds,
            cleanUpPositionId,
            closingPrice,
            PerpDexLib.PositionStatus.Liquidated,
            traderOpenPositionIds[position.traderAddr][uint16(position.tokenType)]
        ); // 🚀

        assertEq(openPositionIds.length, 4);

        for (int256 i = 0; i < int256(openPositionIds.length); i++) {
            assertNotEq(openPositionIds[uint256(i)], cleanUpPositionId);
        }

        position.statusTime.liquidatedTime = block.timestamp;
        position.positionStatus = PerpDexLib.PositionStatus.Liquidated;
        position.finalPrice = closingPrice;
        position.openPositionIndex = type(uint256).max;
        assertPosition(positions[cleanUpPositionId], position);
    }

    function test_cleanUpPosition_rollback() public {
        openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Klay, 2_000_000, 10, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Eth, 2_000_000, 10, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Pepe, 2_000_000, 10, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Trump, 2_000_000, 10, true, 200_000_000, 0, 0);

        uint256 cleanUpPositionId = 2;
        uint256 closingPrice = 100;
        PerpDexLib.Position memory position = positions[cleanUpPositionId];
        PerpDexLib.cleanUpPosition(
            positions,
            openPositionIds,
            cleanUpPositionId,
            closingPrice,
            PerpDexLib.PositionStatus.RolledBack,
            traderOpenPositionIds[position.traderAddr][uint16(position.tokenType)]
        ); // 🚀

        assertEq(openPositionIds.length, 4);

        for (int256 i = 0; i < int256(openPositionIds.length); i++) {
            assertNotEq(openPositionIds[uint256(i)], cleanUpPositionId);
        }

        position.statusTime.closeTime = block.timestamp;
        position.positionStatus = PerpDexLib.PositionStatus.RolledBack;
        position.finalPrice = closingPrice;
        position.openPositionIndex = type(uint256).max;
        assertPosition(positions[cleanUpPositionId], position);
    }

    function test_cleanUpPosition_revert() public {
        openPositionDefault(user, PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Klay, 2_000_000, 10, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Eth, 2_000_000, 10, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Pepe, 2_000_000, 10, true, 200_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Trump, 2_000_000, 10, true, 200_000_000, 0, 0);

        uint256 cleanUpPositionId = 5;
        uint256 closingPrice = 100;
        PerpDexLib.TraderOpenPositionId storage tId = traderOpenPositionIds[msg.sender][uint16(PerpDexLib.TokenType.Btc)];

        vm.expectRevert("Price is 0");
        PerpDexLib.cleanUpPosition(positions, openPositionIds, cleanUpPositionId, 0, PerpDexLib.PositionStatus.Closed, tId); // 🚀

        delete openPositionIds;
        vm.expectRevert("No open positions");
        PerpDexLib.cleanUpPosition(positions, openPositionIds, cleanUpPositionId, closingPrice, PerpDexLib.PositionStatus.Closed, tId); // 🚀

        openPositionIds.push(1);
        openPositionIds.push(2);
        openPositionIds.push(3);
        openPositionIds.push(4);
        // openPositionIds.push(5); missed one

        vm.expectRevert("Invalid position index");
        PerpDexLib.cleanUpPosition(positions, openPositionIds, cleanUpPositionId, closingPrice, PerpDexLib.PositionStatus.Closed, tId); // 🚀

        openPositionIds.push(5);

        vm.expectRevert("Wrong position status");
        PerpDexLib.cleanUpPosition(positions, openPositionIds, cleanUpPositionId, closingPrice, PerpDexLib.PositionStatus.Open, tId); // 🚀
        vm.expectRevert("Wrong position status");
        PerpDexLib.cleanUpPosition(positions, openPositionIds, cleanUpPositionId, closingPrice, PerpDexLib.PositionStatus.Initial, tId); // 🚀
        vm.expectRevert("Wrong position status");
        PerpDexLib.cleanUpPosition(positions, openPositionIds, cleanUpPositionId, closingPrice, PerpDexLib.PositionStatus.RequestOpen, tId); // 🚀
        vm.expectRevert("Wrong position status");
        PerpDexLib.cleanUpPosition(
            positions,
            openPositionIds,
            cleanUpPositionId,
            closingPrice,
            PerpDexLib.PositionStatus.LimitOrderOpen,
            tId // 🚀
        );
        vm.expectRevert("Wrong position status");
        PerpDexLib.cleanUpPosition(
            positions,
            openPositionIds,
            cleanUpPositionId,
            closingPrice,
            PerpDexLib.PositionStatus.LimitOrderClosed,
            tId // 🚀
        );
    }

    function test_mergePosition_ok() public {
        vm.warp(200);
        uint256 oldPId = openPositionDefault(msg.sender, PerpDexLib.TokenType.Btc, 1_000_000_000, 10, true, 100, 101, 99);
        PerpDexLib.Position memory oldP = positions[oldPId];

        PerpDexLib.Position memory newP = PerpDexLib.Position({
            positionId: 2,
            traderAddr: msg.sender,
            tokenType: PerpDexLib.TokenType.Btc,
            margin: 2_000_000_000,
            size: 2_000_000_000 * 30,
            openFee: 4,
            initialPrice: 0,
            isLong: true,
            openPositionIndex: type(uint256).max,
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
            tpPrice: 102,
            slPrice: 0,
            marginUpdatedTime: 0,
            accFundingFeePerSize: 0,
            fundingFee: 0,
            closeFee: 0,
            tpslUpdatedTime: block.timestamp
        });

        positions[2] = newP;

        uint256 currentPrice = 200;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.PositionMerged(
            1,
            2,
            msg.sender,
            PerpDexLib.TokenType.Btc,
            oldP.margin + newP.margin,
            oldP.size + newP.size,
            175,
            true,
            102,
            99,
            oldP.fundingFee
        );

        PerpDexLib.MergePositions memory mergePos = PerpDexLib.MergePositions({oldPos: 1, newPos: 2});
        PerpDexLib.mergePosition(
            positions, fundingFeeTokenStates[positions[0].tokenType], fundingFeeGlobalState, externalContracts, mergePos, currentPrice
        ); // 🚀

        oldP.margin += newP.margin;
        oldP.size += newP.size;
        oldP.openFee += newP.openFee;
        oldP.initialPrice = 175;
        oldP.statusTime.openTime = block.timestamp;
        oldP.tpslUpdatedTime = block.timestamp;
        oldP.tpPrice = 102;
        assertPosition(positions[1], oldP);

        newP.positionStatus = PerpDexLib.PositionStatus.Merged;
        newP.statusTime.openTime = block.timestamp;
        newP.initialPrice = currentPrice;
        assertPosition(positions[2], newP);
    }

    function test_mergePosition_revert() public {
        vm.warp(200);
        PerpDexLib.Position memory pos0 = PerpDexLib.Position({
            positionId: 0,
            traderAddr: msg.sender,
            tokenType: PerpDexLib.TokenType.Btc,
            margin: 1_000_000_000,
            size: 1_000_000_000 * 10,
            openFee: 3,
            initialPrice: 100,
            isLong: true,
            openPositionIndex: 0,
            finalPrice: 0,
            positionStatus: PerpDexLib.PositionStatus.Open,
            limitOrderPrice: 0,
            limitOrderIndex: type(uint256).max,
            statusTime: PerpDexLib.StatusTime({
                requestOpenTime: 0,
                openTime: block.timestamp - 50,
                closeTime: 0,
                limitOpenTime: 0,
                limitCloseTime: 0,
                liquidatedTime: 0
            }),
            pnl: 0,
            liquidationPrice: 90,
            tpPrice: 0,
            slPrice: 0,
            marginUpdatedTime: 0,
            accFundingFeePerSize: 0,
            fundingFee: 0,
            closeFee: 0,
            tpslUpdatedTime: block.timestamp
        });

        PerpDexLib.Position memory pos1 = PerpDexLib.Position({
            positionId: 1,
            traderAddr: msg.sender,
            tokenType: PerpDexLib.TokenType.Btc,
            margin: 2_000_000_000,
            size: 2_000_000_000 * 10,
            openFee: 4,
            initialPrice: 0,
            isLong: true,
            openPositionIndex: type(uint256).max,
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
            tpPrice: 0,
            slPrice: 0,
            marginUpdatedTime: 0,
            accFundingFeePerSize: 0,
            fundingFee: 0,
            closeFee: 0,
            tpslUpdatedTime: block.timestamp
        });

        positions[0] = pos0;
        positions[1] = pos1;

        PerpDexLib.MergePositions memory mergePos = PerpDexLib.MergePositions({oldPos: 0, newPos: 1});
        uint256 currentPrice = 200;

        positions[1].statusTime.openTime = 0;
        vm.expectRevert("Position to merge must be being newly open or opened by limit order");
        PerpDexLib.mergePosition(
            positions, fundingFeeTokenStates[positions[0].tokenType], fundingFeeGlobalState, externalContracts, mergePos, currentPrice
        ); // 🚀

        positions[1].statusTime.openTime = block.timestamp;
        positions[1].positionStatus = PerpDexLib.PositionStatus.Closed;
        vm.expectRevert("Position to merge must be being newly open or opened by limit order");
        PerpDexLib.mergePosition(
            positions, fundingFeeTokenStates[positions[0].tokenType], fundingFeeGlobalState, externalContracts, mergePos, currentPrice
        ); // 🚀

        positions[1].positionStatus = PerpDexLib.PositionStatus.Open;
        PerpDexLib.mergePosition(
            positions, fundingFeeTokenStates[positions[0].tokenType], fundingFeeGlobalState, externalContracts, mergePos, currentPrice
        ); // 🚀

        resetPositions(2);
        positions[0] = pos0;
        positions[1] = pos1;
        positions[1].statusTime.openTime = 0;
        positions[1].positionStatus = PerpDexLib.PositionStatus.LimitOrderOpen;
        PerpDexLib.mergePosition(
            positions, fundingFeeTokenStates[positions[0].tokenType], fundingFeeGlobalState, externalContracts, mergePos, currentPrice
        ); // 🚀

        resetPositions(2);
        positions[0] = pos0;
        positions[1] = pos1;
        positions[1].positionStatus = PerpDexLib.PositionStatus.Open;
        positions[0].positionStatus = PerpDexLib.PositionStatus.Closed;
        vm.expectRevert("Old position status is not Open");
        PerpDexLib.mergePosition(
            positions, fundingFeeTokenStates[positions[0].tokenType], fundingFeeGlobalState, externalContracts, mergePos, currentPrice
        ); // 🚀

        currentPrice = 0;
        positions[0].positionStatus = PerpDexLib.PositionStatus.Open;
        vm.expectRevert("Price is 0");
        PerpDexLib.mergePosition(
            positions, fundingFeeTokenStates[positions[0].tokenType], fundingFeeGlobalState, externalContracts, mergePos, currentPrice
        ); // 🚀

        positions[1].traderAddr = address(1);
        currentPrice = 200;
        vm.expectRevert("Trader is different");
        PerpDexLib.mergePosition(
            positions, fundingFeeTokenStates[positions[0].tokenType], fundingFeeGlobalState, externalContracts, mergePos, currentPrice
        ); // 🚀

        positions[1].traderAddr = msg.sender;
        positions[1].tokenType = PerpDexLib.TokenType.Eth;
        vm.expectRevert("TokenType is different");
        PerpDexLib.mergePosition(
            positions, fundingFeeTokenStates[positions[0].tokenType], fundingFeeGlobalState, externalContracts, mergePos, currentPrice
        ); // 🚀

        positions[1].tokenType = PerpDexLib.TokenType.Btc;
        positions[1].isLong = false;
        vm.expectRevert("IsLong is different");
        PerpDexLib.mergePosition(
            positions, fundingFeeTokenStates[positions[0].tokenType], fundingFeeGlobalState, externalContracts, mergePos, currentPrice
        ); // 🚀

        positions[1].isLong = true;
        positions[0].statusTime.openTime = block.timestamp + 1;
        vm.expectRevert("Old position status time is not correct");
        PerpDexLib.mergePosition(
            positions, fundingFeeTokenStates[positions[0].tokenType], fundingFeeGlobalState, externalContracts, mergePos, currentPrice
        ); // 🚀

        positions[0].statusTime.openTime = block.timestamp - 50;
        PerpDexLib.mergePosition(
            positions, fundingFeeTokenStates[positions[0].tokenType], fundingFeeGlobalState, externalContracts, mergePos, currentPrice
        ); // 🚀
    }

    function test_createNewPosition_ok() public {
        (,,, PerpDexLib.OraclePrices memory bisonAIData,) = getOracleBase(1);
        PerpDexLib.OpenPositionData memory data = PerpDexLib.OpenPositionData({
            tokenType: PerpDexLib.TokenType.Btc,
            marginAmount: 2_000_000,
            leverage: 10,
            long: true,
            trader: user,
            priceData: bisonAIData,
            tpPrice: 0,
            slPrice: 0,
            expectedPrice: 200_000_000,
            userSignedData: hex"1234"
        });

        PerpDexLib.Position memory p = PerpDexLib.createNewPosition(
            1, data, 200_000_000, 2, fundingFeeTokenStates[data.tokenType].accFeePerSize, tokenTotalSizes, externalContracts.feeContract
        ); // 🚀

        PerpDexLib.Position memory expected = PerpDexLib.Position({
            positionId: 1,
            traderAddr: user,
            tokenType: PerpDexLib.TokenType.Btc,
            margin: 2_000_000 - 14_000,
            size: (2_000_000 - 14_000) * 10,
            openFee: 14_000,
            initialPrice: 200_000_000,
            isLong: true,
            openPositionIndex: 2,
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
            tpPrice: 0,
            slPrice: 0,
            marginUpdatedTime: 0,
            accFundingFeePerSize: 0,
            fundingFee: 0,
            closeFee: 0,
            tpslUpdatedTime: block.timestamp
        });

        assertPosition(p, expected);
    }

    function test_createNewPosition_revert() public {
        delete tokenTotalSizes;
        PerpDexLib._addInitialTokenTotalSizes(tokenTotalSizes, tokenCount);
        PerpDexLib._changeMaxTokenTotalSizes(tokenTotalSizes);
        (,,, PerpDexLib.OraclePrices memory bisonAIData,) = getOracleBase(1);
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

        data.leverage = 2;

        vm.expectRevert("Leverage must be within range");
        PerpDexLib.createNewPosition(
            1, data, 200_000_000, 2, fundingFeeTokenStates[data.tokenType].accFeePerSize, tokenTotalSizes, externalContracts.feeContract
        ); // 🚀

        data.leverage = 101;
        vm.expectRevert("Leverage must be within range");
        PerpDexLib.createNewPosition(
            1, data, 200_000_000, 2, fundingFeeTokenStates[data.tokenType].accFeePerSize, tokenTotalSizes, externalContracts.feeContract
        ); // 🚀

        // -----
        data.leverage = 3;
        tokenTotalSizes[0].maxLong = 0;
        vm.expectRevert("Maximum position size reached");
        PerpDexLib.createNewPosition(
            1, data, 200_000_000, 2, fundingFeeTokenStates[data.tokenType].accFeePerSize, tokenTotalSizes, externalContracts.feeContract
        ); // 🚀
    }

    function test_openPositionForLimitOrder_ok() public {
        uint256 wantedPrice = 1_000_000;
        uint256 orderId = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, wantedPrice, 0, 0);
        PerpDexLib.Position memory order = positions[orderId];

        uint256 openPositionIdsLengthBefore = openPositionIds.length;

        uint256 currentPrice = 500_000;

        vm.mockCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector), abi.encode());

        vm.expectCall(address(PerpDexLib), abi.encodeWithSelector(PerpDexLib.updateTraderOpenPositionId.selector), 1);

        vm.expectEmit(true, true, true, true);
        emit PerpDex.PositionOpened(
            order.positionId,
            order.traderAddr,
            order.tokenType,
            order.margin,
            order.size,
            currentPrice,
            order.isLong,
            order.tpPrice,
            order.slPrice
        );

        PerpDexBotLib.openPositionForLimitOrder(
            positions[orderId],
            currentPrice,
            openPositionIds,
            traderOpenPositionIds[order.traderAddr][uint16(order.tokenType)],
            fundingFeeTokenStates[order.tokenType].accFeePerSize,
            externalContracts.feeContract
        ); // 🚀

        order.initialPrice = currentPrice;
        order.openPositionIndex = openPositionIds.length - 1;
        order.positionStatus = PerpDexLib.PositionStatus.Open;
        order.statusTime.openTime = block.timestamp;

        order.accFundingFeePerSize = 0;
        order.limitOrderIndex = 0; // cleanUpLimitOrder is not called inside openPositionForLimitOrder
        assertPosition(positions[orderId], order);

        assertEq(openPositionIds.length, openPositionIdsLengthBefore + 1);
        assertEq(openPositionIds[openPositionIds.length - 1], orderId);
        assertEq(traderOpenPositionIds[order.traderAddr][uint16(order.tokenType)].longPositionId, orderId);
    }

    function test_openPositionForLimitOrder_revert() public {
        uint256 wantedPrice = 1_000_000;
        uint256 limitOrderId = 3;
        positions[1] = PerpDexLib.Position({
            positionId: limitOrderId,
            traderAddr: user,
            tokenType: PerpDexLib.TokenType.Btc,
            margin: 2_000_000,
            size: 2_000_000 * 10,
            openFee: 0, // Fee is paid later when limitOrder is opened.
            initialPrice: 100_000,
            isLong: true,
            openPositionIndex: 0,
            finalPrice: 0,
            positionStatus: PerpDexLib.PositionStatus.LimitOrderOpen,
            limitOrderPrice: wantedPrice,
            limitOrderIndex: type(uint256).max,
            statusTime: PerpDexLib.StatusTime({
                requestOpenTime: 0,
                openTime: 0,
                closeTime: 0,
                limitOpenTime: block.timestamp,
                limitCloseTime: 0,
                liquidatedTime: 0
            }),
            pnl: 0,
            liquidationPrice: 0,
            tpPrice: 0,
            slPrice: 0,
            marginUpdatedTime: 0,
            accFundingFeePerSize: 0,
            fundingFee: 0,
            closeFee: 0,
            tpslUpdatedTime: block.timestamp
        });

        PerpDexLib.Position storage order = positions[1];

        uint256 currentPrice = 500_000;

        PerpDexLib.TraderOpenPositionId storage traderOpenPositionId = traderOpenPositionIds[order.traderAddr][uint16(order.tokenType)];

        vm.expectRevert("Price is 0");
        PerpDexBotLib.openPositionForLimitOrder(
            order,
            0,
            openPositionIds,
            traderOpenPositionId,
            fundingFeeTokenStates[order.tokenType].accFeePerSize,
            externalContracts.feeContract
        ); // 🚀

        order.positionStatus = PerpDexLib.PositionStatus.Open;
        vm.expectRevert("Status is not limit order open");
        PerpDexBotLib.openPositionForLimitOrder(
            order,
            currentPrice,
            openPositionIds,
            traderOpenPositionId,
            fundingFeeTokenStates[order.tokenType].accFeePerSize,
            externalContracts.feeContract
        ); // 🚀

        order.positionStatus = PerpDexLib.PositionStatus.LimitOrderClosed;
        vm.expectRevert("Status is not limit order open");
        PerpDexBotLib.openPositionForLimitOrder(
            order,
            currentPrice,
            openPositionIds,
            traderOpenPositionId,
            fundingFeeTokenStates[order.tokenType].accFeePerSize,
            externalContracts.feeContract
        ); // 🚀
    }

    function test_createLimitOrder_ok() public view {
        PerpDexLib.OpenLimitOrderData memory o = PerpDexLib.OpenLimitOrderData({
            tokenType: PerpDexLib.TokenType.Eth,
            marginAmount: 2_000_000,
            leverage: 3,
            long: true,
            trader: user,
            wantedPrice: 190_000_000,
            tpPrice: 1234,
            slPrice: 123,
            userSignedData: hex"1234"
        });

        PerpDexLib.Position memory _order = PerpDexLib.createLimitOrder(123, o, 29, externalContracts.feeContract); // 🚀
        PerpDexLib.Position memory expected = PerpDexLib.Position({
            positionId: 123,
            traderAddr: user,
            tokenType: PerpDexLib.TokenType.Eth,
            margin: 1_995_800,
            size: 1_995_800 * 3,
            openFee: 4200,
            initialPrice: 0,
            isLong: true,
            openPositionIndex: type(uint256).max,
            finalPrice: 0,
            positionStatus: PerpDexLib.PositionStatus.LimitOrderOpen,
            limitOrderPrice: 190_000_000,
            limitOrderIndex: 29,
            statusTime: PerpDexLib.StatusTime({
                requestOpenTime: 0,
                openTime: 0,
                closeTime: 0,
                limitOpenTime: block.timestamp,
                limitCloseTime: 0,
                liquidatedTime: 0
            }),
            pnl: 0,
            liquidationPrice: 0,
            tpPrice: 1234,
            slPrice: 123,
            marginUpdatedTime: 0,
            accFundingFeePerSize: 0,
            fundingFee: 0,
            closeFee: 0,
            tpslUpdatedTime: block.timestamp
        });

        assertPosition(_order, expected);
    }

    function test_setTpslPrice_ok() public {
        uint256 positionId = openPositionDefault(user, PerpDexLib.TokenType.Pepe, 1000, 10, true, 0, 1200, 800);
        PerpDexLib.Position storage order = positions[positionId];

        vm.expectEmit(true, true, true, true);
        emit PerpDex.TPSLSet(1, user, 0, 0);
        PerpDexLib._setTpslPrice(order, 0, 0);
        assertEq(order.tpPrice, 0);
        assertEq(order.slPrice, 0);

        vm.expectEmit(true, true, true, true);
        emit PerpDex.TPSLSet(1, user, 1100, 900);
        PerpDexLib._setTpslPrice(order, 1100, 900);
        assertEq(order.tpPrice, 1100);
        assertEq(order.slPrice, 900);

        vm.expectEmit(true, true, true, true);
        emit PerpDex.TPSLSet(1, user, 0, 900);
        PerpDexLib._setTpslPrice(order, 0, 900);
        assertEq(order.tpPrice, 0);
        assertEq(order.slPrice, 900);

        vm.expectEmit(true, true, true, true);
        emit PerpDex.TPSLSet(1, user, 1100, 0);
        PerpDexLib._setTpslPrice(order, 1100, 0);
        assertEq(order.tpPrice, 1100);
        assertEq(order.slPrice, 0);

        order.positionStatus = PerpDexLib.PositionStatus.Open;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.TPSLSet(1, user, 1100, 900);
        PerpDexLib._setTpslPrice(order, 1100, 900);
        assertEq(order.tpPrice, 1100);
        assertEq(order.slPrice, 900);

        assertEq(order.tpslUpdatedTime, block.timestamp, "tpslUpdatedTime");

        order.positionStatus = PerpDexLib.PositionStatus.Closed;
        vm.expectRevert("Position is not open");
        PerpDexLib._setTpslPrice(order, 1100, 900);
    }

    function test__openLimitOrder_ok() public {
        OpenPositionInput memory input = getOpenPositionInput(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 0, 0);

        // Execute openLimitOrder
        PerpDexLib.OpenLimitOrderData memory o = PerpDexLib.OpenLimitOrderData({
            tokenType: input.inputTokenType,
            marginAmount: input.marginAmount,
            leverage: input.leverage,
            long: input.isLong,
            trader: input.traderAddr,
            wantedPrice: 190_000_000,
            tpPrice: input.tpPrice,
            slPrice: input.slPrice,
            userSignedData: mockSignedData
        });

        uint256 limitOrderId = this.nextPositionId();
        uint256 limitOrderLengthBefore = limitOrderIds.length;

        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferFromAndCheckBalance.selector), abi.encode()
        );

        uint256 fee = PerpDexLib.calculateOpenFee(input.marginAmount, input.leverage, externalContracts.feeContract);
        uint256 marginAfterFee = input.marginAmount - fee;
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(
                PerpDexPricesLib.safeTransferFromAndCheckBalance.selector, input.traderAddr, address(this), input.marginAmount
            ),
            1
        );
        vm.expectCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector, input.traderAddr, fee), 0);

        vm.expectEmit(true, true, true, true);
        emit LimitOrderOpened(
            limitOrderId,
            input.traderAddr,
            input.inputTokenType,
            marginAfterFee,
            marginAfterFee * input.leverage,
            190_000_000,
            input.isLong,
            input.tpPrice,
            input.slPrice
        );

        vm.prank(singleOpenAdmin);
        PerpDexLib._openLimitOrder(o, nextPositionId, positions, traderPositionIds, limitOrderIds, externalContracts); // 🚀

        PerpDexLib.Position memory limitOrder = positions[limitOrderId];
        PerpDexLib.Position memory compareTo = PerpDexLib.Position({
            positionId: limitOrderId,
            traderAddr: input.traderAddr,
            tokenType: input.inputTokenType,
            margin: marginAfterFee,
            size: marginAfterFee * input.leverage,
            openFee: fee,
            initialPrice: 0,
            isLong: input.isLong,
            openPositionIndex: type(uint256).max,
            finalPrice: 0,
            positionStatus: PerpDexLib.PositionStatus.LimitOrderOpen,
            limitOrderPrice: 190_000_000,
            limitOrderIndex: limitOrderLengthBefore,
            statusTime: PerpDexLib.StatusTime({
                requestOpenTime: 0,
                openTime: 0,
                closeTime: 0,
                limitOpenTime: block.timestamp,
                limitCloseTime: 0,
                liquidatedTime: 0
            }),
            pnl: 0,
            liquidationPrice: 0,
            tpPrice: input.tpPrice,
            slPrice: input.slPrice,
            marginUpdatedTime: 0,
            accFundingFeePerSize: 0,
            fundingFee: 0,
            closeFee: 0,
            tpslUpdatedTime: block.timestamp
        });

        assertPosition(limitOrder, compareTo);

        assertEq(limitOrderIds.length, limitOrderLengthBefore + 1);
        assertEq(limitOrderIds.length, limitOrder.limitOrderIndex + 1);
        assertEq(limitOrderIds[limitOrderIds.length - 1], limitOrderId);
        uint256[] storage positionIds = traderPositionIds[input.traderAddr];
        assertEq(positionIds[positionIds.length - 1], limitOrderId, "positionIds");
    }

    function test__openLimitOrder_revert() public {
        OpenPositionInput memory input = getOpenPositionInput(PerpDexLib.TokenType.Btc, 2_000_000, 1, true, 0, 0);

        PerpDexLib.OpenLimitOrderData memory o = PerpDexLib.OpenLimitOrderData({
            tokenType: input.inputTokenType,
            marginAmount: input.marginAmount,
            leverage: input.leverage,
            long: input.isLong,
            trader: input.traderAddr,
            wantedPrice: 190_000_000,
            tpPrice: input.tpPrice,
            slPrice: input.slPrice,
            userSignedData: hex"1234"
        });

        vm.startPrank(singleOpenAdmin);
        vm.expectRevert("Leverage must be within range"); // leverage 1 (too low)

        PerpDexLib._openLimitOrder(o, nextPositionId, positions, traderPositionIds, limitOrderIds, externalContracts); // 🚀

        o.leverage = 101;
        vm.expectRevert("Leverage must be within range"); // leverage 101 (too high)
        PerpDexLib._openLimitOrder(o, nextPositionId, positions, traderPositionIds, limitOrderIds, externalContracts); // 🚀

        o.wantedPrice = 0;
        o.leverage = 3;
        vm.expectRevert("Price is 0"); // price is 0
        PerpDexLib._openLimitOrder(o, nextPositionId, positions, traderPositionIds, limitOrderIds, externalContracts); // 🚀

        o.wantedPrice = 190_000_000;
        positions[nextPositionId].positionStatus = PerpDexLib.PositionStatus.LimitOrderOpen;
        vm.expectRevert(abi.encodeWithSelector(NextPositionIdExists.selector));
        PerpDexLib._openLimitOrder(o, nextPositionId, positions, traderPositionIds, limitOrderIds, externalContracts); // 🚀
    }

    function test__closeLimitOrder_ok() public {
        uint256 orderId = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);
        PerpDexLib.Position memory order = positions[orderId];
        uint256 limitOrderIdsLengthBefore = limitOrderIds.length;

        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());
        vm.expectCall(
            address(PerpDexPricesLib),
            abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector, order.traderAddr, order.margin + order.openFee),
            1
        );

        vm.expectCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector), 0);

        vm.expectEmit(true, true, true, true);
        emit LimitOrderClosed(orderId, order.traderAddr);

        vm.startPrank(closeAdmin);
        PerpDexLib._closeLimitOrder(positions[orderId], positions, limitOrderIds, externalContracts); // 🚀

        PerpDexLib.Position memory orderAfter = positions[orderId];
        order.positionStatus = PerpDexLib.PositionStatus.LimitOrderClosed;
        order.statusTime.limitCloseTime = block.timestamp;
        order.limitOrderIndex = type(uint256).max;

        assertPosition(orderAfter, order);

        assertEq(limitOrderIds.length, limitOrderIdsLengthBefore - 1);
    }

    function test__closeLimitOrder_revert() public {
        uint256 orderId = createLimitOrderDefault(PerpDexLib.TokenType.Btc, 2_000_000, 10, true, 200_000_000, 0, 0);

        vm.startPrank(closeAdmin);

        positions[orderId].positionStatus = PerpDexLib.PositionStatus.LimitOrderClosed;
        vm.expectRevert(abi.encodeWithSelector(InvalidPositionStatus.selector));
        PerpDexLib._closeLimitOrder(positions[orderId], positions, limitOrderIds, externalContracts); // 🚀

        positions[orderId].positionStatus = PerpDexLib.PositionStatus.Open;
        vm.expectRevert(abi.encodeWithSelector(InvalidPositionStatus.selector));
        PerpDexLib._closeLimitOrder(positions[orderId], positions, limitOrderIds, externalContracts); // 🚀
    }
}
