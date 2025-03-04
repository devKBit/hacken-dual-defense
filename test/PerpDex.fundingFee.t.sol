// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./PerpDexTestBase.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Test, console} from "forge-std/Test.sol";

contract PerpDexFundingFeeTest is PerpDexTestBase {
    function initFundingFee() public {
        vm.startPrank(owner());
        this.updateFundingFeeStates();
        vm.stopPrank();
    }

    function initBufferBalance(uint256 balance) public {
        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferFromAndCheckBalance.selector), abi.encode()
        );
        vm.prank(admin);
        this.depositFundingFeeGlobalStateBalance(balance);
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
        this.closePosition(positionId, bisonAIData, hex"1234");
    }

    function test_fundingFee_0() public {
        initFundingFee();
        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());

        // open
        vm.warp(2454);
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(block.timestamp, PerpDexLib.TokenType.Btc, 0, 0, 0, 0);
        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 40_000_000, 100, true, 9_758_229_718_051, 0, 0);

        vm.warp(2500);
        vm.expectEmit(true, true, true, true);
        int256 fundingRate1 = int256(875 * 1e20 / 1e7);
        int256 timeDiff = 2500 - 2454;
        emit PerpDex.FundingFeeStateUpdated(
            block.timestamp, PerpDexLib.TokenType.Btc, fundingRate1, fundingRate1 * timeDiff / 3600, 3_720_000_000, 0
        );
        uint256 shortPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 20_000_000, 100, false, 1_000_000, 0, 0);

        // close
        vm.warp(2513);
        int256 fundingRate2 = int256(875 * 1e20 / 1e7) / 3;
        int256 timeDiff2 = 2513 - 2500;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(
            block.timestamp,
            PerpDexLib.TokenType.Btc,
            fundingRate2,
            (fundingRate1 * timeDiff / 3600) + (fundingRate2 * timeDiff2 / 3600),
            3_720_000_000,
            1_860_000_000
        );
        closePositionDefault(longPId, 1_000_000);

        vm.warp(2527);
        int256 fundingRate3 = int256(-875 * 1e20 / 1e7);
        int256 timeDiff3 = 2527 - 2513;
        int256 accFeePerSize3 = (fundingRate1 * timeDiff / 3600) + (fundingRate2 * timeDiff2 / 3600) + (fundingRate3 * timeDiff3 / 3600);
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(block.timestamp, PerpDexLib.TokenType.Btc, fundingRate3, accFeePerSize3, 0, 1_860_000_000);
        closePositionDefault(shortPId, 1_000_000);

        assertEq(positions[longPId].fundingFee, (int256(positions[longPId].size) * ((875 * 46 + int256(875 * 13) / 3))) / (1e7 * 3600)); // 10922
        assertEq(positions[longPId].accFundingFeePerSize, 0);

        assertEq(positions[shortPId].fundingFee, int256(positions[shortPId].size) * ((-int256(875 * 13) / 3) + 875 * 14) / (1e7 * 3600)); // 1048
        assertEq(positions[shortPId].accFundingFeePerSize, 111_805_555_555_555);

        // Check final funding fee state
        assertEq(fundingFeeTokenStates[PerpDexLib.TokenType.Btc].accFeePerSize, accFeePerSize3);
        assertEq(fundingFeeTokenStates[PerpDexLib.TokenType.Btc].lastAppliedRate, fundingRate3);
        assertEq(fundingFeeTokenStates[PerpDexLib.TokenType.Btc].lastUpdatedTime, block.timestamp);

        assertEq(
            fundingFeeGlobalState.protocolClaimable,
            uint256(fundingRate1 * int256(timeDiff) / 3600 * (3_720_000_000 - 0))
                + uint256(fundingRate2 * int256(timeDiff2) / 3600 * (3_720_000_000 - 1_860_000_000))
                + uint256(fundingRate3 * int256(timeDiff3) / 3600 * (0 - 1_860_000_000))
        );
    }

    /**
     * 1. Equal and Opposite Positions (Simple):
     *
     * Actions:
     * At t=0: Open 1 long of size 10.
     * At t=0: Open 1 short of size 10.
     * Let time pass for a certain period (e.g., 1 hour).
     * Close the long.
     * Close the short.
     *
     * Checks:
     * Since long = short initially, the initial funding rate should be zero or minimal.
     * Accumulated funding fees should reflect symmetrical conditions. The net paid by one side should roughly equal net received by the other.
     * At the end, both should have near zero net funding (except for any rounding).
     */
    function test_fundingFee_1() public {
        initFundingFee();
        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());

        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 10_000_000, 100, true, 1_000_000, 0, 0);
        uint256 shortPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 10_000_000, 100, false, 1_000_000, 0, 0);
        uint256 durationSec = 60 * 60;
        vm.warp(block.timestamp + durationSec);
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(block.timestamp, PerpDexLib.TokenType.Btc, 0, 0, 930_000_000, 930_000_000);
        closePositionDefault(longPId, 1_000_000);

        vm.expectEmit(true, true, true, true);
        int256 fundingRate = int256(1e20 * 875 / 1e7) * (0 - 10_000_000) / (0 + 10_000_000);
        emit PerpDex.FundingFeeStateUpdated(block.timestamp, PerpDexLib.TokenType.Btc, fundingRate, 0, 0, 930_000_000);
        closePositionDefault(shortPId, 1_000_000);

        PerpDexLib.Position memory longP = this.getPosition(longPId);
        PerpDexLib.Position memory shortP = this.getPosition(shortPId);

        assertEq(longP.fundingFee, 0);
        assertEq(longP.accFundingFeePerSize, 0);
        assertEq(shortP.fundingFee, 0);
        assertEq(shortP.accFundingFeePerSize, 0);

        // Check final funding fee state
        PerpDexLib.FundingFeeTokenState memory tokenState = fundingFeeTokenStates[PerpDexLib.TokenType.Btc];
        assertEq(tokenState.accFeePerSize, 0);
        assertEq(tokenState.lastAppliedRate, fundingRate);
        assertEq(tokenState.lastUpdatedTime, block.timestamp);

        uint256 protocolClaimable = uint256(fundingRate * int256(durationSec / 3600) * (930_000_000 - 930_000_000));
        protocolClaimable += uint256(fundingRate * int256(0 / 3600) * (0 - 930_000_000));
        assertEq(fundingFeeGlobalState.protocolClaimable, protocolClaimable);
    }

    /**
     * 2. Only One Side (All Long, No Shorts):
     *
     * Actions:
     * At t=0: Open 1 long of size 10.
     * Let time pass (e.g., 2 hours).
     * Close the long.
     *
     * Checks:
     * With no opposing side, (long - short)/(long + short) = 1.
     * Funding rate should be at its maximum positive (indicating longs pay).
     * Since there is no short to pay, logically the long position itself just accumulates a positive funding rate that would reduce its margin. Ensure this matches expected calculations.
     */
    function test_fundingFee_2() public {
        initFundingFee();
        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());

        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 10_000_000, 100, true, 1_000_000, 0, 0);

        uint256 durationSec = 60 * 60 * 2;
        vm.warp(block.timestamp + durationSec);
        int256 fundingRate = int256(1e20 * 875 / 1e7) * (10_000_000 - 0) / (10_000_000 + 0);
        int256 timeWeightedFundingRate = fundingRate * int256(durationSec) / 3600;
        emit PerpDex.FundingFeeStateUpdated(block.timestamp, PerpDexLib.TokenType.Btc, fundingRate, timeWeightedFundingRate, 0, 0);
        closePositionDefault(longPId, 1_000_000);

        PerpDexLib.Position memory longP = this.getPosition(longPId);
        assertEq(longP.fundingFee, int256(longP.size) * timeWeightedFundingRate / 1e20);

        // Check final funding fee state
        PerpDexLib.FundingFeeTokenState memory tokenState = fundingFeeTokenStates[PerpDexLib.TokenType.Btc];
        assertEq(tokenState.accFeePerSize, timeWeightedFundingRate);
        assertEq(tokenState.lastAppliedRate, fundingRate);
        assertEq(tokenState.lastUpdatedTime, block.timestamp);

        uint256 protocolClaimable = uint256(fundingRate * int256(durationSec / 3600) * (930_000_000 - 0));
        assertEq(fundingFeeGlobalState.protocolClaimable, protocolClaimable);
    }

    /**
     * 3. Staggered Opening and Closing (Reversed Close Order):
     *
     * Actions:
     * At t=0: Open 1 long of size 10.
     * At t=0: Open 1 short of size 5.
     * Let time pass (e.g., 30 minutes).
     * Close the short first.
     * Let more time pass (another 30 minutes).
     * Close the long.
     *
     * Checks:
     * Initially, long > short, so longs pay shorts. The short that closes earlier should realize some funding fee profit.
     * After the short is closed, only the long remains. For the remaining time, the long continues to pay (theoretically to a non-existent short side), so the long should lose more margin.
     * Verify the calculation of funding fees matches incremental off-chain calculation.
     */
    function test_fundingFee_3() public {
        initFundingFee();
        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());

        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 10_000_000, 100, true, 1_000_000, 0, 0);
        uint256 shortPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 5_000_000, 100, false, 1_000_000, 0, 0);

        uint256 durationSec = 60 * 30;
        vm.warp(block.timestamp + durationSec);
        int256 fundingRate1 = int256(1e20 * 875 / 1e7) * (10_000_000 - 5_000_000) / (10_000_000 + 5_000_000);
        int256 timeWeightedFundingRate1 = fundingRate1 * int256(durationSec) / 3600;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(
            block.timestamp, PerpDexLib.TokenType.Btc, fundingRate1, timeWeightedFundingRate1, 930_000_000, 465_000_000
        );
        closePositionDefault(shortPId, 1_000_000);

        vm.warp(block.timestamp + durationSec);

        int256 fundingRate2 = int256(1e20 * 875 / 1e7) * (10_000_000 - 0) / (10_000_000 + 0);
        int256 timeWeightedFundingRate2 = fundingRate2 * int256(durationSec) / 3600;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(
            block.timestamp, PerpDexLib.TokenType.Btc, fundingRate2, timeWeightedFundingRate1 + timeWeightedFundingRate2, 930_000_000, 0
        );
        closePositionDefault(longPId, 1_000_000);

        PerpDexLib.Position memory longP = this.getPosition(longPId);
        assertEq(
            longP.fundingFee,
            (int256(longP.size) * timeWeightedFundingRate1 / 1e20) + (int256(longP.size) * timeWeightedFundingRate2 / 1e20)
        );

        PerpDexLib.Position memory shortP = this.getPosition(shortPId);
        assertEq(shortP.fundingFee, -(int256(shortP.size) * timeWeightedFundingRate1 / 1e20));

        // Check final funding fee state
        PerpDexLib.FundingFeeTokenState memory tokenState = fundingFeeTokenStates[PerpDexLib.TokenType.Btc];
        assertEq(tokenState.accFeePerSize, timeWeightedFundingRate1 + timeWeightedFundingRate2);
        assertEq(tokenState.lastAppliedRate, fundingRate2);
        assertEq(tokenState.lastUpdatedTime, block.timestamp);

        uint256 protocolClaimable = uint256(timeWeightedFundingRate1 * (930_000_000 - 465_000_000));
        protocolClaimable += uint256(timeWeightedFundingRate2 * (930_000_000 - 0));
        assertEq(fundingFeeGlobalState.protocolClaimable, protocolClaimable);
    }

    /**
     * 4. Multiple Positions with Changing Dominance:
     *
     * Actions:
     * At t=0: Open long1 = 5 units.
     * At t=0: Open short = 10 units.
     * (Now short > long, so shorts are the "dominant" side receiving funding.)
     * Let time pass (e.g., 1 hour).
     * At t=1h: Open long2 = 10 units.
     * After this, we have long1+long2 = 15 units total long, short = 10 units short.
     * Now long > short, reversing the payment direction.
     * Let another hour pass.
     * Close all positions.
     *
     * Checks:
     * First hour: short side dominates, so longs pay shorts.
     * Second hour (after long2 is added): longs dominate, so longs pay shorts. Wait, this is counter-intuitive since if longs dominate, we expect longs to pay. Actually, verify the sign logic carefully:
     * If long > short, (long - short)/(long + short) is positive, hence funding rate is positive, meaning the long side pays. Initially short > long, so short side should be receiving, meaning a negative ratio if you interpret it as (long - short). Double-check the sign convention you have: If (long - short) is positive and your formula results in a positive funding rate, that means longs pay. Ensure this matches your intended logic.
     * Verify the incremental sums match the on-chain accumulator at each update.
     * Validate the final payouts align with the total time each position existed under each regime.
     */
    function test_fundingFee_4() public {
        initFundingFee();
        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());

        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 5_000_000, 100, true, 1_000_000, 0, 0);
        uint256 shortPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 10_000_000, 100, false, 1_000_000, 0, 0);

        uint256 durationSec = 60 * 60;
        vm.warp(block.timestamp + durationSec);
        int256 fundingRate1 = int256(1e20 * 875 / 1e7) * (5_000_000 - 10_000_000) / (5_000_000 + 10_000_000);
        int256 timeWeightedFundingRate1 = fundingRate1 * int256(durationSec) / 3600;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(
            block.timestamp, PerpDexLib.TokenType.Btc, fundingRate1, timeWeightedFundingRate1, 465_000_000, 930_000_000
        );
        uint256 longPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 10_000_000, 100, true, 1_000_000, 0, 0);

        vm.warp(block.timestamp + durationSec);
        int256 fundingRate2 = int256(1e20 * 875 / 1e7) * (15_000_000 - 10_000_000) / (15_000_000 + 10_000_000);
        int256 timeWeightedFundingRate2 = fundingRate2 * int256(durationSec) / 3600;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(
            block.timestamp,
            PerpDexLib.TokenType.Btc,
            fundingRate2,
            timeWeightedFundingRate1 + timeWeightedFundingRate2,
            465_000_000 + 930_000_000,
            930_000_000
        );
        closePositionDefault(shortPId, 1_000_000);
        closePositionDefault(longPId, 1_000_000);
        closePositionDefault(longPId2, 1_000_000);

        PerpDexLib.Position memory longP = this.getPosition(longPId);
        PerpDexLib.Position memory shortP = this.getPosition(shortPId);
        PerpDexLib.Position memory longP2 = this.getPosition(longPId2);

        assertEq(
            longP.fundingFee,
            ((int256(longP.size) * timeWeightedFundingRate1) + (int256(longP.size) * timeWeightedFundingRate2)) / 1e20,
            "longP.fundingFee"
        );

        assertEq(
            shortP.fundingFee,
            ((int256(shortP.size) * -timeWeightedFundingRate1) + (int256(shortP.size) * -timeWeightedFundingRate2)) / 1e20,
            "shortP.fundingFee"
        );

        assertEq(longP2.fundingFee, int256(longP2.size) * timeWeightedFundingRate2 / 1e20, "longP2.fundingFee");
    }

    /**
     * 5. Multiple Longs and Shorts with Partial Dominance Shifts:
     *
     * Actions:
     * Open long1 = 5 units, long2 = 5 units, long3 = 5 units (total long = 15).
     * Open short1 = 10 units, short2 = 2 units (total short = 12).
     * Initially, (L=15, S=12), so L > S, longs pay shorts.
     * Let time pass (e.g., 2 hours).
     * Close long1 and long2 (now long3=5 units left).
     * Let another hour pass.
     * Close long3, short1, and short2.
     *
     * Checks:
     * For the first 2 hours, L > S, so longs pay.
     * After closing long1 and long2, total long is 5 and total short is still 12, now S > L, meaning shorts pay should reverse. Actually, if the formula (long - short)/(long + short) is positive when L > S, it becomes negative when S > L. Negative funding rate means shorts pay longs.
     * Verify that the shift in dominance happens exactly at the close event and is reflected in the accFeePerSize.
     * Confirm the final funding fees align with the theoretical cumulative calculations.
     */
    function test_fundingFee_5() public {
        initFundingFee();
        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());

        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 5_000_000, 100, true, 1_000_000, 0, 0);
        uint256 longPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 5_000_000, 100, true, 1_000_000, 0, 0);
        uint256 longPId3 = openPositionDefault(user3, PerpDexLib.TokenType.Btc, 5_000_000, 100, true, 1_000_000, 0, 0);
        uint256 shortPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 10_000_000, 100, false, 1_000_000, 0, 0);
        uint256 shortPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 2_000_000, 100, false, 1_000_000, 0, 0);

        uint256 durationSec = 60 * 60;
        vm.warp(block.timestamp + durationSec);
        int256 fundingRate1 = int256(1e20 * 875 / 1e7) * (15_000_000 - 12_000_000) / (15_000_000 + 12_000_000);
        int256 timeWeightedFundingRate1 = fundingRate1 * int256(durationSec) / 3600;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(
            block.timestamp, PerpDexLib.TokenType.Btc, fundingRate1, timeWeightedFundingRate1, 465_000_000 * 3, 930_000_000 + 186_000_000
        );
        closePositionDefault(longPId, 1_000_000);
        closePositionDefault(longPId2, 1_000_000);

        vm.warp(block.timestamp + durationSec);
        int256 fundingRate2 = int256(1e20 * 875 / 1e7) * (5_000_000 - 12_000_000) / (5_000_000 + 12_000_000);
        int256 timeWeightedFundingRate2 = fundingRate2 * int256(durationSec) / 3600;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(
            block.timestamp,
            PerpDexLib.TokenType.Btc,
            fundingRate2,
            timeWeightedFundingRate1 + timeWeightedFundingRate2,
            465_000_000,
            930_000_000 + 186_000_000
        );
        closePositionDefault(longPId3, 1_000_000);
        closePositionDefault(shortPId, 1_000_000);
        closePositionDefault(shortPId2, 1_000_000);

        PerpDexLib.Position memory longP = this.getPosition(longPId);
        PerpDexLib.Position memory longP2 = this.getPosition(longPId);
        assertEq(longP.fundingFee, (int256(longP.size) * timeWeightedFundingRate1 / 1e20));
        assertEq(longP2.fundingFee, (int256(longP2.size) * timeWeightedFundingRate1 / 1e20));

        PerpDexLib.Position memory longP3 = this.getPosition(longPId3);
        PerpDexLib.Position memory shortP = this.getPosition(shortPId);
        PerpDexLib.Position memory shortP2 = this.getPosition(shortPId2);
        assertEq(longP3.fundingFee, (int256(longP3.size) * (timeWeightedFundingRate1 + timeWeightedFundingRate2) / 1e20));
        assertEq(shortP.fundingFee, -(int256(shortP.size) * (timeWeightedFundingRate1 + timeWeightedFundingRate2) / 1e20));
        assertEq(shortP2.fundingFee, -(int256(shortP2.size) * (timeWeightedFundingRate1 + timeWeightedFundingRate2) / 1e20));
    }

    /**
     * 6. Positions with Increasing Complexity and Time Delays:
     *
     * Actions:
     * At t=0: Open Long1 = 10, Short1 = 5, Short2 = 5 (Equal aggregate: L=10, S=10).
     * Initially, equal sides mean nearly zero funding.
     * Let 1 hour pass. Then open Long2 = 20 (Now L=30, S=10).
     * Let 2 hours pass. Close Short1 and Short2 (just longs remain).
     * Let 1 hour pass. Close Long1 and Long2.
     *
     * Checks:
     * For the first hour, L=S, minimal funding movement.
     * After adding Long2, L=30 and S=10, L > S, longs pay.
     * When shorts are closed, only longs remain. Still, longs pay, but there's no one receiving—check if logic holds that accFeePerSize still increments properly. The final settlement for the longs should reflect a net payment.
     * Carefully match each time period’s funding increment to accFeePerSize changes.
     */
    function test_fundingFee_6() public {
        initFundingFee();
        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());

        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 10_000_000, 100, true, 1_000_000, 0, 0);
        uint256 shortPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 5_000_000, 100, false, 1_000_000, 0, 0);
        uint256 shortPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 5_000_000, 100, false, 1_000_000, 0, 0);

        uint256 durationSec = 60 * 60;
        vm.warp(block.timestamp + durationSec);
        int256 fundingRate1 = 0;
        int256 timeWeightedFundingRate1 = 0;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(
            block.timestamp, PerpDexLib.TokenType.Btc, fundingRate1, timeWeightedFundingRate1, 930_000_000, 930_000_000
        );

        uint256 longPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 20_000_000, 100, true, 1_000_000, 0, 0);

        vm.warp(block.timestamp + durationSec * 2);
        int256 fundingRate2 = int256(875 * 1e20 / 1e7) * (30_000_000 - 10_000_000) / (30_000_000 + 10_000_000);
        int256 timeWeightedFundingRate2 = fundingRate2 * int256(durationSec * 2) / 3600;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(
            block.timestamp,
            PerpDexLib.TokenType.Btc,
            fundingRate2,
            timeWeightedFundingRate1 + timeWeightedFundingRate2,
            930_000_000 + 1_860_000_000,
            930_000_000
        );
        closePositionDefault(shortPId, 1_000_000);
        closePositionDefault(shortPId2, 1_000_000);

        vm.warp(block.timestamp + durationSec);
        int256 fundingRate3 = int256(875 * 1e20 / 1e7);
        int256 timeWeightedFundingRate3 = fundingRate3 * int256(durationSec) / 3600;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(
            block.timestamp,
            PerpDexLib.TokenType.Btc,
            fundingRate3,
            timeWeightedFundingRate1 + timeWeightedFundingRate2 + timeWeightedFundingRate3,
            930_000_000 + 1_860_000_000,
            0
        );

        closePositionDefault(longPId, 1_000_000);
        closePositionDefault(longPId2, 1_000_000);

        PerpDexLib.Position memory longP = this.getPosition(longPId);
        PerpDexLib.Position memory longP2 = this.getPosition(longPId);
        assertEq(
            longP.fundingFee, (int256(longP.size) * (timeWeightedFundingRate1 + timeWeightedFundingRate2 + timeWeightedFundingRate3) / 1e20)
        );
        assertEq(longP2.fundingFee, (int256(longP2.size) * (timeWeightedFundingRate2 + timeWeightedFundingRate3) / 1e20));

        PerpDexLib.Position memory shortP = this.getPosition(shortPId);
        PerpDexLib.Position memory shortP2 = this.getPosition(shortPId2);
        assertEq(shortP.fundingFee, -(int256(shortP.size) * (timeWeightedFundingRate1 + timeWeightedFundingRate2) / 1e20));
        assertEq(shortP2.fundingFee, -(int256(shortP2.size) * (timeWeightedFundingRate1 + timeWeightedFundingRate2) / 1e20));
    }

    /**
     * 7. Extreme Edge Cases:
     *
     * Actions:
     * Open only one large long position (e.g., L=1000) at t=0.
     * Let a significant amount of time pass with no opposing side (S=0).
     * Then open a tiny short (S=1) after a long delay.
     * Wait a short period, then close both.
     *
     * Checks:
     * Large imbalance from the start: (L - S)/(L + S) should be close to 1 when S=0.
     * Large time gap without any updates ensures a big funding accumulation.
     * Adding a tiny short changes the ratio slightly. Verify that the incremental funding from the moment the short enters matches your off-chain calculations.
     * Confirm no overflow or unexpected rounding occurs with large values.
     */
    function test_fundingFee_7() public {
        initFundingFee();
        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());

        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 1_000_000_000, 100, true, 1_000_000, 0, 0);

        uint256 durationSec = 60 * 60;
        vm.warp(block.timestamp + durationSec);
        int256 fundingRate1 = int256(1e20 * 875 / 1e7);
        int256 timeWeightedFundingRate1 = fundingRate1 * int256(durationSec) / 3600;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(
            block.timestamp, PerpDexLib.TokenType.Btc, fundingRate1, timeWeightedFundingRate1, 93_000_000_000, 0
        );

        uint256 shortPId = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 1_000_000, 100, false, 1_000_000, 0, 0);

        uint256 shortPeriod = 60;
        vm.warp(block.timestamp + shortPeriod);
        int256 fundingRate2 = int256(1e20 * 875 / 1e7) * (1_000_000_000 - 1_000_000) / (1_000_000_000 + 1_000_000);
        int256 timeWeightedFundingRate2 = fundingRate2 * int256(shortPeriod) / 3600;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(
            block.timestamp,
            PerpDexLib.TokenType.Btc,
            fundingRate2,
            timeWeightedFundingRate1 + timeWeightedFundingRate2,
            93_000_000_000,
            93_000_000
        );
        closePositionDefault(longPId, 1_000_000);
        closePositionDefault(shortPId, 1_000_000);

        PerpDexLib.Position memory longP = this.getPosition(longPId);
        PerpDexLib.Position memory shortP = this.getPosition(shortPId);
        assertEq(longP.fundingFee, (int256(longP.size) * (timeWeightedFundingRate1 + timeWeightedFundingRate2) / 1e20));
        assertEq(shortP.fundingFee, -(int256(shortP.size) * (timeWeightedFundingRate2) / 1e20));
    }

    /**
     * 8. Rapid Repeated Opens and Closes in Short Time Frames:
     *
     * Actions:
     * At t=0: Open Long = 10, Short = 5.
     * Immediately close and re-open positions within a few seconds multiple times.
     * Let a few minutes pass between some cycles.
     *
     * Checks:
     * Ensure that minimal time increments show minimal funding accrual.
     * Frequent events test that accFeePerSize updates correctly and doesn’t produce nonsensical values due to integer truncations or sign flips.
     * Confirm the final net funding after several rapid cycles matches the sum of all increments.
     *
     * NOTE
     * to see integer truncation user small size (small margin * leverage)
     * => user1 opens long/short
     * => user2 opens long/short within a short seconds multiple times, maintaining same funding rate
     * user1's position should pay funding fee correctly
     */
    function test_fundingFee_8() public {
        initFundingFee();
        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());

        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 1_000_000_000, 3, true, 1_000_000, 0, 0);
        uint256 shortPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 1_000_000, 3, false, 1_000_000, 0, 0);

        vm.warp(block.timestamp + 1);
        uint256 longPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 1_000_000_000, 3, true, 1_000_000, 0, 0);
        uint256 shortPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 1_000_000, 3, false, 1_000_000, 0, 0);

        vm.warp(block.timestamp + 1);
        closePositionDefault(longPId2, 1_000_000);
        closePositionDefault(shortPId2, 1_000_000);

        vm.warp(block.timestamp + 1);
        longPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 1_000_000_000, 3, true, 1_000_000, 0, 0);
        shortPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 1_000_000, 3, false, 1_000_000, 0, 0);

        vm.warp(block.timestamp + 60);
        closePositionDefault(longPId2, 1_000_000);
        closePositionDefault(shortPId2, 1_000_000);

        vm.warp(block.timestamp + 1);
        longPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 1_000_000_000, 3, true, 1_000_000, 0, 0);
        shortPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 1_000_000, 3, false, 1_000_000, 0, 0);

        vm.warp(block.timestamp + 1);
        closePositionDefault(longPId2, 1_000_000);
        closePositionDefault(shortPId2, 1_000_000);

        vm.warp(block.timestamp + 1);
        longPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 1_000_000_000, 3, true, 1_000_000, 0, 0);
        shortPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 1_000_000, 3, false, 1_000_000, 0, 0);

        vm.warp(block.timestamp + 1);
        closePositionDefault(longPId2, 1_000_000);
        closePositionDefault(shortPId2, 1_000_000);

        vm.warp(block.timestamp + 1);
        longPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 1_000_000_000, 3, true, 1_000_000, 0, 0);
        shortPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 1_000_000, 3, false, 1_000_000, 0, 0);

        vm.warp(block.timestamp + 1);
        closePositionDefault(longPId2, 1_000_000);
        closePositionDefault(shortPId2, 1_000_000);

        vm.warp(block.timestamp + 1);
        longPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 1_000_000_000, 3, true, 1_000_000, 0, 0);
        shortPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 1_000_000, 3, false, 1_000_000, 0, 0);

        vm.warp(block.timestamp + 1);
        closePositionDefault(longPId2, 1_000_000);
        closePositionDefault(shortPId2, 1_000_000);

        vm.warp(block.timestamp + 1);
        longPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 1_000_000_000, 3, true, 1_000_000, 0, 0);
        shortPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 1_000_000, 3, false, 1_000_000, 0, 0);

        vm.warp(block.timestamp + 1);
        closePositionDefault(longPId2, 1_000_000);
        closePositionDefault(shortPId2, 1_000_000);

        vm.warp(block.timestamp + 1);
        closePositionDefault(longPId, 1_000_000);
        closePositionDefault(shortPId, 1_000_000);

        PerpDexLib.Position memory longP = this.getPosition(longPId);
        PerpDexLib.Position memory shortP = this.getPosition(shortPId);
        int256 fundingRate = int256(875 * 1e20 / 1e7) * 999_000_000 / 1_001_000_000;
        int256 timeWeightedFundingRate = fundingRate * 74 / 3600;
        assertEq(longP.fundingFee, (int256(longP.size) * timeWeightedFundingRate / 1e20));
        assertEq(shortP.fundingFee, -(int256(shortP.size) * timeWeightedFundingRate / 1e20));
    }

    /**
     * 9. Testing with Varying Time Deltas:
     *
     * Actions:
     * Open Long = 10, Short = 5 at t=0.
     * Immediately open another Short = 5 at t=0 (so total S=10 now).
     * No time passes yet, funding rate should be computed right away with zero timeDelta.
     * Advance time by a large increment (e.g., 5 hours) without any intermediate opens/closes.
     * After 5 hours, close one side and verify large accrued funding.
     *
     * Checks:
     * Confirm that no funding accrues when timeDelta=0.
     * After 5 hours, the correct large accumulation appears.
     * Confirm arithmetic precision when dealing with large time intervals.
     *
     * NOTE accrued funding is still 0 after 5 hours, because funding rate is 0 when L=10, S=10
     */
    function test_fundingFee_9() public {}

    /**
     * Similar with test_fundingFee_4, but use same user to merge Long position
     * Actions:
     * Open Long = 5, Short = 10 at t=0. (L < S)
     * After 1 hour, open Long = 10, which will be merged into first Long position L = 15 (L > S)
     */
    function test_fundingFee_merge() public {
        initFundingFee();
        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());

        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 5_000_000, 100, true, 1_000_000, 0, 0);
        uint256 shortPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 10_000_000, 100, false, 1_000_000, 0, 0);

        uint256 durationSec = 60 * 60;
        vm.warp(block.timestamp + durationSec);
        int256 fundingRate1 = int256(1e20 * 875 / 1e7) * (5_000_000 - 10_000_000) / (5_000_000 + 10_000_000);
        int256 timeWeightedFundingRate1 = fundingRate1 * int256(durationSec) / 3600;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(
            block.timestamp, PerpDexLib.TokenType.Btc, fundingRate1, timeWeightedFundingRate1, 465_000_000, 930_000_000
        );

        uint256 longPId2 = openPositionDefault(user, PerpDexLib.TokenType.Btc, 10_000_000, 100, true, 1_000_000, 0, 0);
        PerpDexLib.Position memory longP = this.getPosition(longPId);
        assertEq(longP.fundingFee, 465_000_000 * timeWeightedFundingRate1 / 1e20);

        vm.warp(block.timestamp + durationSec);
        int256 fundingRate2 = int256(1e20 * 875 / 1e7) * (15_000_000 - 10_000_000) / (15_000_000 + 10_000_000);
        int256 timeWeightedFundingRate2 = fundingRate2 * int256(durationSec) / 3600;
        vm.expectEmit(true, true, true, true);
        emit PerpDex.FundingFeeStateUpdated(
            block.timestamp,
            PerpDexLib.TokenType.Btc,
            fundingRate2,
            timeWeightedFundingRate1 + timeWeightedFundingRate2,
            465_000_000 + 930_000_000,
            930_000_000
        );
        closePositionDefault(shortPId, 1_000_000);
        closePositionDefault(longPId, 1_000_000);

        PerpDexLib.Position memory longPAfter = this.getPosition(longPId);
        PerpDexLib.Position memory shortP = this.getPosition(shortPId);
        PerpDexLib.Position memory longP2 = this.getPosition(longPId2);

        assertEq(
            longPAfter.fundingFee,
            (int256(longPAfter.size - longP2.size) * timeWeightedFundingRate1 / 1e20)
                + (int256(longPAfter.size) * timeWeightedFundingRate2 / 1e20)
        );

        assertEq(
            shortP.fundingFee,
            (int256(shortP.size) * -timeWeightedFundingRate1 / 1e20) + (int256(shortP.size) * -timeWeightedFundingRate2 / 1e20)
        );
    }

    /**
     * Liquidation bot stopped for a long time, results in margin < fundingFee
     * Actions:
     * Open Long = 10, Short = 5 at t=0. (L > S)
     * After a long period of time, close Long
     *
     * Checks:
     * fundingFeeBuffer.balance has decreased by the exact deficit funding fee amount
     * when market skew = 1 / 3, and leverage = 100
     * liquidation should have triggered after ? seconds
     * ? = hourToSec * ( (margin) / fundingRate * lev ) )
     *   = 3600 * 1 / ((0.0000875 / 3) * 100 )
     *   = 1234285.71428571
     */
    function test_fundingFee_missed_liquidation_1_zero_pnl() public {
        initFundingFee();

        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());

        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 10_000_000, 100, true, 1_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Btc, 5_000_000, 100, false, 1_000_000, 0, 0); // short

        uint256 durationSec = 1_234_285 + 1; // 1234285.71428571
        vm.warp(block.timestamp + durationSec);
        vm.expectRevert("Funding Fee buffer balance is insufficient");
        closePositionDefault(longPId, 1_000_000);

        // fill buffer
        uint256 initialBufferBalance = 5_000_000_000;
        initBufferBalance(initialBufferBalance);

        // marginAfterFundingFee <= 0
        closePositionDefault(longPId, 1_000_000);
        PerpDexLib.Position memory longP = this.getPosition(longPId);
        int256 fundingRate = int256(1e20 * 875 / 1e7) * (10_000_000 - 5_000_000) / (10_000_000 + 5_000_000);
        int256 timeWeightedFundingRate = fundingRate * int256(durationSec) / 3600;
        int256 expectingFundingFee = int256(longP.size) * timeWeightedFundingRate / 1e20;
        int256 deficitFundingFee = expectingFundingFee - int256(longP.margin);
        assertEq(longP.fundingFee, expectingFundingFee);
        assertEq(longP.closeFee, 0); // no margin left to pay closeFee

        (uint256 bufferBalance,) = this.fundingFeeGlobalState();
        assertEq(bufferBalance, initialBufferBalance - uint256(deficitFundingFee));
    }

    // marginAfterFundingFee <= 0
    // pnl > 0
    // 1️⃣ pnl > closeFee
    // 2️⃣ pnl < closeFee
    function test_fundingFee_missed_liquidation_1_with_profit() public {
        initFundingFee();

        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());

        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 5_000_000, 100, true, 1_000_000, 0, 0);
        uint256 longPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 5_000_000, 100, true, 1_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Btc, 5_000_000, 100, false, 1_000_000, 0, 0); // short

        uint256 durationSec = 1_234_285 + 1; // 1234285.71428571
        vm.warp(block.timestamp + durationSec);

        // fill buffer
        uint256 initialBufferBalance = 5_000_000_000;
        initBufferBalance(initialBufferBalance);
        vm.mockCall(address(externalContracts.lp), abi.encodeWithSelector(ILP.giveProfit.selector), abi.encode());

        // 1️⃣ pnl > closeFee
        closePositionDefault(longPId, 1_500_000);
        PerpDexLib.Position memory longP = this.getPosition(longPId);
        int256 fundingRate = int256(1e20 * 875 / 1e7) * (10_000_000 - 5_000_000) / (10_000_000 + 5_000_000);
        int256 timeWeightedFundingRate = fundingRate * int256(durationSec) / 3600;
        int256 expectingFundingFee = int256(longP.size) * timeWeightedFundingRate / 1e20;
        int256 deficitFundingFee = expectingFundingFee - int256(longP.margin);
        assertEq(longP.fundingFee, expectingFundingFee);

        uint256 expectingProfit = (longP.size * 1_500_000 / 1_000_000) - longP.size;
        if (expectingProfit > longP.margin * 5 || expectingProfit > longP.size) {
            // Max profit for the trader
            expectingProfit = Math.min(longP.margin * 5, longP.size);
        }
        uint256 fee = (longP.size + expectingProfit) * defaultTotalFeePercent / defaultFeeDenominator;
        assertEq(longP.pnl, int256(expectingProfit - fee));
        assertEq(longP.closeFee, fee);

        (uint256 bufferBalance,) = this.fundingFeeGlobalState();
        assertEq(bufferBalance, initialBufferBalance - uint256(deficitFundingFee));

        // 2️⃣ pnl < closeFee
        closePositionDefault(longPId2, 1_000_001);
        PerpDexLib.Position memory longP2 = this.getPosition(longPId2);
        assertEq(longP2.fundingFee, expectingFundingFee);

        uint256 expectingProfit2 = (longP2.size * 1_000_001 / 1_000_000) - longP2.size;
        if (expectingProfit2 > longP2.margin * 5 || expectingProfit2 > longP2.size) {
            // Max profit for the trader
            expectingProfit2 = Math.min(longP2.margin * 5, longP2.size);
        }

        assertEq(longP2.pnl, 0);
        assertEq(longP2.closeFee, expectingProfit2);

        (uint256 bufferBalance2,) = this.fundingFeeGlobalState();
        assertEq(bufferBalance2, initialBufferBalance - uint256(deficitFundingFee * 2));
    }

    // marginAfterFundingFee - closeFee <= 0
    // pnl = 0
    function test_fundingFee_missed_liquidation_2_zero_pnl() public {
        initFundingFee();

        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());

        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 10_000_000, 100, true, 1_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Btc, 5_000_000, 100, false, 1_000_000, 0, 0); // short

        uint256 durationSec = 1_234_285; // 1234285.71428571
        vm.warp(block.timestamp + durationSec);

        closePositionDefault(longPId, 1_000_000);
        PerpDexLib.Position memory longP = this.getPosition(longPId);
        int256 fundingRate = int256(1e20 * 875 / 1e7) * (10_000_000 - 5_000_000) / (10_000_000 + 5_000_000);
        int256 timeWeightedFundingRate = fundingRate * int256(durationSec) / 3600;
        assertEq(longP.fundingFee, int256(longP.size) * timeWeightedFundingRate / 1e20);
        assertEq(uint256(longP.positionStatus), uint256(PerpDexLib.PositionStatus.Liquidated));
        assertEq(int256(longP.closeFee), int256(longP.margin) - longP.fundingFee);
    }

    // marginAfterFundingFee - closeFee <= 0
    // pnl > 0
    // 1️⃣ pnl > deficitCloseFee
    // 2️⃣ pnl < deficitCloseFee
    function test_fundingFee_missed_liquidation_2_with_profit() public {
        initFundingFee();

        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());

        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 5_000_000, 100, true, 1_000_000, 0, 0);
        uint256 longPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 5_000_000, 100, true, 1_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Btc, 5_000_000, 100, false, 1_000_000, 0, 0); // short

        uint256 durationSec = 1_234_285; // 1234285.71428571
        vm.warp(block.timestamp + durationSec);

        vm.mockCall(address(externalContracts.lp), abi.encodeWithSelector(ILP.giveProfit.selector), abi.encode());

        // 1️⃣ pnl > deficitCloseFee
        closePositionDefault(longPId, 1_500_000);
        PerpDexLib.Position memory longP = this.getPosition(longPId);
        int256 fundingRate = int256(1e20 * 875 / 1e7) * (10_000_000 - 5_000_000) / (10_000_000 + 5_000_000);
        int256 timeWeightedFundingRate = fundingRate * int256(durationSec) / 3600;
        assertEq(longP.fundingFee, int256(longP.size) * timeWeightedFundingRate / 1e20);

        uint256 expectingProfit = (longP.size * 1_500_000 / 1_000_000) - longP.size;
        if (expectingProfit > longP.margin * 5 || expectingProfit > longP.size) {
            // Max profit for the trader
            expectingProfit = Math.min(longP.margin * 5, longP.size);
        }
        uint256 fee = (longP.size + expectingProfit) * defaultTotalFeePercent / defaultFeeDenominator;
        uint256 deficitCloseFee = fee - (longP.margin - uint256(longP.fundingFee));
        assertEq(longP.closeFee, fee);
        assertEq(longP.pnl, int256(expectingProfit - deficitCloseFee));

        // 2️⃣ pnl < deficitCloseFee
        closePositionDefault(longPId2, 1_000_001);
        PerpDexLib.Position memory longP2 = this.getPosition(longPId2);
        assertEq(longP2.fundingFee, int256(longP2.size) * timeWeightedFundingRate / 1e20);

        uint256 expectingProfit2 = (longP2.size * 1_000_001 / 1_000_000) - longP2.size;
        if (expectingProfit2 > longP2.margin * 5 || expectingProfit2 > longP2.size) {
            // Max profit for the trader
            expectingProfit2 = Math.min(longP2.margin * 5, longP2.size);
        }
        assertEq(longP2.pnl, 0);
        assertEq(longP2.closeFee, longP2.margin - uint256(longP2.fundingFee) + expectingProfit2);
    }

    /**
     *  marginAfterFundingFee - closeFee + pnl <= 0
     *  closeFee = 0.0007 * size
     *  when leverage is 100, closeFee = 0.07 * margin
     *  when loss is zero, liquidation will be triggered after ? seconds
     *  ? = hourToSec * ( (margin - closeFee) / fundingRate * lev ) )
     *    = 3600 * (1 - 0.07) / ((0.0000875 / 3) * 100 )
     *    = 1147885.71428571
     */
    function test_fundingFee_missed_liquidation_with_loss() public {
        initFundingFee();
        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());

        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 10_000_000, 100, true, 1_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Btc, 5_000_000, 100, false, 1_000_000, 0, 0); // short

        uint256 longPId2 = openPositionDefault(user2, PerpDexLib.TokenType.Btc, 10_000_000, 100, true, 1_000_000, 0, 0);
        openPositionDefault(user2, PerpDexLib.TokenType.Btc, 5_000_000, 100, false, 1_000_000, 0, 0); // short

        // margin - fundingFee - closeFee > 0
        // almost 0
        uint256 durationSec = 1_147_885; // 1147885.71428571
        vm.warp(block.timestamp + durationSec);
        vm.mockCall(address(externalContracts.lp), abi.encodeWithSelector(ILP.giveProfit.selector), abi.encode());

        // margin - fundingFee - closeFee > 0
        // margin - fundingFee - closeFee - loss > 0
        // pnl = 0
        // 1️⃣ closed, not liquidated
        closePositionDefault(longPId, 1_000_000);
        PerpDexLib.Position memory longP = this.getPosition(longPId);
        int256 fundingRate = int256(1e20 * 875 / 1e7) * (10_000_000 - 5_000_000) / (10_000_000 + 5_000_000);
        int256 timeWeightedFundingRate = fundingRate * int256(durationSec) / 3600;
        assertEq(longP.fundingFee, int256(longP.size) * timeWeightedFundingRate / 1e20);
        assertEq(uint256(longP.positionStatus), uint256(PerpDexLib.PositionStatus.Closed));
        assertEq(longP.closeFee, longP.size * defaultTotalFeePercent / defaultFeeDenominator);
        assertEq(longP.pnl, 0);

        // margin - fundingFee - closeFee > 0
        // margin - fundingFee - closeFee - loss < 0;
        // 2️⃣ liquidated
        closePositionDefault(longPId2, 999_999);
        PerpDexLib.Position memory longP2 = this.getPosition(longPId2);
        assertEq(longP2.fundingFee, int256(longP2.size) * timeWeightedFundingRate / 1e20);
        assertEq(uint256(longP2.positionStatus), uint256(PerpDexLib.PositionStatus.Liquidated));

        uint256 expectingLoss = longP2.size - (longP2.size * 999_999 / 1_000_000);
        uint256 loss = Math.min(uint256(int256(longP2.margin) - longP2.fundingFee), expectingLoss);
        uint256 fee = (longP2.size - loss) * defaultTotalFeePercent / defaultFeeDenominator;
        emit log_uint(expectingLoss);
        emit log_uint(uint256(longP2.fundingFee));
        emit log_uint(fee);
        emit log_uint(longP2.margin);
        emit log_uint(uint256(longP2.fundingFee) + fee); // < margin
        emit log_uint(uint256(longP2.fundingFee) + fee + expectingLoss); // > margin
        assertEq(longP2.closeFee, fee);
        assertEq(longP2.pnl, -int256(longP2.margin - uint256(longP2.fundingFee) - fee));
    }

    function test_changeMargin_ok() public {
        initFundingFee();
        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());

        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 10_000_000, 50, true, 1_000_000, 0, 0);
        PerpDexLib.Position memory longP = this.getPosition(longPId);

        uint256 durationSec = 60 * 60;
        vm.warp(block.timestamp + durationSec);
        // pnl = 0;
        mockCurrentPrice(1_000_000);
        vm.mockCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), abi.encode());
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(1);

        uint256 marginDelta = 10_000_000;
        uint256 expectingFee = marginDelta * defaultMarginFeePercent / defaultFeeDenominator;

        // 1️⃣ addMargin true
        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferFromAndCheckBalance.selector), abi.encode()
        );
        vm.expectCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferFromAndCheckBalance.selector), 1);

        vm.expectEmit(true, true, true, true);
        emit PerpDex.PositionMarginChanged(longPId, longP.traderAddr, longP.tokenType, true, marginDelta);
        vm.prank(singleOpenAdmin);
        this.changeMargin(longPId, true, marginDelta, bisonAIData, hex"1234");

        PerpDexLib.Position memory longPAfter = this.getPosition(longPId);
        assertEq(longPAfter.margin, longP.margin + marginDelta - expectingFee);
        assertEq(longPAfter.openFee, longP.openFee + expectingFee);
        assertEq(longPAfter.fundingFee, 0);

        // 2️⃣ addMargin false
        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());
        vm.expectCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), 1);

        vm.expectEmit(true, true, true, true);
        emit PerpDex.PositionMarginChanged(longPId, longP.traderAddr, longP.tokenType, false, marginDelta);
        vm.prank(singleOpenAdmin);
        this.changeMargin(longPId, false, marginDelta, bisonAIData, hex"1234");

        PerpDexLib.Position memory longPAfter2 = this.getPosition(longPId);
        assertEq(longPAfter2.margin, longPAfter.margin - marginDelta);
        assertEq(longPAfter2.openFee, longP.openFee + expectingFee + expectingFee);
        assertEq(longPAfter2.fundingFee, 0);
    }

    // revert by liquidation
    function test_changeMargin_revert() public {
        initFundingFee();
        initBufferBalance(5_000_000);
        vm.mockCall(address(externalContracts.usdt), abi.encodeWithSelector(IERC20.transfer.selector), abi.encode());
        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferFromAndCheckBalance.selector), abi.encode()
        );
        vm.mockCall(address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferAndCheckBalance.selector), abi.encode());

        uint256 longPId = openPositionDefault(user, PerpDexLib.TokenType.Btc, 10_000_000, 50, true, 1_000_000, 0, 0);
        openPositionDefault(user, PerpDexLib.TokenType.Btc, 5_000_000, 50, false, 1_000_000, 0, 0); // short

        // pnl = 0;
        mockCurrentPrice(1_000_000);
        vm.mockCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), abi.encode());
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(1);

        uint256 marginDelta = 10_000_000;
        vm.startPrank(singleOpenAdmin);

        // margin - fundingFee <= 0
        // lev 100 => 1234285.71428571 seconds to liquidate
        // lev 50  => 1234285.71428571 * 2 = 2468571.42857142
        vm.warp(1 + 2_468_571 + 1);
        vm.expectRevert("Position will be liquidated");
        this.changeMargin(longPId, true, marginDelta, bisonAIData, hex"1234");

        // margin - fundingFee - closeFee <= 0

        // ? = hourToSec * ( (margin - closeFee) / fundingRate * lev ) )
        //   = 3600 * 0.965 / ((0.0000875 / 3) * 50 )
        //   = 2382171.42857143
        vm.warp(1 + 2_382_171 + 1); // 2382171.42857143
        vm.expectRevert("Position will be liquidated");
        this.changeMargin(longPId, true, marginDelta, bisonAIData, hex"1234");

        // pnl = 0
        // int256(position.margin - marginDelta) - fundingFee - int256(closeFee) - pnl <= 0
        vm.warp(1 + 2_382_171); // 2382171.42857143
        vm.expectRevert("Position will be liquidated after margin is removed");
        this.changeMargin(longPId, false, 1000, bisonAIData, hex"1234");

        // pnl > 0
        // int256(position.margin - marginDelta) - fundingFee - int256(closeFee) <= 0
        mockCurrentPrice(1_000_001);
        vm.expectRevert("Position will be liquidated after margin is removed");
        this.changeMargin(longPId, false, 1000, bisonAIData, hex"1234");

        vm.stopPrank();
    }
}
