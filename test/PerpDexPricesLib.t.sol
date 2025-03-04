// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./PerpDexTestBase.sol";

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Test, console} from "forge-std/Test.sol";

contract PerpDexPricesLibTest is PerpDexTestBase {
    address[] admins;
    bytes mockSignedData;

    /**
     * ⬇️ test oracles below
     */
    function test_getPythPrice() public {
        (, IBisonAIRouter mockBisonAIRouter, IPyth mockPyth,,) = getOracleBase(6);

        int64 testPrice = 50_000;

        vm.expectCall(address(mockPyth), abi.encodeWithSelector(IPyth.getPriceNoOlderThan.selector), tokenCount);
        vm.expectCall(address(mockBisonAIRouter), abi.encodeWithSelector(IBisonAIRouter.latestRoundData.selector), 0);
        for (uint64 i = 0; i < tokenCount; i++) {
            IPyth.PythPrice memory pythPrice =
                IPyth.PythPrice({price: (i == 5 || i == 10) ? testPrice * 100 : testPrice, conf: 0, expo: 0, publishTime: 0});
            bytes32 feedHash = getPythPriceFeedId(PerpDexLib.TokenType(i));
            vm.mockCall(address(mockPyth), abi.encodeWithSelector(IPyth.getPriceNoOlderThan.selector, feedHash, 10), abi.encode(pythPrice));
            vm.expectCall(
                address(mockPyth),
                abi.encodeWithSelector(IPyth.getPriceNoOlderThan.selector, getPythPriceFeedId(PerpDexLib.TokenType(i)), 10),
                1
            );
            uint256 price = PerpDexPricesLib.getPythPrice(PerpDexLib.TokenType(i), mockPyth);
            assertEq(int256(price), int256(testPrice));
        }
    }

    function test_getPythPriceRevertPriceZero() public {
        (,, IPyth mockPyth,,) = getOracleBase(1);

        IPyth.PythPrice memory pythPrice = IPyth.PythPrice({price: 0, conf: 0, expo: 0, publishTime: 0});
        bytes32 feedHash = getPythPriceFeedId(PerpDexLib.TokenType(0));
        vm.mockCall(address(mockPyth), abi.encodeWithSelector(IPyth.getPriceNoOlderThan.selector, feedHash, 10), abi.encode(pythPrice));
        vm.expectCall(address(mockPyth), abi.encodeWithSelector(IPyth.getPriceNoOlderThan.selector, feedHash, 10), 1);
        vm.expectRevert("Price is 0 (Pyth)");
        PerpDexPricesLib.getPythPrice(PerpDexLib.TokenType.Btc, mockPyth);
    }

    function test_getPreviousPriceAndTime_bisonai() public {
        vm.warp(200);

        uint64[] memory roundIds = new uint64[](tokenCount);
        (, IBisonAIRouter mockBisonAIRouter, IPyth mockPyth, PerpDexLib.OraclePrices memory bisonAIData,) = getOracleBase(tokenCount);

        int256 testPrice = 50_000;

        vm.expectCall(address(mockBisonAIRouter), abi.encodeWithSelector(IBisonAIRouter.getRoundData.selector), tokenCount);
        for (uint64 i = 0; i < tokenCount; i++) {
            roundIds[i] = i + 1;
            bisonAIData.feedHashes[i] = getBisonAIFeedHash(PerpDexLib.TokenType(i));
            bisonAIData.answers[i] = testPrice;
            bisonAIData.timestamps[i] = block.timestamp - i;

            vm.mockCall(
                address(mockBisonAIRouter),
                abi.encodeWithSelector(
                    IBisonAIRouter.getRoundData.selector, PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType(i)), uint64(i + 1)
                ),
                abi.encode(uint64(i + 1), int256(testPrice), uint64(block.timestamp - i))
            );

            vm.expectCall(
                address(mockBisonAIRouter),
                abi.encodeWithSelector(
                    IBisonAIRouter.getRoundData.selector, PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType(i)), uint64(i + 1)
                ),
                1
            );
        }

        (uint256[] memory prices, uint256[] memory times) =
            PerpDexPricesLib.getPreviousPriceAndTime(roundIds, bisonAIData, mockBisonAIRouter, mockPyth);

        assertEq(prices.length, tokenCount);
        assertEq(times.length, tokenCount);
        for (uint64 i = 0; i < tokenCount; i++) {
            assertEq(prices[i], 50_000);
            assertEq(times[i], block.timestamp - i);
        }
    }

    function test_getPreviousPriceAndTime_pyth() public {
        vm.roll(200);
        vm.warp(1_641_070_800);

        uint64[] memory roundIds = new uint64[](0);
        (, IBisonAIRouter mockBisonAIRouter, IPyth mockPyth,, PerpDexLib.OraclePrices memory pythData) = getOracleBase(tokenCount);

        int256 testPrice = 50_000;

        IPyth.PythPriceFeed[] memory priceFeeds = new IPyth.PythPriceFeed[](tokenCount);
        for (uint64 i = 0; i < tokenCount; i++) {
            uint256 timestampForTest = block.timestamp - i;
            pythData.answers[i] = testPrice;
            pythData.timestamps[i] = timestampForTest;
            pythData.feedHashes[i] = getPythPriceFeedId(PerpDexLib.TokenType(i));
            int64 price = (i == 5 || i == 10) ? int64(testPrice * 100) : int64(testPrice);
            IPyth.PythPrice memory pythPrice = IPyth.PythPrice({price: price, conf: 0, expo: 0, publishTime: uint64(timestampForTest)});
            priceFeeds[i] = IPyth.PythPriceFeed({id: pythData.feedHashes[i], price: pythPrice, emaPrice: pythPrice});
        }

        vm.mockCall(
            address(mockPyth),
            abi.encodeWithSelector(
                IPyth.parsePriceFeedUpdates.selector,
                pythData.proofs,
                pythData.feedHashes,
                uint64(pythData.timestamps[0]),
                uint64(pythData.timestamps[0])
            ),
            abi.encode(priceFeeds)
        );

        vm.expectCall(
            address(mockPyth),
            abi.encodeWithSelector(
                IPyth.parsePriceFeedUpdates.selector,
                pythData.proofs,
                pythData.feedHashes,
                uint64(pythData.timestamps[0]),
                uint64(pythData.timestamps[0])
            ),
            1
        );

        vm.expectCall(address(mockPyth), abi.encodeWithSelector(IPyth.getUpdateFee.selector), 1);

        (uint256[] memory prices, uint256[] memory times) =
            PerpDexPricesLib.getPreviousPriceAndTime(roundIds, pythData, mockBisonAIRouter, mockPyth);

        assertEq(prices.length, tokenCount);
        assertEq(times.length, tokenCount);
        for (uint64 i = 0; i < tokenCount; i++) {
            assertEq(uint256(prices[i]), uint256(testPrice));
            assertEq(times[i], block.timestamp - i);
        }
    }

    function test_getPreviousPriceAndTime_pyth_checkPythPriceFeedOrder() public {
        vm.roll(200);
        vm.warp(1_641_070_800);

        uint64[] memory roundIds = new uint64[](0);
        (, IBisonAIRouter mockBisonAIRouter, IPyth mockPyth,, PerpDexLib.OraclePrices memory pythData) = getOracleBase(tokenCount);

        int64 testPrice = 50_000;

        for (uint64 i = 0; i < tokenCount; i++) {
            pythData.answers[i] = testPrice;
            pythData.timestamps[i] = block.timestamp;
            pythData.feedHashes[i] = getPythPriceFeedId(PerpDexLib.TokenType(i));
        }

        IPyth.PythPrice memory pythPrice = IPyth.PythPrice({price: testPrice, conf: 0, expo: 0, publishTime: uint64(block.timestamp)});
        IPyth.PythPriceFeed[] memory priceFeeds = new IPyth.PythPriceFeed[](tokenCount);
        priceFeeds[0] = IPyth.PythPriceFeed({id: pythData.feedHashes[1], price: pythPrice, emaPrice: pythPrice});
        priceFeeds[1] = IPyth.PythPriceFeed({id: pythData.feedHashes[0], price: pythPrice, emaPrice: pythPrice});

        vm.mockCall(
            address(mockPyth),
            abi.encodeWithSelector(
                IPyth.parsePriceFeedUpdates.selector,
                pythData.proofs,
                pythData.feedHashes,
                uint64(pythData.timestamps[0]),
                uint64(pythData.timestamps[0])
            ),
            abi.encode(priceFeeds)
        );

        vm.expectRevert("Feed hash is not correct");
        PerpDexPricesLib.getPreviousPriceAndTime(roundIds, pythData, mockBisonAIRouter, mockPyth);

        priceFeeds[0] = IPyth.PythPriceFeed({id: pythData.feedHashes[0], price: pythPrice, emaPrice: pythPrice});
        priceFeeds[1] = IPyth.PythPriceFeed({id: pythData.feedHashes[0], price: pythPrice, emaPrice: pythPrice});

        vm.mockCall(
            address(mockPyth),
            abi.encodeWithSelector(
                IPyth.parsePriceFeedUpdates.selector,
                pythData.proofs,
                pythData.feedHashes,
                uint64(pythData.timestamps[0]),
                uint64(pythData.timestamps[0])
            ),
            abi.encode(priceFeeds)
        );
        vm.expectRevert("Feed hash is not correct");
        PerpDexPricesLib.getPreviousPriceAndTime(roundIds, pythData, mockBisonAIRouter, mockPyth);
    }

    function test_checkPriceDataOrder_using_getPreviousPriceAndTime() public {
        uint64[] memory roundIds = new uint64[](0);

        (, IBisonAIRouter mockBisonAIRouter, IPyth mockPyth, PerpDexLib.OraclePrices memory bisonAIData2,) = getOracleBase(tokenCount);
        for (uint64 i = 0; i < tokenCount; i++) {
            bisonAIData2.feedHashes[i] = getBisonAIFeedHash(PerpDexLib.TokenType(0));
        }

        vm.expectRevert("Feed hash is not correct (BisonAI)");
        PerpDexPricesLib.getPreviousPriceAndTime(roundIds, bisonAIData2, mockBisonAIRouter, mockPyth);
    }

    /**
     * roundIds.length == 0 but it's not pyth
     */
    function test_getPreviousPriceAndTime_bisonai_roundIds() public {
        uint64[] memory roundIds = new uint64[](0);
        (, IBisonAIRouter mockBisonAIRouter, IPyth mockPyth, PerpDexLib.OraclePrices memory bisonAIData,) = getOracleBase(tokenCount);
        for (uint64 i = 0; i < tokenCount; i++) {
            bisonAIData.feedHashes[i] = getBisonAIFeedHash(PerpDexLib.TokenType(i));
        }

        vm.expectRevert("RoundIds length is 0");
        PerpDexPricesLib.getPreviousPriceAndTime(roundIds, bisonAIData, mockBisonAIRouter, mockPyth);
    }

    function test_submitAndGetBisonAIRoundId() public {
        (IBisonAISubmissionProxy mockBisonAISubmissionProxy, IBisonAIRouter mockBisonAIRouter,, PerpDexLib.OraclePrices memory bisonAIData,)
        = getOracleBase(tokenCount);

        for (uint64 i = 0; i < tokenCount; i++) {
            bisonAIData.feedHashes[i] = getBisonAIFeedHash(PerpDexLib.TokenType(i));
            bisonAIData.timestamps[i] = i + 100;
        }

        uint64 roundId = 1;
        int256 answer = 1;
        uint256 updatedAt = block.timestamp;

        vm.expectCall(
            address(mockBisonAISubmissionProxy),
            abi.encodeWithSelector(
                IBisonAISubmissionProxy.submitWithoutSupersedValidation.selector,
                bisonAIData.feedHashes,
                bisonAIData.answers,
                bisonAIData.timestamps,
                bisonAIData.proofs
            ),
            1
        );

        for (uint256 i; i < tokenCount; i++) {
            vm.mockCall(
                address(mockBisonAISubmissionProxy),
                abi.encodeWithSelector(IBisonAISubmissionProxy.lastSubmissionTimes.selector, bisonAIData.feedHashes[i]),
                abi.encode(i + 100)
            );
            vm.mockCall(
                address(mockBisonAIRouter),
                abi.encodeWithSelector(
                    IBisonAIRouter.latestRoundData.selector, PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType(i))
                ),
                abi.encode(roundId, answer, updatedAt)
            );
            vm.expectCall(
                address(mockBisonAIRouter),
                abi.encodeWithSelector(
                    IBisonAIRouter.latestRoundData.selector, PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType(i))
                ),
                1
            );

            vm.expectEmit(true, true, true, true);
            emit PerpDex.SubmittedRoundId(PerpDexLib.TokenType(i), roundId);
        }

        PerpDexPricesLib.submitAndGetBisonAIRoundId(bisonAIData, mockBisonAISubmissionProxy, mockBisonAIRouter);
    }

    function test_submitAndGetBisonAIRoundId_revert() public {
        (
            IBisonAISubmissionProxy mockBisonAISubmissionProxy,
            IBisonAIRouter mockBisonAIRouter,
            ,
            PerpDexLib.OraclePrices memory bisonAIData,
            PerpDexLib.OraclePrices memory pythData
        ) = getOracleBase(tokenCount);

        // Wrong oracle
        vm.expectRevert("Wrong oracle type");
        PerpDexPricesLib.submitAndGetBisonAIRoundId(pythData, mockBisonAISubmissionProxy, mockBisonAIRouter);

        // Wrong length
        bisonAIData.answers = new int256[](1);
        vm.expectRevert("Lengths are not equal");
        PerpDexPricesLib.submitAndGetBisonAIRoundId(bisonAIData, mockBisonAISubmissionProxy, mockBisonAIRouter);
        bisonAIData.answers = new int256[](tokenCount);
        bisonAIData.timestamps = new uint256[](1);
        vm.expectRevert("Lengths are not equal");
        PerpDexPricesLib.submitAndGetBisonAIRoundId(bisonAIData, mockBisonAISubmissionProxy, mockBisonAIRouter);
        bisonAIData.timestamps = new uint256[](tokenCount);
        bisonAIData.proofs = new bytes[](1);
        vm.expectRevert("Lengths are not equal");
        PerpDexPricesLib.submitAndGetBisonAIRoundId(bisonAIData, mockBisonAISubmissionProxy, mockBisonAIRouter);
        bisonAIData.proofs = new bytes[](tokenCount);

        // order
        for (uint64 i = 0; i < tokenCount; i++) {
            bisonAIData.feedHashes[i] = getBisonAIFeedHash(PerpDexLib.TokenType(i));
        }
        bisonAIData.feedHashes[1] = bisonAIData.feedHashes[0];
        vm.expectRevert("Feed hash is not correct (BisonAI)");
        PerpDexPricesLib.submitAndGetBisonAIRoundId(bisonAIData, mockBisonAISubmissionProxy, mockBisonAIRouter);
        for (uint64 i = 0; i < tokenCount; i++) {
            bisonAIData.feedHashes[i] = getBisonAIFeedHash(PerpDexLib.TokenType(i));
            bisonAIData.timestamps[i] = i + 100;
        }

        // Price is not up to date
        vm.mockCall(
            address(mockBisonAISubmissionProxy),
            abi.encodeWithSelector(
                IBisonAISubmissionProxy.submitWithoutSupersedValidation.selector,
                bisonAIData.feedHashes,
                bisonAIData.answers,
                bisonAIData.timestamps,
                bisonAIData.proofs
            ),
            abi.encode()
        );
        vm.mockCall(
            address(mockBisonAISubmissionProxy),
            abi.encodeWithSelector(IBisonAISubmissionProxy.lastSubmissionTimes.selector, bisonAIData.feedHashes[0]),
            abi.encode(100)
        );
        vm.mockCall(
            address(mockBisonAISubmissionProxy),
            abi.encodeWithSelector(IBisonAISubmissionProxy.lastSubmissionTimes.selector, bisonAIData.feedHashes[1]),
            abi.encode(100)
        );
        vm.mockCall(address(mockBisonAIRouter), abi.encodeWithSelector(IBisonAIRouter.latestRoundData.selector), abi.encode(1, 2, 3));
        vm.expectRevert("Price is not up to date (BisonAI)");
        PerpDexPricesLib.submitAndGetBisonAIRoundId(bisonAIData, mockBisonAISubmissionProxy, mockBisonAIRouter);

        // Price is 0
        vm.mockCall(
            address(mockBisonAISubmissionProxy),
            abi.encodeWithSelector(IBisonAISubmissionProxy.lastSubmissionTimes.selector, bisonAIData.feedHashes[0]),
            abi.encode(100)
        );
        vm.mockCall(
            address(mockBisonAIRouter), abi.encodeWithSelector(IBisonAIRouter.latestRoundData.selector), abi.encode(1, 0, block.timestamp)
        );
        vm.expectRevert("Price is 0 (BisonAI)");
        PerpDexPricesLib.submitAndGetBisonAIRoundId(bisonAIData, mockBisonAISubmissionProxy, mockBisonAIRouter);
    }

    function test_submitAndGetLatestPrice() public {
        (
            IBisonAISubmissionProxy mockBisonAISubmissionProxy,
            IBisonAIRouter mockBisonAIRouter,
            IPyth mockPyth,
            PerpDexLib.OraclePrices memory bisonAIData,
            PerpDexLib.OraclePrices memory pythData
        ) = getOracleBase(1);

        bisonAIData.feedHashes[0] = getBisonAIFeedHash(PerpDexLib.TokenType.Btc);
        bisonAIData.timestamps[0] = 100;

        // BisonAI
        vm.mockCall(
            address(mockBisonAISubmissionProxy),
            abi.encodeWithSelector(
                IBisonAISubmissionProxy.submitSingleWithoutSupersedValidation.selector,
                bisonAIData.feedHashes[0],
                bisonAIData.answers[0],
                bisonAIData.timestamps[0],
                bisonAIData.proofs[0]
            ),
            abi.encode()
        );
        vm.expectCall(
            address(mockBisonAISubmissionProxy),
            abi.encodeWithSelector(
                IBisonAISubmissionProxy.submitSingleWithoutSupersedValidation.selector,
                bisonAIData.feedHashes[0],
                bisonAIData.answers[0],
                bisonAIData.timestamps[0],
                bisonAIData.proofs[0]
            ),
            1
        );
        vm.mockCall(
            address(mockBisonAISubmissionProxy),
            abi.encodeWithSelector(IBisonAISubmissionProxy.lastSubmissionTimes.selector, bisonAIData.feedHashes[0]),
            abi.encode(100)
        );
        vm.expectCall(
            address(mockBisonAISubmissionProxy),
            abi.encodeWithSelector(IBisonAISubmissionProxy.lastSubmissionTimes.selector, bisonAIData.feedHashes[0]),
            1
        );
        vm.mockCall(
            address(mockBisonAIRouter), abi.encodeWithSelector(IBisonAIRouter.latestRoundData.selector), abi.encode(1, 1, block.timestamp)
        );
        vm.expectCall(
            address(mockBisonAIRouter),
            abi.encodeWithSelector(IBisonAIRouter.latestRoundData.selector, PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Btc)),
            1
        );
        uint256 answer = PerpDexPricesLib.submitAndGetLatestPrice(
            bisonAIData, PerpDexLib.TokenType.Btc, mockBisonAISubmissionProxy, mockBisonAIRouter, mockPyth
        );
        vm.assertEq(answer, 1);

        // Pyth
        pythData.feedHashes[0] = 0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43;
        vm.mockCall(address(mockPyth), abi.encodeWithSelector(IPyth.getUpdateFee.selector), abi.encode(1));
        vm.mockCall(address(mockPyth), abi.encodeWithSelector(IPyth.updatePriceFeeds.selector), abi.encode());
        IPyth.PythPrice memory pythPrice = IPyth.PythPrice({price: 1, conf: 2, expo: 3, publishTime: 4});
        vm.mockCall(address(mockPyth), abi.encodeWithSelector(IPyth.getPriceNoOlderThan.selector), abi.encode(pythPrice));

        vm.expectCall(address(mockPyth), abi.encodeWithSelector(IPyth.getUpdateFee.selector), 1);
        vm.expectCall(address(mockPyth), abi.encodeWithSelector(IPyth.updatePriceFeeds.selector), 1);
        vm.expectCall(address(mockPyth), abi.encodeWithSelector(IPyth.getPriceNoOlderThan.selector), 1);
        PerpDexPricesLib.submitAndGetLatestPrice(
            pythData, PerpDexLib.TokenType.Btc, mockBisonAISubmissionProxy, mockBisonAIRouter, mockPyth
        );
    }

    function test_submitAndGetLatestPrice_revert() public {
        (
            IBisonAISubmissionProxy mockBisonAISubmissionProxy,
            IBisonAIRouter mockBisonAIRouter,
            IPyth mockPyth,
            PerpDexLib.OraclePrices memory bisonAIData,
            PerpDexLib.OraclePrices memory pythData
        ) = getOracleBase(1);

        bisonAIData.feedHashes = new bytes32[](2);
        vm.expectRevert("Length is not 1");
        PerpDexPricesLib.submitAndGetLatestPrice(
            bisonAIData, PerpDexLib.TokenType.Btc, mockBisonAISubmissionProxy, mockBisonAIRouter, mockPyth
        );
        bisonAIData.feedHashes = new bytes32[](1);
        bisonAIData.proofs = new bytes[](2);
        vm.expectRevert("Length is not 1");
        PerpDexPricesLib.submitAndGetLatestPrice(
            bisonAIData, PerpDexLib.TokenType.Btc, mockBisonAISubmissionProxy, mockBisonAIRouter, mockPyth
        );
        bisonAIData.proofs = new bytes[](1);

        bisonAIData.timestamps[0] = 100;
        vm.mockCall(
            address(mockBisonAISubmissionProxy),
            abi.encodeWithSelector(IBisonAISubmissionProxy.lastSubmissionTimes.selector, bisonAIData.feedHashes[0]),
            abi.encode(99)
        );
        vm.expectRevert("Price is not up to date (BisonAI)");
        PerpDexPricesLib.submitAndGetLatestPrice(
            bisonAIData, PerpDexLib.TokenType.Btc, mockBisonAISubmissionProxy, mockBisonAIRouter, mockPyth
        );

        pythData.feedHashes[0] = 0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43;
        vm.mockCall(address(mockPyth), abi.encodeWithSelector(IPyth.getUpdateFee.selector), abi.encode(1));
        vm.mockCall(address(mockPyth), abi.encodeWithSelector(IPyth.updatePriceFeeds.selector), abi.encode());
        IPyth.PythPrice memory pythPrice = IPyth.PythPrice({price: 0, conf: 2, expo: 3, publishTime: 4});
        vm.mockCall(address(mockPyth), abi.encodeWithSelector(IPyth.getPriceNoOlderThan.selector), abi.encode(pythPrice));
        vm.expectRevert("Price is 0 (Pyth)");
        PerpDexPricesLib.submitAndGetLatestPrice(
            pythData, PerpDexLib.TokenType.Btc, mockBisonAISubmissionProxy, mockBisonAIRouter, mockPyth
        );
    }

    function test_getPythFeedHashOrder() public view {
        bytes32[] memory feedHash = PerpDexPricesLib.getPythFeedHashOrder();
        for (uint256 i = 0; i < tokenCount; i++) {
            PerpDexLib.TokenType tokenType = PerpDexLib.TokenType(i);
            bytes32 feedHashTest = getPythPriceFeedId(tokenType);
            assertEq(feedHash[i], feedHashTest);
        }
    }

    function test_getPreviousPriceAndTime_checkOrder() public {
        vm.warp(200);

        uint64[] memory roundIds = new uint64[](tokenCount);
        (
            ,
            IBisonAIRouter mockBisonAIRouter,
            IPyth mockPyth,
            PerpDexLib.OraclePrices memory bisonAIData,
            PerpDexLib.OraclePrices memory pythData
        ) = getOracleBase(tokenCount);

        int256 testPrice = 50_000;

        for (uint64 i = 0; i < tokenCount; i++) {
            roundIds[i] = i + 1;
            bisonAIData.feedHashes[i] = getBisonAIFeedHash(PerpDexLib.TokenType(i));
            bisonAIData.answers[i] = testPrice;
            bisonAIData.timestamps[i] = block.timestamp - i;

            vm.mockCall(
                address(mockBisonAIRouter),
                abi.encodeWithSelector(
                    IBisonAIRouter.getRoundData.selector, PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType(i)), uint64(i + 1)
                ),
                abi.encode(uint64(i + 1), int256(testPrice), uint64(block.timestamp - i))
            );
        }

        PerpDexPricesLib.getPreviousPriceAndTime(roundIds, bisonAIData, mockBisonAIRouter, mockPyth);

        bytes32 temp = bisonAIData.feedHashes[4];
        bisonAIData.feedHashes[4] = bisonAIData.feedHashes[5];
        bisonAIData.feedHashes[5] = temp;

        vm.expectRevert("Feed hash is not correct (BisonAI)");
        PerpDexPricesLib.getPreviousPriceAndTime(roundIds, bisonAIData, mockBisonAIRouter, mockPyth);

        IPyth.PythPriceFeed[] memory priceFeeds = new IPyth.PythPriceFeed[](tokenCount);
        for (uint64 i = 0; i < tokenCount; i++) {
            uint256 timestampForTest = block.timestamp - i;
            pythData.answers[i] = testPrice;
            pythData.timestamps[i] = timestampForTest;
            pythData.feedHashes[i] = getPythPriceFeedId(PerpDexLib.TokenType(i));
            int64 price = (i == 5 || i == 10) ? int64(testPrice * 100) : int64(testPrice);
            IPyth.PythPrice memory pythPrice = IPyth.PythPrice({price: price, conf: 0, expo: 0, publishTime: uint64(timestampForTest)});
            priceFeeds[i] = IPyth.PythPriceFeed({id: pythData.feedHashes[i], price: pythPrice, emaPrice: pythPrice});
        }
        vm.mockCall(
            address(mockPyth),
            abi.encodeWithSelector(
                IPyth.parsePriceFeedUpdates.selector,
                pythData.proofs,
                pythData.feedHashes,
                uint64(pythData.timestamps[0]),
                uint64(pythData.timestamps[0])
            ),
            abi.encode(priceFeeds)
        );
        PerpDexPricesLib.getPreviousPriceAndTime(roundIds, pythData, mockBisonAIRouter, mockPyth);

        temp = pythData.feedHashes[4];
        pythData.feedHashes[4] = pythData.feedHashes[5];
        pythData.feedHashes[5] = temp;

        vm.expectRevert("Feed hash is not correct (Pyth)");
        PerpDexPricesLib.getPreviousPriceAndTime(roundIds, pythData, mockBisonAIRouter, mockPyth);
    }

    function test_getBisonAIFeedName() public {
        // Test for each token type
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Btc), "BTC-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Klay), "KAIA-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Wemix), "WEMIX-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Eth), "ETH-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Doge), "DOGE-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Pepe), "PEPE-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Sol), "SOL-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Xrp), "XRP-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Apt), "APT-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Sui), "SUI-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Shib), "SHIB-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Sei), "SEI-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Ada), "ADA-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Pol), "POL-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Bnb), "BNB-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Dot), "DOT-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Ltc), "LTC-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Avax), "AVAX-USDT");
        assertEq(PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType.Trump), "TRUMP-USDT");

        // Test revert for invalid token type
        uint256 invalidTokenType = 100;
        vm.expectRevert(); // panic: failed to convert value into enum type (0x21)
        PerpDexPricesLib.getBisonAIFeedName(PerpDexLib.TokenType(invalidTokenType));
    }
}
