// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../src/PerpDex.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Test, console} from "forge-std/Test.sol";

using SafeERC20 for IERC20;

// @see: https://github.com/jordaniza/OZ-Upgradeable-Foundry/blob/main/script/DeployUUPS.s.sol
contract UUPSProxy is ERC1967Proxy {
    constructor(address _implementation, bytes memory _data) ERC1967Proxy(_implementation, _data) {}
}

contract PerpDexTestBase is PerpDex, Test {
    using ECDSA for bytes32;

    address liqAdmin;
    address limitAdmin;
    address singleOpenAdmin;
    address closeAdmin;
    address tpslAdmin;

    address user;
    address user2;
    address user3;

    uint256 userPk;
    uint256 userPk2;
    uint256 userPk3;

    uint64 tokenCount = 19;
    uint256 defaultTotalFeePercent = 70;
    uint256 defaultFeeDenominator = 100_000;
    uint256 defaultMarginFeePercent = 100;

    function setUp() public virtual {
        vm.chainId(8217);

        vm.startPrank(owner());
        this.addInitialTokenTotalSizes(tokenCount);
        this.changeMaxTokenTotalSizes();

        address usdt = address(1);
        address lp = address(2);
        address feeContract = address(3);

        vm.mockCall(usdt, abi.encodeWithSelector(IERC20.approve.selector, feeContract, type(uint256).max), abi.encode(true));
        vm.mockCall(usdt, abi.encodeWithSelector(IERC20Metadata.decimals.selector), abi.encode(6));
        this.setupAddr(usdt, lp, feeContract);

        bisonAIRouter = IBisonAIRouter(address(4));
        bisonAISubmissionProxy = IBisonAISubmissionProxy(address(5));
        pyth = IPyth(address(6));
        this.setOracles(address(bisonAIRouter), address(bisonAISubmissionProxy), address(pyth));

        vm.stopPrank();
        adminSetUp();
        userSetUp();
    }

    function adminSetUp() public {
        (admin,) = makeAddrAndKey("admin");
        vm.startPrank(owner());
        this.setAdmin(admin);

        liqAdmin = makeAddr("liqAdmin");
        limitAdmin = makeAddr("limitAdmin");
        singleOpenAdmin = makeAddr("singleOpenAdmin");
        closeAdmin = makeAddr("closeAdmin");
        tpslAdmin = makeAddr("tpslAdmin");

        address[] memory closeAdminsArray = new address[](1);
        closeAdminsArray[0] = closeAdmin;
        this.setAdmins(PerpDexAuthLib.AdminType.Close, closeAdminsArray);

        address[] memory liqAdminsArray = new address[](1);
        liqAdminsArray[0] = liqAdmin;
        this.setAdmins(PerpDexAuthLib.AdminType.Liquidation, liqAdminsArray);

        address[] memory limitAdminsArray = new address[](1);
        limitAdminsArray[0] = limitAdmin;
        this.setAdmins(PerpDexAuthLib.AdminType.LimitOrder, limitAdminsArray);

        address[] memory singleOpenAdminsArray = new address[](1);
        singleOpenAdminsArray[0] = singleOpenAdmin;
        this.setAdmins(PerpDexAuthLib.AdminType.SingleOpen, singleOpenAdminsArray);

        address[] memory tpslAdminsArray = new address[](1);
        tpslAdminsArray[0] = tpslAdmin;
        this.setAdmins(PerpDexAuthLib.AdminType.Tpsl, tpslAdminsArray);

        vm.stopPrank();
    }

    function userSetUp() public {
        (user, userPk) = makeAddrAndKey("user");
        (user2, userPk2) = makeAddrAndKey("user2");
        (user2, userPk2) = makeAddrAndKey("user2");
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

    function getAdminsByRole(PerpDexAuthLib.AdminType adminType) public view returns (address[] memory) {
        return adminsByRole[adminType];
    }

    function getTraderOpenPositionId(address trader, uint16 tokenType) public view returns (uint256 long, uint256 short) {
        PerpDexLib.TraderOpenPositionId memory res = traderOpenPositionIds[trader][tokenType];
        return (res.longPositionId, res.shortPositionId);
    }

    function checkLiquidationAdminModifier() public onlyLiquidationAdmin {}
    function checkLimitOrderAdminModifier() public onlyLimitOrderAdmin {}
    function checkLimitOrLiquidationAdminModifier() public onlyLimitOrLiquidationAdmin {}
    function checkSingleOpenAdminModifier() public onlySingleOpenAdmin {}
    function checkCloseAdminModifier() public onlyCloseAdmin {}
    function checkTpslAdminModifier() public onlyTpslAdmin {}

    function mockFee(uint256 totalFeePercent, uint256 feeDenominator, uint256 marginFeePercent) public {
        vm.mockCall(address(externalContracts.feeContract), abi.encodeWithSelector(IFee.payFee.selector), abi.encode());
        vm.mockCall(
            address(externalContracts.feeContract), abi.encodeWithSelector(IFee.getTotalFeePercent.selector), abi.encode(totalFeePercent)
        );
        vm.mockCall(
            address(externalContracts.feeContract), abi.encodeWithSelector(IFee.getFeeDenominator.selector), abi.encode(feeDenominator)
        );
        vm.mockCall(
            address(externalContracts.feeContract), abi.encodeWithSelector(IFee.getMarginFeePercent.selector), abi.encode(marginFeePercent)
        );
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

    struct OpenPositionInput {
        address traderAddr;
        PerpDexLib.TokenType inputTokenType;
        uint256 marginAmount;
        uint256 leverage;
        bool isLong;
        uint256 tpPrice;
        uint256 slPrice;
    }

    function getOpenPositionInput(
        PerpDexLib.TokenType inputTokenType,
        uint256 marginAmount,
        uint256 leverage,
        bool isLong,
        uint256 tpPrice,
        uint256 slPrice
    ) public view returns (OpenPositionInput memory o) {
        return OpenPositionInput({
            traderAddr: user,
            inputTokenType: inputTokenType,
            marginAmount: marginAmount,
            leverage: leverage,
            isLong: isLong,
            tpPrice: tpPrice,
            slPrice: slPrice
        });
    }

    function openPositionDefault(
        address _trader,
        PerpDexLib.TokenType _inputTokenType,
        uint256 _marginAmount,
        uint256 _leverage,
        bool _isLong,
        uint256 openPrice,
        uint256 tpPrice,
        uint256 slPrice
    ) public returns (uint256) {
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(1);
        mockCurrentPrice(openPrice);
        PerpDexLib.OpenPositionData memory data = PerpDexLib.OpenPositionData({
            tokenType: _inputTokenType,
            marginAmount: _marginAmount,
            leverage: _leverage,
            long: _isLong,
            trader: _trader,
            priceData: bisonAIData,
            tpPrice: tpPrice,
            slPrice: slPrice,
            expectedPrice: openPrice,
            userSignedData: hex"1234"
        });

        vm.mockCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), abi.encode());
        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferFromAndCheckBalance.selector), abi.encode()
        );
        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);

        vm.prank(singleOpenAdmin);
        this.openPosition(data);
        return this.nextPositionId() - 1;
    }

    function openPositionDefaultWithMerge(
        PerpDexLib.TokenType _inputTokenType,
        uint256 _marginAmount,
        uint256 _leverage,
        bool _isLong,
        uint256 openPrice,
        uint256 tpPrice,
        uint256 slPrice
    ) public returns (uint256) {
        (PerpDexLib.OraclePrices memory bisonAIData,) = getOraclePricesDefault(1);
        mockCurrentPrice(openPrice);
        PerpDexLib.OpenPositionData memory data = PerpDexLib.OpenPositionData({
            tokenType: _inputTokenType,
            marginAmount: _marginAmount,
            leverage: _leverage,
            long: _isLong,
            trader: user,
            priceData: bisonAIData,
            tpPrice: tpPrice,
            slPrice: slPrice,
            expectedPrice: openPrice,
            userSignedData: hex"1234"
        });

        vm.mockCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), abi.encode());
        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferFromAndCheckBalance.selector), abi.encode()
        );
        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);

        vm.prank(singleOpenAdmin);
        this.openPosition(data);
        return this.nextPositionId() - 1;
    }

    function createLimitOrderDefault(
        PerpDexLib.TokenType _inputTokenType,
        uint256 _marginAmount,
        uint256 _leverage,
        bool _isLong,
        uint256 _wantedPrice,
        uint256 _tpPrice,
        uint256 _slPrice
    ) public returns (uint256) {
        uint256 positionId = this.nextPositionId();
        OpenPositionInput memory input = getOpenPositionInput(_inputTokenType, _marginAmount, _leverage, _isLong, _tpPrice, _slPrice);
        mockFee(defaultTotalFeePercent, defaultFeeDenominator, defaultMarginFeePercent);

        vm.mockCall(address(PerpDexAuthLib), abi.encodeWithSelector(PerpDexAuthLib.checkUser.selector), abi.encode());
        vm.mockCall(
            address(PerpDexPricesLib), abi.encodeWithSelector(PerpDexPricesLib.safeTransferFromAndCheckBalance.selector), abi.encode()
        );
        PerpDexLib.OpenLimitOrderData memory o = PerpDexLib.OpenLimitOrderData({
            tokenType: input.inputTokenType,
            marginAmount: input.marginAmount,
            leverage: input.leverage,
            long: input.isLong,
            trader: user,
            wantedPrice: _wantedPrice,
            tpPrice: input.tpPrice,
            slPrice: input.slPrice,
            userSignedData: hex"1234"
        });
        vm.prank(singleOpenAdmin);
        this.openLimitOrder(o);

        return positionId;
    }

    function signMessage(string memory message, uint256 privateKey) internal returns (bytes memory) {
        emit log_string(message);
        bytes32 ethSignedMessageHash =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(bytes(message).length), message));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }

    function createOpenPositionMessage(
        uint256 tokenType,
        uint256 margin,
        uint256 leverage,
        bool isLong,
        uint256 tpPrice,
        uint256 slPrice,
        uint256 expectedPrice,
        uint256 nonce
    ) internal view returns (string memory) {
        return string(
            abi.encodePacked(
                "Open position for Token: ",
                Strings.toString(tokenType),
                ", Margin: ",
                Strings.toString(margin),
                ", Leverage: ",
                Strings.toString(leverage),
                ", Long: ",
                Strings.toString(isLong ? 1 : 0),
                ", TP: ",
                Strings.toString(tpPrice),
                ", SL: ",
                Strings.toString(slPrice),
                ", Price: ",
                Strings.toString(expectedPrice),
                ", Nonce: ",
                Strings.toString(nonce),
                ", Chain: 8217, Contract: ",
                Strings.toHexString(address(this))
            )
        );
    }

    function createOpenLimitOrderMessage(
        uint256 tokenType,
        uint256 margin,
        uint256 leverage,
        bool isLong,
        uint256 wantedPrice,
        uint256 tpPrice,
        uint256 slPrice,
        uint256 nonce
    ) internal view returns (string memory) {
        return string(
            abi.encodePacked(
                "Open Limit Order for Token: ",
                Strings.toString(tokenType),
                ", Margin: ",
                Strings.toString(margin),
                ", Leverage: ",
                Strings.toString(leverage),
                ", Long: ",
                Strings.toString(isLong ? 1 : 0),
                ", Wanted Price: ",
                Strings.toString(wantedPrice),
                ", TP: ",
                Strings.toString(tpPrice),
                ", SL: ",
                Strings.toString(slPrice),
                ", Nonce: ",
                Strings.toString(nonce),
                ", Chain: 8217, Contract: ",
                Strings.toHexString(address(this))
            )
        );
    }

    function createClosePositionMessage(uint256 positionId, uint256 nonce) internal view returns (string memory) {
        return string(
            abi.encodePacked(
                "Close Position: ",
                Strings.toString(positionId),
                ", Nonce: ",
                Strings.toString(nonce),
                ", Chain: 8217, Contract: ",
                Strings.toHexString(address(this))
            )
        );
    }

    function createCloseLimitOrderMessage(uint256 positionId, uint256 nonce) internal view returns (string memory) {
        return string(
            abi.encodePacked(
                "Close Limit Order: ",
                Strings.toString(positionId),
                ", Nonce: ",
                Strings.toString(nonce),
                ", Chain: 8217, Contract: ",
                Strings.toHexString(address(this))
            )
        );
    }

    function getOracleBase(uint256 count)
        public
        pure
        returns (
            IBisonAISubmissionProxy mockBisonAISubmissionProxy,
            IBisonAIRouter mockBisonAIRouter,
            IPyth mockPyth,
            PerpDexLib.OraclePrices memory bisonAIData,
            PerpDexLib.OraclePrices memory pythData
        )
    {
        mockBisonAISubmissionProxy = IBisonAISubmissionProxy(address(1));
        mockBisonAIRouter = IBisonAIRouter(address(2));
        mockPyth = IPyth(address(3));

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
            proofs: new bytes[](1)
        });
    }

    function getPythPriceFeedId(PerpDexLib.TokenType tokenType) public pure returns (bytes32 feedHash) {
        if (tokenType == PerpDexLib.TokenType.Btc) {
            feedHash = 0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43;
        } else if (tokenType == PerpDexLib.TokenType.Klay) {
            feedHash = 0x452d40e01473f95aa9930911b4392197b3551b37ac92a049e87487b654b4ebbe;
        } else if (tokenType == PerpDexLib.TokenType.Wemix) {
            feedHash = 0xf63f008474fad630207a1cfa49207d59bca2593ea64fc0a6da9bf3337485791c;
        } else if (tokenType == PerpDexLib.TokenType.Eth) {
            feedHash = 0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace;
        } else if (tokenType == PerpDexLib.TokenType.Doge) {
            feedHash = 0xdcef50dd0a4cd2dcc17e45df1676dcb336a11a61c69df7a0299b0150c672d25c;
        } else if (tokenType == PerpDexLib.TokenType.Pepe) {
            feedHash = 0xd69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e4;
        } else if (tokenType == PerpDexLib.TokenType.Sol) {
            feedHash = 0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d;
        } else if (tokenType == PerpDexLib.TokenType.Xrp) {
            feedHash = 0xec5d399846a9209f3fe5881d70aae9268c94339ff9817e8d18ff19fa05eea1c8;
        } else if (tokenType == PerpDexLib.TokenType.Apt) {
            feedHash = 0x03ae4db29ed4ae33d323568895aa00337e658e348b37509f5372ae51f0af00d5;
        } else if (tokenType == PerpDexLib.TokenType.Sui) {
            feedHash = 0x23d7315113f5b1d3ba7a83604c44b94d79f4fd69af77f804fc7f920a6dc65744;
        } else if (tokenType == PerpDexLib.TokenType.Shib) {
            feedHash = 0xf0d57deca57b3da2fe63a493f4c25925fdfd8edf834b20f93e1f84dbd1504d4a;
        } else if (tokenType == PerpDexLib.TokenType.Sei) {
            feedHash = 0x53614f1cb0c031d4af66c04cb9c756234adad0e1cee85303795091499a4084eb;
        } else if (tokenType == PerpDexLib.TokenType.Ada) {
            feedHash = 0x2a01deaec9e51a579277b34b122399984d0bbf57e2458a7e42fecd2829867a0d;
        } else if (tokenType == PerpDexLib.TokenType.Pol) {
            feedHash = 0xffd11c5a1cfd42f80afb2df4d9f264c15f956d68153335374ec10722edd70472;
        } else if (tokenType == PerpDexLib.TokenType.Bnb) {
            feedHash = 0x2f95862b045670cd22bee3114c39763a4a08beeb663b145d283c31d7d1101c4f;
        } else if (tokenType == PerpDexLib.TokenType.Dot) {
            feedHash = 0xca3eed9b267293f6595901c734c7525ce8ef49adafe8284606ceb307afa2ca5b;
        } else if (tokenType == PerpDexLib.TokenType.Ltc) {
            feedHash = 0x6e3f3fa8253588df9326580180233eb791e03b443a3ba7a1d892e73874e19a54;
        } else if (tokenType == PerpDexLib.TokenType.Avax) {
            feedHash = 0x93da3352f9f1d105fdfe4971cfa80e9dd777bfc5d0f683ebb6e1294b92137bb7;
        } else if (tokenType == PerpDexLib.TokenType.Trump) {
            feedHash = 0x879551021853eec7a7dc827578e8e69da7e4fa8148339aa0d3d5296405be4b1a;
        } else {
            revert("Unknown token type");
        }
    }

    function getBisonAIFeedHash(PerpDexLib.TokenType tokenType) public pure returns (bytes32 feedHash) {
        return keccak256(abi.encodePacked(PerpDexPricesLib.getBisonAIFeedName(tokenType)));
    }

    function resetPositions(uint256 count) public {
        for (uint256 i = 0; i < count; i++) {
            delete positions[i];
        }
    }

    function assertPosition(PerpDexLib.Position memory position, PerpDexLib.Position memory data) public pure {
        assertEq(position.positionId, data.positionId, "positionId");
        assertEq(position.traderAddr, data.traderAddr, "traderAddr");
        assertEq(uint256(position.tokenType), uint256(data.tokenType), "tokenType");
        assertEq(position.margin, data.margin, "margin");
        assertEq(position.size, data.size, "size");
        assertEq(position.openFee, data.openFee, "openFee");
        assertEq(position.initialPrice, data.initialPrice, "initialPrice");
        assertEq(position.isLong, data.isLong, "isLong");
        assertEq(position.openPositionIndex, data.openPositionIndex, "openPositionIndex");
        assertEq(position.finalPrice, data.finalPrice, "finalPrice");
        assertEq(uint256(position.positionStatus), uint256(data.positionStatus), "positionStatus");
        assertEq(position.limitOrderPrice, data.limitOrderPrice, "limitOrderPrice");
        assertEq(position.limitOrderIndex, data.limitOrderIndex, "limitOrderIndex");
        assertEq(position.statusTime.requestOpenTime, data.statusTime.requestOpenTime, "requestOpenTime");
        assertEq(position.statusTime.openTime, data.statusTime.openTime, "openTime");
        assertEq(position.statusTime.closeTime, data.statusTime.closeTime, "closeTime");
        assertEq(position.statusTime.limitOpenTime, data.statusTime.limitOpenTime, "limitOpenTime");
        assertEq(position.statusTime.limitCloseTime, data.statusTime.limitCloseTime, "limitCloseTime");
        assertEq(position.statusTime.liquidatedTime, data.statusTime.liquidatedTime, "liquidatedTime");
        assertEq(position.pnl, data.pnl, "pnl");
        assertEq(position.liquidationPrice, data.liquidationPrice, "liquidationPrice");
        assertEq(position.tpPrice, data.tpPrice, "tpPrice");
        assertEq(position.slPrice, data.slPrice, "slPrice");
        assertEq(position.marginUpdatedTime, data.marginUpdatedTime, "marginUpdatedTime");
        assertEq(position.accFundingFeePerSize, data.accFundingFeePerSize, "accFundingFeePerSize");
        assertEq(position.fundingFee, data.fundingFee, "fundingFee");
        assertEq(position.closeFee, data.closeFee, "closeFee");
        assertEq(position.tpslUpdatedTime, data.tpslUpdatedTime, "tpslUpdatedTime");
    }
}
