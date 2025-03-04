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

contract PerpDexForkPythTest is Test {
    using ECDSA for bytes32;

    UUPSProxy public perpDexProxy;
    // Interface to interact with the proxy as PerpDex
    PerpDex public perpDex;

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
        openPositionForkId = vm.createFork(KAIA_RPC_URL, 167_759_290);
        closeForkId = vm.createFork(KAIA_RPC_URL, 167_580_639);

        // limitOrderForkId = vm.createFork(KAIA_RPC_URL, 167_822_927);
        // liquidationForkId = vm.createFork(KAIA_RPC_URL, 167_581_872);
        limitOrderForkId = vm.createFork(KAIA_RPC_URL, 169_474_582);
        liquidationForkId = vm.createFork(KAIA_RPC_URL, 169_828_869);
    }

    function deployAndSet() public {
        lpContract = LP(0xfFD3928Be7FA924Aa9c19b7CD4c107e9F276d9e8);
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
        UUPSProxy feeProxy = new UUPSProxy(address(feeImpl), "");
        feeContract = Fee(address(feeProxy));
        feeContract.initialize(owner);

        feeContract.setUsdtAddr(address(usdtContract));
        feeContract.setPerpDexAddr(address(perpDex));

        LP lpImpl = new LP();
        UUPSProxy lpProxy = new UUPSProxy(address(lpImpl), "");
        lpContract = LP(address(lpProxy));
        lpContract.initialize(owner, address(usdtContract), address(perpDex));

        deal(address(usdtContract), address(lpContract), initialLpBalance);
        deal(address(lpContract), initialLpBalance);

        bisonAIRouter = IBisonAIRouter(0x653078F0D3a230416A59aA6486466470Db0190A2);
        bisonAISubmissionProxy = IBisonAISubmissionProxy(0x3a251c738e19806A546815eb6065e139A8D65B4b);
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
        deal(user, initialUserBalance);
    }

    function getSignedMessage(uint256 pk, bytes memory message) internal pure returns (bytes memory) {
        bytes32 ethSignedMessageHash =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(message.length), message));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }

    function test_getUpdateFee_getPriceNoOlderThan() public {
        vm.selectFork(openPositionForkId);
        vm.rollFork(167_759_290);
        deployAndSet();
        PerpDexLib.OraclePrices memory priceData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.Pyth,
            feedHashes: new bytes32[](1),
            answers: new int256[](1),
            timestamps: new uint256[](1),
            proofs: new bytes[](1)
        });

        priceData.feedHashes[0] = 0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43;
        priceData.answers[0] = 6_694_292_072_563;
        priceData.timestamps[0] = 1_729_766_814;

        priceData.proofs[0] =
            hex"504e41550100000003b801000000040d02b7f9d624bddd972f48ce19cfb053bf5f7b4ff9908d76ca04938623c2b959104276a0c9374d198d463adb3a642549ab0614c841f6ef1088278fec1e970331f0bd010372e2953243517e36672311d2d64d35d11042c37c38b247a80a641cb0924daf527261ec8ed73960c8e65d2d1eaf691be35112f1dde3fb6bffa3ca0ae155673f90000430906d40ab1590c0d505910423995675e3d34d583bc9e904150df40cf6eddc607b3cdcbbb10e766e674cdeb7f0e20a7f3ca206943adeac9c9978e7480718e3e101068046a669b6a911f8fe1ab6f61b7dc82dcb6c4637c665c55ba10dff416087839b7847fe186d9caeb096c942b4209a9b6e84f0eba2f10afa0b81cd69de2bf010f1010836d0bfacb58f43805ff721d571a8147d7252400c8c1f3fbb161abaeae873df2a76d7e96f8d60708e95c9d0949ebeda525c1b6b6e013a7e266c52c1a7c9f01f0a010a8c904f51159ff04677520f5e17f931a5c87dcceb53bfb7e12c7916488bb26c3226ea2105647c3f5609b62fa341358db77f832330e1ff82d6880ae1c57f63d192010b3008d1a03137a70d586ad55fd9f42d9a926720ea19973f25210b618c2f8fd01c2d3f2547690f21260cc1276c1408cdde073ae8c25720f4b2a94e9504a9b2f3fd010d5ad540333a470f605e3240af70a9950f488b5abfcf1301390190f44891d4b1302962bd4ba3e62b19516122c20dc7caf01a116b8d29f38661a40cccfa72974893010e7c8191dc1df84e715cc84fb20af1a929d2ff08726c3f379cf12ce8bb87f4837a767a4ef649736fac54cc71e81ec8f82572bdf26b4f3187041a9e29a3bff7ee17010fecfb1c0b745f3557682b3cf1d81e8a4ec29d081e00daf2a626db5284fa236d6d68525ca2773b362b667b90223cb4153a655fc3ef44ff353c45ef8bdd927d533801102683100e212fca1ee3fc55d55b788c25d4cbf5fb1fd9f23dce056b099d63ce523271437e39c81e0bf5adb14272fc5d77651ebb4e0d07c0fef214b40058e42ccf0111d5c15f1d292e2a99597d06a3f2d51281a639c1db56981a14ea25a481cfd2ad362df123861fd1653d11c5d49d0fe7c7393865dc416b35b91d1745e4acba14137d00126eb17330b4e35010c783c1f6e63c13a5f6e404ca90b4161831c99cdcd5fd42c73b48e750bdcc38e864826c0371ef2ba8b091f9224c498a89aedb37b549f329b801671a259e00000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa71000000000548bebf014155575600000000000a553a4000002710196f5b7717e9ea3f80d9b8b7ed5260a20ba8320f01005500e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b4300000616a2e6a87300000001919807f2fffffff800000000671a259e00000000671a259d0000061603fd9e800000000169bc1f140a18148307d543ab71b73b7ea9dda7611cf125b44b2ac06f03fb9da527e16462e265e46772f7f4291ccff93458cb93722a8775587dd300ddcd70a01644416db175fc8b3f6fd42084cc175595f79ab271f648c55fd5ebee72f4da44b8f00c47f9bf99d794dea6d34e8851c257a977bc4aa904a714ce6ea5e64ca920ebc2cbb5e255d636b53dd423d2f2695d5d993cca300ed878f3e029a25f4a94a5c4d858a052d5f99a4046b1c1a79b5294b0ae73a8e60c2ab08c7076ae0752e3fced992f9586c0cec9506b5b58ba0b";

        uint256 currentPrice =
            PerpDexPricesLib.submitAndGetLatestPrice(priceData, PerpDexLib.TokenType.Btc, bisonAISubmissionProxy, bisonAIRouter, pyth);
        assertEq(currentPrice, 6_694_292_072_563, "answer");
    }

    // @see https://kaiascan.io/tx/0x8b5e0b936a5ea94c87ec17b0a6d3d0c9db55cfca7e75d18e4fe95eaa45da3300
    // block number 167_580_064
    function test_openPosition_pyth_ok() public {
        vm.selectFork(openPositionForkId);
        vm.rollFork(167_759_290);
        deployAndSet();
        PerpDexLib.OraclePrices memory priceData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.Pyth,
            feedHashes: new bytes32[](1),
            answers: new int256[](1),
            timestamps: new uint256[](1),
            proofs: new bytes[](1)
        });

        priceData.feedHashes[0] = 0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43;
        priceData.answers[0] = 6_694_292_072_563;
        priceData.timestamps[0] = 1_729_766_814;

        priceData.proofs[0] =
            hex"504e41550100000003b801000000040d02b7f9d624bddd972f48ce19cfb053bf5f7b4ff9908d76ca04938623c2b959104276a0c9374d198d463adb3a642549ab0614c841f6ef1088278fec1e970331f0bd010372e2953243517e36672311d2d64d35d11042c37c38b247a80a641cb0924daf527261ec8ed73960c8e65d2d1eaf691be35112f1dde3fb6bffa3ca0ae155673f90000430906d40ab1590c0d505910423995675e3d34d583bc9e904150df40cf6eddc607b3cdcbbb10e766e674cdeb7f0e20a7f3ca206943adeac9c9978e7480718e3e101068046a669b6a911f8fe1ab6f61b7dc82dcb6c4637c665c55ba10dff416087839b7847fe186d9caeb096c942b4209a9b6e84f0eba2f10afa0b81cd69de2bf010f1010836d0bfacb58f43805ff721d571a8147d7252400c8c1f3fbb161abaeae873df2a76d7e96f8d60708e95c9d0949ebeda525c1b6b6e013a7e266c52c1a7c9f01f0a010a8c904f51159ff04677520f5e17f931a5c87dcceb53bfb7e12c7916488bb26c3226ea2105647c3f5609b62fa341358db77f832330e1ff82d6880ae1c57f63d192010b3008d1a03137a70d586ad55fd9f42d9a926720ea19973f25210b618c2f8fd01c2d3f2547690f21260cc1276c1408cdde073ae8c25720f4b2a94e9504a9b2f3fd010d5ad540333a470f605e3240af70a9950f488b5abfcf1301390190f44891d4b1302962bd4ba3e62b19516122c20dc7caf01a116b8d29f38661a40cccfa72974893010e7c8191dc1df84e715cc84fb20af1a929d2ff08726c3f379cf12ce8bb87f4837a767a4ef649736fac54cc71e81ec8f82572bdf26b4f3187041a9e29a3bff7ee17010fecfb1c0b745f3557682b3cf1d81e8a4ec29d081e00daf2a626db5284fa236d6d68525ca2773b362b667b90223cb4153a655fc3ef44ff353c45ef8bdd927d533801102683100e212fca1ee3fc55d55b788c25d4cbf5fb1fd9f23dce056b099d63ce523271437e39c81e0bf5adb14272fc5d77651ebb4e0d07c0fef214b40058e42ccf0111d5c15f1d292e2a99597d06a3f2d51281a639c1db56981a14ea25a481cfd2ad362df123861fd1653d11c5d49d0fe7c7393865dc416b35b91d1745e4acba14137d00126eb17330b4e35010c783c1f6e63c13a5f6e404ca90b4161831c99cdcd5fd42c73b48e750bdcc38e864826c0371ef2ba8b091f9224c498a89aedb37b549f329b801671a259e00000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa71000000000548bebf014155575600000000000a553a4000002710196f5b7717e9ea3f80d9b8b7ed5260a20ba8320f01005500e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b4300000616a2e6a87300000001919807f2fffffff800000000671a259e00000000671a259d0000061603fd9e800000000169bc1f140a18148307d543ab71b73b7ea9dda7611cf125b44b2ac06f03fb9da527e16462e265e46772f7f4291ccff93458cb93722a8775587dd300ddcd70a01644416db175fc8b3f6fd42084cc175595f79ab271f648c55fd5ebee72f4da44b8f00c47f9bf99d794dea6d34e8851c257a977bc4aa904a714ce6ea5e64ca920ebc2cbb5e255d636b53dd423d2f2695d5d993cca300ed878f3e029a25f4a94a5c4d858a052d5f99a4046b1c1a79b5294b0ae73a8e60c2ab08c7076ae0752e3fced992f9586c0cec9506b5b58ba0b";

        bytes memory userSignedData = getSignedMessage(
            userPk,
            abi.encodePacked(
                "Open position for Token: 0, Margin: 2000000, Leverage: 3, Long: 1, TP: 0, SL: 0, Price: 6694292072563, Nonce: 0, Chain: 8217, Contract: ",
                Strings.toHexString(address(perpDex))
            )
        );

        vm.deal(singleOpenAdmin, 100_000);

        vm.startPrank(singleOpenAdmin);
        uint256 feeAmount = pyth.getUpdateFee(priceData.proofs);
        assertEq(feeAmount, 1);
        perpDex.openPosition{value: feeAmount}(
            PerpDexLib.OpenPositionData({
                tokenType: PerpDexLib.TokenType.Btc,
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
        assertEq(p.initialPrice, 6_694_292_072_563);
        assertEq(uint256(p.positionStatus), 1);
    }

    // @see https://kaiascan.io/tx/0xcf85da9dceec7576fa35d6d744eb5b32e38c74f6fb3e5682298cc625452799e9
    // block number 167_567_825
    // 167567825 fail
    // 167567824 fail
    // -- 1. 0xa3a43285c3d6dafe137bf01b268c4b8bcac043e46fab600f40391581b15740a4 success
    // -- 2. 0x35f6a18722b665ed24904933089b33fc357d2b12dbfb889571a4fed49179a06d success
    // -- 3. 0x25316a13477e5b8e912dfe2d379ca0e32385b9da0bd7fd4aa1bdf3c2520ca9f1 success
    // -- 4. 0x40f4903e9034880e188dd09104e1c04d44a25d7c87a4e1bfc31243f8f9f94d91 success
    // -- 5. 0xfa5b5ff8e3d125f17ccee65bc574c217ff21777d23d9f1544d5c7dfd383941be fail - failed committing transaction - maybe number 4 is not replayable 
    // 167567823 success
    function test_openPosition_pyth_revert() public {
        vm.selectFork(openPositionForkId);
        vm.rollFork(167_759_290);
        deployAndSet();
        PerpDexLib.OraclePrices memory priceData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.Pyth,
            feedHashes: new bytes32[](1),
            answers: new int256[](1),
            timestamps: new uint256[](1),
            proofs: new bytes[](1)
        });

        priceData.feedHashes[0] = 0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43;
        priceData.answers[0] = 6_694_292_072_563;
        priceData.timestamps[0] = 1_729_766_814;

        priceData.proofs[0] =
            hex"504e41550100000003b801000000040d02b7f9d624bddd972f48ce19cfb053bf5f7b4ff9908d76ca04938623c2b959104276a0c9374d198d463adb3a642549ab0614c841f6ef1088278fec1e970331f0bd010372e2953243517e36672311d2d64d35d11042c37c38b247a80a641cb0924daf527261ec8ed73960c8e65d2d1eaf691be35112f1dde3fb6bffa3ca0ae155673f90000430906d40ab1590c0d505910423995675e3d34d583bc9e904150df40cf6eddc607b3cdcbbb10e766e674cdeb7f0e20a7f3ca206943adeac9c9978e7480718e3e101068046a669b6a911f8fe1ab6f61b7dc82dcb6c4637c665c55ba10dff416087839b7847fe186d9caeb096c942b4209a9b6e84f0eba2f10afa0b81cd69de2bf010f1010836d0bfacb58f43805ff721d571a8147d7252400c8c1f3fbb161abaeae873df2a76d7e96f8d60708e95c9d0949ebeda525c1b6b6e013a7e266c52c1a7c9f01f0a010a8c904f51159ff04677520f5e17f931a5c87dcceb53bfb7e12c7916488bb26c3226ea2105647c3f5609b62fa341358db77f832330e1ff82d6880ae1c57f63d192010b3008d1a03137a70d586ad55fd9f42d9a926720ea19973f25210b618c2f8fd01c2d3f2547690f21260cc1276c1408cdde073ae8c25720f4b2a94e9504a9b2f3fd010d5ad540333a470f605e3240af70a9950f488b5abfcf1301390190f44891d4b1302962bd4ba3e62b19516122c20dc7caf01a116b8d29f38661a40cccfa72974893010e7c8191dc1df84e715cc84fb20af1a929d2ff08726c3f379cf12ce8bb87f4837a767a4ef649736fac54cc71e81ec8f82572bdf26b4f3187041a9e29a3bff7ee17010fecfb1c0b745f3557682b3cf1d81e8a4ec29d081e00daf2a626db5284fa236d6d68525ca2773b362b667b90223cb4153a655fc3ef44ff353c45ef8bdd927d533801102683100e212fca1ee3fc55d55b788c25d4cbf5fb1fd9f23dce056b099d63ce523271437e39c81e0bf5adb14272fc5d77651ebb4e0d07c0fef214b40058e42ccf0111d5c15f1d292e2a99597d06a3f2d51281a639c1db56981a14ea25a481cfd2ad362df123861fd1653d11c5d49d0fe7c7393865dc416b35b91d1745e4acba14137d00126eb17330b4e35010c783c1f6e63c13a5f6e404ca90b4161831c99cdcd5fd42c73b48e750bdcc38e864826c0371ef2ba8b091f9224c498a89aedb37b549f329b801671a259e00000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa71000000000548bebf014155575600000000000a553a4000002710196f5b7717e9ea3f80d9b8b7ed5260a20ba8320f01005500e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b4300000616a2e6a87300000001919807f2fffffff800000000671a259e00000000671a259d0000061603fd9e800000000169bc1f140a18148307d543ab71b73b7ea9dda7611cf125b44b2ac06f03fb9da527e16462e265e46772f7f4291ccff93458cb93722a8775587dd300ddcd70a01644416db175fc8b3f6fd42084cc175595f79ab271f648c55fd5ebee72f4da44b8f00c47f9bf99d794dea6d34e8851c257a977bc4aa904a714ce6ea5e64ca920ebc2cbb5e255d636b53dd423d2f2695d5d993cca300ed878f3e029a25f4a94a5c4d858a052d5f99a4046b1c1a79b5294b0ae73a8e60c2ab08c7076ae0752e3fced992f9586c0cec9506b5b58ba0b";

        bytes memory userSignedData = getSignedMessage(
            userPk,
            abi.encodePacked(
                "Open position for Token: 0, Margin: 2000000, Leverage: 3, Long: 1, TP: 0, SL: 0, Price: 6694292072563, Nonce: 0, Chain: 8217, Contract: ",
                Strings.toHexString(address(perpDex))
            )
        );

        vm.warp(1_729_766_814 + 20); // 🚨 Past 10 seconds
        emit log_string("Past 10 seconds");
        emit log_uint(block.timestamp);

        vm.deal(singleOpenAdmin, 100_000);
        vm.startPrank(singleOpenAdmin);
        uint256 feeAmount = pyth.getUpdateFee(priceData.proofs);
        vm.expectRevert(abi.encodeWithSignature("StalePrice()"));
        perpDex.openPosition{value: feeAmount}(
            PerpDexLib.OpenPositionData({
                tokenType: PerpDexLib.TokenType.Btc,
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

        vm.warp(1_729_766_814 + 10);
        emit log_string("Within 10 seconds");
        emit log_uint(block.timestamp);

        vm.expectRevert(); // 🚨 OutOfFunds cannot be specified
        perpDex.openPosition{value: feeAmount - 1}(
            PerpDexLib.OpenPositionData({
                tokenType: PerpDexLib.TokenType.Btc,
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

        perpDex.openPosition{value: feeAmount}(
            PerpDexLib.OpenPositionData({
                tokenType: PerpDexLib.TokenType.Btc,
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
        assertEq(p.initialPrice, 6_694_292_072_563);
    }

    // 167_580_639 price standard
    function test_closePosition_pyth_ok() public {
        vm.selectFork(openPositionForkId);
        vm.rollFork(167_759_290);
        uint256 time1 = block.timestamp;
        deployAndSet();
        PerpDexLib.OraclePrices memory priceData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.Pyth,
            feedHashes: new bytes32[](1),
            answers: new int256[](1),
            timestamps: new uint256[](1),
            proofs: new bytes[](1)
        });

        priceData.feedHashes[0] = 0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43;
        priceData.answers[0] = 6_694_292_072_563;
        priceData.timestamps[0] = 1_729_766_814;

        priceData.proofs[0] =
            hex"504e41550100000003b801000000040d02b7f9d624bddd972f48ce19cfb053bf5f7b4ff9908d76ca04938623c2b959104276a0c9374d198d463adb3a642549ab0614c841f6ef1088278fec1e970331f0bd010372e2953243517e36672311d2d64d35d11042c37c38b247a80a641cb0924daf527261ec8ed73960c8e65d2d1eaf691be35112f1dde3fb6bffa3ca0ae155673f90000430906d40ab1590c0d505910423995675e3d34d583bc9e904150df40cf6eddc607b3cdcbbb10e766e674cdeb7f0e20a7f3ca206943adeac9c9978e7480718e3e101068046a669b6a911f8fe1ab6f61b7dc82dcb6c4637c665c55ba10dff416087839b7847fe186d9caeb096c942b4209a9b6e84f0eba2f10afa0b81cd69de2bf010f1010836d0bfacb58f43805ff721d571a8147d7252400c8c1f3fbb161abaeae873df2a76d7e96f8d60708e95c9d0949ebeda525c1b6b6e013a7e266c52c1a7c9f01f0a010a8c904f51159ff04677520f5e17f931a5c87dcceb53bfb7e12c7916488bb26c3226ea2105647c3f5609b62fa341358db77f832330e1ff82d6880ae1c57f63d192010b3008d1a03137a70d586ad55fd9f42d9a926720ea19973f25210b618c2f8fd01c2d3f2547690f21260cc1276c1408cdde073ae8c25720f4b2a94e9504a9b2f3fd010d5ad540333a470f605e3240af70a9950f488b5abfcf1301390190f44891d4b1302962bd4ba3e62b19516122c20dc7caf01a116b8d29f38661a40cccfa72974893010e7c8191dc1df84e715cc84fb20af1a929d2ff08726c3f379cf12ce8bb87f4837a767a4ef649736fac54cc71e81ec8f82572bdf26b4f3187041a9e29a3bff7ee17010fecfb1c0b745f3557682b3cf1d81e8a4ec29d081e00daf2a626db5284fa236d6d68525ca2773b362b667b90223cb4153a655fc3ef44ff353c45ef8bdd927d533801102683100e212fca1ee3fc55d55b788c25d4cbf5fb1fd9f23dce056b099d63ce523271437e39c81e0bf5adb14272fc5d77651ebb4e0d07c0fef214b40058e42ccf0111d5c15f1d292e2a99597d06a3f2d51281a639c1db56981a14ea25a481cfd2ad362df123861fd1653d11c5d49d0fe7c7393865dc416b35b91d1745e4acba14137d00126eb17330b4e35010c783c1f6e63c13a5f6e404ca90b4161831c99cdcd5fd42c73b48e750bdcc38e864826c0371ef2ba8b091f9224c498a89aedb37b549f329b801671a259e00000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa71000000000548bebf014155575600000000000a553a4000002710196f5b7717e9ea3f80d9b8b7ed5260a20ba8320f01005500e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b4300000616a2e6a87300000001919807f2fffffff800000000671a259e00000000671a259d0000061603fd9e800000000169bc1f140a18148307d543ab71b73b7ea9dda7611cf125b44b2ac06f03fb9da527e16462e265e46772f7f4291ccff93458cb93722a8775587dd300ddcd70a01644416db175fc8b3f6fd42084cc175595f79ab271f648c55fd5ebee72f4da44b8f00c47f9bf99d794dea6d34e8851c257a977bc4aa904a714ce6ea5e64ca920ebc2cbb5e255d636b53dd423d2f2695d5d993cca300ed878f3e029a25f4a94a5c4d858a052d5f99a4046b1c1a79b5294b0ae73a8e60c2ab08c7076ae0752e3fced992f9586c0cec9506b5b58ba0b";

        bytes memory userSignedData = getSignedMessage(
            userPk,
            abi.encodePacked(
                "Open position for Token: 0, Margin: 2000000, Leverage: 3, Long: 1, TP: 0, SL: 0, Price: 6694292072563, Nonce: 0, Chain: 8217, Contract: ",
                Strings.toHexString(address(perpDex))
            )
        );

        vm.deal(singleOpenAdmin, 100_000);
        vm.startPrank(singleOpenAdmin);
        uint256 feeAmount = pyth.getUpdateFee(priceData.proofs);
        assertEq(feeAmount, 1);
        perpDex.openPosition{value: feeAmount}(
            PerpDexLib.OpenPositionData({
                tokenType: PerpDexLib.TokenType.Btc,
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

        emit log_uint(perpDex.traderNonce(user));
        vm.warp(1_729_766_879);
        uint256 time2 = block.timestamp;
        vm.roll(167_759_354);
        priceData.feedHashes[0] = 0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43;
        priceData.answers[0] = 6_696_119_929_737;
        priceData.timestamps[0] = 1_729_766_879;
        priceData.proofs[0] =
            hex"504e41550100000003b801000000040d0019f5e6453de9e9503378687500bb4d88e9cc48f76e52fc14c6d778bf3e87bea36cfcce3563b1c78db85f09502d87672366d6837adc8993ce86274e71d6e40d790102038252ebe1608f91cba9e2dcbffd25def674308473095390980975c81a43ed0e32d5952bc6d0ce7c5c0a854ae15712dbaa2c5fabcc11c4d6f8e8e1a7ea237bff0103190d81682b010f59018bdffc486fb17ace96852cb87404af661ca8210dfbe3ee54c6156ecaa00193c76ca84013c18669ffad6896a1881a706531c9307cd53eb5010479f0a74064bb3546616f67eb29fbff098c7fc5409a8addc03cc5100abef2640f0734f5fade0efab80c9d622d50f9dcc42a997edc343bd1b42c557a19049d61bb0106b3cbdb7563cdde5404aff80e0c5f86c618f8d4fa1b3a6556fd8bcc95cb9078ef3b4b7d003e9435e6ad9b98728238edcb9795ad812d421df8c37ffaba8d314a810008c040b432d8f8a3da973623262fc690c128a404a4fd2897cee42e2b48c886990e43130efa912fced3727299400d25dbe1dd71555c0056642c7003a6939f6a8e3a000a352fb2a177ddbfc663d241466587aa47f1c34296679b1ac921fcb186464cbb8424cdcfc053ca1f2666c8b7b30f9b5a42a4afd85f601a39f8e0330854421efc67010bfc6a70da5a1d5d62a03490a23bc9b547c79de9ff7301d89a2f3e7b8ff2760306155763bbfa73ae87321914a52e81e4cf1efb9edd9dd211b4c485812af6674df1010d64aada18f53b9b86cd292f0ee227fd363a3797cb58dd404826e2f9a9035c720905201c26d0afd75836395d534a49aafbc679b045b1a0ecb20fdf5ab746b1dade010ec8491e5fe9d2e0a8b6ae0e40fba230b62ab7fb14f6b41d82cbd7fa3a109b21ad24cdd4a6f57eb8de8b8c5a5956d08719e3622d3f35dfd149b986d12b097014a7000f3be154e2c7d0ef12df670a4dd13504b3df8ab590e57be76b9ac11c21b95748a810d671d0140f95e64c3552ee1af8eada2a34f8691adec75927785068871b62a401119b92c1d608bc11ac6fa1a617258cf0d7e14e17d74074a3fe83fad8b6364edefa1ccda7f7907010773a444ea3d0aa8fc5144d5838e32b2a2c296c9c90acd79ee901121cdd71f6877cf5504fac1f68bb2ed54389e30c87ea89171263f9aa2d6d52c4061869476e2844a491138d69c16230179f3e8b5aec0061a4f29bb97e4032d0bff901671a25df00000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa71000000000548bf5b014155575600000000000a553ae000002710934b4102e5f67950cf9e6f59c7ce1a30709b726d08005500e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43000006170fd98b89000000019ea97e05fffffff800000000671a25df00000000671a25de0000061607bbdf00000000016a43e4800a18148307d543ab71b73b7ea9dda7611cf125b44be3d06efb9d37c38b765001a94581cc9b887c0a069e0c687c1242f76a1d48aa412a61a81a7bb5308e7a7b179da283a79bc2404a7b2e779afe12c964cd54c418800c95e0e43026444831029b236f54f8f60fb13afd849cab33edbc3a5c65e859e05aa86dca52a71993fa01e91c126deaf80d4af4df89a89211c26658d3f4668fe427f8ce831c9db9edbf774147605ece7cf41822acc2b032e8dab6da6a7c62a78830345467fbdb9f061928cd53c0e86e01cdfeb785005500de5e6ef09931fecc7fdd8aaa97844e981f3e7bb1c86a6ffc68e9166bb0db37430000000000b7c54a0000000000004e50fffffff800000000671a25df00000000671a25de0000000000b80b470000000000005bf60a9095e7cb0aac2e6f4377bb09b1b20ea0a85f0d799d79f65cfbbf526b4ee73a6b5df750d66edff9ab2abbae5149eccfc7e2e6c12693617b1f550b399f65692c5855bd87422ec3c1df0619fe29a9a6cd3763d446e7e18839b8ab3d23667921cc7f3404083e0fb13afd849cab33edbc3a5c65e859e05aa86dca52a71993fa01e91c126deaf80d4af4df89a89211c26658d3f4668fe427f8ce831c9db9edbf774147605ece7cf41822acc2b032e8dab6da6a7c62a78830345467fbdb9f061928cd53c0e86e01cdfeb785005500f63f008474fad630207a1cfa49207d59bca2593ea64fc0a6da9bf3337485791c0000000004931ea0000000000002c8f6fffffff800000000671a25df00000000671a25de000000000494a5a8000000000002d8190a5cfc31b4f6636bf5a0e14a3aa522073b986d61789d212c13957ed4543870291c7d553ec13087ad5d491e5c89415eb6753d4342a58e4bb0b7d65e16da69b99dc5210d0021a10f4b29b85da5a206823cc91626500864f53293f7e24d3a66b6216390f1f449f1228a92625a027933569fae5c286331c6583bd77cf52da428b7b88df31a3042e43462e5c99ace51c26658d3f4668fe427f8ce831c9db9edbf774147605ece7cf41822acc2b032e8dab6da6a7c62a78830345467fbdb9f061928cd53c0e86e01cdfeb785005500ff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace0000003ac8da903d000000000ec621f5fffffff800000000671a25df00000000671a25de0000003acfd5a3e0000000000e05c4d70a17b83a1a0daf13dee0c927a2767b3443c008980c228a90f6ff92ad792969dab27e35a14263ea4d79874574de4144e0b891c537b6964ac3baa24a5b7c160d7344f79c33e9f5ff73a7aeb1342a8966dfcd58d76bcce638839979084d45661d562375eb938fac6ec99ea2895f017e61db6c81460d57735ec1d07cf52da428b7b88df31a3042e43462e5c99ace51c26658d3f4668fe427f8ce831c9db9edbf774147605ece7cf41822acc2b032e8dab6da6a7c62a78830345467fbdb9f061928cd53c0e86e01cdfeb785005500dcef50dd0a4cd2dcc17e45df1676dcb336a11a61c69df7a0299b0150c672d25c0000000000d2148700000000000038fdfffffff800000000671a25df00000000671a25de0000000000d23d6a00000000000036ea0a8cabe72eeac803a5996525ee176e4c5de3fe7f883694cc248e30770c577c363b3e00c6add05b8d248d20e113f456c7fa181065dcef01dfa3c5f704db5c9b11a156eea01000108ea7c30c3a98aa9750ae63d446e7e18839b8ab3d23667921cc7f3404083e0fb13afd849cab33edbc3a5c65e859e05aa86dca52a71993fa01e91c126deaf80d4af4df89a89211c26658d3f4668fe427f8ce831c9db9edbf774147605ece7cf41822acc2b032e8dab6da6a7c62a78830345467fbdb9f061928cd53c0e86e01cdfeb785005500d69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e40000000000017c5100000000000000b0fffffff600000000671a25df00000000671a25de0000000000017d3700000000000000a70adf8e7ccd086cfcc3f1c8b75a46f8502f4fed2e9e88f56f00468d3c7f982fac72c3ca94cb2772305c21f4d71f00994661fea3a8c1b622c6d347e7fb935c9b11a156eea01000108ea7c30c3a98aa9750ae63d446e7e18839b8ab3d23667921cc7f3404083e0fb13afd849cab33edbc3a5c65e859e05aa86dca52a71993fa01e91c126deaf80d4af4df89a89211c26658d3f4668fe427f8ce831c9db9edbf774147605ece7cf41822acc2b032e8dab6da6a7c62a78830345467fbdb9f061928cd53c0e86e01cdfeb785005500ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d0000000403f1fde0000000000117b32cfffffff800000000671a25df00000000671a25de0000000403118508000000000111b6ce0af937fbb47d73d4e72300497963ee16c8cef34bfec516c5b752f94bd8ebb2f62b6202b153dbdf0fcacebe8c53e24b0cc72dca8f676dbd2de598de8543c20744f4f709775eb59dfe49d6cdfcff5c9c105fa34894877955cd57f06c88925ce0d6395f126e44f1228a92625a027933569fae5c286331c6583bd77cf52da428b7b88df31a3042e43462e5c99ace51c26658d3f4668fe427f8ce831c9db9edbf774147605ece7cf41822acc2b032e8dab6da6a7c62a78830345467fbdb9f061928cd53c0e86e01cdfeb785005500ec5d399846a9209f3fe5881d70aae9268c94339ff9817e8d18ff19fa05eea1c80000000003223730000000000000d88cfffffff800000000671a25df00000000671a25de00000000032434a3000000000000d1ca0ac8f1b368ff209fc1f15605c6e211ae826d432242d662173a9551e3c6c9dc2f67f82494bfd9bd964744ad121a266aa4fc2b4be320941c3fd93a0f9e4c014c124321572645d330cca6bb511550162a5723a34894877955cd57f06c88925ce0d6395f126e44f1228a92625a027933569fae5c286331c6583bd77cf52da428b7b88df31a3042e43462e5c99ace51c26658d3f4668fe427f8ce831c9db9edbf774147605ece7cf41822acc2b032e8dab6da6a7c62a78830345467fbdb9f061928cd53c0e86e01cdfeb785";

        bytes memory userSignedData2 = getSignedMessage(
            userPk, abi.encodePacked("Close Position: 1, Nonce: 1, Chain: 8217, Contract: ", Strings.toHexString(address(perpDex)))
        );

        // IPyth.PythPrice memory pythPriceData = pyth.getPriceNoOlderThan(priceData.feedHashes[0], 10);
        // emit log_uint(pythPriceData.publishTime);

        vm.deal(closeAdmin, 100_000);
        vm.startPrank(closeAdmin);
        perpDex.closePosition{value: pyth.getUpdateFee(priceData.proofs)}(1, priceData, userSignedData2);
        vm.stopPrank();

        PerpDexLib.Position memory p = perpDex.getPosition(1);
        assertEq(p.finalPrice, 6_696_119_929_737, "finalPrice");
        assertEq(uint256(p.positionStatus), 2, "positionStatus");
        assertEq(p.openFee, 2_000_000 * 3 * 70 / 100_000, "openFee");

        int256 expectingFundingFee = int256(p.size * 1e20 * (time2 - time1) * 875 / (1e20 * 1e7 * 3600));
        uint256 profit = p.size * p.finalPrice / p.initialPrice - p.size;
        uint256 closeFee = (p.size * p.finalPrice / p.initialPrice) * 70 / 100_000;
        assertEq(p.closeFee, closeFee, "closeFee"); // loss

        assertEq(p.fundingFee, expectingFundingFee, "fundingFee");
        assertEq(p.pnl, int256(profit));

        assertEq(usdtContract.balanceOf(address(lpContract)), initialLpBalance - profit);
        assertEq(usdtContract.balanceOf(address(feeContract)), p.closeFee + p.openFee);
        assertEq(
            usdtContract.balanceOf(address(user)),
            initialUserBalance - p.margin - p.openFee + (p.margin - uint256(p.fundingFee) - closeFee) + profit
        );
    }

    // 167_580_639 price standard
    function test_closePosition_pyth_revert_StalePrice() public {
        vm.selectFork(openPositionForkId);
        vm.rollFork(167_759_290);
        deployAndSet();
        PerpDexLib.OraclePrices memory priceData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.Pyth,
            feedHashes: new bytes32[](1),
            answers: new int256[](1),
            timestamps: new uint256[](1),
            proofs: new bytes[](1)
        });

        priceData.feedHashes[0] = 0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43;
        priceData.answers[0] = 6_694_292_072_563;
        priceData.timestamps[0] = 1_729_766_814;
        priceData.proofs[0] =
            hex"504e41550100000003b801000000040d02b7f9d624bddd972f48ce19cfb053bf5f7b4ff9908d76ca04938623c2b959104276a0c9374d198d463adb3a642549ab0614c841f6ef1088278fec1e970331f0bd010372e2953243517e36672311d2d64d35d11042c37c38b247a80a641cb0924daf527261ec8ed73960c8e65d2d1eaf691be35112f1dde3fb6bffa3ca0ae155673f90000430906d40ab1590c0d505910423995675e3d34d583bc9e904150df40cf6eddc607b3cdcbbb10e766e674cdeb7f0e20a7f3ca206943adeac9c9978e7480718e3e101068046a669b6a911f8fe1ab6f61b7dc82dcb6c4637c665c55ba10dff416087839b7847fe186d9caeb096c942b4209a9b6e84f0eba2f10afa0b81cd69de2bf010f1010836d0bfacb58f43805ff721d571a8147d7252400c8c1f3fbb161abaeae873df2a76d7e96f8d60708e95c9d0949ebeda525c1b6b6e013a7e266c52c1a7c9f01f0a010a8c904f51159ff04677520f5e17f931a5c87dcceb53bfb7e12c7916488bb26c3226ea2105647c3f5609b62fa341358db77f832330e1ff82d6880ae1c57f63d192010b3008d1a03137a70d586ad55fd9f42d9a926720ea19973f25210b618c2f8fd01c2d3f2547690f21260cc1276c1408cdde073ae8c25720f4b2a94e9504a9b2f3fd010d5ad540333a470f605e3240af70a9950f488b5abfcf1301390190f44891d4b1302962bd4ba3e62b19516122c20dc7caf01a116b8d29f38661a40cccfa72974893010e7c8191dc1df84e715cc84fb20af1a929d2ff08726c3f379cf12ce8bb87f4837a767a4ef649736fac54cc71e81ec8f82572bdf26b4f3187041a9e29a3bff7ee17010fecfb1c0b745f3557682b3cf1d81e8a4ec29d081e00daf2a626db5284fa236d6d68525ca2773b362b667b90223cb4153a655fc3ef44ff353c45ef8bdd927d533801102683100e212fca1ee3fc55d55b788c25d4cbf5fb1fd9f23dce056b099d63ce523271437e39c81e0bf5adb14272fc5d77651ebb4e0d07c0fef214b40058e42ccf0111d5c15f1d292e2a99597d06a3f2d51281a639c1db56981a14ea25a481cfd2ad362df123861fd1653d11c5d49d0fe7c7393865dc416b35b91d1745e4acba14137d00126eb17330b4e35010c783c1f6e63c13a5f6e404ca90b4161831c99cdcd5fd42c73b48e750bdcc38e864826c0371ef2ba8b091f9224c498a89aedb37b549f329b801671a259e00000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa71000000000548bebf014155575600000000000a553a4000002710196f5b7717e9ea3f80d9b8b7ed5260a20ba8320f01005500e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b4300000616a2e6a87300000001919807f2fffffff800000000671a259e00000000671a259d0000061603fd9e800000000169bc1f140a18148307d543ab71b73b7ea9dda7611cf125b44b2ac06f03fb9da527e16462e265e46772f7f4291ccff93458cb93722a8775587dd300ddcd70a01644416db175fc8b3f6fd42084cc175595f79ab271f648c55fd5ebee72f4da44b8f00c47f9bf99d794dea6d34e8851c257a977bc4aa904a714ce6ea5e64ca920ebc2cbb5e255d636b53dd423d2f2695d5d993cca300ed878f3e029a25f4a94a5c4d858a052d5f99a4046b1c1a79b5294b0ae73a8e60c2ab08c7076ae0752e3fced992f9586c0cec9506b5b58ba0b";

        bytes memory userSignedData = getSignedMessage(
            userPk,
            abi.encodePacked(
                "Open position for Token: 0, Margin: 2000000, Leverage: 3, Long: 1, TP: 0, SL: 0, Price: 6694292072563, Nonce: 0, Chain: 8217, Contract: ",
                Strings.toHexString(address(perpDex))
            )
        );

        vm.deal(singleOpenAdmin, 100_000);
        vm.startPrank(singleOpenAdmin);
        perpDex.openPosition{value: pyth.getUpdateFee(priceData.proofs)}(
            PerpDexLib.OpenPositionData({
                tokenType: PerpDexLib.TokenType.Btc,
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

        priceData.answers[0] = 6_696_119_929_737;
        priceData.timestamps[0] = 1_729_766_879;
        priceData.proofs[0] =
            hex"504e41550100000003b801000000040d0019f5e6453de9e9503378687500bb4d88e9cc48f76e52fc14c6d778bf3e87bea36cfcce3563b1c78db85f09502d87672366d6837adc8993ce86274e71d6e40d790102038252ebe1608f91cba9e2dcbffd25def674308473095390980975c81a43ed0e32d5952bc6d0ce7c5c0a854ae15712dbaa2c5fabcc11c4d6f8e8e1a7ea237bff0103190d81682b010f59018bdffc486fb17ace96852cb87404af661ca8210dfbe3ee54c6156ecaa00193c76ca84013c18669ffad6896a1881a706531c9307cd53eb5010479f0a74064bb3546616f67eb29fbff098c7fc5409a8addc03cc5100abef2640f0734f5fade0efab80c9d622d50f9dcc42a997edc343bd1b42c557a19049d61bb0106b3cbdb7563cdde5404aff80e0c5f86c618f8d4fa1b3a6556fd8bcc95cb9078ef3b4b7d003e9435e6ad9b98728238edcb9795ad812d421df8c37ffaba8d314a810008c040b432d8f8a3da973623262fc690c128a404a4fd2897cee42e2b48c886990e43130efa912fced3727299400d25dbe1dd71555c0056642c7003a6939f6a8e3a000a352fb2a177ddbfc663d241466587aa47f1c34296679b1ac921fcb186464cbb8424cdcfc053ca1f2666c8b7b30f9b5a42a4afd85f601a39f8e0330854421efc67010bfc6a70da5a1d5d62a03490a23bc9b547c79de9ff7301d89a2f3e7b8ff2760306155763bbfa73ae87321914a52e81e4cf1efb9edd9dd211b4c485812af6674df1010d64aada18f53b9b86cd292f0ee227fd363a3797cb58dd404826e2f9a9035c720905201c26d0afd75836395d534a49aafbc679b045b1a0ecb20fdf5ab746b1dade010ec8491e5fe9d2e0a8b6ae0e40fba230b62ab7fb14f6b41d82cbd7fa3a109b21ad24cdd4a6f57eb8de8b8c5a5956d08719e3622d3f35dfd149b986d12b097014a7000f3be154e2c7d0ef12df670a4dd13504b3df8ab590e57be76b9ac11c21b95748a810d671d0140f95e64c3552ee1af8eada2a34f8691adec75927785068871b62a401119b92c1d608bc11ac6fa1a617258cf0d7e14e17d74074a3fe83fad8b6364edefa1ccda7f7907010773a444ea3d0aa8fc5144d5838e32b2a2c296c9c90acd79ee901121cdd71f6877cf5504fac1f68bb2ed54389e30c87ea89171263f9aa2d6d52c4061869476e2844a491138d69c16230179f3e8b5aec0061a4f29bb97e4032d0bff901671a25df00000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa71000000000548bf5b014155575600000000000a553ae000002710934b4102e5f67950cf9e6f59c7ce1a30709b726d08005500e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43000006170fd98b89000000019ea97e05fffffff800000000671a25df00000000671a25de0000061607bbdf00000000016a43e4800a18148307d543ab71b73b7ea9dda7611cf125b44be3d06efb9d37c38b765001a94581cc9b887c0a069e0c687c1242f76a1d48aa412a61a81a7bb5308e7a7b179da283a79bc2404a7b2e779afe12c964cd54c418800c95e0e43026444831029b236f54f8f60fb13afd849cab33edbc3a5c65e859e05aa86dca52a71993fa01e91c126deaf80d4af4df89a89211c26658d3f4668fe427f8ce831c9db9edbf774147605ece7cf41822acc2b032e8dab6da6a7c62a78830345467fbdb9f061928cd53c0e86e01cdfeb785005500de5e6ef09931fecc7fdd8aaa97844e981f3e7bb1c86a6ffc68e9166bb0db37430000000000b7c54a0000000000004e50fffffff800000000671a25df00000000671a25de0000000000b80b470000000000005bf60a9095e7cb0aac2e6f4377bb09b1b20ea0a85f0d799d79f65cfbbf526b4ee73a6b5df750d66edff9ab2abbae5149eccfc7e2e6c12693617b1f550b399f65692c5855bd87422ec3c1df0619fe29a9a6cd3763d446e7e18839b8ab3d23667921cc7f3404083e0fb13afd849cab33edbc3a5c65e859e05aa86dca52a71993fa01e91c126deaf80d4af4df89a89211c26658d3f4668fe427f8ce831c9db9edbf774147605ece7cf41822acc2b032e8dab6da6a7c62a78830345467fbdb9f061928cd53c0e86e01cdfeb785005500f63f008474fad630207a1cfa49207d59bca2593ea64fc0a6da9bf3337485791c0000000004931ea0000000000002c8f6fffffff800000000671a25df00000000671a25de000000000494a5a8000000000002d8190a5cfc31b4f6636bf5a0e14a3aa522073b986d61789d212c13957ed4543870291c7d553ec13087ad5d491e5c89415eb6753d4342a58e4bb0b7d65e16da69b99dc5210d0021a10f4b29b85da5a206823cc91626500864f53293f7e24d3a66b6216390f1f449f1228a92625a027933569fae5c286331c6583bd77cf52da428b7b88df31a3042e43462e5c99ace51c26658d3f4668fe427f8ce831c9db9edbf774147605ece7cf41822acc2b032e8dab6da6a7c62a78830345467fbdb9f061928cd53c0e86e01cdfeb785005500ff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace0000003ac8da903d000000000ec621f5fffffff800000000671a25df00000000671a25de0000003acfd5a3e0000000000e05c4d70a17b83a1a0daf13dee0c927a2767b3443c008980c228a90f6ff92ad792969dab27e35a14263ea4d79874574de4144e0b891c537b6964ac3baa24a5b7c160d7344f79c33e9f5ff73a7aeb1342a8966dfcd58d76bcce638839979084d45661d562375eb938fac6ec99ea2895f017e61db6c81460d57735ec1d07cf52da428b7b88df31a3042e43462e5c99ace51c26658d3f4668fe427f8ce831c9db9edbf774147605ece7cf41822acc2b032e8dab6da6a7c62a78830345467fbdb9f061928cd53c0e86e01cdfeb785005500dcef50dd0a4cd2dcc17e45df1676dcb336a11a61c69df7a0299b0150c672d25c0000000000d2148700000000000038fdfffffff800000000671a25df00000000671a25de0000000000d23d6a00000000000036ea0a8cabe72eeac803a5996525ee176e4c5de3fe7f883694cc248e30770c577c363b3e00c6add05b8d248d20e113f456c7fa181065dcef01dfa3c5f704db5c9b11a156eea01000108ea7c30c3a98aa9750ae63d446e7e18839b8ab3d23667921cc7f3404083e0fb13afd849cab33edbc3a5c65e859e05aa86dca52a71993fa01e91c126deaf80d4af4df89a89211c26658d3f4668fe427f8ce831c9db9edbf774147605ece7cf41822acc2b032e8dab6da6a7c62a78830345467fbdb9f061928cd53c0e86e01cdfeb785005500d69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e40000000000017c5100000000000000b0fffffff600000000671a25df00000000671a25de0000000000017d3700000000000000a70adf8e7ccd086cfcc3f1c8b75a46f8502f4fed2e9e88f56f00468d3c7f982fac72c3ca94cb2772305c21f4d71f00994661fea3a8c1b622c6d347e7fb935c9b11a156eea01000108ea7c30c3a98aa9750ae63d446e7e18839b8ab3d23667921cc7f3404083e0fb13afd849cab33edbc3a5c65e859e05aa86dca52a71993fa01e91c126deaf80d4af4df89a89211c26658d3f4668fe427f8ce831c9db9edbf774147605ece7cf41822acc2b032e8dab6da6a7c62a78830345467fbdb9f061928cd53c0e86e01cdfeb785005500ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d0000000403f1fde0000000000117b32cfffffff800000000671a25df00000000671a25de0000000403118508000000000111b6ce0af937fbb47d73d4e72300497963ee16c8cef34bfec516c5b752f94bd8ebb2f62b6202b153dbdf0fcacebe8c53e24b0cc72dca8f676dbd2de598de8543c20744f4f709775eb59dfe49d6cdfcff5c9c105fa34894877955cd57f06c88925ce0d6395f126e44f1228a92625a027933569fae5c286331c6583bd77cf52da428b7b88df31a3042e43462e5c99ace51c26658d3f4668fe427f8ce831c9db9edbf774147605ece7cf41822acc2b032e8dab6da6a7c62a78830345467fbdb9f061928cd53c0e86e01cdfeb785005500ec5d399846a9209f3fe5881d70aae9268c94339ff9817e8d18ff19fa05eea1c80000000003223730000000000000d88cfffffff800000000671a25df00000000671a25de00000000032434a3000000000000d1ca0ac8f1b368ff209fc1f15605c6e211ae826d432242d662173a9551e3c6c9dc2f67f82494bfd9bd964744ad121a266aa4fc2b4be320941c3fd93a0f9e4c014c124321572645d330cca6bb511550162a5723a34894877955cd57f06c88925ce0d6395f126e44f1228a92625a027933569fae5c286331c6583bd77cf52da428b7b88df31a3042e43462e5c99ace51c26658d3f4668fe427f8ce831c9db9edbf774147605ece7cf41822acc2b032e8dab6da6a7c62a78830345467fbdb9f061928cd53c0e86e01cdfeb785";

        bytes memory userSignedData2 = getSignedMessage(
            userPk, abi.encodePacked("Close Position: 1, Nonce: 1, Chain: 8217, Contract: ", Strings.toHexString(address(perpDex)))
        );

        vm.warp(1_729_766_879 + 11);
        vm.roll(167_759_354);
        emit log_string("Past 10 seconds");
        emit log_uint(block.timestamp);

        vm.deal(closeAdmin, 100_000);
        uint256 value = pyth.getUpdateFee(priceData.proofs);
        vm.expectRevert(abi.encodeWithSignature("StalePrice()"));
        vm.startPrank(closeAdmin);
        perpDex.closePosition{value: value}(1, priceData, userSignedData2);

        vm.warp(1_729_766_879 + 10);
        emit log_string("Within 10 seconds");
        emit log_uint(block.timestamp);
        perpDex.closePosition{value: pyth.getUpdateFee(priceData.proofs)}(1, priceData, userSignedData2);
        vm.stopPrank();

        PerpDexLib.Position memory p = perpDex.getPosition(1);
        assertEq(p.finalPrice, 6_696_119_929_737);
    }

    function getLimitOrderValidPriceData() public pure returns (PerpDexLib.OraclePrices memory) {
        PerpDexLib.OraclePrices memory priceData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.Pyth,
            feedHashes: new bytes32[](13),
            answers: new int256[](13),
            timestamps: new uint256[](13),
            proofs: new bytes[](1)
        });
        priceData.proofs[0] =
            hex"504e41550100000003b801000000040d009d1fbf29f06ee3b180934b986ddd236262c20fc9866356fe51c3a3a85dfb701963cf983e63baa30274283dc280df96bf06926be8389742b461c5588ac0aa1b0801023d129a7d3d1eae63b42093eda83e97c59951d2b43fbcddc0f56b1ce020894fd55906cfad26bdb30dc9e2f379dc0cb62b01f0db245cbba5564e23b9b50b8033e501033f73d36cb7a0f149332d347b7ef653cd4bc0a64ce661627fe991ff53d7e9886b5defd66d24068fd2ee3d525481b5798aa7729993dbe50fb20b865c7744edc2580004f01c83704eea79c29fc22ea02f0a2336d193a385048ea406fa567fe525f45a024f84775c90fa91bf02cd3cb90f9e5214d607866e79d0477df1332b467d2efaf50106e2a4a851cde2167139e46e3eeebb290cd2df4e2574d16af5e52f086a5592879c3ba9b9cad0b35796e525540a4cc9971ec8b13b0ed7b6b5209274315f00fdc855000b4adc2944d33c0c547663c3be4dbb983bcd2904c1027c30aa8dc68fa525ed2e395601029266046cdeb6a74da640b4f45d466db2c80cfcd8674254098e020cf1aa010c3bc88a631e7beb528b981881772c895dbacc7ebc8d103afe925c03d4c275d8b356a472b27a3cc4a1837388027d738d193371d15f1a5ac4739853fe94cbd36781010d2aa5f82a343374f37ba5b59c4fc1c5e7925e7b457b3fc87f6a77c208a40882497497e62b1bee21e2ab0da8fe3e16b910923df31d1a876e526435fc3101ab1f18000e639eae386c4bbe49a4550ffdda1bbe3435b35bbc44f44e937d2edd48ad7c85467ffb8b940ab1027607a17d04f5be3cd1027c04e8ea777ef1117e3722e2b734e5010f72d7b63e0eb44ded1c6f650dd5df42fc4b68fc638d803b31f1154509f88cde6e4efa7449bf0f33669923aa4a102f7c2a48a9ffd4971ae502fdb0dacfe87c73320110ff3182730e07e9a29607faa807f070cad70b00b1c9f843b4807d3f701419bb9565d5032f60da3b6c8ee81e5beb7a9be4a97cbc0e8e0c635f3e46dd4ae051b6560011dd7eddd8b585a080709eaa08b258d06b46114c2ac72534f3ced262cea80244ff73b761f1fb07be256c8cb8744ce95718c98ba3e70ce0bcee06476d3c02f2d2170112c11453ae01b7e80e7a77cd118da411b117006f7139513ce630fbb35873dd2af1612449e8788af4a46d17663a4b4e950211400d8166b4215988e69308c6f2a540016734642a00000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa7100000000058a2c0e014155575600000000000a96f6ae00002710bb77444a8742c4c1950bab5efcab80d65f6b20150d0055002a01deaec9e51a579277b34b122399984d0bbf57e2458a7e42fecd2829867a0d000000000335f933000000000001207bfffffff8000000006734642a000000006734642900000000032ca1c00000000000012eb30b585ed7d227df17cbd418b7ca88a5e88ea0bd51c428475277643c61c72b3e1db7025868eade64146dc7df9c6478f808c4c246325aa710fc3254b5d1eb6a806bc517c726552cf46df7993cf04b9ee3f4238fba9e6ef4858bd32199ed054cf87cc8ac02aba38a48cb7851b307e3b37313129c0f889b670785b9d3e164ff585786d1b0dbf47260687facaa94f3cc5749b9b376efb312a1af084bd54de661d42da7ec619ed4f7f6a9bfe660e9cefcd61a603e1e4a239663aa22eaf0375e24759411787acd046b007665176c817594632dc10863f8a0a84f954fc6cd2e665c00550003ae4db29ed4ae33d323568895aa00337e658e348b37509f5372ae51f0af00d500000000472467ab00000000001984f4fffffff8000000006734642a0000000067346429000000004643691c00000000001b94560b57143e5b73c569cba8f4ca8bf8085233495c206e44c13a1505cb8efbece233afd092efb786f2cb424adec5ae8b8abb20a7a11f3e88eb62029ce1fa741275519c8b22596c9ef8cf7cae23c851a0f08c6289e5b5a19b0522bf23f86993a4462dfd7a958d303671d5f5d37d68748eef74ac9eca6b8d74b0280167b07c3132aaaf23cd6c1fdf79803983a6ea489e5749b9b376efb312a1af084bd54de661d42da7ec619ed4f7f6a9bfe660e9cefcd61a603e1e4a239663aa22eaf0375e24759411787acd046b007665176c817594632dc10863f8a0a84f954fc6cd2e665c005500e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43000007fa2d11a6fe0000000279c2beeffffffff8000000006734642a0000000067346429000007f0414b4f400000000258959df40bda195296a93fe63754710000ede9ff6f4a1afac07aae7d0947ba1b169b8262c25cf17ce5fe950de5d52c0f0cea10bf4ddbaa0ea1a9b0d4a9ec818184069a2b3f70664df105f9f1a101a946979d4c3d4a0c3d9f0ad6fc5fe07537c67ea8946e0cf9214957469ca8c018d8b50061a1b52104870f258c345a4b7ad8888e69cc3704d4c72bc4d59c67e201968d211c0f33e6a0c82f4e62a67c98bef59378d8b20d23aa15082430d409b15f84262fce9b666f61e86c7c63aa22eaf0375e24759411787acd046b007665176c817594632dc10863f8a0a84f954fc6cd2e665c005500dcef50dd0a4cd2dcc17e45df1676dcb336a11a61c69df7a0299b0150c672d25c00000000024a109b000000000000cd28fffffff8000000006734642a000000006734642900000000023b4b22000000000000c9060b6b826b9d8cfb4b2735daa00f37df41f0296c9c47b5b7dbacd43d730ed1c47d6ddcbedc503f54190dfa9f3ae06950003158b887814bf08f45ece9442576575120e11f267eb0f280fe82ff517c6f53afd3d13ea986bdbc87cfab38d9cb9fa2b35d2597577a996fdc12288f4c887ec2e3061125d4060fb30de27ad8888e69cc3704d4c72bc4d59c67e201968d211c0f33e6a0c82f4e62a67c98bef59378d8b20d23aa15082430d409b15f84262fce9b666f61e86c7c63aa22eaf0375e24759411787acd046b007665176c817594632dc10863f8a0a84f954fc6cd2e665c005500ff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace00000049e7226fa00000000018a4b84ffffffff8000000006734642a0000000067346429000000497ab625100000000016ede1b00b1197a527a5f15b210b8d2393c90c9606425e6b46492e7ba98d2df93c8e24d564033338c34a82e75de85bf418eeff9344ce3143ae5205ca28951def7712a044a2fc972a0801864b2399510a77cda6adc10f485a63f12e7977aad9a85cf80bc0c05411c6f0628716575b7450194529ebb7ccf10c07c66b6b875007305a4d87b0d3d99218462730ca33c7af81750b4c1c26dde167d2ae64d580bbfcac87535fbe3db0380814f00514504a97073ed2f5b8cff7a978dde228906dacac192978681d4363420f49643750cb6c817594632dc10863f8a0a84f954fc6cd2e665c005500452d40e01473f95aa9930911b4392197b3551b37ac92a049e87487b654b4ebbe0000000000b75cee0000000000005140fffffff8000000006734642a00000000673464290000000000b7184000000000000049ab0b6cbb8d75c2d6da635ce6a4d9b6d5c7aadfc29d232bacfed44dc2208ea806c3a1d235ca6329acc812fb5940f36566be37f6e0eac03ac3e0d1d494c3f4970d998c7e44b694d079b2215fe696ac465cb3ea4cdbbb10ee816ba7bde4ce6e5818607daac3ac95b8fb42669c119fe1b93536f645355d875b475941969e9707e78b9d16e30d092746d1c707cee92b4d8f3e7bbfe629141d0d71f5ceb044776a02128c80619ed4f7f6a9bfe660e9cefcd61a603e1e4a239663aa22eaf0375e24759411787acd046b007665176c817594632dc10863f8a0a84f954fc6cd2e665c005500d69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e4000000000001fec30000000000000108fffffff6000000006734642a0000000067346429000000000001f87200000000000000e70b476df28711a0cf37be843b115524a194017aac4792fbd17a45b0a6a5f437723c030a27895f8ac7c9cf1890321f5426e0733e1148b80dcf296d9d00a18b6155ac94f3ae25a7278b3a4f578aded11bc947d13ea986bdbc87cfab38d9cb9fa2b35d2597577a996fdc12288f4c887ec2e3061125d4060fb30de27ad8888e69cc3704d4c72bc4d59c67e201968d211c0f33e6a0c82f4e62a67c98bef59378d8b20d23aa15082430d409b15f84262fce9b666f61e86c7c63aa22eaf0375e24759411787acd046b007665176c817594632dc10863f8a0a84f954fc6cd2e665c00550053614f1cb0c031d4af66c04cb9c756234adad0e1cee85303795091499a4084eb0000000002a4cf9a000000000000fd0cfffffff8000000006734642a00000000673464290000000002a03edc00000000000117c30bc72eac616dedbfc2a430d1f42d6a096b749a6fa92f42e42839316eaa040f959038ea5e7a84739e5b28b84a7a61325683e9ba8f3f715fc3ee53248dffcff56f8fb3d646c941eb48c6c8d80b8ef585741adf7b068c4693ad11e4f494682502ff1725e92a099c5b9a3b3b6de6bf2ed9f1e35759a8e412796107969e9707e78b9d16e30d092746d1c707cee92b4d8f3e7bbfe629141d0d71f5ceb044776a02128c80619ed4f7f6a9bfe660e9cefcd61a603e1e4a239663aa22eaf0375e24759411787acd046b007665176c817594632dc10863f8a0a84f954fc6cd2e665c005500f0d57deca57b3da2fe63a493f4c25925fdfd8edf834b20f93e1f84dbd1504d4a000000000003b9080000000000000174fffffff6000000006734642a0000000067346429000000000003b126000000000000018c0bd1abc6f7ce090279144cfbfe201729cec66af4b2e2f9d01daf26dd54702c365aaa39d023c41ed735f61a6e5fefebd420da4e37b55539c68afad1dbf3458cbe6b1f1fb1c6f7ae81923d50064f5b5fd9fa11c9b3182fd9c117c2efe42e25374b0449e21d681a0c61f46eebd11d0e2301e08f9eb2ab8d2956575007305a4d87b0d3d99218462730ca33c7af81750b4c1c26dde167d2ae64d580bbfcac87535fbe3db0380814f00514504a97073ed2f5b8cff7a978dde228906dacac192978681d4363420f49643750cb6c817594632dc10863f8a0a84f954fc6cd2e665c005500ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d00000004d17732080000000001a34b77fffffff8000000006734642a000000006734642900000004c55e783c00000000018175120b28bf7d76e425c1600cfc35b5378e3c2fd70f8bc595539207177d2ea29e2bd7a29fae7b5202fa93245d899134a8887efe9845c577e4887cf8a813c2c9bdb06b77159d64fed14e696b0a9ede5734c77e11733b0a6662f8103cff546636b42d8f25b18e25e7469ca8c018d8b50061a1b52104870f258c345a4b7ad8888e69cc3704d4c72bc4d59c67e201968d211c0f33e6a0c82f4e62a67c98bef59378d8b20d23aa15082430d409b15f84262fce9b666f61e86c7c63aa22eaf0375e24759411787acd046b007665176c817594632dc10863f8a0a84f954fc6cd2e665c00550023d7315113f5b1d3ba7a83604c44b94d79f4fd69af77f804fc7f920a6dc657440000000011fa00dd000000000007210ffffffff8000000006734642a00000000673464290000000011bb9fd4000000000005c12a0b7199ef067b8453c3095de872de2b9c912f2466e3e45848c3defa08270c6f6cd1b0d78f53a53637ec5ac1f3caea3f9277597e1de32c35483ff2d080f9094c22513258354c5813406435094ce934924c3eb31ada4093e57f729afb14edc1b9491f718f69288a48cb7851b307e3b37313129c0f889b670785b9d3e164ff585786d1b0dbf47260687facaa94f3cc5749b9b376efb312a1af084bd54de661d42da7ec619ed4f7f6a9bfe660e9cefcd61a603e1e4a239663aa22eaf0375e24759411787acd046b007665176c817594632dc10863f8a0a84f954fc6cd2e665c005500f63f008474fad630207a1cfa49207d59bca2593ea64fc0a6da9bf3337485791c000000000474235f000000000003e155fffffff8000000006734642a0000000067346429000000000480a0fd00000000000492860b479127e3f364973d6dc6e43905449058eab4cb3338e2ef93a89e586215253932c80c11c51567607cb1d00d8460d387e48df86026fe91dcf2adcec2df819ed41e447210c56935843a79d6eec5c83f0a2b11c9b3182fd9c117c2efe42e25374b0449e21d681a0c61f46eebd11d0e2301e08f9eb2ab8d2956575007305a4d87b0d3d99218462730ca33c7af81750b4c1c26dde167d2ae64d580bbfcac87535fbe3db0380814f00514504a97073ed2f5b8cff7a978dde228906dacac192978681d4363420f49643750cb6c817594632dc10863f8a0a84f954fc6cd2e665c005500ec5d399846a9209f3fe5881d70aae9268c94339ff9817e8d18ff19fa05eea1c8000000000401374f0000000000015aaefffffff8000000006734642a00000000673464290000000003ee859b000000000001437b0bf4d1cb61111e7946ed11583a2aa15e8146c42569e9648aca3e419fdb5160857a9851a31ad35e1ebe8690d86498839ccbfabe3c41775869ff77ffc65553f949b05eb47436bd320052edefc1fb6f3d6ee2733b0a6662f8103cff546636b42d8f25b18e25e7469ca8c018d8b50061a1b52104870f258c345a4b7ad8888e69cc3704d4c72bc4d59c67e201968d211c0f33e6a0c82f4e62a67c98bef59378d8b20d23aa15082430d409b15f84262fce9b666f61e86c7c63aa22eaf0375e24759411787acd046b007665176c817594632dc10863f8a0a84f954fc6cd2e665c";

        priceData.feedHashes[0] = 0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43;
        priceData.answers[0] = 8_771_079_350_014;
        priceData.timestamps[0] = 1_731_486_762;

        // KLAY/USD feedHash not KAIA/USD
        priceData.feedHashes[1] = 0x452d40e01473f95aa9930911b4392197b3551b37ac92a049e87487b654b4ebbe; // KLAY/USD feedHash not KAIA/USD
        priceData.answers[1] = 12_016_878;
        priceData.timestamps[1] = 1_731_486_762;

        priceData.feedHashes[2] = 0xf63f008474fad630207a1cfa49207d59bca2593ea64fc0a6da9bf3337485791c;
        priceData.answers[2] = 74_720_095;
        priceData.timestamps[2] = 1_731_486_762;

        priceData.feedHashes[3] = 0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace;
        priceData.answers[3] = 317_410_406_304;
        priceData.timestamps[3] = 1_731_486_762;

        priceData.feedHashes[4] = 0xdcef50dd0a4cd2dcc17e45df1676dcb336a11a61c69df7a0299b0150c672d25c;
        priceData.answers[4] = 38_408_347;
        priceData.timestamps[4] = 1_731_486_762;

        priceData.feedHashes[5] = 0xd69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e4;
        priceData.answers[5] = 1307; // divide by 100
        priceData.timestamps[5] = 1_731_486_762;

        priceData.feedHashes[6] = 0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d;
        priceData.answers[6] = 20_694_118_920;
        priceData.timestamps[6] = 1_731_486_762;

        priceData.feedHashes[7] = 0xec5d399846a9209f3fe5881d70aae9268c94339ff9817e8d18ff19fa05eea1c8;
        priceData.answers[7] = 67_188_559;
        priceData.timestamps[7] = 1_731_486_762;

        priceData.feedHashes[8] = 0x03ae4db29ed4ae33d323568895aa00337e658e348b37509f5372ae51f0af00d5;
        priceData.answers[8] = 1_193_568_171;
        priceData.timestamps[8] = 1_731_486_762;

        priceData.feedHashes[9] = 0x23d7315113f5b1d3ba7a83604c44b94d79f4fd69af77f804fc7f920a6dc65744;
        priceData.answers[9] = 301_596_893;
        priceData.timestamps[9] = 1_731_486_762;

        priceData.feedHashes[10] = 0xf0d57deca57b3da2fe63a493f4c25925fdfd8edf834b20f93e1f84dbd1504d4a;
        priceData.answers[10] = 2439; // divide by 100
        priceData.timestamps[10] = 1_731_486_762;

        priceData.feedHashes[11] = 0x53614f1cb0c031d4af66c04cb9c756234adad0e1cee85303795091499a4084eb;
        priceData.answers[11] = 44_355_482;
        priceData.timestamps[11] = 1_731_486_762;

        priceData.feedHashes[12] = 0x2a01deaec9e51a579277b34b122399984d0bbf57e2458a7e42fecd2829867a0d;
        priceData.answers[12] = 53_868_851;
        priceData.timestamps[12] = 1_731_486_762;

        return priceData;
    }

    // @see https://kaiascan.io/tx/0xed13f3fbac2299d63067bcde006cfcd0e1ab255c231cf09ec678c2d61213ab41?tabId=inputData&page=1
    // block numebr 169474582
    function test_executeLimitOrders_ok() public {
        vm.selectFork(limitOrderForkId);
        vm.rollFork(169_474_568); // limitOpen time must be lesser than 1_731_486_762
        deployAndSet();

        uint256 nextPositionId = perpDex.nextPositionId();
        emit log_named_uint("nextPositionId", nextPositionId);

        bytes memory userSignedData = getSignedMessage(
            userPk,
            abi.encodePacked(
                "Open Limit Order for Token: 1, Margin: 1995800, Leverage: 3, Long: 1, Wanted Price: 12017000, TP: 0, SL: 0, Nonce: 0, Chain: 8217, Contract: ",
                Strings.toHexString(address(perpDex))
            )
        );

        PerpDexLib.OpenLimitOrderData memory o = PerpDexLib.OpenLimitOrderData({
            tokenType: PerpDexLib.TokenType.Klay,
            marginAmount: 1_995_800,
            leverage: 3,
            long: true,
            trader: user,
            wantedPrice: 12_017_000, // edited (not a actual watned price of positionId 2118)
            tpPrice: 0,
            slPrice: 0,
            userSignedData: userSignedData
        });
        vm.prank(singleOpenAdmin);
        perpDex.openLimitOrder(o);

        uint64[] memory roundIds = new uint64[](tokenCount);

        uint256[] memory ordersToExecute = new uint256[](1);
        ordersToExecute[0] = nextPositionId;
        PerpDexLib.OraclePrices memory priceData = getLimitOrderValidPriceData();

        vm.warp(block.timestamp + 10);
        vm.roll(169_474_582);
        vm.deal(limitAdmin, 100_000);

        vm.startPrank(limitAdmin);
        uint256 feeAmount = pyth.getUpdateFee(priceData.proofs);
        assertEq(feeAmount, 13);
        perpDex.executeLimitOrders{value: feeAmount}(ordersToExecute, roundIds, priceData);
        vm.stopPrank();

        PerpDexLib.Position memory p = perpDex.getPosition(nextPositionId);
        emit log_named_uint("limitOrderPrice", p.limitOrderPrice);
        emit log_named_uint("tokenType", uint256(priceData.answers[uint64(p.tokenType)]));
        emit log_named_uint("positionStatus", uint256(p.positionStatus));
        emit log_named_uint("limitOpenTime", p.statusTime.limitOpenTime);
        emit log_named_uint("openTime", p.statusTime.openTime);
        assertEq(p.initialPrice, uint256(priceData.answers[uint64(p.tokenType)]));
        assertEq(uint256(p.positionStatus), uint256(PerpDexLib.PositionStatus.Open));
    }

    function test_executeLimitOrders_revert() public {
        vm.selectFork(limitOrderForkId);
        vm.rollFork(169_474_581);
        deployAndSet();
        vm.deal(limitAdmin, 100_000);

        vm.startPrank(limitAdmin);
        uint64[] memory roundIds = new uint64[](tokenCount);

        uint256[] memory ordersToExecute = new uint256[](1);
        ordersToExecute[0] = 0;
        PerpDexLib.OraclePrices memory priceData = getLimitOrderValidPriceData();

        // switch priceData
        // 🔥 switch order => no problem
        priceData.feedHashes[5] = 0xdcef50dd0a4cd2dcc17e45df1676dcb336a11a61c69df7a0299b0150c672d25c;
        priceData.answers[5] = 38_408_347;
        priceData.timestamps[5] = 1_731_486_762;

        priceData.feedHashes[4] = 0xd69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e4;
        priceData.answers[4] = 1307; // divide by 100
        priceData.timestamps[4] = 1_731_486_762;

        uint256 feeAmount = pyth.getUpdateFee(priceData.proofs);
        vm.expectRevert("Feed hash is not correct (Pyth)");
        perpDex.executeLimitOrders{value: feeAmount}(ordersToExecute, roundIds, priceData);

        priceData = getLimitOrderValidPriceData();
        // mix priceData - feedHash is ok
        priceData.answers[5] = 38_408_347;
        priceData.timestamps[5] = 1_731_486_762;

        priceData.answers[4] = 1307; // divide by 100
        priceData.timestamps[4] = 1_731_486_762;
        vm.expectRevert("Price is not correct (Pyth)");
        perpDex.executeLimitOrders{value: feeAmount}(ordersToExecute, roundIds, priceData);

        priceData = getLimitOrderValidPriceData();
        vm.expectRevert(); // OutOfFunds cannot be specified
        perpDex.executeLimitOrders{value: feeAmount - 1}(ordersToExecute, roundIds, priceData);
    }

    function getLiquidateValidPriceData() public pure returns (PerpDexLib.OraclePrices memory) {
        PerpDexLib.OraclePrices memory priceData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.Pyth,
            feedHashes: new bytes32[](13),
            answers: new int256[](13),
            timestamps: new uint256[](13),
            proofs: new bytes[](1)
        });
        priceData.proofs[0] =
            hex"504e41550100000003b801000000040d00cd044208c81e5df042ad4881639f8073bb524f5e8e769378c3cbab6f78de146d28f03084481930744109286a6a75a80eb48a6950c64dd0ea597b1f6e5890283801047660d1f4899f3d40c2cbdfc8d8d4a91d43f887f6bb6e97dcd6b8b5170cec92112e65a4ccd6357c0f73dce89b2acd2117481c59338c2e4ace29aaa81a7a85b6460006e523e40e125f488698e90e3804fdcdab59e1558f0b2d32cedf14301280d3e78440c58829af4300feedcbededf7d874c392e9471902d9d48a5fe0b9c2a3a0f8f6010818d965296f73708b2f8bb56811aadb3fc0ecaff2e1616f223fcfc643a101f59b540688265b83cfaa750e4270fda84cdfc79ebde58c1389fae73cd7b77aa9a1db000ab0f870e9ad764cf7ae1e5ac4188256c6fbfbe32d10a190119d130e768e8411fc4115a53641f1adca80330af069b7eb9d98bbc230724061544004fadff1004bbb000b4f87a6960dde167c80d6d296478c5c68182f3fcf75768bee514fb3794111f6772983909f75595cad612a92b5995eaac519bc1786294a1f550f3faa9ba736a1c8010c166afc84d8ead5ab9ca566c295a194bd7953b33ae0c0baaa167aa955519ed0a679d3889187539820119fa46f521233981d17459e917d3a2a050d75668bfe6371010dcd164ea82837923ae21bfe28f03354ba19de4896870793b4c9c5782c2ca22b4b547b8ae335f546700399bdff2429bd74ea52b86ef51cf983d50d23d5c74e7ca7010e067618e95c32e0bd1ef78fd36f8cad7ab6d5f9d13ffbde609fcac9a8b7d5c5b71b4bf2b9baa15c88796d9fce16b0312867dccb331db9d1435331208b3872d8ab010f14d551526a63dc500e4841633f78df65c9079e8bc27aefb9b7e69e533d5a1b4e6935086cc5fa7871cc10608c1f37e410994ce668c919027ef50fc511df5d1593001028992430cebde22f7b639373a89e530351904cab3cdf6f46f636051fa73ba804232a5f5acc4903d8b886bf4531fedd991ec378f72163046245edbe3610be6ee80111aad85c431f5f7875ce7c69d4102a000749731735f827406124039fc41cd0542c153af2aa0583edfe7921879cb5460a1d9390bf451792bc44b0f9496b9acd361601125e47b34de64d25ee42244115862c3ddedee7240b63d26bd3ebd9a38e87f383a715855b09eda029696e8ab52ace6365cc6bc15f90075fd3c7525d9f4890a20a5d016739cd9700000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa71000000000597caa4014155575600000000000aa49546000027107a1d55ba8278e99aebbdae4b14132ed83076289d0d0055002a01deaec9e51a579277b34b122399984d0bbf57e2458a7e42fecd2829867a0d00000000044456a3000000000001201afffffff8000000006739cd97000000006739cd9600000000044fa8fe00000000000117d80b86c34ce75824418c0cb038dff5e206219277e7cba77e2623f710892573330f0e0311ed08dff283d68ab791319738b3f98b6991fadc76baf445ef074603107276a9702a493617a08a1c9a1e65138661e7ae9581cb9b134872dcfdd27f79f93d0d4f4121d83f90ba16482730f4f71dbe908b8541199936b48fe608ebaec9e55c9123dc4d9cf027467228a66f963e8896a7d2451f23e24123c9aef7a2a89d54e1049fc1be003721a6299c35fce787c85867bc8a9f897ed56ba28a2927f253ce2bc2b13a2588de6ad11575e9498dea1d220d6dfae691d18c20bbd14623bd00550003ae4db29ed4ae33d323568895aa00337e658e348b37509f5372ae51f0af00d5000000004aa5f2190000000000108ce3fffffff8000000006739cd97000000006739cd96000000004a8653cc000000000012272e0bedf5c1c1df6288888c03cf03a84524645c78135f58e03cd2879073c69dda9d8685f43767c4322bcc3cda583dd1317cffe7b3c8cc3d4662a85672daf17e131790e93e504d6a06567b78559ffa8982c43311c41f7188e985b6639272a910c187728142d12335bf2d742aab66bd178717c971d2ea21283e61cec2d6b580f4e469e90e9f24dc8da90abe0119e7743e8896a7d2451f23e24123c9aef7a2a89d54e1049fc1be003721a6299c35fce787c85867bc8a9f897ed56ba28a2927f253ce2bc2b13a2588de6ad11575e9498dea1d220d6dfae691d18c20bbd14623bd005500e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b4300000843df1c3d35000000011d0e366bfffffff8000000006739cd97000000006739cd9600000848a641d600000000011f3b72640b4dc5ac43bee3ef6bef18b42f6e20da6b8ba0f7fa2291380e665c7538f7086acbf7da1b28ba3d9bfbeab1ac555f37d0cd14f9a1a2c25ba81cf818921f7a09dc29f01137399806de44a865d4496271abf0b291005cfbcffc3d9dc25e57d2048b16c1ecb48fb147890db93dc2f9195a35d4c447634405478e49c04a2baf08a088f6bb1b09482efb3b251ec17fe0f23986d066d25c1f58bd2e9a49d76e91644b67968af914cfb50870353a69cdb16a3791cd002f094c7ed56ba28a2927f253ce2bc2b13a2588de6ad11575e9498dea1d220d6dfae691d18c20bbd14623bd005500dcef50dd0a4cd2dcc17e45df1676dcb336a11a61c69df7a0299b0150c672d25c000000000227b0f60000000000008ab6fffffff8000000006739cd97000000006739cd9600000000022e09dd000000000000806d0b22c055751cf9e833e2496b80d559b909734e1914f1c47b9e6af25a691403e353f55bcd90addd18a8645858708f45d600d4bf79a4227b68640edf528cbb7d3e69910450e2515b3e5ed87363f6745954b8fb350d6bde3474b8f1a335e0c6ed15c4fd355ef4310d06bafbe5b872fe54c0508c44f90bf643e219c04a2baf08a088f6bb1b09482efb3b251ec17fe0f23986d066d25c1f58bd2e9a49d76e91644b67968af914cfb50870353a69cdb16a3791cd002f094c7ed56ba28a2927f253ce2bc2b13a2588de6ad11575e9498dea1d220d6dfae691d18c20bbd14623bd005500ff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace00000048c5846019000000000d6a82b3fffffff8000000006739cd97000000006739cd960000004927e483e0000000000a7e57630bc08f1036d9b4e74bdb5ab6bdd009d5e60c8a4000a9e20a95425ce103b7542c7b25800b1c46edc0cd3c2fa1ecca6f3684e7b414cc0674fed01f4e46674a953caddca674ba710d85010a00798fa9b7755f99920e5b90165c727ddfadd3b33526e6e9885f563b5d5e963ef0239df628c8d5870373686d455c0d4eea3bd6c3714f085e490e93db2d8e6fa86c82e34843a477920500531c2c1ef4682e87cdaeb61ffb8c641843159b450534e6e8de1bc0aae1cdb6eb99a34336451cb82146f9bdf139062e7e7ca60727bc75e9498dea1d220d6dfae691d18c20bbd14623bd005500452d40e01473f95aa9930911b4392197b3551b37ac92a049e87487b654b4ebbe0000000000ce84f60000000000004a59fffffff8000000006739cd97000000006739cd960000000000d041f90000000000004cc20bd452b5db940aa90239e23a137173cdedb2b0ed2cee09144da26f8860a055c3c265ca385c1f4e51b0f791a2ebff9ae2ba841b72d175d508f387559dfe01d80c8615bf2486221663d01bc41da52921f498efa3c9533e60c4653bfcbe65672f7e23bb98f19889cdd7c2b8660415f8fbfa407c24731bb6a01d78232bbf15997d363eb60808df743efa5b407697510d067be459a1a6b480df764a5ba3a5602120c58b9fc1be003721a6299c35fce787c85867bc8a9f897ed56ba28a2927f253ce2bc2b13a2588de6ad11575e9498dea1d220d6dfae691d18c20bbd14623bd005500d69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e4000000000003318d0000000000000134fffffff6000000006739cd97000000006739cd9600000000000341de00000000000001380b28d5d6c4c37fc6c6e71f6cf676b213a4c71bcf25639a9245db902ccd23f3362b7ff783b15586d68183f46fb12923cfb7475357d7f4211db345650b35c9470bd07425670d09255276aa50b4595eb4eab5fb350d6bde3474b8f1a335e0c6ed15c4fd355ef4310d06bafbe5b872fe54c0508c44f90bf643e219c04a2baf08a088f6bb1b09482efb3b251ec17fe0f23986d066d25c1f58bd2e9a49d76e91644b67968af914cfb50870353a69cdb16a3791cd002f094c7ed56ba28a2927f253ce2bc2b13a2588de6ad11575e9498dea1d220d6dfae691d18c20bbd14623bd00550053614f1cb0c031d4af66c04cb9c756234adad0e1cee85303795091499a4084eb000000000316c3a60000000000019b8afffffff8000000006739cd97000000006739cd9600000000032259a400000000000125890bc72eac616dedbfc2a430d1f42d6a096b749a6fa939150a889a017a2aec3f80af8b725f8083950597157c0be5c66944b1fbfd0d1bd260ccd01dda1802f2a63d34ab957d217d5106e19ab97620b0cc2fa7dccdae639f3400bd0b62dcf69bd0909cde420c7dc369e7065066e11711e806145f8667f4f30aecae232bbf15997d363eb60808df743efa5b407697510d067be459a1a6b480df764a5ba3a5602120c58b9fc1be003721a6299c35fce787c85867bc8a9f897ed56ba28a2927f253ce2bc2b13a2588de6ad11575e9498dea1d220d6dfae691d18c20bbd14623bd005500f0d57deca57b3da2fe63a493f4c25925fdfd8edf834b20f93e1f84dbd1504d4a000000000003becc0000000000000157fffffff6000000006739cd97000000006739cd96000000000003cad400000000000001400b09d8d02e5adaa82442632d593fe24875e0a613c31621c092ae67ef4908c6ddde8e8b67ae98da7aba9cb26366a207dc6f95748d0bf6fac9d3e15584991dcaeb1ab62c76577b0b71a6eb9d505a9ecd1f8d01215c634f83a3d74025c0298bbea4e66e09b9a4a2f3ee4dfc669701a5d95d50a94197e5a0048a814eea3bd6c3714f085e490e93db2d8e6fa86c82e34843a477920500531c2c1ef4682e87cdaeb61ffb8c641843159b450534e6e8de1bc0aae1cdb6eb99a34336451cb82146f9bdf139062e7e7ca60727bc75e9498dea1d220d6dfae691d18c20bbd14623bd005500ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d0000000594ba2276000000000152219ffffffff8000000006739cd97000000006739cd9600000005909921a000000000011959950be3e831a9d0c1769b56209cef5a8a9ee39b085bdaf31fec80e75815cc35ae923235fbe95cbf3e4bd9a8f54e053c7cdd1c4c438e596219bd3a05d63e3f47ef773b7ddfb6585813ccf48738488bda3ca00a47763b43451d522e4cb20fa6b5f03e568efc736cb147890db93dc2f9195a35d4c447634405478e49c04a2baf08a088f6bb1b09482efb3b251ec17fe0f23986d066d25c1f58bd2e9a49d76e91644b67968af914cfb50870353a69cdb16a3791cd002f094c7ed56ba28a2927f253ce2bc2b13a2588de6ad11575e9498dea1d220d6dfae691d18c20bbd14623bd00550023d7315113f5b1d3ba7a83604c44b94d79f4fd69af77f804fc7f920a6dc6574400000000164d8dcf0000000000049344fffffff8000000006739cd97000000006739cd9600000000165e820e000000000004c0ce0b842adc04973b2ccd44e658e079aa4a10e334e7fb6d5d3764a03809c428d9576b9378668c7cf524cdf7c3b1af0a511de1056901378aef5408d019b439a8af04231ab9e77a81ba9c5820ba20302744da5f8cf02087c6029e4197fa84d09ce3cebe606843013f90ba16482730f4f71dbe908b8541199936b48fe608ebaec9e55c9123dc4d9cf027467228a66f963e8896a7d2451f23e24123c9aef7a2a89d54e1049fc1be003721a6299c35fce787c85867bc8a9f897ed56ba28a2927f253ce2bc2b13a2588de6ad11575e9498dea1d220d6dfae691d18c20bbd14623bd005500f63f008474fad630207a1cfa49207d59bca2593ea64fc0a6da9bf3337485791c0000000005b3454e0000000000052342fffffff8000000006739cd97000000006739cd960000000005b8d72c0000000000060c190b88bf8fa4bf4280c45bbbf4cc6f52e9a88bf83f52f2373e768794184893e546d3df02bf2feed088248dacf52e0b3493e52ea621355e71af62292fd987564059d8a5d20bc48a9bdd493a978352f0113fd701215c634f83a3d74025c0298bbea4e66e09b9a4a2f3ee4dfc669701a5d95d50a94197e5a0048a814eea3bd6c3714f085e490e93db2d8e6fa86c82e34843a477920500531c2c1ef4682e87cdaeb61ffb8c641843159b450534e6e8de1bc0aae1cdb6eb99a34336451cb82146f9bdf139062e7e7ca60727bc75e9498dea1d220d6dfae691d18c20bbd14623bd005500ec5d399846a9209f3fe5881d70aae9268c94339ff9817e8d18ff19fa05eea1c80000000006476deb0000000000017849fffffff8000000006739cd97000000006739cd960000000006639c5700000000000128de0bd0bf9d87bfd7665e35d5fe4d59ce6c7fdad77c242e7ecaeca2e7ac431fc7fed7dc69e5ce6736e1b77e78c62822bec3e92e22009c9a17aa4e35cb15f44ace29139f818f44c2c93062be120fccff0a968b47763b43451d522e4cb20fa6b5f03e568efc736cb147890db93dc2f9195a35d4c447634405478e49c04a2baf08a088f6bb1b09482efb3b251ec17fe0f23986d066d25c1f58bd2e9a49d76e91644b67968af914cfb50870353a69cdb16a3791cd002f094c7ed56ba28a2927f253ce2bc2b13a2588de6ad11575e9498dea1d220d6dfae691d18c20bbd14623bd";

        priceData.feedHashes[0] = 0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43;
        priceData.answers[0] = 9_087_599_000_885;
        priceData.timestamps[0] = 1_731_841_431;

        priceData.feedHashes[1] = 0x452d40e01473f95aa9930911b4392197b3551b37ac92a049e87487b654b4ebbe;
        priceData.answers[1] = 13_534_454;
        priceData.timestamps[1] = 1_731_841_431;

        priceData.feedHashes[2] = 0xf63f008474fad630207a1cfa49207d59bca2593ea64fc0a6da9bf3337485791c;
        priceData.answers[2] = 95_634_766;
        priceData.timestamps[2] = 1_731_841_431;

        priceData.feedHashes[3] = 0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace;
        priceData.answers[3] = 312_551_432_217;
        priceData.timestamps[3] = 1_731_841_431;

        priceData.feedHashes[4] = 0xdcef50dd0a4cd2dcc17e45df1676dcb336a11a61c69df7a0299b0150c672d25c;
        priceData.answers[4] = 36_155_638;
        priceData.timestamps[4] = 1_731_841_431;

        priceData.feedHashes[5] = 0xd69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e4;
        priceData.answers[5] = 2092;
        priceData.timestamps[5] = 1_731_841_431;

        priceData.feedHashes[6] = 0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d;
        priceData.answers[6] = 23_970_062_966;
        priceData.timestamps[6] = 1_731_841_431;

        priceData.feedHashes[7] = 0xec5d399846a9209f3fe5881d70aae9268c94339ff9817e8d18ff19fa05eea1c8;
        priceData.answers[7] = 105_344_491;
        priceData.timestamps[7] = 1_731_841_431;

        priceData.feedHashes[8] = 0x03ae4db29ed4ae33d323568895aa00337e658e348b37509f5372ae51f0af00d5;
        priceData.answers[8] = 1_252_389_401;
        priceData.timestamps[8] = 1_731_841_431;

        priceData.feedHashes[9] = 0x23d7315113f5b1d3ba7a83604c44b94d79f4fd69af77f804fc7f920a6dc65744;
        priceData.answers[9] = 374_181_327;
        priceData.timestamps[9] = 1_731_841_431;

        priceData.feedHashes[10] = 0xf0d57deca57b3da2fe63a493f4c25925fdfd8edf834b20f93e1f84dbd1504d4a;
        priceData.answers[10] = 2454;
        priceData.timestamps[10] = 1_731_841_431;

        priceData.feedHashes[11] = 0x53614f1cb0c031d4af66c04cb9c756234adad0e1cee85303795091499a4084eb;
        priceData.answers[11] = 51_823_526;
        priceData.timestamps[11] = 1_731_841_431;

        priceData.feedHashes[12] = 0x2a01deaec9e51a579277b34b122399984d0bbf57e2458a7e42fecd2829867a0d;
        priceData.answers[12] = 71_587_491;
        priceData.timestamps[12] = 1_731_841_431;

        return priceData;
    }
    // @see
    // open 0xe5ef042e36d3f9f227811dd2beb84b56c8edde87950f48d54d58af484fd3bf74
    // 167772315 10/24/2024, 11:24:13 PM GMT+9

    // liquidate 0xb1f8bc6d4a51804156627d57f2847a3bd1de7e54eb7fdcf4fc16be5cbc03179f
    // 167822927 10/25/2024, 01:29:47 PM GMT+9

    function test_liquidatePositions_ok() public {
        vm.selectFork(liquidationForkId);
        vm.rollFork(169_811_776); // 2219 opened 169811777
        uint256 time1 = block.timestamp;
        deployAndSet();

        PerpDexLib.OraclePrices memory priceData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.Pyth,
            feedHashes: new bytes32[](1),
            answers: new int256[](1),
            timestamps: new uint256[](1),
            proofs: new bytes[](1)
        });

        priceData.feedHashes[0] = 0xd69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e4;
        priceData.answers[0] = 2112;
        priceData.timestamps[0] = 1_731_824_326;
        priceData.proofs[0] =
            hex"504e41550100000003b801000000040d0093247920cccbeeb0b5e67b59174faaf34c9a859188f5d760402d5f93b4b0000c6e66553cfb8c74e8e82489c5ae66fc6834631fa2aa96dade1e3128cc4d24106900049523197b4e86a7b398e43240d4d63d0d054aa9a4eced357fcdcab89566298b6930093987a66839066c0ea8cd2cb897b7ed5984e439d35db61a34c0200013504c00066ee9d635df61ad56591a7ee5ca9409eadc6cf9e34b1e4c36f72b849ee7e8dc7869879b8738ef5ad3e5322b85133ed5cc28e080e09f26613978950269c373c8fe0008291003c98daf1ff6bf2e574aa4f38f56c70604507d3e17efe3fb5ce337d900840c3bf92be8026a269066a011e1d3a4b13d59063e21dccab62703394cb8073fff000a73740fd2a849e9c2c5476c92d9493db7e8ce2a4fef150b254a6440b74cc99fe521ff382acac3362c86b6939565b13efbdde972e30cde1b66fe8834155cfff650010b63127b3f668088f3d62ef12ab7ad29db90a2d03228a856a0a6e411c60b38a5326d399d0fd5b132aba6b2bdb59ee93a31183ee241efacdc047a38c7de6592617a010cdc3ac8b963f703f94d30c6f9064874478ba91a5c0821f6acad238ebb69bcea0a7ca8ba0c573bda90ddcaa8e292bc17cca7d670a2289ae908ec099703008821b4000d1a020882e251081a22db4a5f67135f923cd2d90dccb82e067016efbfb50e12ee3b8f197f682d3499757ddd78aaa9c723bab880ab8b0b53a8cd3ae54408976d0f000eab981b64ec5423372a1aa66c8435378f8364db7c73e54e34856ee2052e322ce16ffadd772cf5507de6cc61671e3b5d292433bcd8bff5bf186c75e6c4c3c6929b010f98b0c0bb722bffcc405fb48d784cc13a43b161c2cc503761b4d28d52cca40539315891d55114b6bdfbcd34d540465c9890c96de40af358215af0f36568f704ec011036470a692e5a79c8330684080694e30eefc7a7daffadb54889e5096721317fd722821c3bdcbc1e0aedb313d8722c1547ce4356c7d8f278cf41fb41072fb551d901113c4a383fae6e5e89f36821c422d570e3edb44216bc920c9c3724b42c34694c6a53191b13188234bd5ad7fd932fdce3bc5bc7e799f8d9311774e12dc0d1b254f700122e08d60563e976e09dbd87a4fb1a35da5e6755670162d2b39143ce630be837df0765d469133effcf971820f3e280c3758be16d1aa3c21ac264db01752a7e6b5a0067398ac600000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa710000000005972276014155575600000000000aa3ed180000271066b96404bfc251d47e0c0b2a3b2b95a7202e3f7301005500d69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e40000000000033954000000000000011dfffffff60000000067398ac60000000067398ac5000000000003362a000000000000013a0b508cef6da66a2c0458b079fef9ded0220363f1446238bb2049d763b9c56003c94a637ac30e1854aca82ed0aa3a0926ee214b0565de719075b8b52548e4ab22a0305f9e3a8bd2d65ab7ec615c7a6a42a89e2034532949ebd16103b28947449fd7f603074118cea06ee778c82b6580e0fa225c12343649f0435890c137220f17d91e57d6f813bcf2b642a1c595fe6ac60aaad9c03332957100004ddd15544a6c9950350903ebf1e5b73579beafc8ffb3ce7235192b5d2df4082c15ece1a44bc8618a36a8d1145d5c0aa23696a957346143530a2c0ee01053863f573d89";

        bytes memory userSignedData = getSignedMessage(
            userPk,
            abi.encodePacked(
                "Open position for Token: 5, Margin: 7598100, Leverage: 100, Long: 1, TP: 0, SL: 0, Price: 2112, Nonce: 0, Chain: 8217, Contract: ",
                Strings.toHexString(address(perpDex))
            )
        );

        vm.deal(singleOpenAdmin, 100_000);
        vm.startPrank(singleOpenAdmin);

        perpDex.openPosition{value: pyth.getUpdateFee(priceData.proofs)}(
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

        vm.makePersistent(user);
        vm.makePersistent(address(perpDex));
        vm.makePersistent(address(lpContract));
        vm.makePersistent(address(usdtContract));

        vm.deal(liqAdmin, 100_000);
        vm.startPrank(liqAdmin);
        vm.warp(block.timestamp + 169_828_865 - 169_811_776);
        vm.roll(169_828_865);
        uint256 time2 = block.timestamp;
        uint64[] memory roundIds = new uint64[](0);
        uint256[] memory candidates = new uint256[](1);
        candidates[0] = 1;
        priceData = getLiquidateValidPriceData();
        emit log_array(priceData.answers);
        emit log_array(priceData.timestamps);
        perpDex.liquidatePositions{value: pyth.getUpdateFee(priceData.proofs)}(candidates, roundIds, priceData);

        PerpDexLib.Position memory p2 = perpDex.getPosition(1);
        assertEq(uint256(p2.positionStatus), uint256(PerpDexLib.PositionStatus.Liquidated));
        assertEq(p2.finalPrice, 2092, "finalPrice");

        // pnl < 0 && marginAfterFundingFee - closeFee + pnl <= 0
        int256 expectingFundingFee = int256(p2.size * 1e20 * (time2 - time1) * 875 / (1e20 * 1e7 * 3600));
        int256 marginAfterFundingFee = int256(p2.margin) - expectingFundingFee;

        int256 pnl = int256((p2.size * p2.finalPrice) / p2.initialPrice) - int256(p2.size);
        uint256 loss = Math.min(uint256(marginAfterFundingFee), uint256(-pnl));
        int256 closeFee = int256((p2.size - loss) * 70 / 100_000);
        emit log_int(expectingFundingFee);
        emit log_int(marginAfterFundingFee);
        emit log_int(closeFee);

        assertEq(p2.fundingFee, expectingFundingFee, "fundingFee");
        assertEq(p2.pnl, -(marginAfterFundingFee - closeFee), "pnl");
        assertEq(p2.closeFee, uint256(closeFee), "closeFee");
        assertEq(usdtContract.balanceOf(address(lpContract)), initialLpBalance + uint256(marginAfterFundingFee - closeFee), "lp balance");
        assertEq(usdtContract.balanceOf(address(feeContract)), p2.closeFee + p2.openFee, "fee balance");
        assertEq(usdtContract.balanceOf(address(user)), initialUserBalance - p2.margin - p2.openFee, "user balance");
    }

    function test_liquidatePositions_revert() public {
        vm.selectFork(liquidationForkId);
        vm.rollFork(169_811_776); // 2219 opened 169811777
        emit log_uint(block.timestamp);
        deployAndSet();

        PerpDexLib.OraclePrices memory priceData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.Pyth,
            feedHashes: new bytes32[](1),
            answers: new int256[](1),
            timestamps: new uint256[](1),
            proofs: new bytes[](1)
        });

        priceData.feedHashes[0] = 0xd69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e4;
        priceData.answers[0] = 2112;
        priceData.timestamps[0] = 1_731_824_326;
        priceData.proofs[0] =
            hex"504e41550100000003b801000000040d0093247920cccbeeb0b5e67b59174faaf34c9a859188f5d760402d5f93b4b0000c6e66553cfb8c74e8e82489c5ae66fc6834631fa2aa96dade1e3128cc4d24106900049523197b4e86a7b398e43240d4d63d0d054aa9a4eced357fcdcab89566298b6930093987a66839066c0ea8cd2cb897b7ed5984e439d35db61a34c0200013504c00066ee9d635df61ad56591a7ee5ca9409eadc6cf9e34b1e4c36f72b849ee7e8dc7869879b8738ef5ad3e5322b85133ed5cc28e080e09f26613978950269c373c8fe0008291003c98daf1ff6bf2e574aa4f38f56c70604507d3e17efe3fb5ce337d900840c3bf92be8026a269066a011e1d3a4b13d59063e21dccab62703394cb8073fff000a73740fd2a849e9c2c5476c92d9493db7e8ce2a4fef150b254a6440b74cc99fe521ff382acac3362c86b6939565b13efbdde972e30cde1b66fe8834155cfff650010b63127b3f668088f3d62ef12ab7ad29db90a2d03228a856a0a6e411c60b38a5326d399d0fd5b132aba6b2bdb59ee93a31183ee241efacdc047a38c7de6592617a010cdc3ac8b963f703f94d30c6f9064874478ba91a5c0821f6acad238ebb69bcea0a7ca8ba0c573bda90ddcaa8e292bc17cca7d670a2289ae908ec099703008821b4000d1a020882e251081a22db4a5f67135f923cd2d90dccb82e067016efbfb50e12ee3b8f197f682d3499757ddd78aaa9c723bab880ab8b0b53a8cd3ae54408976d0f000eab981b64ec5423372a1aa66c8435378f8364db7c73e54e34856ee2052e322ce16ffadd772cf5507de6cc61671e3b5d292433bcd8bff5bf186c75e6c4c3c6929b010f98b0c0bb722bffcc405fb48d784cc13a43b161c2cc503761b4d28d52cca40539315891d55114b6bdfbcd34d540465c9890c96de40af358215af0f36568f704ec011036470a692e5a79c8330684080694e30eefc7a7daffadb54889e5096721317fd722821c3bdcbc1e0aedb313d8722c1547ce4356c7d8f278cf41fb41072fb551d901113c4a383fae6e5e89f36821c422d570e3edb44216bc920c9c3724b42c34694c6a53191b13188234bd5ad7fd932fdce3bc5bc7e799f8d9311774e12dc0d1b254f700122e08d60563e976e09dbd87a4fb1a35da5e6755670162d2b39143ce630be837df0765d469133effcf971820f3e280c3758be16d1aa3c21ac264db01752a7e6b5a0067398ac600000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa710000000005972276014155575600000000000aa3ed180000271066b96404bfc251d47e0c0b2a3b2b95a7202e3f7301005500d69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e40000000000033954000000000000011dfffffff60000000067398ac60000000067398ac5000000000003362a000000000000013a0b508cef6da66a2c0458b079fef9ded0220363f1446238bb2049d763b9c56003c94a637ac30e1854aca82ed0aa3a0926ee214b0565de719075b8b52548e4ab22a0305f9e3a8bd2d65ab7ec615c7a6a42a89e2034532949ebd16103b28947449fd7f603074118cea06ee778c82b6580e0fa225c12343649f0435890c137220f17d91e57d6f813bcf2b642a1c595fe6ac60aaad9c03332957100004ddd15544a6c9950350903ebf1e5b73579beafc8ffb3ce7235192b5d2df4082c15ece1a44bc8618a36a8d1145d5c0aa23696a957346143530a2c0ee01053863f573d89";

        bytes memory userSignedData = getSignedMessage(
            userPk,
            abi.encodePacked(
                "Open position for Token: 5, Margin: 7598100, Leverage: 100, Long: 1, TP: 0, SL: 0, Price: 2112, Nonce: 0, Chain: 8217, Contract: ",
                Strings.toHexString(address(perpDex))
            )
        );

        vm.deal(singleOpenAdmin, 100_000);
        vm.startPrank(singleOpenAdmin);

        emit log_uint(1_731_824_326);
        emit log_uint(block.timestamp);

        perpDex.openPosition{value: pyth.getUpdateFee(priceData.proofs)}(
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

        vm.makePersistent(user);
        vm.makePersistent(address(perpDex));
        vm.makePersistent(address(lpContract));
        vm.makePersistent(address(usdtContract));

        vm.deal(liqAdmin, 100_000);
        vm.startPrank(liqAdmin);
        vm.roll(169_828_865);
        uint64[] memory roundIds = new uint64[](0);
        uint256[] memory candidates = new uint256[](1);
        candidates[0] = 0;
        priceData = getLiquidateValidPriceData();

        // switch priceData order
        priceData.feedHashes[5] = 0xdcef50dd0a4cd2dcc17e45df1676dcb336a11a61c69df7a0299b0150c672d25c;
        priceData.answers[5] = 36_155_638;
        priceData.feedHashes[4] = 0xd69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e4;
        priceData.answers[4] = 2092;
        uint256 feeAmount = pyth.getUpdateFee(priceData.proofs);
        vm.expectRevert("Feed hash is not correct (Pyth)");
        perpDex.liquidatePositions{value: feeAmount}(candidates, roundIds, priceData);

        priceData = getLiquidateValidPriceData();
        // mix priceData order - feedHash is ok
        priceData.answers[5] = 36_155_638;
        priceData.answers[4] = 2092;
        vm.expectRevert("Price is not correct (Pyth)");
        perpDex.liquidatePositions{value: feeAmount}(candidates, roundIds, priceData);
    }

    function getTpslValidPriceData() public pure returns (PerpDexLib.OraclePrices memory) {
        PerpDexLib.OraclePrices memory priceData = PerpDexLib.OraclePrices({
            oracleType: PerpDexLib.OracleType.Pyth,
            feedHashes: new bytes32[](13),
            answers: new int256[](13),
            timestamps: new uint256[](13),
            proofs: new bytes[](1)
        });
        priceData.proofs[0] =
            hex"504e41550100000003b801000000040d009334b31ddc3fc8319830ce4ac289513cbfa4ffa3b064b4af19ee24557a65d5c757f9dfa125d6a1b0267f4d32693f4fbc06a6d1cff067f527ba93c4d64f80104c0102784b5c74836f03f1be57196abb78c37234dd2ba8454b226abcab939f9be43dff5757c90a0586fad426aebab6e69e0f8dfab91693ff0c31fd2062261dda42709f000389eb31705261a2dbacb595b40c86172325c3a9636b92fa3c106db9955cad9cc52c13a52977556a0e82516a8319a9f2d7814130f40d84ca7fb56ed492e61193ff0004899c16e9edf148c924d5f8dea846e9cb89f1639fd7f4ae263aae8bf0978d0cd43be6ac72d6037d27ff18b69f7a1b226ec2e8a5b3f2ebb9ed07f8f3f60411c7860106bcc81d34bfaa680c964cd41fcad4b65cbc81be920b35618a3b7be5d5422597903ca6fd7d69dbfaed81ab7e33f0704903284035cf2eb74d5d91d2dd7a7c5dfc5d0008f80d8efd1f6faca2d9f9b927c65c19c1fd6b02df9c7c5a234f08f824c3c25242200c74bc1e962ed9fbbdeff59c56f105802ce0817a7e01f23f01a65590d0b61a000aafb40ef8013d50f366f3366ec0cf951e5fc4902813756b5897f8f277ffd470693a639656e8e40303f02bbd4e60fd66bed45fc295761f45e97c37ef63360f3f1a000b76983d4b5d5534b84fb0238c3f0cbb240481b13fb7cac7052a1c411caf1c08a30d8aeaa5885510b4c132e51099796b17aa02971d56286c21aa2420910f6ad522000ce69167e5e48464165737c665c330275286be5a0dbf4c1d7cf94f10e90b77d34618ff90b8f5c28e52cbba91f24b037239b2dfe791c959da58666583b03d12b093010d280c82cb95ec4621ef83d30fb48552c8763add10a453c635d97f0102e697fde63fe44cbe373107d923daff96f19473fb774bba208da3b4e4a69e3577da8e50be010e19577101c842e45f22d9ca747542d5f7534e59ba138d8dd50c8804da478803a302c2d944a45394280b691c580cd91dd53c96cdbef5901da9a498a7c88ee9da90010fd86fdc51a02255afc694a2279f6f305d670478627391bd1f8cc7adc524c6ac21055810df04d820b31a8a8396001db741074eba9ed5ed0c6b469ec93f24fe310b00119777ba2f56859550451492cc3e30af0137cabc155e2b517f9cabd390cd999ca12f3d23c8e23b9136d46208eb7f65afe9400d8a0ed4ab2a12837a77429eaf1fab0167715b9e00000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa710000000006243758014155575600000000000b311b0c0000271090e97588cb7e12ae0a6d27d477972a291436ef9f0d0055002a01deaec9e51a579277b34b122399984d0bbf57e2458a7e42fecd2829867a0d000000000559fc890000000000016b3efffffff80000000067715b9e0000000067715b9d00000000056039fa000000000001790e0b7db031c61d3a4cab4122ed0ea66a0b2c03117a3f31e6f5aee6226aa664e9dcd0237be1790e96d0da746f003066ba644df3da186f814e88f10de4915661fe5995c600592eaae4311736d5902da5969885be6291642abdf3cdbbe06145e23e5c3aff52dbf32bd1a0051f1c9631ef27bbd7583cd8064162756de8b992a92f6befcdd256e42219a5f0acfcf7cdd342c6e427fb006b8c53d7c5fd97ba57267c65406781ebe431281db7e7278dda1660414ac04861f8fd894a72742a959e2f7b9de1cdf7650fa894386819f7822625afde43a681c385cb05919050bacec1ff00550003ae4db29ed4ae33d323568895aa00337e658e348b37509f5372ae51f0af00d50000000035f2fcce0000000000154181fffffff80000000067715b9e0000000067715b9d0000000036122434000000000015f5d40ba2a18ddc14f40bd63e271ee7d9d0474a1ff9fdbd6bf614056c54fc0a6682eda067dd79562c6bd102835f5160b9f4fd58c377be7e9a49096d0d51953c291fbc64b528b10e4f822f16f5b8962dcb106c1d64a4ddb2ff423de49e4165c5a48c41d4db86f3d7ad78e11924748c2fde894b9bf68018ad72f039bc6b567d9609df9b1b06e57eb34ce1b00d7bdc5f8342c6e427fb006b8c53d7c5fd97ba57267c65406781ebe431281db7e7278dda1660414ac04861f8fd894a72742a959e2f7b9de1cdf7650fa894386819f7822625afde43a681c385cb05919050bacec1ff005500e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43000008979455ad400000000140d506e5fffffff80000000067715b9e0000000067715b9d0000089f451dc080000000015d44de240bd2034765eb3cb74fd004a1fb30f1800c87adaa14916f5cac1a1af34fcef02944db0ab4a02d2e7e40d8aa977d4941fe2b6a4773b7a89ee66c18211b1a4201ce4715f016ae2b0ba3462d8aed31c5717b00ff332633f72691cb310cf0aaaed65f63322b531991e5d35de97074749b3d671ea930e478675247ef726a4389cfbca2816f6090d7c7d6418db7be04a51fe101df9d8f16ec6963a22d5c9ce62a5b9c758ecdccfaf82a5a6cffe533f7d1035fe9ede8def10bc109ddec53a0ba0e73e010468dca7b0687fe8db9f7822625afde43a681c385cb05919050bacec1ff005500dcef50dd0a4cd2dcc17e45df1676dcb336a11a61c69df7a0299b0150c672d25c0000000001eb834a000000000000600cfffffff80000000067715b9e0000000067715b9d0000000001ef556f00000000000067140b050dbacfe1978934ca31e2cf8a2518785730129fcd86d2b8304d145fc95209a89b7851a8f4504138309786fddc295bb07f300c719b5a690086ce38e9271f9655df63924d22412901b1b7108dbbfaa0795f9003bb8fad212a622313da3ce4a6960bbf8d5adf94dbfa7e692ad2d30ad56e75fd953e342d84b9726a4389cfbca2816f6090d7c7d6418db7be04a51fe101df9d8f16ec6963a22d5c9ce62a5b9c758ecdccfaf82a5a6cffe533f7d1035fe9ede8def10bc109ddec53a0ba0e73e010468dca7b0687fe8db9f7822625afde43a681c385cb05919050bacec1ff005500ff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace0000004ead9c942b00000000128f5866fffffff80000000067715b9e0000000067715b9d0000004f00cdbe600000000012db6dfe0b316259a99da80df82a0763b747bfcd6872c783c42e396dad4d1a898a7c8a6ab5413d90dcfc898cd592e4b7f131a5fd612b7a22ab3a79bfe1ac371729f1bf5d8500ecda04185716c7fee0a265ca54b467adec47d3e9e7ec1516406e69906d940684323abf1c1f100dd9847b05650cdca77c951a04d7c3174cd7400d11de85e5fb0d47b9dd860a49a45a35d45b1fe101df9d8f16ec6963a22d5c9ce62a5b9c758ecdccfaf82a5a6cffe533f7d1035fe9ede8def10bc109ddec53a0ba0e73e010468dca7b0687fe8db9f7822625afde43a681c385cb05919050bacec1ff005500452d40e01473f95aa9930911b4392197b3551b37ac92a049e87487b654b4ebbe00000000013a13b6000000000000681afffffff80000000067715b9e0000000067715b9d00000000013afcfb000000000000797a0b6c9c58a06758eb3f792ccea02b3e5b38123125726191586ab1e29c0efe6d6723f4704feb7a814837cc859c9ff62925fefa01e2acd81f4e0556e7923abcfde467baefd4278a3bb7604287ecba2970ac25e101814c690372576833871cd95939999cc85b9ebe920f5fb59d8d22e2688184cdb4362814014e841f82ba4dc8b384d578879f691b755202fa3869691d0bdae71ae2d1ebab7d955ec251e4416c46a4b281ebe431281db7e7278dda1660414ac04861f8fd894a72742a959e2f7b9de1cdf7650fa894386819f7822625afde43a681c385cb05919050bacec1ff005500d69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e4000000000002cf800000000000000120fffffff60000000067715b9e0000000067715b9d000000000002d7f9000000000000011d0bcd6c13187a4fd19c6936eb9cd495c287bd0ead856398bd4e150e2a73f6a1e828d04cfaa8edb371d7fbb45223c86575857d43c6eb57735deca130e9432b0f53ee05f32532f783f49a81675bea86a5647c5f9003bb8fad212a622313da3ce4a6960bbf8d5adf94dbfa7e692ad2d30ad56e75fd953e342d84b9726a4389cfbca2816f6090d7c7d6418db7be04a51fe101df9d8f16ec6963a22d5c9ce62a5b9c758ecdccfaf82a5a6cffe533f7d1035fe9ede8def10bc109ddec53a0ba0e73e010468dca7b0687fe8db9f7822625afde43a681c385cb05919050bacec1ff00550053614f1cb0c031d4af66c04cb9c756234adad0e1cee85303795091499a4084eb0000000002821543000000000000b5f1fffffff80000000067715b9e0000000067715b9d0000000002844aaa000000000000d6670bc72eac616dedbfc2a430d1f42d6a096b749a6fa90dc83d713585294357bcf6850c6be3154c470ee693f0cceb61dccd974344447829bcf02ef8f3405d844c1b5d819142ee0093c5da26cde1f78fcfb4507352360a20453bee1cde0c1cf2675bc8d8d6830408550755921a375ad016f0f88c1f6ba501fad4b476ad13782131abc092c7883671b25031c9986f801d0bdae71ae2d1ebab7d955ec251e4416c46a4b281ebe431281db7e7278dda1660414ac04861f8fd894a72742a959e2f7b9de1cdf7650fa894386819f7822625afde43a681c385cb05919050bacec1ff005500f0d57deca57b3da2fe63a493f4c25925fdfd8edf834b20f93e1f84dbd1504d4a000000000003598d0000000000000115fffffff60000000067715b9e0000000067715b9d0000000000035e4f000000000000011c0ba0823ddfdb0a16004c4d816a03165f1fba20638857048f16f12f1d00f88f480b01ee3c9fb1ba26bc97fe9bdcb3d52f7adf22d4398651c85cd64a548b07cd364ec3c8bbc5f17542d2a71873b7ff99da4570444de700b725598fe0992e9fb993d00986e12d12114e5930f44b18c703f3d2e74b91f85fced734d7400d11de85e5fb0d47b9dd860a49a45a35d45b1fe101df9d8f16ec6963a22d5c9ce62a5b9c758ecdccfaf82a5a6cffe533f7d1035fe9ede8def10bc109ddec53a0ba0e73e010468dca7b0687fe8db9f7822625afde43a681c385cb05919050bacec1ff005500ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d00000004870884cf00000000011ac819fffffff80000000067715b9e0000000067715b9d000000048efdbff0000000000112d2b10b98830e04fe6f6a700760d327d6a6f834119c01e5b32d5cd6c1fa05bcf3008a21c307f358c9fa1d856026e2ee666c8dd365fc84bfa889c18ab39591a12186adc67e304c3749e8f119ccd0cddb94d8873a70444de700b725598fe0992e9fb993d00986e12d12114e5930f44b18c703f3d2e74b91f85fced734d7400d11de85e5fb0d47b9dd860a49a45a35d45b1fe101df9d8f16ec6963a22d5c9ce62a5b9c758ecdccfaf82a5a6cffe533f7d1035fe9ede8def10bc109ddec53a0ba0e73e010468dca7b0687fe8db9f7822625afde43a681c385cb05919050bacec1ff00550023d7315113f5b1d3ba7a83604c44b94d79f4fd69af77f804fc7f920a6dc657440000000018f3e4f40000000000067403fffffff80000000067715b9e0000000067715b9d000000001911617e000000000006b9d50b594964aa1a8323aadba63aa29c2743713f3a60288abb1baa6550dfafa0844ee2ed222de267c1f81e92bd7f06e0255e198458adccbebbcdd86af772b75494d356e34930b1d9c58aed69454c8fedc4be2eb321744add91ab3962112815aebe2ddd622ed9a0068b35ae20e87ba50b5d8ecd473f67ae41e2a980e8b992a92f6befcdd256e42219a5f0acfcf7cdd342c6e427fb006b8c53d7c5fd97ba57267c65406781ebe431281db7e7278dda1660414ac04861f8fd894a72742a959e2f7b9de1cdf7650fa894386819f7822625afde43a681c385cb05919050bacec1ff005500f63f008474fad630207a1cfa49207d59bca2593ea64fc0a6da9bf3337485791c0000000004c2f1ea000000000004c260fffffff80000000067715b9e0000000067715b9d0000000004c6cdf600000000000415800b3a9fc9467fcafb958a6b68e354a2618ce5dc8243b78222101afcc038f4633fe63122b9be0787bed25c8f1d858a97b7f7c54a077f83dca79f321e704252b4237778193217ffc2471b801e4ba38876114870044513259de261d79a050723d625a085d99efa12114e5930f44b18c703f3d2e74b91f85fced734d7400d11de85e5fb0d47b9dd860a49a45a35d45b1fe101df9d8f16ec6963a22d5c9ce62a5b9c758ecdccfaf82a5a6cffe533f7d1035fe9ede8def10bc109ddec53a0ba0e73e010468dca7b0687fe8db9f7822625afde43a681c385cb05919050bacec1ff005500ec5d399846a9209f3fe5881d70aae9268c94339ff9817e8d18ff19fa05eea1c8000000000ce6bcc30000000000035775fffffff80000000067715b9e0000000067715b9d000000000cf3e2c400000000000389980b02531655b751b2dd32257100b8fa62d7a1b045422a87f5c49745ddb2dcf1b81c9a24a0968bc3d87fdd907adace347bddfbe455805e1ed86926e7cf64db788b3730e5b5ac0b19328d31b4be4fe092593fff332633f72691cb310cf0aaaed65f63322b531991e5d35de97074749b3d671ea930e478675247ef726a4389cfbca2816f6090d7c7d6418db7be04a51fe101df9d8f16ec6963a22d5c9ce62a5b9c758ecdccfaf82a5a6cffe533f7d1035fe9ede8def10bc109ddec53a0ba0e73e010468dca7b0687fe8db9f7822625afde43a681c385cb05919050bacec1ff";

        priceData.feedHashes[0] = 0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43;
        priceData.answers[0] = 9_447_121_726_784;
        priceData.timestamps[0] = 1_735_482_270;

        priceData.feedHashes[1] = 0x452d40e01473f95aa9930911b4392197b3551b37ac92a049e87487b654b4ebbe;
        priceData.answers[1] = 20_583_350;
        priceData.timestamps[1] = 1_735_482_270;

        priceData.feedHashes[2] = 0xf63f008474fad630207a1cfa49207d59bca2593ea64fc0a6da9bf3337485791c;
        priceData.answers[2] = 79_884_778;
        priceData.timestamps[2] = 1_735_482_270;

        priceData.feedHashes[3] = 0xff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace;
        priceData.answers[3] = 337_920_169_003;
        priceData.timestamps[3] = 1_735_482_270;

        priceData.feedHashes[4] = 0xdcef50dd0a4cd2dcc17e45df1676dcb336a11a61c69df7a0299b0150c672d25c;
        priceData.answers[4] = 32_211_786;
        priceData.timestamps[4] = 1_735_482_270;

        priceData.feedHashes[5] = 0xd69731a2e74ac1ce884fc3890f7ee324b6deb66147055249568869ed700882e4;
        priceData.answers[5] = 1841;
        priceData.timestamps[5] = 1_735_482_270;

        priceData.feedHashes[6] = 0xef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d;
        priceData.answers[6] = 19_445_351_631;
        priceData.timestamps[6] = 1_735_482_270;

        priceData.feedHashes[7] = 0xec5d399846a9209f3fe5881d70aae9268c94339ff9817e8d18ff19fa05eea1c8;
        priceData.answers[7] = 216_448_195;
        priceData.timestamps[7] = 1_735_482_270;

        priceData.feedHashes[8] = 0x03ae4db29ed4ae33d323568895aa00337e658e348b37509f5372ae51f0af00d5;
        priceData.answers[8] = 905_116_878;
        priceData.timestamps[8] = 1_735_482_270;

        priceData.feedHashes[9] = 0x23d7315113f5b1d3ba7a83604c44b94d79f4fd69af77f804fc7f920a6dc65744;
        priceData.answers[9] = 418_637_044;
        priceData.timestamps[9] = 1_735_482_270;

        priceData.feedHashes[10] = 0xf0d57deca57b3da2fe63a493f4c25925fdfd8edf834b20f93e1f84dbd1504d4a;
        priceData.answers[10] = 2195;
        priceData.timestamps[10] = 1_735_482_270;

        priceData.feedHashes[11] = 0x53614f1cb0c031d4af66c04cb9c756234adad0e1cee85303795091499a4084eb;
        priceData.answers[11] = 42_079_555;
        priceData.timestamps[11] = 1_735_482_270;

        priceData.feedHashes[12] = 0x2a01deaec9e51a579277b34b122399984d0bbf57e2458a7e42fecd2829867a0d;
        priceData.answers[12] = 89_783_433;
        priceData.timestamps[12] = 1_735_482_270;

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
            oracleType: PerpDexLib.OracleType.Pyth,
            feedHashes: new bytes32[](1),
            answers: new int256[](1),
            timestamps: new uint256[](1),
            proofs: new bytes[](1)
        });

        priceData.feedHashes[0] = 0xe62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43;
        priceData.answers[0] = 9_498_508_556_249;
        priceData.timestamps[0] = 1_735_454_339;
        priceData.proofs[0] =
            hex"504e41550100000003b801000000040d0025c17447487ccc5ea63cf22ad93dd3157b232eed8bc3b8c96908b51e4f86afd6271fb981ee650fc932eb37aa85e4a9c08accf0864701137ac68713a95e7b72300002b0e7aa05bccc9dd25a97c5c49fe434f74ad79939fbb39662839391fd694ff9b629b95d2a3e5a780e7cea43544d06dc652d9f787d5f2c99a4d2d67761bc56ced500039bfe996a4479d787e821621d2fad786cc39b04b49839fe153533a612f4f21025441d0dababb5a9d6d55823070128398d6a72b12c791e56f06fd4c4a3fd4aec2b01042245d5bbb190c701508677d37489fa632a580c711ffea81a3c579e3cec581482114432b6c8db21d42022163113e2aca6ef624ab2c6837dec309d2aa11c161e9d000622850a3877cab53dbb616cf59cfc7d3acfc1ccfe6f5c39e59c66364f4a218b56640eea1e067b363032b4991c640f919e55c5aff90e81535c7bb2cd19ed9eee1f000a3c6aeda15c4698a71ae0ef90b9a5990cc51e9a83c3394f4cbde7d98b1e35a50a047c7ff27f807e5c6e438a35bf563b9eb6d3596da2058ccd4ca0db1929e6e4b4010b91c7b0cbbf54002e7556b31ec2286c5c5fc4f7e780514c4860258793ebc4560621d642bcc01101459bbecad99c17150deecd9153c838f75fdb70c91639db2756010ce59a7f35c7461d5a151bf68efcfd9cab68140cb94c9625db0bf5b3a87f1a4be35855d5a037afff988406ea94b080aa7275afa74093a883680e97b1b906478a75010dd2381cf49799c3e58c3a3122136227dbcda500d7a3fffadf2406f5a09733ad557bc94edda29564553a85b9735253c35c8ba7c46244f754fa00c537dc2750a3f1010e88bad27731936224528f4414e67811daa41cce4029fa6a683af405d756f9a3486828b28a35ef299ae7f41cd112fd442927d8038c2efc4b849b1962afc0e13b66010f185a0223a92b195f4518d935480844e27adf86cba162d1cfb2e2698d066c95d644c39cfd07c4bdb029e4bf08c9ab72bfc84b201cf8bbe226bb0b5aaddc2aa7640110f6511c9a571f79242db9462ff11332440a86e3aa6945661feb0ec2d2d543ce763b1c6f9ae4266108ac86505e732ba24ca5a4bf7c61bba006bbf54943f609df6900112bf1af6ca57db908df6d80d5784a263bf08e6cfad48cd0847ae164ba95976ba375e542de94ac8ae427ed5abd9f0577ac49cd361e6a7f44116c443c34a1e5452a006770ee8300000000001ae101faedac5851e32b9b23b5f9411a8c2bac4aae3ed4dd7b811dd1a72ea4aa7100000000062322d2014155575600000000000b300680000027109ff417ff349b4059727a7011ba6c9fcc9d6ce95c01005500e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43000008a38b3a77d900000001d9d77649fffffff8000000006770ee83000000006770ee82000008a26abd122000000001742bd0fc0b08ee5ce97f1e7167aa25a0fc955a78a450d4d50a800249630c4d4aaad0bf9c44405aed9d9a1aee489dab701ddcc9c881df0f63e9a424079fb4af5acd3b9f5d4ce7f575270815f73053f3502b6d78d765903d24d6115f6fb12c4fe01b915a8038ace8f7c976595c6d4037e3f1ce99be07277505f750d3303abc4bed8d6212d50741301dd75241cf282002a3701911a847b3fd5003287d950dfc538270288dabe82b3c20a82d8fca705f0042677cb3c4c9ce81c5d8da4863b5d5f072365835fcf43d7fef5145f68cf0e2eb01dd2ba40b6b03a5f574257e3aae39551d9c";

        bytes memory userSignedData = getSignedMessage(
            userPk,
            abi.encodePacked(
                "Open position for Token: 0, Margin: 1000000000, Leverage: 35, Long: 1, TP: 0, SL: 9460000000000, Price: 9498508556249, Nonce: 0, Chain: 8217, Contract: ",
                Strings.toHexString(address(perpDex))
            )
        );

        vm.deal(singleOpenAdmin, 100_000);
        vm.startPrank(singleOpenAdmin);

        perpDex.openPosition{value: pyth.getUpdateFee(priceData.proofs)}(
            PerpDexLib.OpenPositionData({
                tokenType: PerpDexLib.TokenType.Btc,
                marginAmount: 1_000_000_000,
                leverage: 35,
                long: true,
                trader: user,
                priceData: priceData,
                tpPrice: 0,
                slPrice: 9_460_000_000_000,
                expectedPrice: 9_498_508_556_249,
                userSignedData: userSignedData
            })
        );
        vm.stopPrank();
        PerpDexLib.Position memory p = perpDex.getPosition(1);
        assertEq(p.initialPrice, 9_498_508_556_249);
        assertEq(p.slPrice, 9_460_000_000_000);

        vm.makePersistent(user);
        vm.makePersistent(address(perpDex));
        vm.makePersistent(address(lpContract));
        vm.makePersistent(address(usdtContract));

        vm.deal(tpslAdmin, 100_000);
        vm.startPrank(tpslAdmin);
        vm.roll(173_465_574);
        vm.warp(block.timestamp + 173_465_574 - 173_437_647);
        uint256 time2 = block.timestamp;
        uint64[] memory roundIds = new uint64[](0);
        uint256[] memory candidates = new uint256[](1);
        candidates[0] = 1;
        priceData = getTpslValidPriceData();
        emit log_array(priceData.answers);
        emit log_array(priceData.timestamps);
        perpDex.tpslClosePositions{value: pyth.getUpdateFee(priceData.proofs)}(candidates, roundIds, priceData);

        PerpDexLib.Position memory p2 = perpDex.getPosition(1);
        assertEq(uint256(p2.positionStatus), uint256(PerpDexLib.PositionStatus.Closed));
        assertEq(p2.finalPrice, 9_447_121_726_784);

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
