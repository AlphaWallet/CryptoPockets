package tapi.api;

import io.reactivex.Single;
import io.reactivex.schedulers.Schedulers;
import okhttp3.OkHttpClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.*;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.*;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpString;
import org.web3j.rlp.RlpType;
import org.web3j.utils.Bytes;
import org.web3j.utils.Numeric;

import java.io.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.SignatureException;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.web3j.protocol.core.methods.request.Transaction.createEthCallTransaction;

@Controller
@RequestMapping("/")
public class APIController
{
    private static final String CONTRACT = "0xeAC4F618232B5cA1C895B6e5468363fdd128E873";
    private static final String ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
    private static final String deploymentAddress = "http://"; //<-- points to where this server sits eg http://cryptopockets.com:8080/
    private static final String DAI_CONTRACT = "0x792A5dF74641bE309146F4D5cF99D61dd78bAF08";
    private static final BigDecimal DAI_WEI_FACTOR = BigDecimal.valueOf(1000000000000000000L);

    private final List<String> hashClaims = new ArrayList<>();

    private static final long CHAIN_ID = 42; //KOVAN
    private static final String CHAIN_NAME = "Kovan";
    private static final BigDecimal GWEI_FACTOR = BigDecimal.valueOf(1000000000L);
    private static final BigDecimal WEI_FACTOR = BigDecimal.valueOf(1000000000000000000L);

    private static final BigInteger GAS_LIMIT_CONTRACT = new BigInteger("432000"); //
    private static final BigInteger POCKET_CLAIM_COST = new BigInteger("35000");  //claim cost is actually 32,058
    private static final BigInteger POCKET_CLAIM_LIMIT = new BigInteger("100000");  //claim cost is actually 32,058
    private static final BigInteger GAS_LIMIT_CREATE = new BigInteger("125000");   //gas for pocket create

    private final String CONTRACT_KEY;
    private final String INFURA_KEY;

    @Autowired
    public APIController()
    {
        String keys = load("./keys.secret");
        String[] sep = keys.split(",");
        INFURA_KEY = sep[0];
        CONTRACT_KEY = sep[1];
    }

    private String getPocketHashCalc(BigInteger nonce, BigInteger pocketValue, BigInteger gasExitPrice) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Address contractAddr = new Address(CONTRACT);
        try
        {
            baos.write(Numeric.toBytesPadded(nonce, 32));
            baos.write(Numeric.toBytesPadded(pocketValue, 32));
            baos.write(Numeric.toBytesPadded(gasExitPrice, 32));
            baos.write(Numeric.toBytesPadded(BigInteger.valueOf(CHAIN_ID), 32));
            baos.write(Numeric.toBytesPadded(contractAddr.toUint().getValue(), 20));
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        String hashOut = Numeric.toHexString(Hash.sha3(baos.toByteArray()));
        return hashOut;
    }

    public Single<String> createTransaction(ECKeyPair key, String toAddress, BigInteger value,
                                            BigInteger gasPrice, BigInteger gasLimit, byte[] data, long chainId)
    {
        final Web3j web3j = getWeb3j();

        return getLastTransactionNonce(web3j, "0x" + Keys.getAddress(key.getPublicKey()))
                .flatMap(nonce -> {
                    return signTransaction(key, toAddress, value, gasPrice, gasLimit, nonce.longValue(), data, chainId);
                })
                .map(signedTransactionBytes -> {
                    EthSendTransaction raw = web3j
                            .ethSendRawTransaction(Numeric.toHexString(signedTransactionBytes))
                            .send();

                    if (raw.hasError())
                    {
                        throw new Exception(raw.getError().getMessage());
                    }
                    return raw.getTransactionHash().toString();
                });
    }

    public Single<BigInteger> getLastTransactionNonce(Web3j web3j, String walletAddress)
    {
        return Single.fromCallable(() -> {
            try
            {
                EthGetTransactionCount ethGetTransactionCount = web3j
                        .ethGetTransactionCount(walletAddress, DefaultBlockParameterName.PENDING)
                        .send();
                return ethGetTransactionCount.getTransactionCount();
            }
            catch (Exception e)
            {
                return BigInteger.ZERO;
            }
        });
    }

    private BigDecimal getGasPriceGWEI()
    {
        BigInteger gasPrice = BigInteger.valueOf(2000000000L);
        try {
            gasPrice = getWeb3j().ethGasPrice().send().getGasPrice();
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return new BigDecimal(gasPrice).divide(GWEI_FACTOR).setScale(1, RoundingMode.DOWN);
    }

    private BigDecimal parseBigDecimal(String s)
    {
        BigDecimal val = BigDecimal.ZERO;

        try {
            val = new BigDecimal(s);
        } catch (Exception e) {
            //
        }

        return val;
    }

    @GetMapping(value = "/")
    public String handleCreateAddress(@RequestHeader("User-Agent") String agent, Model model)
    {
        //determine current gas price
        // TODO: maintain background thread which keeps the current gas value to minimise user wait
        BigDecimal gasPrice = getGasPriceGWEI();
        gasPrice = gasPrice.multiply(BigDecimal.valueOf(1.2)); //increase by 20%
        model.addAttribute("gas_price", gasPrice.toString());

        return "createpocket";
    }

    @GetMapping(value = "/initTokenUSDC/{dai}/{gas}/{addr}")
    public String handleCreatePocketUSDC(@PathVariable("dai") String daiValue,
                                     @PathVariable("gas") String gasPrice,
                                     @PathVariable("addr") String userAddr,
                                     Model model)
    {
        BigDecimal daiVal = parseBigDecimal(daiValue);
        BigDecimal gasPriceVal = parseBigDecimal(gasPrice);
        BigDecimal currentGasPrice = getGasPriceGWEI();

        if (gasPriceVal.equals(BigDecimal.ZERO))
        {
            gasPriceVal = currentGasPrice.multiply(BigDecimal.valueOf(1.2)); //increase by 20%
        }

        if (daiVal.equals(BigDecimal.ZERO) && daiVal.equals(BigDecimal.ZERO))
        {
            return "Must enter amount for gift.";
        }
        else
        {
            //byte[] adminPrivKey = Numeric.hexStringToByteArray(CONTRACT_KEY1);
            ECKeyPair adminKey = getAdminKeyPair();// ECKeyPair.create(adminPrivKey);
            String adminAddress = "0x" + Keys.getAddress(adminKey.getPublicKey());

            //calculate transaction values
            daiVal = daiVal.multiply(WEI_FACTOR);
            gasPriceVal = gasPriceVal.multiply(GWEI_FACTOR);

            //get the current approval amount for this account
            Function allowance = getCurrentAllowance(userAddr, CONTRACT);//  DAI_CONTRACT);
            BigInteger allowanceVal = callFunction(allowance, DAI_CONTRACT, ZERO_ADDRESS);

            BigInteger newAllowance = allowanceVal.add(daiVal.toBigInteger());

            //first transaction is for allowance for contract to spend the token
            //second transaction is the function itself

            //form push transaction
            Function getAllowance = approve(CONTRACT, newAllowance);
            String encodedFunction = FunctionEncoder.encode(getAllowance);
            byte[] functionCode = Numeric.hexStringToByteArray(Numeric.cleanHexPrefix(encodedFunction));

            //Now ask user to push the transaction
            model.addAttribute("tx_bytes", "'" + Numeric.toHexString(functionCode) + "'");
            model.addAttribute("contract_address", "'" + DAI_CONTRACT + "'");
            model.addAttribute("gas_price", currentGasPrice.multiply(GWEI_FACTOR).toBigInteger().toString());
            model.addAttribute("gas_limit", GAS_LIMIT_CREATE.toString());
            model.addAttribute("dai_value", daiValue);
            model.addAttribute("gas_price_pocket", gasPriceVal.toString());
            model.addAttribute("expected_id", CHAIN_ID);
            model.addAttribute("expected_text", "'" + CHAIN_NAME + "'");

            return "pushApprove";
        }
    }

    @GetMapping(value = "/createCoinFinal/{txHash}/{contractAddr}/{daiValue}/{currentGasPrice}/{pocketGasPrice}")
    public String createCoinFinal(@PathVariable("txHash") String txHash,
                                  @PathVariable("contractAddr") String contractAddr,
                                  @PathVariable("daiValue") String daiValue,
                                  @PathVariable("currentGasPrice") String currentGasPrice,
                                  @PathVariable("pocketGasPrice") String pocketGasPrice,
                                  Model model)
    {
        //Now push the final exchange transaction
        //calculate transaction values
        BigInteger pocketClaimGasPrice = new BigInteger(pocketGasPrice); //in GWEI
        BigInteger ethVal = pocketClaimGasPrice.multiply(POCKET_CLAIM_LIMIT);// ethVal.multiply(WEI_FACTOR);
        BigInteger daiVal = new BigDecimal(daiValue).multiply(DAI_WEI_FACTOR).toBigInteger();
        //create transaction params:

        Function function = getCurrentNonce();
        BigInteger nonce = callFunction(function, CONTRACT, ZERO_ADDRESS);

        ECKeyPair keys = getAdminKeyPair();

        String pocketHash = getPocketHashCalc(nonce, daiVal, pocketClaimGasPrice);
        System.out.println("Pocket Hash: " + pocketHash);

        String sigHash = getSignedPocket(Numeric.hexStringToByteArray(pocketHash), keys);
        System.out.println("Pocket hashsig: " + sigHash);

        //form push transaction
        Function pocket = createPocketCoin(daiVal, pocketClaimGasPrice, DAI_CONTRACT);

        //push Tx
        String encodedFunction = FunctionEncoder.encode(pocket);
        byte[] functionCode = Numeric.hexStringToByteArray(Numeric.cleanHexPrefix(encodedFunction));
        //currentGasPrice

        //Now ask user to push the transaction
        model.addAttribute("tx_bytes", "'" + Numeric.toHexString(functionCode) + "'");
        model.addAttribute("pocket_code", "'" + sigHash + "'");
        model.addAttribute("value", ethVal.toString());
        model.addAttribute("gas_price", currentGasPrice);
        model.addAttribute("gas_limit", GAS_LIMIT_CONTRACT.toString());
        model.addAttribute("contract_addr", "'" + CONTRACT + "'");
        model.addAttribute("expected_id", CHAIN_ID);
        model.addAttribute("expected_text", "'" + CHAIN_NAME + "'");

        return "pushTx";
    }

    @GetMapping(value = "/initToken/{eth}/{gas}/{addr}")
    public String handleCreatePocket(@PathVariable("eth") String ethValue,
                                     @PathVariable("gas") String gasPrice,
                                     @PathVariable("addr") String userAddr,
                                     Model model)
    {
        BigDecimal ethVal = parseBigDecimal(ethValue);
        BigDecimal gasPriceVal = parseBigDecimal(gasPrice);
        BigDecimal currentGasPrice = getGasPriceGWEI();

        if (gasPriceVal.equals(BigDecimal.ZERO))
        {
            gasPriceVal = currentGasPrice.multiply(BigDecimal.valueOf(1.2)); //increase by 20%
        }

        if (ethVal.equals(BigDecimal.ZERO))
        {
            return "Must enter amount for gift.";
        }
        else
        {
            //calculate transaction values
            ethVal = ethVal.multiply(WEI_FACTOR);
            gasPriceVal = gasPriceVal.multiply(GWEI_FACTOR);
            //create transaction params:

            Function function = getCurrentNonce();
            BigInteger nonce = callFunction(function, CONTRACT, ZERO_ADDRESS);

            ECKeyPair keys = getAdminKeyPair();

            String pocketHash = getPocketHashCalc(nonce, ethVal.toBigInteger(), gasPriceVal.toBigInteger());
            System.out.println("Pocket Hash: " + pocketHash);

            String sigHash = getSignedPocket(Numeric.hexStringToByteArray(pocketHash), keys);
            System.out.println("Pocket hashsig: " + sigHash);

            //form push transaction
            Function pocket = createPocket(ethVal.toBigInteger(), gasPriceVal.toBigInteger());

            //calculate attached value
            BigInteger value = ethVal.add(gasPriceVal.multiply(new BigDecimal(POCKET_CLAIM_COST))).toBigInteger();

            //push Tx
            String encodedFunction = FunctionEncoder.encode(pocket);
            byte[] functionCode = Numeric.hexStringToByteArray(Numeric.cleanHexPrefix(encodedFunction));
            //currentGasPrice

            //Now ask user to push the transaction
            model.addAttribute("tx_bytes", "'" + Numeric.toHexString(functionCode) + "'");
            model.addAttribute("pocket_code", "'" + sigHash + "'");
            model.addAttribute("value", value.toString());
            model.addAttribute("gas_price", currentGasPrice.multiply(GWEI_FACTOR).toBigInteger().toString());
            model.addAttribute("gas_limit", GAS_LIMIT_CREATE.toString());
            model.addAttribute("contract_addr", "'" + CONTRACT + "'");
            model.addAttribute("expected_id", CHAIN_ID);
            model.addAttribute("expected_text", "'" + CHAIN_NAME + "'");

            return "pushTx";
        }
    }

    @GetMapping(value = "/claim/{claimhash}")
    public String claimPocketWeb(@PathVariable("claimhash") String code,
                              Model model)
    {
        model.addAttribute("code", "'" + code + "'");
        return "claimTx";
    }

    @GetMapping(value = "/createFinal/{txHash}/{pocketCode}")
    public String createFinal(@PathVariable("txHash") String txHash,
                              @PathVariable("pocketCode") String pocketCode,
                                 Model model)
    {
        model.addAttribute("pocketUrl", "'" + deploymentAddress + "claim/" + pocketCode + "'");
        model.addAttribute("txHash", "'" + txHash + "'");
        return "pocketCreated";
    }

    @GetMapping(value = "/errorFinal/{error}")
    public String createError(@PathVariable("error") String errorCode,
                              Model model)
    {
        model.addAttribute("code", "'" + errorCode + "'");
        return "Error: " + errorCode;
    }

    @GetMapping(value = "/claimFinal/{claimhash}/{address}")
    public String claimFinal(@PathVariable("claimhash") String code,
                             @PathVariable("address") String address,
                                 Model model) throws SignatureException
    {
        //byte[] adminPrivKey = Numeric.hexStringToByteArray(CONTRACT_KEY);
        ECKeyPair adminKey = getAdminKeyPair(); //ECKeyPair.create(adminPrivKey);
        String adminAddress = "0x" + Keys.getAddress(adminKey.getPublicKey());

        if (hashClaims.contains(code))
        {
            return "Handling";
        }

        hashClaims.add(code);

        byte[] data = Numeric.hexStringToByteArray(code);

        if (code.length() < 97)
        {
            removeEntry(code);
            return "Error";
        }

        byte[] hash = Arrays.copyOfRange(data, 0, 32);
        byte[] sig = Arrays.copyOfRange(data, 32, 97);

        //verify
        Sign.SignatureData sigData = CryptoFunctions.sigFromByteArray(sig);
        BigInteger pubKey = Sign.signedMessageHashToKey(hash, sigData);

        if (!pubKey.equals(adminKey.getPublicKey()))
        {
            removeEntry(code);
            return "Error";
        }

        //now check if this is a valid packet to claim
        Function function = getGasToUse(Numeric.toHexString(hash));
        BigInteger gasToUse = callFunction(function, CONTRACT, adminAddress);

        if (gasToUse.equals(BigInteger.ZERO))
        {
            removeEntry(code);
            return "Invalid code";
        }

        //first determine the secret hash for this pocket
        Function claim = claimPocket(data, address);
        //push Tx
        String encodedFunction = FunctionEncoder.encode(claim);
        byte[] functionCode = Numeric.hexStringToByteArray(Numeric.cleanHexPrefix(encodedFunction));
        BigDecimal gasPrice = getGasPriceGWEI(); //TODO: Use price from background thread
        final BigInteger useGasPrice = gasPrice.multiply(GWEI_FACTOR).toBigInteger().min(gasToUse); //use minimum of either current price or the gas that the creator paid for

        String txHashStr = createTransaction(adminKey, CONTRACT, BigInteger.ZERO, useGasPrice, GAS_LIMIT_CONTRACT, functionCode, CHAIN_ID)
                .blockingGet();

        model.addAttribute("txHash", txHashStr);
        if (txHashStr != null && txHashStr.length() > 30) {
            return "claimed";
        }
        else
        {
            return "ERROR"; //TODO: show real error
        }
    }

    private void removeEntry(String code)
    {
        int i = 0;
        for (String thisCode : hashClaims)
        {
            if (thisCode.equalsIgnoreCase(code))
            {
                hashClaims.remove(i);
                break;
            }
            i++;
        }
    }

    @GetMapping(value = "/claim")
    public String claimPocket(Model model)
    {
        return "claimTxPage";
    }

    public static String getAddress(ECKeyPair keyPair)
    {
        BigInteger pubKeyBI = keyPair.getPublicKey();
        //now get the address
        String addr = Keys.getAddress(pubKeyBI);
        return addr;
    }

    private OkHttpClient buildClient()
    {
        return new OkHttpClient.Builder()
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .writeTimeout(5, TimeUnit.SECONDS)
                .retryOnConnectionFailure(false)
                .build();
    }

    private Web3j getWeb3j()
    {
        //Infura
        String chain = "";
        switch ((int)CHAIN_ID) {
            default:
            case 1:
                break;
            case 4:
                chain = "rinkeby.";
                break;
            case 42:
                chain = "kovan.";
                break;
        }

        HttpService nodeService = new HttpService("https://" + chain + "infura.io/v3/" + INFURA_KEY,  buildClient(), false);
        return Web3j.build(nodeService);
    }

    private static Function checkEncoding(byte[] encoding) {
        return new Function(
                "getCurrentNonce",
                Collections.singletonList(new DynamicBytes(encoding)),
                Collections.singletonList(new TypeReference<Bool>() {}));
    }

    private static Function getCurrentNonce() {
        return new Function("getCurrentNonce",
                Arrays.<Type>asList(),
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() {}));
    }

    private static Function getCurrentAllowance(String tokenOwner, String spender)
    {
        return new Function("allowance",
                Arrays.asList(new Address(tokenOwner), new Address(spender)),
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() {}));
    }

    private static Function approve(String adminAddress, BigInteger newAllowance)
    {
        return new Function("approve",
                Arrays.asList(new Address(adminAddress), new Uint256(newAllowance)),
                Arrays.<TypeReference<?>>asList(new TypeReference<Bool>() {}));
    }

    private static Function getHashNonce(String hashCode) {
        return new Function("getNonce",
                Arrays.asList(new Bytes32(Numeric.hexStringToByteArray(hashCode))),
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() {}));
    }

    private static Function getGasToUse(String hashCode) {
        return new Function("getSendGas",
                Arrays.asList(new Bytes32(Numeric.hexStringToByteArray(hashCode))),
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() {}));
    }

    private static Function getValue(String hash) {
        return new Function("getValue",
                Arrays.asList(new Bytes32(Numeric.hexStringToByteArray(hash))),
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() {}));
    }

    private static Function verifyEncoding(byte[] com1, byte[] com2, byte[] encoding) {
        return new Function(
                "verifyEqualityProof",
                Arrays.asList(new DynamicBytes(com1), new DynamicBytes(com2), new DynamicBytes(encoding)),
                Collections.singletonList(new TypeReference<Bool>() {}));
    }

    private static Function createPocket(BigInteger value, BigInteger useGasFee) {
        return new Function(
                "createPocketEth",
                Arrays.asList(new Uint256(value), new Uint256(useGasFee)),
                Collections.singletonList(new TypeReference<Utf8String>() {}));
    }

    private static Function claimPocket(byte[] hash, String destAddr) {
        return new Function(
                "claimPocket",
                Arrays.asList(new DynamicBytes(hash), new Address(destAddr)),
                Collections.singletonList(new TypeReference<Utf8String>() {}));
    }

    private static Function createPocketCoin(BigInteger daiVal, BigInteger pocketClaimGasPrice, String daiContract)
    {
        return new Function(
                "createPocketCoin",
                Arrays.asList(new Uint256(daiVal), new Uint256(pocketClaimGasPrice), new Address(daiContract)),
                Collections.singletonList(new TypeReference<Utf8String>() {}));
    }

    private static Function getPocketHash(BigInteger nonce, BigInteger value, BigInteger useGasFee) {
        return new Function(
                "getPocketHash",
                Arrays.asList(new Uint256(nonce), new Uint256(value), new Uint256(useGasFee)),
                Collections.singletonList(new TypeReference<Utf8String>() {}));
    }

    private static Function claimPocket2(byte[] hash, String destAddr) {
        return new Function(
                "claimPocket2",
                Arrays.asList(new DynamicBytes(hash), new Address(destAddr)),
                Arrays.asList(new TypeReference<Bytes32>() {}, new TypeReference<Address>() {}, new TypeReference<Uint256>() {}));
    }

    private BigInteger callFunction(Function function, String contractAddress, String fromAddress)
    {
        Web3j web3j = getWeb3j();

        BigInteger result = BigInteger.ZERO;

        try
        {
            String responseValue = callSmartContractFunction(web3j, function, contractAddress, fromAddress);
            List<Type> responseValues = FunctionReturnDecoder.decode(responseValue, function.getOutputParameters());

            if (!responseValues.isEmpty())
            {
                result = (BigInteger)responseValues.get(0).getValue();
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return result;
    }

    private void callFunctionStuff(Function function, String fromAddress)
    {
        Web3j web3j = getWeb3j();

        try
        {
            String responseValue = callSmartContractFunction(web3j, function, CONTRACT, fromAddress);
            List<Type> responseValues = FunctionReturnDecoder.decode(responseValue, function.getOutputParameters());

            System.out.println("Hash: " + responseValues.get(0).getValue().toString() );
            System.out.println("signer: " + responseValues.get(1).toString() );
            System.out.println("Nonce: " + responseValues.get(2).getValue().toString() );
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    private String callFunctionString(Function function)
    {
        Web3j web3j = getWeb3j();

        String result = "";

        try
        {
            result = callSmartContractFunction(web3j, function, CONTRACT, ZERO_ADDRESS);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return result;
    }

    private String callSmartContractFunction(Web3j web3j,
                                             Function function, String contractAddress, String fromAddress)
    {
        String encodedFunction = FunctionEncoder.encode(function);

        try
        {
            org.web3j.protocol.core.methods.request.Transaction transaction
                    = createEthCallTransaction(fromAddress, contractAddress, encodedFunction);
            EthCall response = web3j.ethCall(transaction, DefaultBlockParameterName.LATEST).send();

            return response.getValue();
        }
        catch (IOException e)
        {
            return null;
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }

    private String getSignedPocket(byte[] hash, ECKeyPair key)
    {
        Sign.SignatureData signatureData = Sign.signMessage(
                hash, key, false);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try
        {
            baos.write(hash);
            baos.write(bytesFromSignature(signatureData));
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        return Numeric.toHexString(baos.toByteArray());
    }

    public static byte[] bytesFromSignature(Sign.SignatureData signature)
    {
        byte[] sigBytes = new byte[65];
        Arrays.fill(sigBytes, (byte) 0);

        try
        {
            System.arraycopy(signature.getR(), 0, sigBytes, 0, 32);
            System.arraycopy(signature.getS(), 0, sigBytes, 32, 32);
            System.arraycopy(signature.getV(), 0, sigBytes, 64, 1);
        }
        catch (IndexOutOfBoundsException e)
        {
            e.printStackTrace();
        }

        return sigBytes;
    }

    private static byte[] encode(RawTransaction rawTransaction, Sign.SignatureData signatureData) {
        List<RlpType> values = asRlpValues(rawTransaction, signatureData);
        RlpList rlpList = new RlpList(values);
        return RlpEncoder.encode(rlpList);
    }

    static List<RlpType> asRlpValues(
            RawTransaction rawTransaction, Sign.SignatureData signatureData) {
        List<RlpType> result = new ArrayList<>();

        result.add(RlpString.create(rawTransaction.getNonce()));
        result.add(RlpString.create(rawTransaction.getGasPrice()));
        result.add(RlpString.create(rawTransaction.getGasLimit()));

        // an empty to address (contract creation) should not be encoded as a numeric 0 value
        String to = rawTransaction.getTo();
        if (to != null && to.length() > 0) {
            // addresses that start with zeros should be encoded with the zeros included, not
            // as numeric values
            result.add(RlpString.create(Numeric.hexStringToByteArray(to)));
        } else {
            result.add(RlpString.create(""));
        }

        result.add(RlpString.create(rawTransaction.getValue()));

        // value field will already be hex encoded, so we need to convert into binary first
        byte[] data = Numeric.hexStringToByteArray(rawTransaction.getData());
        result.add(RlpString.create(data));

        if (signatureData != null) {
            result.add(RlpString.create(signatureData.getV()));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getR())));
            result.add(RlpString.create(Bytes.trimLeadingZeroes(signatureData.getS())));
        }

        return result;
    }


    private ECKeyPair getAdminKeyPair()
    {
        byte[] adminPrivKey = Numeric.hexStringToByteArray(CONTRACT_KEY);
        ECKeyPair adminKey = ECKeyPair.create(adminPrivKey);
        return adminKey;
    }

    private Single<byte[]> signTransaction(ECKeyPair key, String toAddress, BigInteger value,
                                           BigInteger gasPrice, BigInteger gasLimit, long nonce, byte[] data,
                                           long chainId) {
        return Single.fromCallable(() -> {
            Sign.SignatureData sigData;
            String dataStr = data != null ? Numeric.toHexString(data) : "";

            RawTransaction rtx = RawTransaction.createTransaction(
                    BigInteger.valueOf(nonce),
                    gasPrice,
                    gasLimit,
                    toAddress,
                    value,
                    dataStr
            );

            byte[] signData = TransactionEncoder.encode(rtx, chainId);
            sigData = Sign.signMessage(signData, key);
            sigData = TransactionEncoder.createEip155SignatureData(sigData, chainId);
            return encode(rtx, sigData);
        }).subscribeOn(Schedulers.io());
    }

    private String load(String fileName) {
        String rtn = "";
        try {
            char[] array = new char[2048];
            FileReader r = new FileReader(fileName);
            r.read(array);

            rtn = new String(array);
            r.close();

        } catch (IOException e)
        {
            e.printStackTrace();
        }

        return rtn;
    }

    private String loadFile(String fileName) {
        byte[] buffer = new byte[0];
        try {
            InputStream in = getClass()
                    .getClassLoader().getResourceAsStream(fileName);
            buffer = new byte[in.available()];
            int len = in.read(buffer);
            if (len < 1) {
                throw new IOException("Nothing is read.");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return new String(buffer);
    }
}